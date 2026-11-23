#!/usr/bin/env python3
"""Fail-closed validation for a VM acceptance receipt bound to a candidate run."""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
import zlib

SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
RUN_MARKER = b"\n__JJDGUARD_ARCHIVE_BELOW__\n"
HEADER_PUBLIC_KEY = re.compile(rb"^EMBEDDED_PUBLIC_KEY='([A-Za-z0-9+/_=-]+)'$", re.MULTILINE)
HEADER_SIGNATURE = re.compile(rb"^EMBEDDED_HEADER_SIGNATURE='([A-Za-z0-9+/_=-]+)'$", re.MULTILINE)
HEADER_SIGNATURE_PLACEHOLDER = b"__EMBEDDED_HEADER_SIGNATURE__"
HEADER_SIGNATURE_DOMAIN = b"jjdguard-offline-run-header/v1\0"
RUN_MANIFEST_SIGNATURE_DOMAIN = b"jjdguard-offline-run-manifest/v2\0"
INNER_MANIFEST_SIGNATURE_DOMAIN = b"jjdguard-offline-manifest/v2\0"
INNER_BUNDLE_ROOT = re.compile(r"(?:jjdguard|agent-platform)-[A-Za-z0-9._-]+$")
AGENT_KIT_PREFIX = "deploy/docker-compose/agent-kit/"
PLATFORM_MANIFEST_KEYS = frozenset(
    {"product_profile", "product_name", "product_version", "product_slug", "agent_kit_sha256"}
)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_RUN_HEADER_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024 * 1024
MAX_RUN_ARTIFACT_BYTES = MAX_PAYLOAD_BYTES + MAX_RUN_HEADER_BYTES + (2 * MAX_JSON_BYTES) + 1024 * 1024
SNAPSHOT_SIDECAR_HEADROOM_BYTES = 64 * 1024 * 1024
MAX_OUTER_MEMBERS = 3
MAX_INNER_MEMBERS = 50_000
MAX_INNER_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
MAX_INNER_UNPACKED_BYTES = 32 * 1024 * 1024 * 1024
MAX_INNER_TRAILING_ZERO_BYTES = 1024 * 1024
MAX_SBOM_DOCUMENTS = 4096
MAX_SBOM_BYTES = 128 * 1024 * 1024
MAX_TASK4_DOCUMENTS = 8
MAX_TASK4_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_ENTRIES = 4096
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024 * 1024
HOME_MIGRATION_BASELINE_NAME = "home-migration-baseline.json"
HOME_MIGRATION_BASELINE_SCHEMA = "jjdguard-home-migration-baseline/v1"
MAX_HOME_MIGRATION_BASELINE_BYTES = 1024 * 1024
MAX_HOME_MIGRATION_ENTRIES = 4096
MIGRATION_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
OUTER_MEMBERS = frozenset({"payload.tar.gz", "run-manifest.json", "run-manifest.sig"})
INNER_REQUIRED_FILES = frozenset(
    {
        "manifest.json",
        "manifest.sig",
        "deploy/docker-compose/manifest.json",
        "deploy/docker-compose/upgrade-min-data-version",
        "deploy/docker-compose/upgrade-bridge-target-version",
        "release-source.json",
        "image-provenance.json",
        "sbom/index.json",
    }
)
TOOLCHAIN_KEYS = {
    "docker_client_version",
    "docker_server_version",
    "buildx_version",
    "buildx_builder",
    "buildx_nodes",
}
BUILD_NODE_KEYS = {"name", "endpoint", "status", "buildkit_version"}
COMMON_IMAGE_KEYS = {
    "runtime_tag",
    "profile",
    "kind",
    "component",
    "expected_digest",
    "actual_digest",
    "dockerfile",
    "context",
    "platform",
    "image_id",
    "oci_config_digest",
    "build_args",
    "sbom",
}
ALLOWED_BUILD_ARGS = {
    "VITE_BILLING_ENABLED",
    "NEXT_PUBLIC_BILLING_ENABLED",
    "LLAMA_CPP_REVISION",
    "LLAMA_CPP_COMMIT_COUNT",
    "LOCAL_RUNTIME_IMAGE",
    "SECURITY_ENGINE_BUILD",
}
HOME_RUNTIME_COMPONENTS = frozenset({"llm-judge", "portal-proxy"})
PORTAL_PROXY_RUNTIME_IMAGE = "chat-portal/portal-proxy:0.1.0"
PORTAL_PROXY_PNPM_LOCK = "portal-proxy/pnpm-lock.yaml"
PRISMA_ENGINE_LOCK = "deploy/docker-compose/release-prisma-engines.lock.json"
SECURITY_ENGINE_PYTHON_DEPS_LOCK = "apps/security-engine/requirements.offline.lock"
SECURITY_ENGINE_BUILD_CONTRACT = "deploy/docker-compose/security-engine-build-identity.contract"
SECURITY_ENGINE_PYTHON_DEPS_SCHEMA = "jjdguard-security-engine-python-deps/v1"
SECURITY_ENGINE_PYTHON_DEPS_ORIGIN = "home-existing-security-engine-image"
SECURITY_ENGINE_PYTHON_DEPS_IMAGE = "docker-compose-security-engine:latest"
REQUIREMENT_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\ ]+)")
SENSITIVE_BUILD_ARG = re.compile(r"(?:api.?key|password|secret|token|cookie)", re.IGNORECASE)
DOCKERFILE_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DOCKERFILE_STAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
DOCKERFILE_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
TASK4_LEGACY_RECEIPTS = {
    "enterprise-ai-portal": "task4/portal-image-receipt.json",
    "tier1-classifier": "task4/tier1-image-receipt.json",
}
TASK4_RECEIPT_COMPONENTS = {
    "enterprise-ai-portal": "portal",
    "tier1-classifier": "tier1",
}
SAFE_TAR_MEMBER_TYPES = frozenset({tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE})

REQUIRED_SCENARIOS = frozenset(
    {
        "n1-install",
        "clean-install",
        "offline-reboot",
        "upgrade-n1-r7",
        "rollback-r7-n1",
        "reupgrade-n1-r7",
        "tamper-run",
        "tamper-manifest",
        "tamper-sbom",
        "tamper-provenance",
        "tamper-receipt",
        "browser-login",
        "model-api",
        "model-stream",
        "security-benign",
        "security-block",
        "security-audit",
        "portal-proxy-idp-chat",
    }
)


def fail(message: str) -> None:
    raise SystemExit(f"[error] acceptance receipt rejected: {message}")


class ExtensionFreeTarInfo(tarfile.TarInfo):
    @classmethod
    def fromtarfile(cls, archive: tarfile.TarFile) -> tarfile.TarInfo:
        header = archive.fileobj.read(tarfile.BLOCKSIZE)
        member = cls.frombuf(header, archive.encoding, archive.errors)
        if member.type not in SAFE_TAR_MEMBER_TYPES:
            raise tarfile.SubsequentHeaderError("tar extension records are forbidden")
        member.offset = archive.fileobj.tell() - tarfile.BLOCKSIZE
        return member._proc_member(archive)


class ExtensionFreeTarFile(tarfile.TarFile):
    tarinfo = ExtensionFreeTarInfo


class InnerMemberReader:
    def __init__(self, archive: "BoundedGzipTar") -> None:
        self.archive = archive

    def __enter__(self) -> "InnerMemberReader":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        return self.archive.read_current_member(size)

    def close(self) -> None:
        pass


class BoundedGzipTar:
    def __init__(self, source: Any) -> None:
        self.source = source
        self.gzip_stream: gzip.GzipFile | None = None
        self.current: tarfile.TarInfo | None = None
        self.current_data_remaining = 0
        self.current_padding_remaining = 0
        self.finished = False

    def _read(self, size: int) -> bytes:
        if self.gzip_stream is None:
            raise tarfile.ReadError("inner gzip stream is unavailable")
        return self.gzip_stream.read(size)

    def _read_exact(self, size: int, label: str) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = self._read(remaining)
            if not chunk:
                raise tarfile.ReadError(f"{label} is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _skip_current_member(self) -> None:
        while self.current_data_remaining:
            amount = min(1024 * 1024, self.current_data_remaining)
            self._read_exact(amount, "inner tar member")
            self.current_data_remaining -= amount
        if self.current_padding_remaining:
            self._read_exact(self.current_padding_remaining, "inner tar member padding")
            self.current_padding_remaining = 0

    def read_current_member(self, size: int = -1) -> bytes:
        if self.current is None or not self.current.isfile():
            return b""
        if size < 0:
            size = self.current_data_remaining
        amount = min(size, self.current_data_remaining)
        if amount == 0:
            return b""
        value = self._read_exact(amount, "inner tar member")
        self.current_data_remaining -= len(value)
        return value

    def extractfile(self, member: tarfile.TarInfo) -> InnerMemberReader | None:
        if member is not self.current or not member.isfile():
            return None
        return InnerMemberReader(self)

    def __iter__(self) -> "BoundedGzipTar":
        return self

    def __next__(self) -> tarfile.TarInfo:
        if self.finished:
            raise StopIteration
        self._skip_current_member()
        header = self._read_exact(tarfile.BLOCKSIZE, "inner tar header")
        if not any(header):
            second = self._read_exact(tarfile.BLOCKSIZE, "inner tar end marker")
            if any(second):
                raise tarfile.ReadError("inner tar end marker is incomplete")
            trailing_zero_bytes = 0
            while True:
                tail = self._read(tarfile.BLOCKSIZE)
                if not tail:
                    break
                if len(tail) != tarfile.BLOCKSIZE:
                    raise tarfile.ReadError("inner bundle trailing tar padding is truncated")
                if any(tail):
                    raise tarfile.ReadError("inner bundle has non-zero trailing tar data")
                trailing_zero_bytes += len(tail)
                if trailing_zero_bytes > MAX_INNER_TRAILING_ZERO_BYTES:
                    raise tarfile.ReadError("inner bundle trailing tar padding exceeds the size limit")
            self.finished = True
            raise StopIteration
        member = tarfile.TarInfo.frombuf(header, tarfile.ENCODING, "surrogateescape")
        if member.type not in SAFE_TAR_MEMBER_TYPES:
            raise tarfile.SubsequentHeaderError("tar extension records are forbidden")
        self.current = member
        self.current_data_remaining = member.size
        self.current_padding_remaining = (-member.size) % tarfile.BLOCKSIZE
        return member

    def __enter__(self) -> "BoundedGzipTar":
        source = self.source
        self.gzip_stream = gzip.GzipFile(fileobj=source, mode="rb")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            if exc_type is None and not self.finished:
                raise tarfile.ReadError("inner tar was not fully consumed")
        finally:
            if self.gzip_stream is not None:
                self.gzip_stream.close()
                self.gzip_stream = None
        return False


class DockerfileContractError(ValueError):
    pass


def require_regular(path: pathlib.Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not a regular non-symlink file")
    return metadata


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def same_regular_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and getattr(left, "st_mtime_ns", None) == getattr(right, "st_mtime_ns", None)
        and getattr(left, "st_ctime_ns", None) == getattr(right, "st_ctime_ns", None)
    )


def read_regular_json(
    path: pathlib.Path, label: str, maximum_size: int = MAX_JSON_BYTES
) -> tuple[Any, str]:
    """Read JSON once from a no-follow descriptor bound to its lstat inode."""
    listed = require_regular(path, label)
    if listed.st_size > maximum_size:
        fail(f"{label} exceeds the size limit")
    try:
        absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError) as error:
        fail(f"{label} path is invalid: {error}")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_absolute_directory(absolute.parent, f"{label} parent")
        file_flags = require_open_flags(
            ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"), label
        )
        descriptor = open_at(absolute.name, file_flags, label, parent_descriptor)
        try:
            opened = os.fstat(descriptor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if not same_regular_file(listed, opened):
            fail(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        copied = 0
        while True:
            try:
                chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - copied))
            except OSError as error:
                fail(f"cannot read {label}: {error}")
            if not chunk:
                break
            copied += len(chunk)
            if copied > maximum_size:
                fail(f"{label} exceeds the size limit while reading")
            chunks.append(chunk)
        try:
            finished = os.fstat(descriptor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if not same_regular_file(opened, finished) or copied != listed.st_size:
            fail(f"{label} changed while it was read")
        raw = b"".join(chunks)
    finally:
        if descriptor >= 0:
            close_descriptor(descriptor)
        if parent_descriptor >= 0:
            close_descriptor(parent_descriptor)
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        fail(f"invalid {label} JSON: {error}")
    return value, hashlib.sha256(raw).hexdigest()


def load_json(path: pathlib.Path, label: str) -> Any:
    value, _ = read_regular_json(path, label)
    return value


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys are not exact")
    return value


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"invalid {label}")
    return value


def require_revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GIT_SHA1.fullmatch(value):
        fail(f"invalid {label}")
    return value


def require_utc_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        fail(f"invalid {label}")
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"invalid {label}")
    return value


def normalize_public_key(raw: bytes, label: str) -> bytes:
    if not raw or len(raw) > MAX_PUBLIC_KEY_BYTES:
        fail(f"{label} has an invalid size")
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-pubout"],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        fail(f"openssl is unavailable while validating {label}: {error}")
    if result.returncode != 0 or not result.stdout:
        fail(f"{label} is not a valid public key")
    return result.stdout


def verify_ed25519(public_key: bytes, signature: bytes, payload: bytes, label: str) -> None:
    if len(signature) != 64:
        fail(f"{label} signature length is invalid")
    with tempfile.TemporaryDirectory(prefix="jjdguard-receipt-") as directory:
        root = pathlib.Path(directory)
        key_path = root / "release.pub"
        signature_path = root / "signature.bin"
        payload_path = root / "payload.bin"
        key_path.write_bytes(public_key)
        signature_path.write_bytes(signature)
        payload_path.write_bytes(payload)
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-sigfile",
                    str(signature_path),
                    "-in",
                    str(payload_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as error:
            fail(f"openssl is unavailable while validating {label}: {error}")
    if result.returncode != 0:
        fail(f"{label} signature is invalid")


def decode_header_value(matches: list[bytes], label: str) -> bytes:
    if len(matches) != 1:
        fail(f"run header {label} is missing or ambiguous")
    try:
        return base64.b64decode(matches[0], validate=True)
    except ValueError as error:
        fail(f"run header {label} is not base64: {error}")


def verify_header_signature(
    run_descriptor: int, supplied_public_key: pathlib.Path | None
) -> tuple[int, bytes | None]:
    try:
        with open_run_artifact_stream(run_descriptor, "run header") as stream:
            stream.seek(0)
            prefix = stream.read(MAX_RUN_HEADER_BYTES + 1)
    except OSError as error:
        fail(f"run header cannot be read: {error}")
    marker_offset = prefix.find(RUN_MARKER)
    if marker_offset < 0:
        fail("run payload marker is missing or too far into the header")
    archive_offset = marker_offset + len(RUN_MARKER)
    if archive_offset > MAX_RUN_HEADER_BYTES:
        fail("run header exceeds the size limit")
    header = prefix[:archive_offset]

    raw_key_matches = HEADER_PUBLIC_KEY.findall(header)
    raw_signature_matches = HEADER_SIGNATURE.findall(header)
    if supplied_public_key is None:
        if raw_key_matches != [b"sha256-only"] or raw_signature_matches != [b"sha256-only"]:
            fail("SHA-256 package header identity is missing or ambiguous")
        return archive_offset, None

    require_regular(supplied_public_key, "release public key")
    if supplied_public_key.stat().st_size > MAX_PUBLIC_KEY_BYTES:
        fail("release public key exceeds the size limit")
    try:
        supplied_key = normalize_public_key(supplied_public_key.read_bytes(), "release public key")
    except OSError as error:
        fail(f"release public key cannot be read: {error}")
    embedded_key = decode_header_value(HEADER_PUBLIC_KEY.findall(header), "public key")
    signature = decode_header_value(HEADER_SIGNATURE.findall(header), "signature")
    canonical_header, substitutions = HEADER_SIGNATURE.subn(
        b"EMBEDDED_HEADER_SIGNATURE='" + HEADER_SIGNATURE_PLACEHOLDER + b"'", header
    )
    if substitutions != 1:
        fail("run header signature field is ambiguous")
    if normalize_public_key(embedded_key, "run header public key") != supplied_key:
        fail("run header public key does not match the supplied release public key")
    verify_ed25519(supplied_key, signature, HEADER_SIGNATURE_DOMAIN + canonical_header, "run header")
    return archive_offset, supplied_key


def verify_signature_or_sha256(
    public_key: bytes | None,
    evidence: bytes,
    signed_payload: bytes,
    hashed_payload: bytes,
    filename: str,
    label: str,
) -> None:
    if public_key is not None:
        verify_ed25519(public_key, evidence, signed_payload, label)
        return
    try:
        line = evidence.decode("ascii")
    except UnicodeError as error:
        fail(f"{label} SHA-256 evidence is invalid: {error}")
    expected = hashlib.sha256(hashed_payload).hexdigest() + "  " + filename + "\n"
    if line != expected:
        fail(f"{label} SHA-256 evidence does not match")


def parse_run_manifest(raw: bytes, payload_size: int) -> dict[str, Any]:
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        fail(f"invalid run manifest: {error}")
    keys = {
        "schema",
        "product",
        "version",
        "target_arch",
        "bundle_profile",
        "include_chat",
        "artifact_stage",
        "source_revision",
        "source_tree",
        "image_provenance_sha256",
        "sbom_index_sha256",
        "payload_sha256",
        "payload_size",
        "built_at",
    }
    manifest = require_exact_object(manifest, keys, "run manifest")
    if manifest["schema"] != "jjdguard-offline-run-manifest/v2" or (
        not isinstance(manifest["product"], str)
        or re.fullmatch(r"[0-9A-Za-z._ -]+", manifest["product"]) is None
    ):
        fail("run manifest schema or product is invalid")
    if manifest["artifact_stage"] != "candidate":
        fail("run manifest is not a candidate")
    if manifest["target_arch"] not in {"amd64", "arm64"}:
        fail("run manifest architecture is invalid")
    if manifest["bundle_profile"] not in {"lite", "full"} or manifest["include_chat"] not in {"0", "1"}:
        fail("run manifest selection is invalid")
    if not isinstance(manifest["version"], str) or not re.fullmatch(r"[0-9A-Za-z.-]+", manifest["version"]):
        fail("run manifest version is invalid")
    if not isinstance(manifest["payload_size"], int) or manifest["payload_size"] != payload_size:
        fail("run manifest payload size drifted")
    if not isinstance(manifest["built_at"], str) or not TIMESTAMP.fullmatch(manifest["built_at"]):
        fail("run manifest build time is invalid")
    require_revision(manifest["source_revision"], "run source revision")
    require_revision(manifest["source_tree"], "run source tree")
    for key in ("image_provenance_sha256", "sbom_index_sha256", "payload_sha256"):
        require_hash(manifest[key], f"run {key}")
    return manifest


def read_member(outer: tarfile.TarFile, member: tarfile.TarInfo, limit: int, label: str) -> bytes:
    if member.size > limit:
        fail(f"{label} exceeds the size limit")
    source = outer.extractfile(member)
    if source is None:
        fail(f"{label} cannot be read")
    with source:
        raw = source.read(limit + 1)
    if len(raw) != member.size or len(raw) > limit:
        fail(f"{label} is truncated or exceeds the size limit")
    return raw


def hash_member(outer: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    source = outer.extractfile(member)
    if source is None:
        fail("run payload cannot be read")
    digest = hashlib.sha256()
    seen = 0
    with source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            seen += len(chunk)
            digest.update(chunk)
    if seen != member.size:
        fail("run payload is truncated")
    return digest.hexdigest()


def validate_outer_member(member: tarfile.TarInfo, members: dict[str, int]) -> None:
    if len(members) >= MAX_OUTER_MEMBERS:
        fail("run outer archive has too many members")
    if (
        member.name not in OUTER_MEMBERS
        or member.name in members
        or not member.isfile()
        or member.issparse()
        or member.issym()
        or member.islnk()
        or member.size < 1
        or (member.name == "payload.tar.gz" and member.size > MAX_PAYLOAD_BYTES)
        or member.pax_headers
    ):
        fail("run outer member is unsafe")
    members[member.name] = member.size


def load_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        fail(f"invalid {label} JSON: {error}")


def git_output(repository: pathlib.Path, *arguments: str) -> str:
    if not repository.is_dir() or repository.is_symlink():
        fail("authoritative source repository is not a real directory")
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError as error:
        fail(f"git is unavailable during source validation: {error}")
    if result.returncode != 0:
        fail(f"authoritative source lookup failed: {' '.join(arguments)}")
    return result.stdout.strip()


def source_archive_sha256(repository: pathlib.Path, revision: str) -> str:
    environment = os.environ.copy()
    environment["GIT_NO_LAZY_FETCH"] = "1"
    try:
        process = subprocess.Popen(
            ["git", "-C", str(repository), "archive", "--format=tar", "--prefix=source/", revision],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
    except OSError as error:
        fail(f"git is unavailable while reproducing the source archive: {error}")
    assert process.stdout is not None
    digest = hashlib.sha256()
    try:
        with process.stdout:
            for block in iter(lambda: process.stdout.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        process.kill()
        process.wait()
        fail(f"source archive cannot be read: {error}")
    if process.wait() != 0:
        fail("source archive cannot be reproduced from the trusted revision")
    return digest.hexdigest()


def authoritative_syft_hash(
    repository: pathlib.Path, remote: str, source_revision: str, source_tree: str
) -> str:
    if not isinstance(remote, str) or not remote:
        fail("authoritative source remote is invalid")
    if git_output(repository, "remote", "get-url", "origin") != remote:
        fail("authoritative source repository remote drifted")
    main_revision = git_output(repository, "rev-parse", "refs/remotes/origin/main^{commit}")
    main_tree = git_output(repository, "rev-parse", "refs/remotes/origin/main^{tree}")
    if main_revision != source_revision or main_tree != source_tree:
        fail("candidate source identity does not match fetched Gitee main")
    lock = git_output(repository, "show", f"{source_revision}:deploy/docker-compose/release-toolchain.lock")
    values = re.findall(r"^syft_binary_sha256=([0-9a-f]{64})$", lock, flags=re.MULTILINE)
    if len(values) != 1:
        fail("authoritative source does not pin one Syft binary hash")
    return values[0]


def parse_image_catalog(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen_tags: set[str] = set()
    seen_components: set[str] = set()
    for number, source_line in enumerate(raw.splitlines(), 1):
        line = source_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 7:
            fail(f"authoritative image catalog line {number} does not contain seven fields")
        runtime_tag, profile, kind, component, digest, dockerfile, context = fields
        if not runtime_tag or "@sha256:" in runtime_tag:
            fail(f"authoritative image catalog line {number} has an invalid runtime tag")
        if profile not in {"common", "full", "chat"}:
            fail(f"authoritative image catalog line {number} has an invalid profile")
        if kind not in {"first-party", "upstream-source", "home-runtime", "third-party"}:
            fail(f"authoritative image catalog line {number} has an invalid source kind")
        if COMPONENT.fullmatch(component) is None:
            fail(f"authoritative image catalog line {number} has an invalid component")
        if kind == "third-party":
            if IMAGE_ID.fullmatch(digest) is None or dockerfile != "-" or context != "-":
                fail(f"authoritative image catalog line {number} has an invalid third-party contract")
        elif digest != "-" or dockerfile == "-" or context == "-":
            fail(f"authoritative image catalog line {number} has an invalid source-built contract")
        if runtime_tag in seen_tags or component in seen_components:
            fail(f"authoritative image catalog line {number} duplicates a tag or component")
        seen_tags.add(runtime_tag)
        seen_components.add(component)
        rows.append(
            {
                "runtime_tag": runtime_tag,
                "profile": profile,
                "kind": kind,
                "component": component,
                "expected_digest": digest,
                "dockerfile": dockerfile,
                "context": context,
            }
        )
    if not rows:
        fail("authoritative image catalog is empty")
    return rows


def selected_image_catalog(
    rows: list[dict[str, str]], profile: str, include_chat: bool
) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row["profile"] == "common"
        or (profile == "full" and row["profile"] == "full")
        or (include_chat and row["profile"] == "chat")
    ]


def provenance_images(raw: bytes) -> dict[str, str]:
    provenance = load_json_bytes(raw, "inner image provenance")
    images = provenance.get("images") if isinstance(provenance, dict) else None
    if not isinstance(images, list) or not images:
        fail("inner image provenance image list is invalid")
    result: dict[str, str] = {}
    for image in images:
        if not isinstance(image, dict):
            fail("inner image provenance entry is invalid")
        component = image.get("component")
        image_id = image.get("image_id")
        if (
            not isinstance(component, str)
            or COMPONENT.fullmatch(component) is None
            or component in result
            or not isinstance(image_id, str)
            or IMAGE_ID.fullmatch(image_id) is None
        ):
            fail("inner image provenance component or image ID is invalid")
        result[component] = image_id
    return result


def validate_provenance_toolchain(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TOOLCHAIN_KEYS:
        fail("inner image provenance build toolchain fields do not match the schema")
    for key in TOOLCHAIN_KEYS - {"buildx_nodes"}:
        if not isinstance(value[key], str) or not value[key] or any(
            character in value[key] for character in "\r\n\x00"
        ):
            fail("inner image provenance build toolchain identity is incomplete")
    nodes = value["buildx_nodes"]
    if not isinstance(nodes, list) or not nodes:
        fail("inner image provenance build toolchain nodes are incomplete")
    names: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict) or set(node) != BUILD_NODE_KEYS:
            fail("inner image provenance build node fields do not match the schema")
        for field in BUILD_NODE_KEYS:
            candidate = node[field]
            if not isinstance(candidate, str) or not candidate or any(
                character in candidate for character in "\r\n\x00"
            ):
                fail("inner image provenance build node identity is incomplete")
        if node["name"] in names:
            fail("inner image provenance build toolchain contains a duplicate node")
        names.add(node["name"])
    return value


def validate_provenance_build_engine(value: Any, toolchain: dict[str, Any], component: str) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        fail(f"inner image provenance build engine is invalid for {component}")
    if value["kind"] == "buildx":
        if set(value) != {"kind", "builder", "nodes"}:
            fail(f"inner image provenance Buildx fields are invalid for {component}")
        if value["builder"] != toolchain["buildx_builder"] or value["nodes"] != toolchain["buildx_nodes"]:
            fail(f"inner image provenance Buildx identity drifted for {component}")
        return
    if value["kind"] == "docker-daemon":
        if set(value) != {"kind", "docker_client_version", "docker_server_version"}:
            fail(f"inner image provenance Docker engine fields are invalid for {component}")
        if (
            value["docker_client_version"] != toolchain["docker_client_version"]
            or value["docker_server_version"] != toolchain["docker_server_version"]
        ):
            fail(f"inner image provenance Docker engine identity drifted for {component}")
        return
    fail(f"inner image provenance build engine kind is invalid for {component}")


def validate_provenance_sbom(value: Any, component: str) -> None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        fail(f"inner image provenance SBOM reference is invalid for {component}")
    path = value["path"]
    digest = value["sha256"]
    if path is None and digest is None:
        return
    if not isinstance(path, str) or not path:
        fail(f"inner image provenance SBOM path is invalid for {component}")
    parts = tuple(path.split("/"))
    if path.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        fail(f"inner image provenance SBOM path is not canonical for {component}")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        fail(f"inner image provenance SBOM hash is invalid for {component}")


def dockerfile_logical_instructions(text: str, source: str):
    escape = "\\"
    pending: list[str] = []
    pending_line = 0
    instructions_started = False

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.lstrip()
        if not pending and stripped.startswith("#"):
            if not instructions_started:
                match = re.fullmatch(r"#\s*escape\s*=\s*([\\`])\s*", stripped, re.IGNORECASE)
                if match:
                    escape = match.group(1)
            continue
        if not pending and not stripped:
            continue

        instructions_started = True
        trimmed = raw_line.rstrip()
        trailing = len(trimmed) - len(trimmed.rstrip(escape))
        continued = trailing % 2 == 1
        if not pending:
            pending_line = line_number
        pending.append((trimmed[:-1] if continued else trimmed).strip())
        if continued:
            continue

        instruction = " ".join(part for part in pending if part)
        pending.clear()
        if instruction:
            yield pending_line, instruction

    if pending:
        raise DockerfileContractError(f"{source}:{pending_line}: unterminated Dockerfile continuation")


def expand_dockerfile_reference(
    reference: str, arguments: dict[str, str | None], source: str, line: int
) -> str:
    resolved = reference
    for _ in range(len(arguments) + 2):
        unresolved: set[str] = set()

        def replace(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            value = arguments.get(name)
            if value is None:
                unresolved.add(name)
                return match.group(0)
            return value

        updated = DOCKERFILE_VARIABLE.sub(replace, resolved)
        if unresolved:
            names = ",".join(sorted(unresolved))
            raise DockerfileContractError(
                f"{source}:{line}: unresolved build argument in FROM: {names}"
            )
        if updated == resolved:
            return updated
        resolved = updated
    raise DockerfileContractError(f"{source}:{line}: recursive build argument in FROM")


def parse_trusted_dockerfile_base_images(text: str, source: str) -> list[dict[str, object]]:
    global_arguments: dict[str, str | None] = {}
    stages: set[str] = set()
    bases: list[dict[str, object]] = []
    from_index = 0
    seen_from = False

    for line_number, instruction in dockerfile_logical_instructions(text, source):
        fields = instruction.split(None, 1)
        keyword = fields[0].upper()
        body = fields[1].strip() if len(fields) == 2 else ""

        if keyword == "ARG" and not seen_from:
            if not body:
                raise DockerfileContractError(f"{source}:{line_number}: empty ARG instruction")
            name, separator, default = body.partition("=")
            name = name.strip()
            if not DOCKERFILE_ARG_NAME.fullmatch(name):
                raise DockerfileContractError(f"{source}:{line_number}: invalid ARG name: {name}")
            global_arguments[name] = default.strip() if separator else None
            continue
        if keyword != "FROM":
            continue

        seen_from = True
        try:
            tokens = shlex.split(body, posix=True)
        except ValueError as error:
            raise DockerfileContractError(f"{source}:{line_number}: invalid FROM: {error}") from error
        while tokens and tokens[0].startswith("--"):
            tokens.pop(0)
        if len(tokens) not in {1, 3} or (len(tokens) == 3 and tokens[1].upper() != "AS"):
            raise DockerfileContractError(f"{source}:{line_number}: invalid FROM instruction")

        raw_reference = tokens[0]
        stage = tokens[2] if len(tokens) == 3 else None
        reference = expand_dockerfile_reference(raw_reference, global_arguments, source, line_number)
        internal = reference.lower() in stages
        if not internal and reference.lower() != "scratch":
            name, separator, digest = reference.rpartition("@")
            if not separator or not name or IMAGE_ID.fullmatch(digest) is None:
                raise DockerfileContractError(
                    f"{source}:{line_number}: external FROM is not pinned to a sha256 digest: {reference}"
                )
            bases.append(
                {
                    "from_index": from_index,
                    "stage": stage,
                    "reference": reference,
                    "digest": digest,
                }
            )
        if stage is not None:
            if not DOCKERFILE_STAGE_NAME.fullmatch(stage):
                raise DockerfileContractError(f"{source}:{line_number}: invalid stage name: {stage}")
            stages.add(stage.lower())
        from_index += 1

    return bases


def git_dockerfile_base_images(
    repository: pathlib.Path, revision: str, dockerfile: str, component: str
) -> list[dict[str, object]]:
    # Dockerfile bytes are accepted-source data. Parsing rules stay in this
    # trusted verifier so promotion never executes fetched source code.
    try:
        dockerfile_text = git_output(repository, "show", f"{revision}:{dockerfile}")
        return parse_trusted_dockerfile_base_images(dockerfile_text, f"{revision}:{dockerfile}")
    except (OSError, ValueError) as error:
        fail(f"inner image provenance Dockerfile contract is invalid for {component}: {error}")


def git_blob_bytes(repository: pathlib.Path, revision: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "blob", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(f"inner image provenance Git blob verification failed for {path}")
    return result.stdout


def security_engine_build_identity_required(repository: pathlib.Path, revision: str) -> bool:
    path = git_output(repository, "ls-tree", "--name-only", revision, "--", SECURITY_ENGINE_BUILD_CONTRACT)
    if not path:
        return False
    if path != SECURITY_ENGINE_BUILD_CONTRACT or git_blob_bytes(repository, revision, path) != b"source-revision-v1\n":
        fail("inner security-engine build identity contract is invalid")
    return True


def validate_security_engine_build_identity(build_args: Any, revision: str, image_env: Any = None) -> None:
    if GIT_SHA1.fullmatch(revision) is None or build_args != {"SECURITY_ENGINE_BUILD": revision}:
        fail("inner security-engine build identity differs from the source revision")
    if image_env is not None and (
        not isinstance(image_env, list)
        or [item for item in image_env if isinstance(item, str) and item.startswith("SECURITY_ENGINE_BUILD=")]
        != ["SECURITY_ENGINE_BUILD=" + revision]
    ):
        fail("inner security-engine image build identity differs from the source revision")


def validate_security_engine_python_deps(
    value: Any, repository: pathlib.Path, revision: str
) -> None:
    required = {
        "schema", "origin", "source_image", "source_image_id", "requirements_lock_sha256",
        "content_sha256", "file_count", "packages",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail("inner image provenance security-engine Python dependency receipt is invalid")
    lock_bytes = git_blob_bytes(repository, revision, SECURITY_ENGINE_PYTHON_DEPS_LOCK)
    try:
        lines = lock_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("inner image provenance security-engine Python dependency lock is invalid")
    packages: dict[str, str] = {}
    for line in lines:
        match = REQUIREMENT_PIN.match(line)
        if match is None:
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        version = match.group(2)
        if name in packages and packages[name] != version:
            fail("inner image provenance security-engine Python dependency lock has conflicts")
        packages[name] = version
    expected_packages = [{"name": name, "version": packages[name]} for name in sorted(packages)]
    if (
        not expected_packages
        or value.get("schema") != SECURITY_ENGINE_PYTHON_DEPS_SCHEMA
        or value.get("origin") != SECURITY_ENGINE_PYTHON_DEPS_ORIGIN
        or not isinstance(value.get("source_image_id"), str)
        or IMAGE_ID.fullmatch(value["source_image_id"]) is None
        or value.get("source_image") not in {
            SECURITY_ENGINE_PYTHON_DEPS_IMAGE, value["source_image_id"]
        }
        or value.get("requirements_lock_sha256") != hashlib.sha256(lock_bytes).hexdigest()
        or not isinstance(value.get("content_sha256"), str)
        or SHA256.fullmatch(value["content_sha256"]) is None
        or type(value.get("file_count")) is not int
        or value["file_count"] < 1
        or value.get("packages") != expected_packages
    ):
        fail("inner image provenance security-engine Python dependency receipt drifted from lock")


def home_runtime_base_images(
    value: dict[str, Any], runtime_bases: list[tuple[int, str | None]]
) -> list[dict[str, object]]:
    image_id = value.get("source_image_id")
    if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
        fail("inner image provenance home runtime image ID is invalid")
    return [{
        "from_index": from_index,
        "stage": stage,
        "reference": f"home-runtime@{image_id}",
        "digest": image_id,
    } for from_index, stage in runtime_bases]


def validate_home_runtime_dockerfile(
    repository: pathlib.Path, revision: str, dockerfile: str, component: str
) -> list[tuple[int, str | None]]:
    text = git_output(repository, "show", f"{revision}:{dockerfile}")
    if re.search(r"^ARG[ \t]+LOCAL_RUNTIME_IMAGE[ \t]*$", text, flags=re.MULTILINE) is None:
        fail(f"inner image provenance home runtime Dockerfile has no LOCAL_RUNTIME_IMAGE for {component}")
    stages: set[str] = set()
    runtime_bases: list[tuple[int, str | None]] = []
    from_bodies = re.findall(r"^FROM[ \t]+(.+?)\s*$", text, flags=re.MULTILINE | re.IGNORECASE)
    if not from_bodies:
        fail(f"inner image provenance home runtime Dockerfile base contract drifted for {component}")
    for from_index, body in enumerate(from_bodies):
        try:
            fields = shlex.split(body, posix=True)
        except ValueError:
            fail(f"inner image provenance home runtime Dockerfile base contract drifted for {component}")
        while fields and fields[0].startswith("--"):
            fields.pop(0)
        if len(fields) not in {1, 3} or (len(fields) == 3 and fields[1].upper() != "AS"):
            fail(f"inner image provenance home runtime Dockerfile base contract drifted for {component}")
        reference = fields[0]
        stage = fields[2] if len(fields) == 3 else None
        if reference == "${LOCAL_RUNTIME_IMAGE}":
            runtime_bases.append((from_index, stage))
        elif reference.lower() not in stages:
            fail(f"inner image provenance home runtime Dockerfile base contract drifted for {component}")
        if stage is not None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", stage):
            stages.add(stage.lower())
        elif stage is not None:
            fail(f"inner image provenance home runtime Dockerfile base contract drifted for {component}")
    if not runtime_bases:
        fail(f"inner image provenance home runtime Dockerfile base contract drifted for {component}")
    return runtime_bases


def validate_portal_proxy_prisma_engines(
    value: Any,
    repository: pathlib.Path,
    revision: str,
    runtime_image: str,
    runtime_image_id: str,
) -> None:
    required = {
        "schema", "origin", "expected_source_image", "expected_source_image_id",
        "approved_lock_sha256", "runtime_image", "runtime_image_id", "content_sha256",
        "manifest",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail("inner image provenance Portal Proxy Prisma engine receipt is invalid")
    lock_bytes = git_blob_bytes(repository, revision, PRISMA_ENGINE_LOCK)
    try:
        lock = json.loads(lock_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("inner image provenance Portal Proxy Prisma engine lock is invalid")
    manifest = lock.get("manifest") if isinstance(lock, dict) else None
    if (
        value.get("schema") != "jjdguard-release-prisma-runtime/v1"
        or value.get("origin") != lock.get("origin")
        or value.get("expected_source_image") != lock.get("source_image")
        or value.get("expected_source_image_id") != lock.get("source_image_id")
        or value.get("approved_lock_sha256") != hashlib.sha256(lock_bytes).hexdigest()
        or value.get("runtime_image") != runtime_image
        or value.get("runtime_image_id") != runtime_image_id
        or value.get("manifest") != manifest
    ):
        fail("inner image provenance Portal Proxy Prisma engine receipt drifted from the release lock")
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if value.get("content_sha256") != hashlib.sha256(content).hexdigest():
        fail("inner image provenance Portal Proxy Prisma engine content digest is invalid")


def validate_home_runtime(
    value: Any,
    component: str,
    repository: pathlib.Path,
    revision: str,
    dockerfile: str,
    build_args: dict[str, Any],
) -> list[dict[str, object]]:
    if component not in HOME_RUNTIME_COMPONENTS or not isinstance(value, dict):
        fail(f"inner image provenance home runtime is invalid for {component}")
    if component == "llm-judge":
        required = {"source_image", "source_image_id", "entrypoint_sha256"}
        if set(value) != required:
            fail("inner image provenance Judge home runtime fields are invalid")
        if (
            not isinstance(value["source_image"], str)
            or not value["source_image"]
            or not isinstance(value["source_image_id"], str)
            or IMAGE_ID.fullmatch(value["source_image_id"]) is None
            or not isinstance(value["entrypoint_sha256"], str)
            or SHA256.fullmatch(value["entrypoint_sha256"]) is None
        ):
            fail("inner image provenance Judge home runtime is invalid")
        expected_alias = (
            f"jjdguard-release-input/llm-judge:{revision[:12]}-"
            f"{value['source_image_id'].removeprefix('sha256:')[:12]}"
        )
        if build_args != {"LOCAL_RUNTIME_IMAGE": expected_alias}:
            fail("inner image provenance Judge home runtime build arguments are invalid")
    else:
        required = {
            "source_image", "source_image_id", "source_revision", "source_tree",
            "pnpm_version", "pnpm_lock", "prisma_engines",
        }
        if set(value) != required or value.get("source_image") != PORTAL_PROXY_RUNTIME_IMAGE:
            fail("inner image provenance Portal Proxy home runtime fields are invalid")
        if (
            not isinstance(value.get("source_revision"), str)
            or GIT_SHA1.fullmatch(value["source_revision"]) is None
            or not isinstance(value.get("source_tree"), str)
            or GIT_SHA1.fullmatch(value["source_tree"]) is None
            or git_output(repository, "rev-parse", f"{value['source_revision']}^{{tree}}")
            != value["source_tree"]
            or value.get("pnpm_version") != "10.10.0"
            or not isinstance(value.get("source_image_id"), str)
            or IMAGE_ID.fullmatch(value["source_image_id"]) is None
        ):
            fail("inner image provenance Portal Proxy home runtime source binding is invalid")
        expected_alias = (
            f"jjdguard-release-input/portal-proxy:{revision[:12]}-"
            f"{value['source_image_id'].removeprefix('sha256:')[:12]}"
        )
        if build_args != {"LOCAL_RUNTIME_IMAGE": expected_alias}:
            fail("inner image provenance Portal Proxy home runtime build arguments are invalid")
        pnpm_lock = value.get("pnpm_lock")
        if not isinstance(pnpm_lock, dict) or set(pnpm_lock) != {"path", "sha256", "blob"}:
            fail("inner image provenance Portal Proxy pnpm lock is invalid")
        lock_bytes = git_blob_bytes(repository, revision, PORTAL_PROXY_PNPM_LOCK)
        if (
            pnpm_lock.get("path") != PORTAL_PROXY_PNPM_LOCK
            or pnpm_lock.get("blob") != git_output(
                repository, "rev-parse", f"{revision}:{PORTAL_PROXY_PNPM_LOCK}")
            or pnpm_lock.get("sha256") != hashlib.sha256(lock_bytes).hexdigest()
        ):
            fail("inner image provenance Portal Proxy pnpm lock drifted from the release source")
        validate_portal_proxy_prisma_engines(
            value.get("prisma_engines"),
            repository,
            revision,
            value["source_image"],
            value["source_image_id"],
        )
    runtime_bases = validate_home_runtime_dockerfile(repository, revision, dockerfile, component)
    return home_runtime_base_images(value, runtime_bases)


def validate_inner_legacy_receipt(
    value: Any, expected_path: str, files: dict[str, bytes], component: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        fail(f"inner image provenance Task4 receipt metadata is invalid for {component}")
    if value.get("path") != expected_path or not isinstance(value.get("sha256"), str):
        fail(f"inner image provenance Task4 receipt path drifted for {component}")
    expected_sha = require_hash(value["sha256"], f"inner image provenance Task4 receipt hash {component}")
    raw = files.get(expected_path)
    if raw is None or hashlib.sha256(raw).hexdigest() != expected_sha:
        fail(f"inner image provenance Task4 receipt hash drifted for {component}")
    receipt = load_json_bytes(raw, f"inner image provenance Task4 receipt {component}")
    if not isinstance(receipt, dict):
        fail(f"inner image provenance Task4 receipt is invalid for {component}")
    return receipt


def validate_task4_receipt_identity(
    receipt: dict[str, Any],
    component: str,
    entry: dict[str, Any],
    expected_source: dict[str, str],
    expected_dockerfile: str,
    expected_blob: str,
    build_args: dict[str, Any],
) -> None:
    required = {
        "schema",
        "component",
        "revision",
        "candidate_tree",
        "archive_sha256",
        "image",
        "image_id",
        "oci_config_digest",
        "base_images",
        "source_blobs",
        "build_engine",
    }
    if component == "enterprise-ai-portal":
        required.add("build_args")
    if not required.issubset(receipt):
        fail(f"inner image provenance Task4 receipt schema is incomplete for {component}")
    task4_config_digest = receipt.get("oci_config_digest")
    if not isinstance(task4_config_digest, str) or IMAGE_ID.fullmatch(task4_config_digest) is None:
        fail(f"inner image provenance Task4 OCI config digest is invalid for {component}")
    if (
        receipt.get("schema") != "jjdguard-task4-image-receipt/v1"
        or receipt.get("component") != TASK4_RECEIPT_COMPONENTS[component]
        or receipt.get("revision") != expected_source["revision"]
        or receipt.get("candidate_tree") != expected_source["tree"]
        or receipt.get("archive_sha256") != expected_source["archive_sha256"]
        or receipt.get("image") != entry["runtime_tag"]
        or receipt.get("image_id") != entry["image_id"]
        or receipt.get("oci_config_digest") != entry["image_id"]
    ):
        fail(f"inner image provenance Task4 receipt identity drifted for {component}")
    source_blobs = receipt.get("source_blobs")
    if not isinstance(source_blobs, dict) or source_blobs.get(expected_dockerfile) != expected_blob:
        fail(f"inner image provenance Task4 source blob drifted for {component}")
    if receipt.get("base_images") != entry["base_images"]:
        fail(f"inner image provenance Task4 base images drifted for {component}")
    if receipt.get("build_engine") != entry["build_engine"]:
        fail(f"inner image provenance Task4 build engine drifted for {component}")
    if component == "enterprise-ai-portal" and receipt.get("build_args") != build_args:
        fail(f"inner image provenance Task4 build arguments drifted for {component}")


def validate_image_provenance(
    raw: bytes,
    run_manifest: dict[str, Any],
    source_repository: pathlib.Path,
    authoritative_remote: str,
    expected_source_archive_sha256: str,
    files: dict[str, bytes],
) -> None:
    provenance = require_exact_object(
        load_json_bytes(raw, "inner image provenance"),
        {"schema", "generated_at", "platform", "selection", "source", "toolchain", "images"},
        "inner image provenance",
    )
    if provenance["schema"] != "jjdguard-image-provenance/v1":
        fail("inner image provenance schema is invalid")
    require_utc_timestamp(provenance["generated_at"], "inner image provenance generation time")
    expected_platform = f"linux/{run_manifest['target_arch']}"
    if provenance["platform"] != expected_platform:
        fail("inner image provenance platform drifted")
    selection = require_exact_object(
        provenance["selection"],
        {"profile", "include_chat"},
        "inner image provenance selection",
    )
    include_chat = run_manifest["include_chat"] == "1"
    if (
        selection["profile"] != run_manifest["bundle_profile"]
        or not isinstance(selection["include_chat"], bool)
        or selection["include_chat"] != include_chat
    ):
        fail("inner image provenance selection drifted")
    source = require_exact_object(
        provenance["source"],
        {"remote", "revision", "tree", "archive_sha256"},
        "inner image provenance source",
    )
    expected_source = {
        "remote": authoritative_remote,
        "revision": run_manifest["source_revision"],
        "tree": run_manifest["source_tree"],
        "archive_sha256": expected_source_archive_sha256,
    }
    if source != expected_source:
        fail("inner image provenance source binding drifted")
    toolchain = validate_provenance_toolchain(provenance["toolchain"])

    catalog_text = git_output(
        source_repository,
        "show",
        f"{run_manifest['source_revision']}:deploy/docker-compose/images.lst",
    )
    catalog = selected_image_catalog(
        parse_image_catalog(catalog_text), run_manifest["bundle_profile"], include_chat
    )
    images = provenance["images"]
    if not isinstance(images, list) or not all(isinstance(image, dict) for image in images):
        fail("inner image provenance image list is invalid")
    by_component: dict[str, dict[str, Any]] = {}
    for image in images:
        component = image.get("component")
        if not isinstance(component, str) or component in by_component:
            fail("inner image provenance contains a missing or duplicate component")
        by_component[component] = image
    expected_components = {row["component"] for row in catalog}
    if set(by_component) != expected_components:
        fail("inner image provenance component set does not match the authoritative image catalog")

    llama_revisions: list[str] = []
    if any(row["kind"] == "upstream-source" for row in catalog):
        lock = git_output(
            source_repository,
            "show",
            f"{run_manifest['source_revision']}:deploy/docker-compose/release-toolchain.lock",
        )
        llama_revisions = re.findall(r"^llama_cpp_revision=([0-9a-f]{40})$", lock, flags=re.MULTILINE)
        if len(llama_revisions) != 1:
            fail("authoritative source does not pin one llama.cpp revision")

    for row in catalog:
        component = row["component"]
        entry = by_component[component]
        if row["kind"] == "third-party":
            allowed_entry_keys = COMMON_IMAGE_KEYS
        elif row["kind"] == "first-party":
            allowed_entry_keys = COMMON_IMAGE_KEYS | {
                "source",
                "source_blobs",
                "base_images",
                "toolchain",
                "build_engine",
            }
            if component in TASK4_LEGACY_RECEIPTS:
                allowed_entry_keys = allowed_entry_keys | {"legacy_receipt"}
            if component == "security-engine":
                allowed_entry_keys = allowed_entry_keys | {"security_engine_python_deps"}
        elif row["kind"] == "home-runtime":
            allowed_entry_keys = COMMON_IMAGE_KEYS | {
                "source",
                "source_blobs",
                "base_images",
                "toolchain",
                "build_engine",
                "home_runtime",
            }
        else:
            allowed_entry_keys = COMMON_IMAGE_KEYS | {
                "source",
                "source_blobs",
                "base_images",
                "toolchain",
                "build_engine",
                "upstream",
                "wrapper_blobs",
            }
            if component in HOME_RUNTIME_COMPONENTS:
                allowed_entry_keys = allowed_entry_keys | {"home_runtime"}
            if component == "llm-judge":
                allowed_entry_keys = allowed_entry_keys | {"build_mode"}
        if set(entry) != allowed_entry_keys:
            fail(f"inner image provenance fields do not match the {row['kind']} schema for {component}")
        if component == "llm-judge" and entry.get("build_mode") != "home-runtime-reuse":
            fail("inner image provenance Judge home runtime build mode is invalid")
        for key in ("runtime_tag", "profile", "kind", "component"):
            if entry.get(key) != row[key]:
                fail(f"inner image provenance catalog field {key} drifted for {component}")
        expected_digest = None if row["expected_digest"] == "-" else row["expected_digest"]
        expected_dockerfile = None if row["dockerfile"] == "-" else row["dockerfile"]
        expected_context = None if row["context"] == "-" else row["context"]
        if entry.get("expected_digest") != expected_digest:
            fail(f"inner image provenance expected digest drifted for {component}")
        if entry.get("dockerfile") != expected_dockerfile or entry.get("context") != expected_context:
            fail(f"inner image provenance Dockerfile or context drifted for {component}")
        if entry.get("platform") != expected_platform:
            fail(f"inner image provenance platform drifted for {component}")
        image_id = entry.get("image_id")
        if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
            fail(f"inner image provenance image ID is invalid for {component}")
        config_digest = entry.get("oci_config_digest")
        if not isinstance(config_digest, str) or IMAGE_ID.fullmatch(config_digest) is None:
            fail(f"inner image provenance OCI config digest is invalid for {component}")
        build_args = entry.get("build_args")
        if (
            not isinstance(build_args, dict)
            or any(SENSITIVE_BUILD_ARG.search(str(key)) for key in build_args)
            or not set(build_args).issubset(ALLOWED_BUILD_ARGS)
        ):
            fail(f"inner image provenance build argument summary is invalid for {component}")
        security_build_required = component == "security-engine" and security_engine_build_identity_required(
            source_repository, run_manifest["source_revision"]
        )
        if component == "enterprise-ai-portal":
            expected_build_args = {"NEXT_PUBLIC_BILLING_ENABLED"}
        elif component == "web-console":
            expected_build_args = {"VITE_BILLING_ENABLED"}
        elif security_build_required:
            expected_build_args = {"SECURITY_ENGINE_BUILD"}
        elif component in {"llm-judge", "portal-proxy"}:
            expected_build_args = {"LOCAL_RUNTIME_IMAGE"}
        elif row["kind"] == "upstream-source":
            expected_build_args = {"LLAMA_CPP_REVISION", "LLAMA_CPP_COMMIT_COUNT"}
        else:
            expected_build_args = set()
        if set(build_args) != expected_build_args:
            fail(f"inner image provenance build argument key set drifted for {component}")
        if security_build_required:
            validate_security_engine_build_identity(build_args, run_manifest["source_revision"])
        for key, value in build_args.items():
            if key in {"VITE_BILLING_ENABLED", "NEXT_PUBLIC_BILLING_ENABLED"} and value not in {"true", "false"}:
                fail(f"inner image provenance billing build argument is invalid for {component}")
            if key == "LLAMA_CPP_REVISION" and (
                not isinstance(value, str) or GIT_SHA1.fullmatch(value) is None
            ):
                fail(f"inner image provenance llama.cpp revision build argument is invalid for {component}")
            if key == "LLAMA_CPP_COMMIT_COUNT" and (not isinstance(value, int) or value < 1):
                fail(f"inner image provenance llama.cpp commit count build argument is invalid for {component}")
        validate_provenance_sbom(entry.get("sbom"), component)

        if row["kind"] == "third-party":
            if entry.get("actual_digest") != expected_digest:
                fail(f"inner image provenance third-party digest drifted for {component}")
            continue

        if entry.get("actual_digest") is not None:
            fail(f"inner image provenance source-built image has a registry digest for {component}")
        if entry.get("toolchain") != toolchain:
            fail(f"inner image provenance toolchain drifted for {component}")
        validate_provenance_build_engine(entry.get("build_engine"), toolchain, component)
        if entry.get("source") != expected_source:
            fail(f"inner image provenance source identity drifted for {component}")
        source_blobs = entry.get("source_blobs")
        if not isinstance(source_blobs, dict) or set(source_blobs) != {expected_dockerfile}:
            fail(f"inner image provenance Dockerfile blob identity is missing for {component}")
        expected_blob = git_output(
            source_repository,
            "rev-parse",
            f"{run_manifest['source_revision']}:{expected_dockerfile}",
        )
        if source_blobs.get(expected_dockerfile) != expected_blob:
            fail(f"inner image provenance Dockerfile blob identity drifted for {component}")
        if component == "security-engine":
            validate_security_engine_python_deps(
                entry.get("security_engine_python_deps"),
                source_repository,
                run_manifest["source_revision"],
            )
        home_runtime = entry.get("home_runtime")
        if row["kind"] == "home-runtime" and home_runtime is None:
            fail(f"inner image provenance home runtime is missing for {component}")
        if home_runtime is None:
            expected_base_images = git_dockerfile_base_images(
                source_repository, run_manifest["source_revision"], expected_dockerfile, component
            )
        else:
            expected_base_images = validate_home_runtime(
                home_runtime,
                component,
                source_repository,
                run_manifest["source_revision"],
                expected_dockerfile,
                build_args,
            )
        if entry.get("base_images") != expected_base_images:
            fail(f"inner image provenance base image contract drifted for {component}")
        context_spec = (
            f"{run_manifest['source_revision']}^{{tree}}"
            if expected_context == "."
            else f"{run_manifest['source_revision']}:{expected_context}"
        )
        git_output(source_repository, "cat-file", "-e", context_spec)

        expected_legacy_path = TASK4_LEGACY_RECEIPTS.get(component)
        legacy_receipt = entry.get("legacy_receipt")
        if expected_legacy_path is not None:
            if legacy_receipt is None:
                fail(f"inner image provenance Task4 receipt is missing for {component}")
            legacy_payload = validate_inner_legacy_receipt(
                legacy_receipt, expected_legacy_path, files, component
            )
            validate_task4_receipt_identity(
                legacy_payload,
                component,
                entry,
                expected_source,
                expected_dockerfile,
                expected_blob,
                build_args,
            )
        elif legacy_receipt is not None:
            fail(f"inner image provenance has an unexpected Task4 receipt for {component}")

        if row["kind"] == "upstream-source":
            upstream = entry.get("upstream")
            required_upstream = {
                "schema",
                "component",
                "remote",
                "revision",
                "tree",
                "commit_count",
                "archive_file",
                "archive_sha256",
                "archive_size",
            }
            if not isinstance(upstream, dict) or set(upstream) != required_upstream:
                fail(f"inner image provenance upstream receipt is invalid for {component}")
            if (
                upstream.get("schema") != "jjdguard-upstream-source/v1"
                or upstream.get("component") != "llama.cpp"
                or upstream.get("remote") != "https://github.com/ggerganov/llama.cpp.git"
                or upstream.get("revision") != llama_revisions[0]
                or not isinstance(upstream.get("tree"), str)
                or GIT_SHA1.fullmatch(upstream["tree"]) is None
                or not isinstance(upstream.get("commit_count"), int)
                or upstream["commit_count"] < 1
                or upstream.get("archive_file") != "llama.cpp.tar"
                or not isinstance(upstream.get("archive_sha256"), str)
                or SHA256.fullmatch(upstream["archive_sha256"]) is None
                or not isinstance(upstream.get("archive_size"), int)
                or upstream["archive_size"] < 1
            ):
                fail(f"inner image provenance upstream identity is invalid for {component}")
            if component != "llm-judge" and (
                build_args.get("LLAMA_CPP_REVISION") != upstream["revision"]
                or build_args.get("LLAMA_CPP_COMMIT_COUNT") != upstream["commit_count"]
            ):
                fail(f"inner image provenance upstream build arguments drifted for {component}")
            wrapper_path = f"{expected_context}/entrypoint.sh"
            wrapper_blobs = entry.get("wrapper_blobs")
            if not isinstance(wrapper_blobs, dict) or set(wrapper_blobs) != {wrapper_path}:
                fail(f"inner image provenance upstream wrapper blob is missing for {component}")
            expected_wrapper_blob = git_output(
                source_repository,
                "rev-parse",
                f"{run_manifest['source_revision']}:{wrapper_path}",
            )
            if wrapper_blobs.get(wrapper_path) != expected_wrapper_blob:
                fail(f"inner image provenance upstream wrapper blob drifted for {component}")


def validate_spdx(raw: bytes, label: str) -> None:
    document = load_json_bytes(raw, label)
    creation = document.get("creationInfo") if isinstance(document, dict) else None
    creators = creation.get("creators") if isinstance(creation, dict) else None
    packages = document.get("packages") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("spdxVersion"), str)
        or not document["spdxVersion"].startswith("SPDX-")
        or not isinstance(creators, list)
        or "Tool: syft-1.44.0" not in creators
        or not isinstance(packages, list)
        or not packages
        or not all(isinstance(package, dict) for package in packages)
    ):
        fail(f"{label} is not a complete Syft SPDX document")


def validate_sbom_index(files: dict[str, bytes], expected_syft_hash: str) -> None:
    index = load_json_bytes(files["sbom/index.json"], "inner SBOM index")
    if not isinstance(index, dict) or set(index) != {"schema", "syft", "bundle", "images"}:
        fail("inner SBOM index schema is invalid")
    if index.get("schema") != "jjdguard-release-sbom-index/v1":
        fail("inner SBOM index schema version is invalid")
    syft = index.get("syft")
    if (
        not isinstance(syft, dict)
        or set(syft) != {"version", "binary_sha256"}
        or syft.get("version") != "1.44.0"
        or syft.get("binary_sha256") != expected_syft_hash
    ):
        fail("inner SBOM Syft identity is invalid")

    def validate_reference(value: Any, expected_path: str, label: str) -> None:
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            fail(f"inner SBOM reference is invalid: {label}")
        if value.get("path") != expected_path or not isinstance(value.get("sha256"), str):
            fail(f"inner SBOM reference path is invalid: {label}")
        require_hash(value["sha256"], f"inner SBOM reference hash {label}")
        raw = files.get(expected_path)
        if raw is None or hashlib.sha256(raw).hexdigest() != value["sha256"]:
            fail(f"inner SBOM reference hash drifted: {label}")
        validate_spdx(raw, f"inner SBOM {label}")

    validate_reference(index.get("bundle"), "sbom/bundle.spdx.json", "bundle")
    expected_images = provenance_images(files["image-provenance.json"])
    entries = index.get("images")
    if not isinstance(entries, list):
        fail("inner SBOM image index is invalid")
    observed: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"component", "image_id", "path", "sha256"}:
            fail("inner SBOM image entry schema is invalid")
        component = entry.get("component")
        image_id = entry.get("image_id")
        if (
            not isinstance(component, str)
            or component in observed
            or component not in expected_images
            or image_id != expected_images[component]
        ):
            fail("inner SBOM image coverage drifted")
        validate_reference(
            {"path": entry["path"], "sha256": entry["sha256"]},
            f"sbom/images/{component}.spdx.json",
            component,
        )
        observed[component] = image_id
    if observed != expected_images:
        fail("inner SBOM image coverage does not match provenance")


def parse_inner_manifest(raw: bytes, run_manifest: dict[str, Any], root: str, label: str) -> dict[str, Any]:
    manifest = load_json_bytes(raw, label)
    keys = {
        "schema",
        "product",
        "version",
        "source_revision",
        "source_tree",
        "image_provenance_sha256",
        "sbom_index_sha256",
        "target_arch",
        "bundle_profile",
        "include_chat",
        "artifact_stage",
        "min_data_version",
        "manifest_signature",
        "built_at",
        "bundle",
    }
    platform = root.startswith("agent-platform-")
    manifest = require_exact_object(manifest, keys | (PLATFORM_MANIFEST_KEYS if platform else set()), label)
    expected = {
        "schema": "offline-manifest/v2",
        "product": "agent-platform" if platform else "jjdguard-enterprise",
        "version": run_manifest["version"],
        "source_revision": run_manifest["source_revision"],
        "source_tree": run_manifest["source_tree"],
        "image_provenance_sha256": run_manifest["image_provenance_sha256"],
        "sbom_index_sha256": run_manifest["sbom_index_sha256"],
        "target_arch": run_manifest["target_arch"],
        "bundle_profile": run_manifest["bundle_profile"],
        "include_chat": run_manifest["include_chat"],
        "artifact_stage": "candidate",
        "bundle": root,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        fail(f"{label} binding drifted")
    if platform:
        if not run_manifest["signed"]:
            fail(f"{label} platform requires a signed run artifact")
        if (
            manifest["product_profile"] != "agent-platform"
            or manifest["product_name"] != run_manifest["product"]
            or not isinstance(manifest["product_version"], str)
            or re.fullmatch(r"[0-9A-Za-z.-]+", manifest["product_version"]) is None
            or not isinstance(manifest["product_slug"], str)
            or re.fullmatch(r"[a-z0-9-]+", manifest["product_slug"]) is None
        ):
            fail(f"{label} platform identity drifted")
        require_hash(manifest["agent_kit_sha256"], f"{label} agent-kit hash")
    elif run_manifest["product"] != "JJDGuard":
        fail(f"{label} gateway product drifted")
    if manifest["manifest_signature"] != (
        "ed25519-domain-v2" if run_manifest["signed"] else "sha256-only"
    ):
        fail(f"{label} identity mode is invalid")
    if not isinstance(manifest["built_at"], str) or not TIMESTAMP.fullmatch(manifest["built_at"]):
        fail(f"{label} build time is invalid")
    return manifest


def validate_inner_member(member: tarfile.TarInfo) -> tuple[str, tuple[str, ...]]:
    raw_name = member.name
    if raw_name.endswith("/"):
        if not member.isdir():
            fail("inner bundle member is unsafe")
        name = raw_name[:-1]
    else:
        name = raw_name
    parts = tuple(name.split("/"))
    if (
        not name
        or len(name) > 1024
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
        or not (member.isdir() or member.isfile())
        or member.issparse()
        or member.issym()
        or member.islnk()
        or member.linkname
        or member.mode & 0o7000
        or member.pax_headers
        or (member.isdir() and member.size != 0)
    ):
        fail("inner bundle member is unsafe")
    if member.isfile() and (member.size < 0 or member.size > MAX_INNER_MEMBER_BYTES):
        fail("inner bundle member exceeds the size limit")
    return name, parts


def validate_agent_kit(files: dict[str, bytes], manifest: dict[str, Any]) -> None:
    kit_files = sorted(
        (
            (relative.removeprefix(AGENT_KIT_PREFIX), digest)
            for relative, digest in files.items()
            if relative.startswith(AGENT_KIT_PREFIX)
        ),
        key=lambda item: tuple(item[0].split("/")),
    )
    if not any(path.rsplit("/", 1)[-1] != ".gitkeep" for path, _ in kit_files):
        fail("inner platform agent-kit has no distributable payload")
    digest = hashlib.sha256()
    for relative, content_hash in kit_files:
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big") + name)
        digest.update(content_hash)
    if digest.hexdigest() != manifest["agent_kit_sha256"]:
        fail("inner platform agent-kit hash drifted")


def verify_inner_payload(
    outer: tarfile.TarFile,
    payload_member: tarfile.TarInfo,
    public_key: bytes | None,
    run_manifest: dict[str, Any],
    source_repository: pathlib.Path,
    authoritative_remote: str,
    expected_syft_hash: str,
    expected_source_archive_sha256: str,
) -> None:
    source = outer.extractfile(payload_member)
    if source is None:
        fail("run payload cannot be read for inner validation")
    root: str | None = None
    files: dict[str, bytes] = {}
    agent_kit_files: dict[str, bytes] = {}
    agent_kit_root_seen = False
    seen_members: set[str] = set()
    member_count = 0
    unpacked_bytes = 0
    sbom_documents = 0
    sbom_bytes = 0
    task4_documents = 0
    task4_bytes = 0
    try:
        with source:
            with BoundedGzipTar(source) as inner:
                for member in inner:
                    member_count += 1
                    if member_count > MAX_INNER_MEMBERS:
                        fail("inner bundle has too many members")
                    name, parts = validate_inner_member(member)
                    if name in seen_members:
                        fail("inner bundle contains duplicate members")
                    seen_members.add(name)
                    if member.isfile():
                        unpacked_bytes += member.size
                        if unpacked_bytes > MAX_INNER_UNPACKED_BYTES:
                            fail("inner bundle exceeds the unpacked size limit")
                    candidate_root = parts[0]
                    if root is None:
                        if not INNER_BUNDLE_ROOT.fullmatch(candidate_root):
                            fail("inner bundle root is invalid")
                        root = candidate_root
                    elif candidate_root != root:
                        fail("inner bundle has ambiguous roots")
                    relative = "/".join(parts[1:])
                    capture = relative in INNER_REQUIRED_FILES or (
                        member.isfile() and relative.startswith("sbom/")
                    ) or (member.isfile() and relative.startswith("task4/"))
                    if relative == AGENT_KIT_PREFIX[:-1] or relative.startswith(AGENT_KIT_PREFIX):
                        if not candidate_root.startswith("agent-platform-"):
                            fail("inner agent-kit member is invalid")
                        if relative == AGENT_KIT_PREFIX[:-1]:
                            if not member.isdir():
                                fail("inner agent-kit root is not a directory")
                            agent_kit_root_seen = True
                        if member.isfile():
                            kit_path = relative[len(AGENT_KIT_PREFIX):]
                            if not kit_path or any(part in {"", ".", ".."} for part in kit_path.split("/")):
                                fail("inner agent-kit path is invalid")
                            digest = hashlib.sha256()
                            reader = inner.extractfile(member)
                            if reader is None:
                                fail("inner agent-kit file cannot be read")
                            with reader:
                                for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                                    digest.update(chunk)
                            agent_kit_files[relative] = digest.digest()
                        continue
                    if capture:
                        if relative in files:
                            fail("inner bundle required evidence is duplicated")
                        limit = MAX_CHECKSUM_BYTES if relative == "manifest.sig" else MAX_JSON_BYTES
                        if relative.startswith("sbom/"):
                            sbom_documents += 1
                            sbom_bytes += member.size
                            if sbom_documents > MAX_SBOM_DOCUMENTS or sbom_bytes > MAX_SBOM_BYTES:
                                fail("inner SBOM evidence exceeds the bounded limit")
                        if relative.startswith("task4/"):
                            task4_documents += 1
                            task4_bytes += member.size
                            if task4_documents > MAX_TASK4_DOCUMENTS or task4_bytes > MAX_TASK4_BYTES:
                                fail("inner Task4 evidence exceeds the bounded limit")
                        files[relative] = read_member(inner, member, limit, f"inner {relative}")
    except zlib.error as error:
        fail(f"inner bundle is invalid: zlib error: {error}")
    except (gzip.BadGzipFile, EOFError, OSError, ValueError, tarfile.TarError) as error:
        fail(f"inner bundle is invalid: {error}")
    if root is None or not INNER_REQUIRED_FILES.issubset(files):
        fail("inner bundle required evidence is absent")

    manifest = parse_inner_manifest(files["manifest.json"], run_manifest, root, "inner manifest")
    if root.startswith("agent-platform-"):
        if not agent_kit_root_seen:
            fail("inner platform agent-kit directory is missing")
        validate_agent_kit(agent_kit_files, manifest)
    compose_manifest = parse_inner_manifest(
        files["deploy/docker-compose/manifest.json"], run_manifest, root, "inner compose manifest"
    )
    if compose_manifest != manifest:
        fail("inner manifests differ")
    try:
        minimum = files["deploy/docker-compose/upgrade-min-data-version"].decode("ascii").strip()
        bridge = files["deploy/docker-compose/upgrade-bridge-target-version"].decode("ascii").strip()
    except UnicodeError as error:
        fail(f"inner compatibility contract is invalid: {error}")
    version_name = re.compile(r"[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql")
    if not version_name.fullmatch(minimum) or not version_name.fullmatch(bridge):
        fail("inner compatibility contract is malformed")
    if manifest.get("min_data_version") != minimum:
        fail("inner manifest minimum data version drifted")
    verify_signature_or_sha256(
        public_key,
        files["manifest.sig"],
        INNER_MANIFEST_SIGNATURE_DOMAIN + files["manifest.json"],
        files["manifest.json"],
        "manifest.json",
        "inner manifest",
    )
    release_source = require_exact_object(
        load_json_bytes(files["release-source.json"], "inner release source"),
        {"schema", "remote", "source_revision", "source_tree"},
        "inner release source",
    )
    if (
        release_source["schema"] != "jjdguard-release-source/v1"
        or not isinstance(release_source["remote"], str)
        or release_source["remote"] != authoritative_remote
        or release_source["source_revision"] != run_manifest["source_revision"]
        or release_source["source_tree"] != run_manifest["source_tree"]
    ):
        fail("inner release source binding drifted")
    if hashlib.sha256(files["image-provenance.json"]).hexdigest() != run_manifest["image_provenance_sha256"]:
        fail("inner image provenance hash drifted")
    if hashlib.sha256(files["sbom/index.json"]).hexdigest() != run_manifest["sbom_index_sha256"]:
        fail("inner SBOM index hash drifted")
    validate_image_provenance(
        files["image-provenance.json"],
        run_manifest,
        source_repository,
        authoritative_remote,
        expected_source_archive_sha256,
        files,
    )
    validate_sbom_index(files, expected_syft_hash)


def verify_inner_bundle_chain(
    run_descriptor: int,
    archive_offset: int,
    public_key: bytes | None,
    run_manifest: dict[str, Any],
    source_repository: pathlib.Path,
    authoritative_remote: str,
    expected_syft_hash: str,
    expected_source_archive_sha256: str,
) -> None:
    members: dict[str, int] = {}
    try:
        with open_run_artifact_stream(run_descriptor, "run outer archive") as stream:
            stream.seek(archive_offset)
            with ExtensionFreeTarFile.open(fileobj=stream, mode="r|") as outer:
                for member in outer:
                    validate_outer_member(member, members)
                    if member.name == "payload.tar.gz":
                        verify_inner_payload(
                            outer,
                            member,
                            public_key,
                            run_manifest,
                            source_repository,
                            authoritative_remote,
                            expected_syft_hash,
                            expected_source_archive_sha256,
                        )
    except (OSError, tarfile.TarError) as error:
        fail(f"run outer archive is invalid during inner validation: {error}")
    if set(members) != OUTER_MEMBERS:
        fail("run outer archive members drifted during inner validation")


def read_run_identity(
    run: pathlib.Path,
    public_key: pathlib.Path | None,
    source_repository: pathlib.Path,
    authoritative_remote: str,
) -> dict[str, Any]:
    run_descriptor = -1
    try:
        run_descriptor, run_metadata = open_run_artifact(run)
        archive_offset, release_public_key = verify_header_signature(run_descriptor, public_key)
        members: dict[str, int] = {}
        manifest_raw: bytes | None = None
        manifest_signature: bytes | None = None
        payload_sha256: str | None = None
        payload_size: int | None = None
        try:
            with open_run_artifact_stream(run_descriptor, "run outer archive") as stream:
                stream.seek(archive_offset)
                with ExtensionFreeTarFile.open(fileobj=stream, mode="r|") as outer:
                    for member in outer:
                        validate_outer_member(member, members)
                        if member.name == "payload.tar.gz":
                            payload_size = member.size
                            payload_sha256 = hash_member(outer, member)
                        elif member.name == "run-manifest.json":
                            manifest_raw = read_member(outer, member, MAX_JSON_BYTES, "run manifest")
                        else:
                            manifest_signature = read_member(outer, member, MAX_CHECKSUM_BYTES, "run manifest signature")
        except (OSError, tarfile.TarError) as error:
            fail(f"run outer archive is invalid: {error}")
        if set(members) != OUTER_MEMBERS or payload_size is None or payload_sha256 is None:
            fail("run outer archive members are invalid")
        if manifest_raw is None or manifest_signature is None:
            fail("run outer archive evidence is incomplete")
        manifest = parse_run_manifest(manifest_raw, payload_size)
        manifest["signed"] = release_public_key is not None
        verify_signature_or_sha256(
            release_public_key,
            manifest_signature,
            RUN_MANIFEST_SIGNATURE_DOMAIN + manifest_raw,
            manifest_raw,
            "run-manifest.json",
            "run manifest",
        )
        if payload_sha256 != manifest["payload_sha256"]:
            fail("run payload hash drifted")
        expected_syft_hash = authoritative_syft_hash(
            source_repository,
            authoritative_remote,
            manifest["source_revision"],
            manifest["source_tree"],
        )
        expected_source_archive_sha256 = source_archive_sha256(source_repository, manifest["source_revision"])
        verify_inner_bundle_chain(
            run_descriptor,
            archive_offset,
            release_public_key,
            manifest,
            source_repository,
            authoritative_remote,
            expected_syft_hash,
            expected_source_archive_sha256,
        )
        return {
            "run_sha256": hash_open_run_artifact(run_descriptor, run_metadata),
            "run_size": run_metadata.st_size,
            "inner_tar_sha256": payload_sha256,
            "version": manifest["version"],
            "source_revision": manifest["source_revision"],
            "source_tree": manifest["source_tree"],
            "image_provenance_sha256": manifest["image_provenance_sha256"],
            "sbom_index_sha256": manifest["sbom_index_sha256"],
        }
    finally:
        if run_descriptor >= 0:
            close_descriptor(run_descriptor)


def validate_identity_object(value: Any, identity: dict[str, Any], label: str) -> None:
    artifact = require_exact_object(value, {"run_sha256", "run_size", "inner_tar_sha256"}, label)
    require_hash(artifact["run_sha256"], f"{label} run hash")
    require_hash(artifact["inner_tar_sha256"], f"{label} inner tar hash")
    if not isinstance(artifact["run_size"], int) or artifact["run_size"] < 1:
        fail(f"invalid {label} run size")
    for key in artifact:
        if artifact[key] != identity[key]:
            fail(f"{label} binding drifted: {key}")


def validate_release_object(value: Any, identity: dict[str, Any], label: str) -> None:
    release = require_exact_object(
        value,
        {"source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256"},
        label,
    )
    require_revision(release["source_revision"], f"{label} source revision")
    require_revision(release["source_tree"], f"{label} source tree")
    require_hash(release["image_provenance_sha256"], f"{label} provenance hash")
    require_hash(release["sbom_index_sha256"], f"{label} SBOM hash")
    for key in release:
        if release[key] != identity[key]:
            fail(f"{label} binding drifted: {key}")


def canonical_relative_path(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        fail(f"{label} path is invalid")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} path is not canonical")
    if any(any(ord(character) < 32 or ord(character) == 127 for character in part) for part in parts):
        fail(f"{label} path contains control characters")
    return parts


def require_open_flags(names: tuple[str, ...], label: str) -> int:
    flags = 0
    for name in names:
        value = getattr(os, name, None)
        if not isinstance(value, int):
            fail(f"{label} requires unsupported {name}")
        flags |= value
    return flags


def open_at(
    path: str | pathlib.Path,
    flags: int,
    label: str,
    directory_descriptor: int | None = None,
) -> int:
    try:
        if directory_descriptor is None:
            return os.open(path, flags)
        return os.open(path, flags, dir_fd=directory_descriptor)
    except (OSError, TypeError, ValueError, NotImplementedError) as error:
        fail(f"cannot open {label}: {error}")


def close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def open_absolute_directory(path: pathlib.Path, label: str) -> int:
    try:
        raw_path = os.fspath(path)
    except TypeError as error:
        fail(f"{label} path is invalid: {error}")
    if not isinstance(raw_path, str) or not raw_path or "\0" in raw_path:
        fail(f"{label} path is invalid")
    if os.path.isabs(raw_path):
        base_components: tuple[str, ...] = ()
        raw_components = raw_path.split(os.sep)[1:]
    else:
        try:
            current_directory = os.getcwd()
        except OSError as error:
            fail(f"cannot resolve {label} path: {error}")
        if not os.path.isabs(current_directory):
            fail(f"{label} path is invalid")
        base_components = tuple(part for part in current_directory.split(os.sep) if part)
        raw_components = raw_path.split(os.sep)
    if any(part in {".", ".."} for part in raw_components) or any(
        not part for part in raw_components[:-1]
    ):
        fail(f"{label} path contains an unsafe component")
    if raw_components and raw_components[-1] == "":
        raw_components = raw_components[:-1]
    components = base_components + tuple(raw_components)
    if any(not part for part in components):
        fail(f"{label} path is invalid")
    directory_flags = require_open_flags(
        ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"), label
    )
    descriptor = -1
    try:
        descriptor = open_at(os.sep, directory_flags, label)
        for component in components:
            next_descriptor = open_at(component, directory_flags, label, descriptor)
            close_descriptor(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        if descriptor >= 0:
            close_descriptor(descriptor)
        raise


def snapshot_run_artifact(
    source_descriptor: int,
    source_metadata: os.stat_result,
    parent_descriptor: int,
) -> tuple[int, os.stat_result]:
    if source_metadata.st_size > MAX_RUN_ARTIFACT_BYTES:
        fail("run artifact exceeds the snapshot size limit")
    try:
        filesystem = os.fstatvfs(parent_descriptor)
        if filesystem.f_frsize < 1 or filesystem.f_bavail < 0:
            fail("run artifact snapshot free-space metadata is invalid")
        available_bytes = filesystem.f_frsize * filesystem.f_bavail
    except OSError as error:
        fail(f"cannot inspect free space for run artifact snapshot: {error}")
    required_bytes = source_metadata.st_size + SNAPSHOT_SIDECAR_HEADROOM_BYTES
    if available_bytes < required_bytes:
        fail("insufficient free space for run artifact snapshot")
    snapshot_descriptor = -1
    try:
        snapshot_flags = require_open_flags(("O_RDWR", "O_TMPFILE", "O_CLOEXEC"), "run artifact snapshot")
        try:
            snapshot_descriptor = os.open(".", snapshot_flags, 0o600, dir_fd=parent_descriptor)
        except OSError as error:
            fail(f"cannot open run artifact snapshot: {error}")
        snapshot_metadata = os.fstat(snapshot_descriptor)
        if not stat.S_ISREG(snapshot_metadata.st_mode) or stat.S_IMODE(snapshot_metadata.st_mode) & 0o077:
            fail("run artifact snapshot is not a private regular file")
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        copied = 0
        while copied < source_metadata.st_size:
            chunk = os.read(source_descriptor, min(1024 * 1024, source_metadata.st_size - copied))
            if not chunk:
                fail("run artifact changed while it was snapshotted")
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_descriptor, view)
                if written < 1:
                    fail("cannot snapshot run artifact safely: short write")
                view = view[written:]
            copied += len(chunk)
        if not same_regular_file(source_metadata, os.fstat(source_descriptor)):
            fail("run artifact changed while it was snapshotted")
        os.fsync(snapshot_descriptor)
        snapshot_metadata = os.fstat(snapshot_descriptor)
        if not stat.S_ISREG(snapshot_metadata.st_mode) or snapshot_metadata.st_size != source_metadata.st_size:
            fail("run artifact snapshot changed while it was created")
        os.lseek(snapshot_descriptor, 0, os.SEEK_SET)
        return snapshot_descriptor, snapshot_metadata
    except OSError as error:
        if snapshot_descriptor >= 0:
            close_descriptor(snapshot_descriptor)
        fail(f"cannot snapshot run artifact safely: {error}")
    except BaseException:
        if snapshot_descriptor >= 0:
            close_descriptor(snapshot_descriptor)
        raise


def open_run_artifact(run: pathlib.Path) -> tuple[int, os.stat_result]:
    try:
        absolute = pathlib.Path(os.path.abspath(os.fspath(run)))
    except (OSError, TypeError) as error:
        fail(f"run artifact path is invalid: {error}")
    parent_descriptor = -1
    source_descriptor = -1
    snapshot_descriptor = -1
    try:
        parent_descriptor = open_absolute_directory(absolute.parent, "run artifact parent")
        flags = require_open_flags(
            ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"), "run artifact"
        )
        source_descriptor = open_at(absolute.name, flags, "run artifact", parent_descriptor)
        try:
            metadata = os.fstat(source_descriptor)
        except OSError as error:
            fail(f"cannot inspect run artifact: {error}")
        if not stat.S_ISREG(metadata.st_mode):
            fail("run artifact is not a regular non-symlink file")
        snapshot_descriptor, snapshot_metadata = snapshot_run_artifact(
            source_descriptor,
            metadata,
            parent_descriptor,
        )
        close_descriptor(source_descriptor)
        source_descriptor = -1
        return snapshot_descriptor, snapshot_metadata
    except BaseException:
        if snapshot_descriptor >= 0:
            close_descriptor(snapshot_descriptor)
        if source_descriptor >= 0:
            close_descriptor(source_descriptor)
        raise
    finally:
        if parent_descriptor >= 0:
            close_descriptor(parent_descriptor)


def open_run_artifact_stream(run_descriptor: int, label: str):
    duplicate = -1
    try:
        duplicate = os.dup(run_descriptor)
        return os.fdopen(duplicate, "rb", closefd=True)
    except OSError as error:
        if duplicate >= 0:
            close_descriptor(duplicate)
        fail(f"cannot duplicate {label}: {error}")


def hash_open_run_artifact(run_descriptor: int, expected: os.stat_result) -> str:
    digest = hashlib.sha256()
    copied = 0
    try:
        with open_run_artifact_stream(run_descriptor, "run artifact") as stream:
            stream.seek(0)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                copied += len(chunk)
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash run artifact: {error}")
    try:
        finished = os.fstat(run_descriptor)
    except OSError as error:
        fail(f"cannot inspect run artifact: {error}")
    if not same_regular_file(expected, finished) or copied != expected.st_size:
        fail("run artifact changed while it was read")
    return digest.hexdigest()


def open_evidence_source(
    root: pathlib.Path, parts: tuple[str, ...], label: str
) -> tuple[int, os.stat_result]:
    directory_flags = require_open_flags(
        ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"), label
    )
    file_flags = require_open_flags(
        ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"), label
    )
    parent_descriptor = -1
    source_descriptor = -1
    try:
        parent_descriptor = open_absolute_directory(root, "evidence root")
        for part in parts[:-1]:
            next_descriptor = open_at(part, directory_flags, f"{label} parent", parent_descriptor)
            close_descriptor(parent_descriptor)
            parent_descriptor = next_descriptor
        source_descriptor = open_at(parts[-1], file_flags, label, parent_descriptor)
        try:
            metadata = os.fstat(source_descriptor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} is not a regular file")
        if metadata.st_size < 0 or metadata.st_size > MAX_EVIDENCE_FILE_BYTES:
            fail(f"{label} exceeds the size limit")
        return source_descriptor, metadata
    except BaseException:
        if source_descriptor >= 0:
            close_descriptor(source_descriptor)
        raise
    finally:
        if parent_descriptor >= 0:
            close_descriptor(parent_descriptor)


def hash_open_evidence_file(
    source_descriptor: int, metadata: os.stat_result, label: str
) -> str:
    digest = hashlib.sha256()
    copied = 0
    try:
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_EVIDENCE_FILE_BYTES:
                fail(f"{label} exceeds the size limit while reading")
            digest.update(chunk)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    if copied != metadata.st_size:
        fail(f"{label} changed while it was read")
    return digest.hexdigest()


def snapshot_open_evidence_file(
    source_descriptor: int,
    metadata: os.stat_result,
    snapshot_root: pathlib.Path,
    parts: tuple[str, ...],
    label: str,
) -> str:
    directory_flags = require_open_flags(
        ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"), label
    )
    destination_flags = require_open_flags(
        ("O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC"), label
    )
    parent_descriptor = -1
    destination_descriptor = -1
    try:
        parent_descriptor = open_absolute_directory(snapshot_root, "evidence snapshot root")
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
            except (OSError, TypeError, ValueError, NotImplementedError) as error:
                fail(f"cannot create evidence snapshot directory: {error}")
            next_descriptor = open_at(
                part, directory_flags, "evidence snapshot directory", parent_descriptor
            )
            close_descriptor(parent_descriptor)
            parent_descriptor = next_descriptor
        try:
            destination_descriptor = os.open(
                parts[-1], destination_flags, 0o600, dir_fd=parent_descriptor
            )
        except (OSError, TypeError, ValueError, NotImplementedError) as error:
            fail(f"cannot create evidence snapshot file: {error}")
        digest = hashlib.sha256()
        copied = 0
        try:
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_EVIDENCE_FILE_BYTES:
                    fail(f"{label} exceeds the size limit while copying")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    if written < 1:
                        fail(f"cannot snapshot {label}: short write")
                    view = view[written:]
            os.fsync(destination_descriptor)
        except OSError as error:
            fail(f"cannot snapshot {label}: {error}")
    finally:
        if destination_descriptor >= 0:
            close_descriptor(destination_descriptor)
        if parent_descriptor >= 0:
            close_descriptor(parent_descriptor)
    if copied != metadata.st_size:
        fail(f"{label} changed while it was snapshotted")
    return digest.hexdigest()


def snapshot_evidence_file(
    source: pathlib.Path,
    expected_size: int,
    snapshot_root: pathlib.Path,
    parts: tuple[str, ...],
    label: str,
) -> str:
    """Compatibility entry point for callers that already hold a leaf path."""
    descriptor, metadata = open_evidence_source(source.parent, (source.name,), label)
    try:
        if metadata.st_size != expected_size:
            fail(f"{label} changed before it was snapshotted")
        return snapshot_open_evidence_file(descriptor, metadata, snapshot_root, parts, label)
    finally:
        close_descriptor(descriptor)


def validate_home_migration_baseline(
    value: Any, identity: dict[str, Any], label: str
) -> dict[str, Any]:
    baseline = require_exact_object(value, {"schema", "artifact", "release", "ledgers"}, label)
    if baseline["schema"] != HOME_MIGRATION_BASELINE_SCHEMA:
        fail(f"{label} schema is invalid")
    validate_identity_object(baseline["artifact"], identity, f"{label} artifact")
    validate_release_object(baseline["release"], identity, f"{label} release")

    expected_ledger_names = ("schema_migrations_before", "schema_migrations_after")
    ledgers = baseline["ledgers"]
    if not isinstance(ledgers, list) or len(ledgers) != len(expected_ledger_names):
        fail(f"{label} ledgers are invalid")
    total_entries = 0
    ledger_entries: list[set[tuple[str, str]]] = []
    for ledger_index, expected_name in enumerate(expected_ledger_names):
        ledger = require_exact_object(
            ledgers[ledger_index], {"name", "entries"}, f"{label} ledger {ledger_index}"
        )
        if ledger["name"] != expected_name:
            fail(f"{label} ledger name is invalid")
        entries = ledger["entries"]
        if not isinstance(entries, list) or not entries:
            fail(f"{label} ledger entries are invalid")
        validated_entries: set[tuple[str, str]] = set()
        ledger_entries.append(validated_entries)
        previous_version: str | None = None
        for entry_index, entry in enumerate(entries):
            total_entries += 1
            if total_entries > MAX_HOME_MIGRATION_ENTRIES:
                fail(f"{label} has too many migration entries")
            entry = require_exact_object(
                entry, {"version", "checksum"}, f"{label} ledger entry {entry_index}"
            )
            version = entry["version"]
            if not isinstance(version, str) or MIGRATION_VERSION.fullmatch(version) is None:
                fail(f"{label} migration version is invalid")
            if previous_version is not None and version <= previous_version:
                fail(f"{label} migration entries are not strictly ordered")
            previous_version = version
            checksum = require_hash(entry["checksum"], f"{label} migration checksum")
            validated_entries.add((version, checksum))
    if not ledger_entries[0].issubset(ledger_entries[1]):
        fail(f"{label} after ledger does not preserve before migration")
    return baseline


def validate_home_migration_baseline_evidence(
    expected_hash: str,
    identity: dict[str, Any],
    evidence_root: pathlib.Path,
    snapshot_root: pathlib.Path | None,
) -> None:
    root = snapshot_root if snapshot_root is not None else evidence_root
    path = root / HOME_MIGRATION_BASELINE_NAME
    metadata = require_regular(path, "home migration baseline")
    if metadata.st_size < 1 or metadata.st_size > MAX_HOME_MIGRATION_BASELINE_BYTES:
        fail("home migration baseline has an invalid size")
    baseline, actual_hash = read_regular_json(
        path, "home migration baseline", MAX_HOME_MIGRATION_BASELINE_BYTES
    )
    if actual_hash != expected_hash:
        fail("home migration baseline hash drifted")
    validate_home_migration_baseline(baseline, identity, "home migration baseline")


def validate_evidence_index(
    path: pathlib.Path,
    identity: dict[str, Any],
    evidence_root: pathlib.Path,
    snapshot_root: pathlib.Path | None = None,
) -> str:
    index, index_sha256 = read_regular_json(path, "evidence index")
    index = require_exact_object(index, {"schema", "artifact", "release", "entries"}, "evidence index")
    if index["schema"] != "jjdguard-acceptance-evidence-index/v1":
        fail("evidence index schema is invalid")
    validate_identity_object(index["artifact"], identity, "evidence index artifact")
    validate_release_object(index["release"], identity, "evidence index release")
    if not isinstance(index["entries"], list) or not index["entries"]:
        fail("evidence index entries are empty")
    if len(index["entries"]) > MAX_EVIDENCE_ENTRIES:
        fail("evidence index contains too many entries")
    seen_paths: set[str] = set()
    total_bytes = 0
    home_migration_baseline_hash: str | None = None
    for entry in index["entries"]:
        entry = require_exact_object(entry, {"path", "sha256"}, "evidence index entry")
        parts = canonical_relative_path(entry["path"], "evidence index")
        relative = "/".join(parts)
        if relative in seen_paths:
            fail("evidence index contains duplicate paths")
        seen_paths.add(relative)
        expected_hash = require_hash(entry["sha256"], "evidence entry hash")
        if parts == (HOME_MIGRATION_BASELINE_NAME,):
            home_migration_baseline_hash = expected_hash
        descriptor, metadata = open_evidence_source(
            evidence_root, parts, f"evidence entry {relative}"
        )
        try:
            total_bytes += metadata.st_size
            if total_bytes > MAX_EVIDENCE_BYTES:
                fail("evidence index exceeds the total size limit")
            if snapshot_root is None:
                actual_hash = hash_open_evidence_file(
                    descriptor, metadata, f"evidence entry {relative}"
                )
            else:
                actual_hash = snapshot_open_evidence_file(
                    descriptor, metadata, snapshot_root, parts, f"evidence entry {relative}"
                )
        finally:
            close_descriptor(descriptor)
        if actual_hash != expected_hash:
            fail(f"evidence entry hash drifted: {relative}")
    if home_migration_baseline_hash is None:
        fail("evidence index is missing home migration baseline")
    validate_home_migration_baseline_evidence(
        home_migration_baseline_hash, identity, evidence_root, snapshot_root
    )
    return index_sha256


def validate_receipt(receipt_path: pathlib.Path, evidence_sha256: str, identity: dict[str, Any]) -> str:
    receipt, receipt_sha256 = read_regular_json(receipt_path, "acceptance receipt")
    receipt = require_exact_object(
        receipt,
        {"schema", "status", "artifact", "release", "scenarios", "evidence_index_sha256", "non_promotable_reasons", "completed_at"},
        "acceptance receipt",
    )
    if receipt["schema"] != "jjdguard-acceptance-receipt/v1" or receipt["status"] != "PASS":
        fail("receipt status is not promotable")
    validate_identity_object(receipt["artifact"], identity, "receipt artifact")
    validate_release_object(receipt["release"], identity, "receipt release")
    if not isinstance(receipt["scenarios"], dict) or set(receipt["scenarios"]) != REQUIRED_SCENARIOS:
        fail("receipt required scenario coverage is incomplete")
    if any(status != "PASS" for status in receipt["scenarios"].values()):
        fail("receipt contains a non-PASS required scenario")
    if receipt["evidence_index_sha256"] != evidence_sha256:
        fail("receipt evidence index hash drifted")
    require_hash(receipt["evidence_index_sha256"], "receipt evidence index hash")
    if receipt["non_promotable_reasons"] != []:
        fail("receipt contains non-promotable reasons")
    if not isinstance(receipt["completed_at"], str) or not TIMESTAMP.fullmatch(receipt["completed_at"]):
        fail("receipt completion time is invalid")
    return receipt_sha256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    parser.add_argument("--artifact", "--run-file", dest="artifact", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-index", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-root", type=pathlib.Path)
    parser.add_argument("--snapshot-evidence-dir", type=pathlib.Path)
    parser.add_argument("--public-key", type=pathlib.Path)
    parser.add_argument("--source-repository", type=pathlib.Path, required=True)
    parser.add_argument("--authoritative-remote", required=True)
    args = parser.parse_args()

    identity = read_run_identity(
        args.artifact,
        args.public_key,
        args.source_repository,
        args.authoritative_remote,
    )
    evidence_root = args.evidence_root or args.evidence_index.parent
    if args.snapshot_evidence_dir is not None:
        try:
            args.snapshot_evidence_dir.mkdir(mode=0o700)
        except FileExistsError:
            fail("evidence snapshot directory already exists")
        except OSError as error:
            fail(f"cannot create evidence snapshot directory: {error}")
    evidence_index_sha256 = validate_evidence_index(
        args.evidence_index,
        identity,
        evidence_root,
        args.snapshot_evidence_dir,
    )
    receipt_sha256 = validate_receipt(args.receipt, evidence_index_sha256, identity)
    result = {
        "receipt_sha256": receipt_sha256,
        "evidence_index_sha256": evidence_index_sha256,
        **identity,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
