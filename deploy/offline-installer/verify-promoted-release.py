#!/usr/bin/env python3
"""Verify and install a promoted offline release from an independent trust root."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any


DEFAULT_TRUST_ROOT = pathlib.Path("/opt/jjdguard-release-trust")
TRUSTED_VERIFIER_NAME = "verify-promoted-release.py"
TRUSTED_PUBLIC_KEY_NAME = "release-public.pem"
PROMOTION_DOMAIN = b"jjdguard-offline-promotion/v1\0"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
RUN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.run$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_RUN_BYTES = 64 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_SIDECAR_BYTES = 64 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_EVIDENCE_ENTRIES = 4096
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024 * 1024
STAGING_MARGIN_BYTES = 16 * 1024 * 1024
HOME_MIGRATION_BASELINE_NAME = "home-migration-baseline.json"
HOME_MIGRATION_BASELINE_SCHEMA = "jjdguard-home-migration-baseline/v1"
MAX_HOME_MIGRATION_BASELINE_BYTES = 1024 * 1024
MAX_HOME_MIGRATION_LEDGERS = 16
MAX_HOME_MIGRATION_ENTRIES = 4096
MIGRATION_LEDGER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MIGRATION_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
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
    raise SystemExit(f"[error] promoted release rejected: {message}")


def is_test_mode() -> bool:
    return os.environ.get("JJD_RELEASE_TESTING") == "1"


def require_regular(path: pathlib.Path, label: str, maximum_size: int | None = None) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not a regular non-symlink file")
    if metadata.st_size < 1:
        fail(f"{label} is empty")
    if maximum_size is not None and metadata.st_size > maximum_size:
        fail(f"{label} exceeds the size limit")
    return metadata


def require_regular_at(
    directory_descriptor: int,
    name: str,
    label: str,
    maximum_size: int | None = None,
) -> os.stat_result:
    try:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except (OSError, TypeError, ValueError, NotImplementedError) as error:
        fail(f"{label} is unavailable: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not a regular non-symlink file")
    if metadata.st_size < 1:
        fail(f"{label} is empty")
    if maximum_size is not None and metadata.st_size > maximum_size:
        fail(f"{label} exceeds the size limit")
    return metadata


def require_trust_root(root: pathlib.Path, testing: bool) -> None:
    try:
        metadata = root.lstat()
    except OSError as error:
        fail(f"trust root is unavailable: {error}")
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        fail("trust root is not a real directory")
    if metadata.st_mode & 0o022:
        fail("trust root is writable by a group or other user")
    expected_owner = os.geteuid() if testing else 0
    if metadata.st_uid != expected_owner:
        fail("trust root owner is not trusted")


def require_trust_file(path: pathlib.Path, label: str, testing: bool, maximum_size: int) -> None:
    metadata = require_regular(path, label, maximum_size)
    expected_owner = os.geteuid() if testing else 0
    if metadata.st_uid != expected_owner:
        fail(f"{label} owner is not trusted")
    if metadata.st_mode & 0o022:
        fail(f"{label} is writable by a group or other user")


def normalize_public_key(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_JSON_BYTES:
        fail("trusted release public key has an invalid size")
    try:
        normalized = subprocess.run(
            ["openssl", "pkey", "-pubin", "-pubout"],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        description = subprocess.run(
            ["openssl", "pkey", "-pubin", "-text", "-noout"],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        fail(f"openssl is unavailable: {error}")
    if normalized.returncode != 0 or not normalized.stdout or description.returncode != 0:
        fail("trusted release public key is invalid")
    if b"ED25519" not in description.stdout.upper():
        fail("trusted release public key is not Ed25519")
    return normalized.stdout


def verify_signature(public_key: pathlib.Path, signature: pathlib.Path, payload: pathlib.Path) -> None:
    signature_size = require_regular(signature, "promotion signature", 64).st_size
    if signature_size != 64:
        fail("promotion signature length is invalid")
    try:
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key),
                "-sigfile", str(signature), "-in", str(payload),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        fail(f"openssl is unavailable: {error}")
    if result.returncode != 0:
        fail("promotion signature is invalid")


def verify_signature_or_sha256(
    public_key: pathlib.Path | None, evidence: pathlib.Path, payload: pathlib.Path
) -> None:
    metadata = require_regular(evidence, "promotion identity", MAX_CHECKSUM_BYTES)
    if metadata.st_size == 64:
        if public_key is None:
            fail("signed promotion requires a trusted release public key")
        verify_signature(public_key, evidence, payload)
        return
    expected = hashlib.sha256(payload.read_bytes()).hexdigest() + "  promotion.payload\n"
    try:
        actual = evidence.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        fail(f"promotion SHA-256 identity is unreadable: {error}")
    if actual != expected:
        fail("promotion SHA-256 identity is invalid")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash staged file {path.name}: {error}")
    return digest.hexdigest()


def same_regular_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and getattr(left, "st_mtime_ns", None) == getattr(right, "st_mtime_ns", None)
        and getattr(left, "st_ctime_ns", None) == getattr(right, "st_ctime_ns", None)
    )


def load_json(path: pathlib.Path, label: str, maximum_size: int) -> tuple[dict[str, Any], bytes]:
    """Read JSON from a no-follow descriptor bound to its listed inode."""
    listed = require_regular(path, label, maximum_size)
    try:
        absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError) as error:
        fail(f"{label} path is invalid: {error}")
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_absolute_directory(absolute.parent, f"{label} parent")
        flags = require_open_flags(
            ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"), label
        )
        descriptor = open_at(absolute.name, flags, label, parent_descriptor)
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
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        fail(f"{label} JSON is invalid: {error}")
    if not isinstance(value, dict):
        fail(f"{label} JSON is not an object")
    return value, raw


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def copy_open_regular(
    source_descriptor: int,
    metadata: os.stat_result,
    destination: pathlib.Path,
    label: str,
    maximum_size: int,
) -> tuple[str, int]:
    try:
        output_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        fail(f"cannot snapshot {label}: {error}")
    digest = hashlib.sha256()
    copied = 0
    try:
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > maximum_size:
                fail(f"{label} exceeds the size limit while copying")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_descriptor, view)
                if written < 1:
                    fail(f"cannot snapshot {label}: short write")
                view = view[written:]
        os.fsync(output_descriptor)
    except OSError as error:
        fail(f"cannot snapshot {label}: {error}")
    finally:
        try:
            os.close(output_descriptor)
        except OSError:
            pass
    if copied != metadata.st_size:
        fail(f"{label} changed while it was being copied")
    return digest.hexdigest(), copied


def copy_regular(source: pathlib.Path, destination: pathlib.Path, label: str, maximum_size: int) -> tuple[str, int]:
    initial = require_regular(source, label, maximum_size)
    flags = require_open_flags(
        ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"), label
    )
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    try:
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != initial.st_size:
            fail(f"{label} changed while it was being opened")
        if metadata.st_size < 1 or metadata.st_size > maximum_size:
            fail(f"{label} has an invalid size")
        return copy_open_regular(descriptor, metadata, destination, label, maximum_size)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def copy_regular_at(
    directory_descriptor: int,
    source_name: str,
    destination: pathlib.Path,
    label: str,
    maximum_size: int,
    staging_root: pathlib.Path,
) -> tuple[str, int]:
    initial = require_regular_at(directory_descriptor, source_name, label, maximum_size)
    flags = require_open_flags(
        ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"), label
    )
    descriptor = open_at(source_name, flags, label, directory_descriptor)
    try:
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != initial.st_size:
            fail(f"{label} changed while it was being opened")
        if metadata.st_size < 1 or metadata.st_size > maximum_size:
            fail(f"{label} has an invalid size")
        ensure_staging_bytes(staging_root, metadata.st_size)
        return copy_open_regular(descriptor, metadata, destination, label, maximum_size)
    finally:
        close_descriptor(descriptor)


def find_run(release_descriptor: int) -> str:
    try:
        with os.scandir(release_descriptor) as directory:
            entries = list(directory)
    except (OSError, TypeError, ValueError, NotImplementedError) as error:
        fail(f"cannot read release directory: {error}")
    if len(entries) > 32:
        fail("release directory contains too many entries")
    runs: list[str] = []
    for entry in entries:
        if not RUN_NAME.fullmatch(entry.name):
            continue
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            fail(f"cannot inspect run artifact: {error}")
        if stat.S_ISREG(metadata.st_mode):
            runs.append(entry.name)
    if len(runs) != 1:
        fail("release directory must contain exactly one regular .run artifact")
    return runs[0]


@dataclass(frozen=True)
class ReleaseFiles:
    run: str
    checksum: str
    sidecar: str
    signature: str
    receipt: str = "acceptance-receipt.json"
    evidence: str = "acceptance-evidence-index.json"


def release_files(run_name: str) -> ReleaseFiles:
    return ReleaseFiles(
        run=run_name,
        checksum=f"{run_name}.sha256",
        sidecar=f"{run_name}.promotion.json",
        signature=f"{run_name}.promotion.sig",
    )


def ensure_staging_capacity(root: pathlib.Path, paths: list[tuple[pathlib.Path, str, int]]) -> None:
    required = 0
    for path, label, maximum_size in paths:
        required += require_regular(path, label, maximum_size).st_size
    ensure_staging_bytes(root, required)


def ensure_staging_capacity_at(
    root: pathlib.Path,
    directory_descriptor: int,
    paths: list[tuple[str, str, int]],
) -> None:
    required = 0
    for name, label, maximum_size in paths:
        required += require_regular_at(directory_descriptor, name, label, maximum_size).st_size
    ensure_staging_bytes(root, required)


def ensure_staging_bytes(root: pathlib.Path, required: int) -> None:
    if required < 0:
        fail("staging size is invalid")
    try:
        stats = os.statvfs(root)
    except OSError as error:
        fail(f"cannot inspect trust-root free space: {error}")
    available = stats.f_bavail * stats.f_frsize
    if required + STAGING_MARGIN_BYTES > available:
        fail("trust-root staging space is insufficient")


def canonical_relative_path(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 1024:
        fail(f"{label} path is invalid")
    parts = tuple(value.split("/"))
    if (
        value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        fail(f"{label} path is not canonical")
    return parts


def evidence_entries(index: dict[str, Any]) -> list[tuple[tuple[str, ...], str]]:
    if set(index) != {"schema", "artifact", "release", "entries"}:
        fail("promoted evidence index schema is invalid")
    if index.get("schema") != "jjdguard-acceptance-evidence-index/v1":
        fail("promoted evidence index schema is invalid")
    entries = index.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_EVIDENCE_ENTRIES:
        fail("promoted evidence index entries are invalid")
    result: list[tuple[tuple[str, ...], str]] = []
    seen: set[tuple[str, ...]] = set()
    prefixes: set[tuple[str, ...]] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            fail("promoted evidence index entry is invalid")
        parts = canonical_relative_path(entry.get("path"), "promoted evidence index")
        if parts in seen:
            fail("promoted evidence index contains duplicate paths")
        if parts in prefixes or any(parts[:length] in seen for length in range(1, len(parts))):
            fail("promoted evidence index contains path prefix collision")
        seen.add(parts)
        prefixes.update(parts[:length] for length in range(1, len(parts)))
        result.append((parts, require_hash(entry.get("sha256"), "promoted evidence entry hash")))
    return result


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


def open_promoted_evidence_source(
    release_descriptor: int,
    parts: tuple[str, ...],
    label: str,
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
        parent_descriptor = open_at(
            "evidence", directory_flags, "promoted evidence root", release_descriptor
        )
        for part in parts[:-1]:
            next_descriptor = open_at(
                part, directory_flags, f"{label} parent", parent_descriptor
            )
            close_descriptor(parent_descriptor)
            parent_descriptor = next_descriptor
        source_descriptor = open_at(parts[-1], file_flags, label, parent_descriptor)
        try:
            metadata = os.fstat(source_descriptor)
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} is not a regular non-symlink file")
        # Successful acceptance commands may have no stdout. The signed index
        # still binds the empty log digest; structured evidence stays nonempty.
        minimum_size = 0 if len(parts) == 2 and parts[0] == "logs" and parts[1].endswith(".log") else 1
        if metadata.st_size < minimum_size or metadata.st_size > MAX_EVIDENCE_FILE_BYTES:
            fail(f"{label} has an invalid size")
        return source_descriptor, metadata
    except BaseException:
        if source_descriptor >= 0:
            close_descriptor(source_descriptor)
        raise
    finally:
        if parent_descriptor >= 0:
            close_descriptor(parent_descriptor)


def stage_promoted_evidence(release_descriptor: int, index: dict[str, Any], stage: pathlib.Path) -> None:
    entries = evidence_entries(index)
    total = 0
    snapshot_root = stage / "evidence"
    try:
        snapshot_root.mkdir(mode=0o700)
    except OSError as error:
        fail(f"cannot create promoted evidence staging directory: {error}")
    copied_total = 0
    for parts, expected_hash in entries:
        relative = "/".join(parts)
        descriptor = -1
        try:
            descriptor, metadata = open_promoted_evidence_source(
                release_descriptor, parts, f"promoted evidence {relative}"
            )
            total += metadata.st_size
            if total > MAX_EVIDENCE_BYTES:
                fail("promoted evidence exceeds the total size limit")
            destination = snapshot_root.joinpath(*parts)
            try:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as error:
                fail(f"cannot create promoted evidence staging parent: {error}")
            ensure_staging_bytes(stage, metadata.st_size)
            actual_hash, copied = copy_open_regular(
                descriptor,
                metadata,
                destination,
                f"promoted evidence {relative}",
                MAX_EVIDENCE_FILE_BYTES,
            )
            copied_total += copied
            if copied_total > MAX_EVIDENCE_BYTES:
                fail("promoted evidence exceeds the total size limit while copying")
            if actual_hash != expected_hash:
                fail(f"promoted evidence hash drifted: {relative}")
        finally:
            if descriptor >= 0:
                close_descriptor(descriptor)


def validate_checksum(raw: bytes, run_name: str, run_sha256: str) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail("run checksum is not ASCII")
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*\.run)\n", text)
    if match is None or match.group(2) != run_name or match.group(1) != run_sha256:
        fail("run checksum does not bind the staged .run")


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is invalid")
    return value


def require_revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA1.fullmatch(value) is None:
        fail(f"{label} is invalid")
    return value


def require_exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} keys are not exact")
    return value


def validate_identity_object(value: Any, identity: dict[str, Any], label: str) -> None:
    artifact = require_exact_object(value, {"run_sha256", "run_size", "inner_tar_sha256"}, label)
    require_hash(artifact["run_sha256"], f"{label} run hash")
    require_hash(artifact["inner_tar_sha256"], f"{label} inner tar hash")
    if type(artifact["run_size"]) is not int or artifact["run_size"] < 1:
        fail(f"{label} run size is invalid")
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


def validate_home_migration_baseline(
    value: Any, identity: dict[str, Any], label: str
) -> dict[str, Any]:
    baseline = require_exact_object(value, {"schema", "artifact", "release", "ledgers"}, label)
    if baseline["schema"] != HOME_MIGRATION_BASELINE_SCHEMA:
        fail(f"{label} schema is invalid")
    validate_identity_object(baseline["artifact"], identity, f"{label} artifact")
    validate_release_object(baseline["release"], identity, f"{label} release")

    ledgers = baseline["ledgers"]
    expected_ledger_names = ("schema_migrations_before", "schema_migrations_after")
    if not isinstance(ledgers, list) or len(ledgers) != len(expected_ledger_names):
        fail(f"{label} ledgers are invalid")
    total_entries = 0
    ledger_entries: list[set[tuple[str, str]]] = []
    for ledger_index, expected_name in enumerate(expected_ledger_names):
        raw_ledger = ledgers[ledger_index]
        ledger = require_exact_object(raw_ledger, {"name", "entries"}, f"{label} ledger {ledger_index}")
        name = ledger["name"]
        if name != expected_name:
            fail(f"{label} ledger name is invalid")
        entries = ledger["entries"]
        if not isinstance(entries, list) or not entries:
            fail(f"{label} ledger entries are invalid")
        validated_entries: set[tuple[str, str]] = set()
        ledger_entries.append(validated_entries)
        previous_version: str | None = None
        for entry_index, raw_entry in enumerate(entries):
            total_entries += 1
            if total_entries > MAX_HOME_MIGRATION_ENTRIES:
                fail(f"{label} has too many migration entries")
            entry = require_exact_object(
                raw_entry, {"version", "checksum"}, f"{label} ledger entry {entry_index}"
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


def load_home_migration_baseline(path: pathlib.Path, identity: dict[str, Any]) -> dict[str, Any]:
    baseline, _ = load_json(path, "home migration baseline", MAX_HOME_MIGRATION_BASELINE_BYTES)
    return validate_home_migration_baseline(baseline, identity, "home migration baseline")


def require_utc_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        fail(f"{label} is invalid")
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"{label} is invalid")


def validate_promoted_receipt(
    receipt: dict[str, Any], evidence_sha256: str, identity: dict[str, Any]
) -> None:
    receipt = require_exact_object(
        receipt,
        {
            "schema",
            "status",
            "artifact",
            "release",
            "scenarios",
            "evidence_index_sha256",
            "non_promotable_reasons",
            "completed_at",
        },
        "promoted acceptance receipt",
    )
    if receipt["schema"] != "jjdguard-acceptance-receipt/v1":
        fail("promoted acceptance receipt schema is invalid")
    if receipt["status"] != "PASS":
        fail("promoted acceptance receipt status is not promotable")
    validate_identity_object(receipt["artifact"], identity, "promoted acceptance receipt artifact")
    validate_release_object(receipt["release"], identity, "promoted acceptance receipt release")
    if not isinstance(receipt["scenarios"], dict) or set(receipt["scenarios"]) != REQUIRED_SCENARIOS:
        fail("promoted acceptance receipt required scenario coverage is incomplete")
    if any(status != "PASS" for status in receipt["scenarios"].values()):
        fail("promoted acceptance receipt contains a non-PASS required scenario")
    if receipt["evidence_index_sha256"] != evidence_sha256:
        fail("promoted acceptance receipt evidence index hash drifted")
    require_hash(receipt["evidence_index_sha256"], "promoted acceptance receipt evidence index hash")
    if receipt["non_promotable_reasons"] != []:
        fail("promoted acceptance receipt contains non-promotable reasons")
    require_utc_timestamp(receipt["completed_at"], "promoted acceptance receipt completion time")


def validate_promoted_evidence_index(index: dict[str, Any], identity: dict[str, Any]) -> None:
    index = require_exact_object(
        index,
        {"schema", "artifact", "release", "entries"},
        "promoted evidence index",
    )
    if index["schema"] != "jjdguard-acceptance-evidence-index/v1":
        fail("promoted evidence index schema is invalid")
    validate_identity_object(index["artifact"], identity, "promoted evidence index artifact")
    validate_release_object(index["release"], identity, "promoted evidence index release")
    if not any(parts == (HOME_MIGRATION_BASELINE_NAME,) for parts, _ in evidence_entries(index)):
        fail("promoted evidence index is missing home migration baseline")


def validate_sidecar(
    sidecar: dict[str, Any],
    run_sha256: str,
    run_size: int,
    receipt_sha256: str,
    evidence_sha256: str,
) -> dict[str, Any]:
    keys = {
        "schema", "run_sha256", "run_size", "inner_tar_sha256", "source_revision", "source_tree",
        "image_provenance_sha256", "sbom_index_sha256", "acceptance_receipt_sha256",
        "evidence_index_sha256", "promoted_at",
    }
    if set(sidecar) != keys or sidecar.get("schema") != "jjdguard-offline-promotion/v1":
        fail("promotion sidecar schema is invalid")
    for key in (
        "run_sha256", "inner_tar_sha256", "image_provenance_sha256", "sbom_index_sha256",
        "acceptance_receipt_sha256", "evidence_index_sha256",
    ):
        require_hash(sidecar.get(key), f"promotion sidecar {key}")
    for key in ("source_revision", "source_tree"):
        require_revision(sidecar.get(key), f"promotion sidecar {key}")
    if sidecar["run_sha256"] != run_sha256 or sidecar.get("run_size") != run_size:
        fail("promotion sidecar does not bind the staged .run")
    if sidecar["acceptance_receipt_sha256"] != receipt_sha256:
        fail("promotion sidecar does not bind the staged acceptance receipt")
    if sidecar["evidence_index_sha256"] != evidence_sha256:
        fail("promotion sidecar does not bind the staged evidence index")
    if not isinstance(sidecar.get("promoted_at"), str) or TIMESTAMP.fullmatch(sidecar["promoted_at"]) is None:
        fail("promotion sidecar timestamp is invalid")
    return sidecar


def verify_installer(run: pathlib.Path) -> None:
    try:
        result = subprocess.run(["bash", str(run), "--verify-only"], check=False)
    except OSError as error:
        fail(f"sealed installer verification cannot run: {error}")
    if result.returncode != 0:
        fail("sealed installer self-check failed after promotion verification")


def run_verified_installer(run: pathlib.Path, testing: bool) -> int:
    override = os.environ.get("JJD_TRUST_TEST_INSTALL_COMMAND")
    if override:
        if not testing:
            fail("test install override is unavailable")
        command = [override, str(run)]
    else:
        if os.geteuid() != 0:
            fail("--install must run as root")
        command = ["bash", str(run), "install"]
    try:
        result = subprocess.run(command, check=False)
    except OSError as error:
        fail(f"verified installer cannot run: {error}")
    return result.returncode


def verify_release(
    release_descriptor: int,
    trust_root: pathlib.Path,
    public_key: pathlib.Path | None,
    install: bool,
    testing: bool,
) -> tuple[int, dict[str, Any]]:
    run_name = find_run(release_descriptor)
    files = release_files(run_name)
    source_names = {
        "run": files.run,
        "checksum": files.checksum,
        "sidecar": files.sidecar,
        "signature": files.signature,
        "receipt": files.receipt,
        "evidence": files.evidence,
    }
    limits = {
        "run": MAX_RUN_BYTES,
        "checksum": MAX_CHECKSUM_BYTES,
        "sidecar": MAX_SIDECAR_BYTES,
        "signature": MAX_CHECKSUM_BYTES,
        "receipt": MAX_JSON_BYTES,
        "evidence": MAX_JSON_BYTES,
    }
    ensure_staging_capacity_at(
        trust_root,
        release_descriptor,
        [(source_names[key], key, limits[key]) for key in ("run", "checksum", "sidecar", "signature", "receipt", "evidence")],
    )

    with tempfile.TemporaryDirectory(prefix=".verify-promoted-", dir=trust_root) as temporary:
        stage = pathlib.Path(temporary)
        copied: dict[str, tuple[str, int]] = {}
        for key in ("run", "checksum", "sidecar", "signature", "receipt", "evidence"):
            copied[key] = copy_regular_at(
                release_descriptor,
                source_names[key],
                stage / source_names[key],
                key,
                limits[key],
                stage,
            )
        staged_run = stage / files.run
        staged_checksum = stage / files.checksum
        staged_sidecar = stage / files.sidecar
        staged_signature = stage / files.signature
        staged_receipt = stage / files.receipt
        staged_evidence = stage / files.evidence
        validate_checksum(staged_checksum.read_bytes(), run_name, copied["run"][0])
        sidecar, sidecar_raw = load_json(staged_sidecar, "promotion sidecar", MAX_SIDECAR_BYTES)
        validate_sidecar(sidecar, copied["run"][0], copied["run"][1], copied["receipt"][0], copied["evidence"][0])
        payload = stage / "promotion.payload"
        payload.write_bytes(PROMOTION_DOMAIN + sidecar_raw)
        verify_signature_or_sha256(public_key, staged_signature, payload)
        receipt, _ = load_json(staged_receipt, "promotion acceptance receipt", MAX_JSON_BYTES)
        evidence_index, _ = load_json(staged_evidence, "promotion evidence index", MAX_JSON_BYTES)
        identity = {
            "run_sha256": copied["run"][0],
            "run_size": copied["run"][1],
            "source_revision": sidecar["source_revision"],
            "source_tree": sidecar["source_tree"],
            "inner_tar_sha256": sidecar["inner_tar_sha256"],
            "image_provenance_sha256": sidecar["image_provenance_sha256"],
            "sbom_index_sha256": sidecar["sbom_index_sha256"],
        }
        validate_promoted_receipt(receipt, copied["evidence"][0], identity)
        validate_promoted_evidence_index(evidence_index, identity)
        stage_promoted_evidence(release_descriptor, evidence_index, stage)
        identity["home_migration_baseline"] = load_home_migration_baseline(
            stage / "evidence" / HOME_MIGRATION_BASELINE_NAME, identity
        )
        verify_installer(staged_run)
        if install:
            return run_verified_installer(staged_run, testing), identity
        return 0, identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--verify", action="store_true")
    action.add_argument("--install", action="store_true")
    parser.add_argument("--release-dir", required=True, type=pathlib.Path)
    parser.add_argument("--trust-root", type=pathlib.Path)
    args = parser.parse_args()

    testing = is_test_mode()
    if args.trust_root is not None and not testing:
        fail("--trust-root is only available in the isolated test harness")
    trust_root = args.trust_root or DEFAULT_TRUST_ROOT
    require_trust_root(trust_root, testing)
    if not testing:
        verifier_path = pathlib.Path(__file__)
        if verifier_path != trust_root / TRUSTED_VERIFIER_NAME:
            fail("trusted verifier must run from the trust root")
        require_trust_file(verifier_path, "trusted verifier", testing, 4 * 1024 * 1024)
    public_key = trust_root / TRUSTED_PUBLIC_KEY_NAME
    normalized_path: pathlib.Path | None = None
    if public_key.exists():
        require_trust_file(public_key, "trusted release public key", testing, MAX_JSON_BYTES)
        normalized_key = normalize_public_key(public_key.read_bytes())
        normalized_path = trust_root / ".normalized-release-public.pem"
    release_descriptor = -1
    try:
        if normalized_path is not None:
            normalized_path.write_bytes(normalized_key)
            os.chmod(normalized_path, 0o600)
        release_descriptor = open_absolute_directory(args.release_dir, "promoted release directory")
        status, identity = verify_release(
            release_descriptor, trust_root, normalized_path, args.install, testing
        )
        if args.verify:
            print(json.dumps(identity, sort_keys=True, separators=(",", ":")))
            return 0
        return status
    finally:
        if release_descriptor >= 0:
            close_descriptor(release_descriptor)
        if normalized_path is not None:
            normalized_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
