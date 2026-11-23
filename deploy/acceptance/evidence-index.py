#!/usr/bin/env python3
"""Build a verifier-compatible evidence index from safe regular files only."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any


HASH = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_INDEX_BYTES = 1024 * 1024
MAX_EVIDENCE_ENTRIES = 256
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
SENSITIVE_LOG_VALUE = re.compile(
    rb"(?:\b(?:password|token|cookie|access[ _-]?token|session[ _-]?cookie|raw[ _-]?payload|payload|prompt|authorization|api[ _-]?key|credential|secret)\b\s*(?:[\"']\s*)?[:=]|\bbearer\s+\S+)",
    re.IGNORECASE,
)
SENSITIVE_DETAIL_VALUE = re.compile(
    r"(?:password|token|cookie|raw[ _-]?payload|payload|prompt|authorization|bearer|api[ _-]?key|secret|credential)",
    re.IGNORECASE,
)
REQUIRED_SCENARIOS = (
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
)
STEP_RECORD_FIELDS = {
    "schema",
    "scenario",
    "step",
    "status",
    "started_at",
    "finished_at",
    "exit_code",
    "log_sha256",
    "log_bytes",
    "details",
}
ARCH = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
DOCKER_VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,128}\|[A-Za-z0-9._+-]{1,128}$")
VERSION_SEQUENCE = re.compile(r"^[A-Za-z0-9._-]{1,64}(?:->[A-Za-z0-9._-]{1,64})+$")
IMAGE_IDS = re.compile(r"^sha256:[0-9a-f]{64}(?:,sha256:[0-9a-f]{64})*$")


class IndexError(ValueError):
    """An index cannot be safely generated."""


def fail(message: str) -> None:
    raise IndexError(message)


def report_rejection(message: str) -> None:
    try:
        print(message, file=sys.stderr)
    except OSError:
        # A capacity probe can constrain stderr to the same full filesystem.
        # Preserve the rejection result even when its diagnostic cannot persist.
        pass


def require_secure_openat() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail("platform lacks required O_NOFOLLOW/O_DIRECTORY support")


def normalized_root(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def load_exact_object(raw: str, keys: set[str], label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{label} JSON is invalid: {error}")
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields are invalid")
    return value


def validate_identity(artifact_raw: str, release_raw: str) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact = load_exact_object(
        artifact_raw,
        {"run_sha256", "run_size", "inner_tar_sha256"},
        "artifact",
    )
    if (
        not isinstance(artifact["run_sha256"], str)
        or HASH.fullmatch(artifact["run_sha256"]) is None
        or not isinstance(artifact["inner_tar_sha256"], str)
        or HASH.fullmatch(artifact["inner_tar_sha256"]) is None
        or not isinstance(artifact["run_size"], int)
        or isinstance(artifact["run_size"], bool)
        or artifact["run_size"] < 1
    ):
        fail("artifact identity is invalid")
    release = load_exact_object(
        release_raw,
        {"source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256"},
        "release",
    )
    for key in ("source_revision", "source_tree"):
        if not isinstance(release[key], str) or REVISION.fullmatch(release[key]) is None:
            fail("release revision identity is invalid")
    for key in ("image_provenance_sha256", "sbom_index_sha256"):
        if not isinstance(release[key], str) or HASH.fullmatch(release[key]) is None:
            fail("release hash identity is invalid")
    return artifact, release


def canonical_parts(root: pathlib.Path, candidate: pathlib.Path, label: str) -> tuple[str, ...]:
    if candidate.is_absolute():
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            fail(f"{label} escapes evidence root")
    else:
        relative = candidate
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} is not canonical")
    return parts


def open_directory(root: pathlib.Path) -> int:
    require_secure_openat()
    absolute_root = normalized_root(root)
    parts = absolute_root.parts
    if not absolute_root.is_absolute() or not parts or parts[0] != os.sep:
        fail("evidence root is not absolute")
    components = parts[1:]
    if any(component in {"", ".", ".."} for component in components):
        fail("evidence root is not canonical")
    directory_fd: int | None = None
    try:
        directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in components:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            previous_fd = directory_fd
            directory_fd = next_fd
            os.close(previous_fd)
        metadata = os.fstat(directory_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            fail("evidence root is not a real directory")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            fail("evidence root ownership boundary is unsafe")
        return directory_fd
    except OSError as error:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        fail(f"evidence root cannot be opened safely: {error}")
    except Exception:
        if directory_fd is not None:
            os.close(directory_fd)
        raise


def open_parent(root_fd: int, parts: tuple[str, ...]) -> int:
    try:
        directory_fd = os.dup(root_fd)
    except OSError as error:
        fail(f"evidence root descriptor is unavailable: {error}")
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            except OSError as error:
                fail(f"evidence path is unsafe: {error}")
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def hash_regular_entry(root_fd: int, parts: tuple[str, ...]) -> tuple[str, int]:
    parent_fd = open_parent(root_fd, parts)
    descriptor: int | None = None
    try:
        try:
            listed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"evidence entry is unavailable: {error}")
        if not stat.S_ISREG(listed.st_mode):
            fail("evidence entry is not a regular non-symlink file")
        if listed.st_size < 0 or listed.st_size > MAX_FILE_BYTES:
            fail("evidence entry exceeds the size limit")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        try:
            descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
        except OSError as error:
            fail(f"evidence entry cannot be opened safely: {error}")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != listed.st_dev
            or opened.st_ino != listed.st_ino
            or opened.st_size != listed.st_size
        ):
            fail("evidence entry changed while it was opened")
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > MAX_FILE_BYTES:
                    fail("evidence entry exceeds the size limit while reading")
                digest.update(chunk)
        if copied != listed.st_size:
            fail("evidence entry changed while it was read")
        return digest.hexdigest(), copied
    except OSError as error:
        fail(f"evidence entry cannot be read: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def read_regular_entry(root_fd: int, parts: tuple[str, ...], label: str) -> tuple[bytes, str]:
    parent_fd = open_parent(root_fd, parts)
    descriptor: int | None = None
    try:
        try:
            listed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"{label} is unavailable: {error}")
        if not stat.S_ISREG(listed.st_mode):
            fail(f"{label} is not a regular non-symlink file")
        if listed.st_size < 0 or listed.st_size > MAX_FILE_BYTES:
            fail(f"{label} exceeds the size limit")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        try:
            descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
        except OSError as error:
            fail(f"{label} cannot be opened safely: {error}")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != listed.st_dev
            or opened.st_ino != listed.st_ino
            or opened.st_size != listed.st_size
        ):
            fail(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) != listed.st_size:
            fail(f"{label} changed while it was read")
        return raw, hashlib.sha256(raw).hexdigest()
    except OSError as error:
        fail(f"{label} cannot be read safely: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def load_json_entry(root_fd: int, parts: tuple[str, ...], label: str) -> tuple[dict[str, Any], str]:
    raw, digest = read_regular_entry(root_fd, parts, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} JSON is invalid: {error}")
    if not isinstance(value, dict):
        fail(f"{label} JSON is not an object")
    return value, digest


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def formal_record_specs() -> tuple[tuple[str, str, str, str], ...]:
    specs: list[tuple[str, str, str, str]] = [
        ("vm-lifecycle", "vm-lifecycle", "verify-boot-id", "lifecycle"),
        ("vm-metadata", "vm-metadata", "collect-runtime", "metadata"),
        ("network", "network", "verify-offline", "network"),
        ("vm-postcheck", "vm-postcheck", "collect-runtime", "postcheck"),
    ]
    for scenario in REQUIRED_SCENARIOS:
        specs.extend(
            (
                (scenario, scenario, "execute", "scenario"),
                (f"{scenario}.migration-probe", scenario, "migration-probe", "migration-probe"),
                (f"{scenario}.business-probe", scenario, "business-probe", "business-probe"),
            )
        )
    return tuple(specs)


def require_text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        fail(f"formal evidence {label} is invalid")
    if any(ord(character) < 32 and character != "\t" for character in value):
        fail(f"formal evidence {label} is invalid")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"formal evidence {label} is invalid")
    return value


def require_timestamp(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        fail(f"formal evidence {label} is invalid")
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"formal evidence {label} is invalid")


def validate_formal_details(kind: str, details: Any, record_id: str) -> None:
    if not isinstance(details, dict):
        fail(f"formal evidence details are invalid: {record_id}")
    details_raw = json.dumps(details, sort_keys=True, separators=(",", ":"))
    if SENSITIVE_DETAIL_VALUE.search(details_raw) is not None:
        fail(f"formal evidence details contain sensitive content: {record_id}")
    if kind == "lifecycle":
        if set(details) != {"boot_id_before", "boot_id_after"}:
            fail(f"formal evidence details are invalid: {record_id}")
        before = require_text(details["boot_id_before"], f"boot ID before: {record_id}")
        after = require_text(details["boot_id_after"], f"boot ID after: {record_id}")
        if before == after:
            fail(f"formal evidence boot IDs did not change: {record_id}")
        return
    if kind == "metadata":
        expected = {"os", "kernel", "arch", "vcpu", "ram_kib", "docker_before"}
        if set(details) != expected:
            fail(f"formal evidence details are invalid: {record_id}")
        require_text(details["os"], f"OS metadata: {record_id}")
        require_text(details["kernel"], f"kernel metadata: {record_id}")
        require_text(details["arch"], f"architecture metadata: {record_id}", ARCH)
        require_text(details["vcpu"], f"vCPU metadata: {record_id}", POSITIVE_INTEGER)
        require_text(details["ram_kib"], f"RAM metadata: {record_id}", POSITIVE_INTEGER)
        require_text(details["docker_before"], f"Docker metadata: {record_id}", DOCKER_VERSION)
        return
    if kind == "network":
        if set(details) != {"public_network", "probe_exit"}:
            fail(f"formal evidence details are invalid: {record_id}")
        if details["public_network"] != "blocked":
            fail(f"formal evidence network is not blocked: {record_id}")
        probe_exit = require_text(details["probe_exit"], f"network probe exit: {record_id}", POSITIVE_INTEGER)
        if int(probe_exit) > 254:
            fail(f"formal evidence network probe exit is invalid: {record_id}")
        return
    if kind == "postcheck":
        if set(details) != {"docker_after", "version_sequence", "image_ids"}:
            fail(f"formal evidence details are invalid: {record_id}")
        require_text(details["docker_after"], f"postcheck Docker metadata: {record_id}", DOCKER_VERSION)
        require_text(details["version_sequence"], f"version sequence: {record_id}", VERSION_SEQUENCE)
        require_text(details["image_ids"], f"image IDs: {record_id}", IMAGE_IDS)
        return
    if kind == "scenario":
        if details != {"migration_probe": "PASS", "business_probe": "PASS"}:
            fail(f"formal evidence scenario probes are incomplete: {record_id}")
        return
    if kind == "migration-probe":
        if details != {"probe": "migration"}:
            fail(f"formal evidence migration probe details are invalid: {record_id}")
        return
    if kind == "business-probe":
        if details != {"probe": "business"}:
            fail(f"formal evidence business probe details are invalid: {record_id}")
        return
    fail(f"formal evidence kind is unknown: {record_id}")


def validate_formal_record(
    record: dict[str, Any],
    record_id: str,
    scenario: str,
    step: str,
    kind: str,
    log_raw: bytes,
    log_sha256: str,
) -> None:
    if SENSITIVE_LOG_VALUE.search(log_raw) is not None:
        fail(f"formal evidence log contains sensitive content: {record_id}")
    if set(record) != STEP_RECORD_FIELDS:
        fail(f"formal evidence record fields are invalid: {record_id}")
    if (
        record["schema"] != "jjdguard-vm-step-record/v1"
        or record["scenario"] != scenario
        or record["step"] != step
        or record["status"] != "PASS"
        or record["exit_code"] != 0
    ):
        fail(f"formal evidence record is not a completed PASS: {record_id}")
    started_at = require_timestamp(record["started_at"], f"start time: {record_id}")
    finished_at = require_timestamp(record["finished_at"], f"finish time: {record_id}")
    if finished_at < started_at:
        fail(f"formal evidence timestamps are out of order: {record_id}")
    if HASH.fullmatch(record["log_sha256"]) is None or record["log_sha256"] != log_sha256:
        fail(f"formal evidence log binding drifted: {record_id}")
    if (
        not isinstance(record["log_bytes"], int)
        or isinstance(record["log_bytes"], bool)
        or record["log_bytes"] != len(log_raw)
    ):
        fail(f"formal evidence log size drifted: {record_id}")
    validate_formal_details(kind, record["details"], record_id)


def validate_formal_index(
    root: pathlib.Path,
    root_fd: int,
    index_parts: tuple[str, ...],
    artifact: dict[str, Any],
    release: dict[str, Any],
) -> str:
    index, index_sha256 = load_json_entry(root_fd, index_parts, "evidence index")
    if set(index) != {"schema", "artifact", "release", "entries"}:
        fail("evidence index fields are invalid")
    if index["schema"] != "jjdguard-acceptance-evidence-index/v1":
        fail("evidence index schema is invalid")
    if index["artifact"] != artifact or index["release"] != release:
        fail("evidence index identity drifted")
    entries = index["entries"]
    if not isinstance(entries, list) or not entries:
        fail("evidence index entries are empty")
    if len(entries) > MAX_EVIDENCE_ENTRIES:
        fail("evidence index contains too many entries")

    indexed: dict[str, str] = {}
    total_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            fail("evidence index entry fields are invalid")
        if not isinstance(entry["path"], str) or not isinstance(entry["sha256"], str):
            fail("evidence index entry types are invalid")
        if HASH.fullmatch(entry["sha256"]) is None:
            fail("evidence index entry hash is invalid")
        parts = canonical_parts(root, pathlib.Path(entry["path"]), "evidence index entry path")
        relative = "/".join(parts)
        if relative in indexed:
            fail("evidence index contains duplicate paths")
        raw, actual_sha256 = read_regular_entry(root_fd, parts, f"evidence entry {relative}")
        total_bytes += len(raw)
        if total_bytes > MAX_EVIDENCE_BYTES:
            fail("evidence index exceeds the total size limit")
        if actual_sha256 != entry["sha256"]:
            fail(f"evidence entry hash drifted: {relative}")
        indexed[relative] = actual_sha256

    required_paths: set[str] = set()
    for record_id, scenario, step, kind in formal_record_specs():
        record_relative = f"records/{record_id}.json"
        log_relative = f"logs/{record_id}.log"
        required_paths.update((record_relative, log_relative))
        if record_relative not in indexed or log_relative not in indexed:
            fail(f"formal evidence manifest is incomplete: {record_id}")
        record, record_sha256 = load_json_entry(
            root_fd,
            ("records", f"{record_id}.json"),
            f"formal evidence record {record_id}",
        )
        if record_sha256 != indexed[record_relative]:
            fail(f"formal evidence record hash drifted: {record_id}")
        log_raw, log_sha256 = read_regular_entry(
            root_fd,
            ("logs", f"{record_id}.log"),
            f"formal evidence log {record_id}",
        )
        if log_sha256 != indexed[log_relative]:
            fail(f"formal evidence index log hash drifted: {record_id}")
        validate_formal_record(record, record_id, scenario, step, kind, log_raw, log_sha256)
    # A formal VM run may additionally bind the observed migration ledger that
    # home recovery consumes. Promotion validates its exact schema and identity.
    if "home-migration-baseline.json" in indexed:
        required_paths.add("home-migration-baseline.json")
    if set(indexed) != required_paths:
        fail("formal evidence manifest is not closed")
    return index_sha256


def write_formal_receipt(
    root: pathlib.Path,
    root_fd: int,
    index_parts: tuple[str, ...],
    receipt_parts: tuple[str, ...],
    artifact: dict[str, Any],
    release: dict[str, Any],
    completed_at: str,
) -> tuple[pathlib.Path, str]:
    if TIMESTAMP.fullmatch(completed_at) is None:
        fail("formal receipt completion time is invalid")
    if receipt_parts == index_parts:
        fail("formal receipt cannot replace the evidence index")
    if len(receipt_parts) < 2 or receipt_parts[0] != ".formal-receipts":
        fail("formal receipt must use a staged path")
    evidence_sha256 = validate_formal_index(root, root_fd, index_parts, artifact, release)
    receipt = {
        "schema": "jjdguard-acceptance-receipt/v1",
        "status": "PASS",
        "artifact": artifact,
        "release": release,
        "scenarios": {scenario: "PASS" for scenario in REQUIRED_SCENARIOS},
        "evidence_index_sha256": evidence_sha256,
        "non_promotable_reasons": [],
        "completed_at": completed_at,
    }
    encoded = canonical_json_bytes(receipt)
    output = write_json(root, root_fd, receipt_parts, receipt)
    return output, hashlib.sha256(encoded).hexdigest()


def same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def read_private_formal_receipt(
    parent_fd: int,
    name: str,
    label: str,
    expected: os.stat_result | None = None,
) -> tuple[os.stat_result, str]:
    descriptor: int | None = None
    try:
        try:
            listed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"{label} is unavailable: {error}")
        if not stat.S_ISREG(listed.st_mode) or stat.S_IMODE(listed.st_mode) != 0o600:
            fail(f"{label} is not a private regular file")
        if listed.st_size < 0 or listed.st_size > MAX_FILE_BYTES:
            fail(f"{label} exceeds the size limit")
        if expected is not None and not same_inode(listed, expected):
            fail(f"{label} changed before publication")
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            fail(f"{label} cannot be opened safely: {error}")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not same_inode(opened, listed)
            or opened.st_size != listed.st_size
        ):
            fail(f"{label} changed while it was opened")
        if expected is not None and not same_inode(opened, expected):
            fail(f"{label} changed before publication")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        finished = os.fstat(descriptor)
        if not same_inode(finished, opened) or finished.st_size != opened.st_size or len(raw) != opened.st_size:
            fail(f"{label} changed while it was read")
        return opened, hashlib.sha256(raw).hexdigest()
    except OSError as error:
        fail(f"{label} cannot be read safely: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def publish_formal_receipt(
    root: pathlib.Path,
    root_fd: int,
    staged_parts: tuple[str, ...],
    receipt_parts: tuple[str, ...],
    expected_staged_sha256: str,
) -> pathlib.Path:
    if staged_parts == receipt_parts:
        fail("staged and final formal receipt paths must differ")
    if len(staged_parts) < 2 or staged_parts[0] != ".formal-receipts":
        fail("formal receipt must be published from a staged path")
    if HASH.fullmatch(expected_staged_sha256) is None:
        fail("expected staged formal receipt hash is invalid")
    staged_parent_fd = open_parent(root_fd, staged_parts)
    receipt_parent_fd: int | None = None
    try:
        staged, staged_sha256 = read_private_formal_receipt(
            staged_parent_fd,
            staged_parts[-1],
            "staged formal receipt",
        )
        if staged_sha256 != expected_staged_sha256:
            fail("staged formal receipt hash drifted before publication")
        receipt_parent_fd = open_parent(root_fd, receipt_parts)
        try:
            os.link(
                staged_parts[-1],
                receipt_parts[-1],
                src_dir_fd=staged_parent_fd,
                dst_dir_fd=receipt_parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            fail("formal receipt target already exists")
        except OSError as error:
            fail(f"formal receipt cannot be published safely: {error}")
        try:
            published = os.stat(receipt_parts[-1], dir_fd=receipt_parent_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"published formal receipt is unavailable: {error}")
        if (
            not stat.S_ISREG(published.st_mode)
            or stat.S_IMODE(published.st_mode) != 0o600
            or not same_inode(published, staged)
        ):
            fail("published formal receipt did not preserve the staged file; manual receipt disposal is required")
        try:
            _, published_sha256 = read_private_formal_receipt(
                receipt_parent_fd,
                receipt_parts[-1],
                "published formal receipt",
                published,
            )
            _, current_staged_sha256 = read_private_formal_receipt(
                staged_parent_fd,
                staged_parts[-1],
                "staged formal receipt",
                staged,
            )
        except IndexError as error:
            fail(f"{error}; manual receipt disposal is required")
        if published_sha256 != expected_staged_sha256 or current_staged_sha256 != expected_staged_sha256:
            fail("staged formal receipt hash drifted during publication; manual receipt disposal is required")
        return root.joinpath(*receipt_parts)
    finally:
        if receipt_parent_fd is not None:
            os.close(receipt_parent_fd)
        os.close(staged_parent_fd)


def discard_formal_receipt(root_fd: int, receipt_parts: tuple[str, ...]) -> None:
    del root_fd
    fail(f"formal receipt requires manual disposal: {'/'.join(receipt_parts)}")


def discard_interrupted_formal_publication(
    root: pathlib.Path,
    root_fd: int,
    staged_parts: tuple[str, ...],
    receipt_parts: tuple[str, ...],
    expected_staged_sha256: str,
) -> None:
    if len(staged_parts) < 2 or staged_parts[0] != ".formal-receipts":
        fail("formal receipt must be recovered from a staged path")
    if HASH.fullmatch(expected_staged_sha256) is None:
        fail("expected staged formal receipt hash is invalid")
    del root, root_fd
    fail(
        "interrupted formal receipt cleanup requires manual disposal: "
        f"staged={'/'.join(staged_parts)} final={'/'.join(receipt_parts)}"
    )


def write_json(root: pathlib.Path, root_fd: int, parts: tuple[str, ...], value: dict[str, Any]) -> pathlib.Path:
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_INDEX_BYTES:
        fail("evidence index exceeds the output size limit")
    try:
        directory_fd = os.dup(root_fd)
    except OSError as error:
        fail(f"evidence root descriptor is unavailable: {error}")
    output_fd: int | None = None
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            except OSError as error:
                fail(f"cannot create index directory: {error}")
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            except OSError as error:
                fail(f"index output path is unsafe: {error}")
            os.close(directory_fd)
            directory_fd = next_fd
        temporary_flag = getattr(os, "O_TMPFILE", None)
        if temporary_flag is None:
            fail("platform lacks required O_TMPFILE support")
        try:
            output_fd = os.open(".", os.O_WRONLY | temporary_flag, 0o600, dir_fd=directory_fd)
        except OSError as error:
            fail(f"cannot create private evidence index safely: {error}")
        metadata = os.fstat(output_fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail("created evidence file is not a private regular file")
        view = memoryview(encoded)
        while view:
            try:
                written = os.write(output_fd, view)
            except OSError as error:
                fail(f"cannot write evidence index safely: {error}")
            if written < 1:
                fail("cannot write evidence index safely: short write")
            view = view[written:]
        try:
            os.fsync(output_fd)
        except OSError as error:
            fail(f"cannot sync evidence index safely: {error}")
        try:
            os.link(
                f"/proc/self/fd/{output_fd}",
                parts[-1],
                dst_dir_fd=directory_fd,
                follow_symlinks=True,
            )
        except FileExistsError:
            fail("evidence index target already exists")
        except OSError as error:
            fail(f"cannot publish evidence index safely: {error}")
        return root.joinpath(*parts)
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(directory_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--artifact-json")
    parser.add_argument("--release-json")
    parser.add_argument("--entry", action="append")
    parser.add_argument("--write-formal-receipt", type=pathlib.Path)
    parser.add_argument("--discard-formal-receipt", type=pathlib.Path)
    parser.add_argument("--discard-interrupted-formal-receipt", type=pathlib.Path)
    parser.add_argument("--publish-formal-receipt", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--completed-at")
    parser.add_argument("--expected-staged-sha256")
    args = parser.parse_args()

    root_fd: int | None = None
    try:
        root = normalized_root(args.evidence_root)
        root_fd = open_directory(root)
        if args.publish_formal_receipt is not None:
            if args.receipt is None or args.expected_staged_sha256 is None:
                fail("publish mode requires a final formal receipt path and staged receipt hash")
            if any(
                value is not None
                for value in (
                    args.output,
                    args.artifact_json,
                    args.release_json,
                    args.write_formal_receipt,
                    args.discard_formal_receipt,
                    args.discard_interrupted_formal_receipt,
                    args.completed_at,
                )
            ) or args.entry:
                fail("publish mode does not accept index arguments")
            staged_parts = canonical_parts(root, args.publish_formal_receipt, "staged formal receipt path")
            receipt_parts = canonical_parts(root, args.receipt, "formal receipt path")
            output = publish_formal_receipt(root, root_fd, staged_parts, receipt_parts, args.expected_staged_sha256)
            print(json.dumps({"action": "publish-formal-receipt", "path": str(output)}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.discard_interrupted_formal_receipt is not None:
            if args.receipt is None or args.expected_staged_sha256 is None:
                fail("interrupted publication recovery requires final receipt path and staged receipt hash")
            if any(
                value is not None
                for value in (
                    args.output,
                    args.artifact_json,
                    args.release_json,
                    args.write_formal_receipt,
                    args.discard_formal_receipt,
                    args.publish_formal_receipt,
                    args.completed_at,
                )
            ) or args.entry:
                fail("interrupted publication recovery does not accept index arguments")
            staged_parts = canonical_parts(root, args.discard_interrupted_formal_receipt, "staged formal receipt path")
            receipt_parts = canonical_parts(root, args.receipt, "formal receipt path")
            discard_interrupted_formal_publication(root, root_fd, staged_parts, receipt_parts, args.expected_staged_sha256)
            print(json.dumps({"action": "discard-interrupted-formal-publication", "path": "/".join(receipt_parts)}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.discard_formal_receipt is not None:
            if any(
                value is not None
                for value in (
                    args.output,
                    args.artifact_json,
                    args.release_json,
                    args.write_formal_receipt,
                    args.discard_interrupted_formal_receipt,
                    args.receipt,
                    args.completed_at,
                    args.expected_staged_sha256,
                )
            ) or args.entry:
                fail("discard mode does not accept index arguments")
            receipt_parts = canonical_parts(root, args.discard_formal_receipt, "formal receipt path")
            discard_formal_receipt(root_fd, receipt_parts)
            print(json.dumps({"action": "discard-formal-receipt", "path": "/".join(receipt_parts)}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.output is None or args.artifact_json is None or args.release_json is None:
            fail("index mode requires output and identity arguments")
        if args.expected_staged_sha256 is not None:
            fail("staged receipt hash only applies to publish mode")
        if args.receipt is not None:
            fail("receipt only applies to publish mode")
        output_parts = canonical_parts(root, args.output, "index output path")
        artifact, release = validate_identity(args.artifact_json, args.release_json)
        if args.write_formal_receipt is not None:
            if args.entry:
                fail("formal receipt mode does not accept evidence entries")
            if args.completed_at is None:
                fail("formal receipt mode requires completion time")
            receipt_parts = canonical_parts(root, args.write_formal_receipt, "formal receipt path")
            output, staged_sha256 = write_formal_receipt(root, root_fd, output_parts, receipt_parts, artifact, release, args.completed_at)
            print(json.dumps({"action": "write-formal-receipt", "path": str(output), "sha256": staged_sha256}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.completed_at is not None:
            fail("completion time only applies to formal receipt mode")
        if not args.entry:
            fail("index mode requires evidence entries")
        if len(args.entry) > MAX_EVIDENCE_ENTRIES:
            fail("evidence index contains too many entries")
        entries: list[dict[str, str]] = []
        seen: set[str] = set()
        total_bytes = 0
        for raw in args.entry:
            parts = canonical_parts(root, pathlib.Path(raw), "evidence entry path")
            relative = "/".join(parts)
            if relative == "/".join(output_parts):
                fail("index cannot include itself")
            if relative in seen:
                fail("evidence entry path is duplicated")
            seen.add(relative)
            entry_sha256, entry_bytes = hash_regular_entry(root_fd, parts)
            total_bytes += entry_bytes
            if total_bytes > MAX_EVIDENCE_BYTES:
                fail("evidence index exceeds the total size limit")
            entries.append({"path": relative, "sha256": entry_sha256})
        if not entries:
            fail("evidence entries are empty")
        index = {
            "schema": "jjdguard-acceptance-evidence-index/v1",
            "artifact": artifact,
            "release": release,
            "entries": entries,
        }
        output = write_json(root, root_fd, output_parts, index)
    except IndexError as error:
        report_rejection(f"[error] evidence-index rejected: {error}")
        return 2
    finally:
        if root_fd is not None:
            os.close(root_fd)
    print(json.dumps({"path": str(output), "entries": len(entries)}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
