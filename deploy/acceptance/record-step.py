#!/usr/bin/env python3
"""Write fail-closed, redacted VM acceptance evidence below one real root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any


MAX_LOG_BYTES = 64 * 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVENT = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
HASH = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY = re.compile(
    r"(?:password|token|cookie|raw[ _-]?payload|payload|prompt|authorization|secret|api[ _-]?key|credential)",
    re.IGNORECASE,
)
SENSITIVE_VALUE = re.compile(
    r"(?:password|token|cookie|raw[ _-]?payload|payload|prompt|authorization|bearer|api[ _-]?key|secret|credential)",
    re.IGNORECASE,
)
SENSITIVE_LOG_VALUE = re.compile(
    rb"(?:\b(?:password|token|cookie|access[ _-]?token|session[ _-]?cookie|raw[ _-]?payload|payload|prompt|authorization|api[ _-]?key|credential|secret)\b\s*(?:[\"']\s*)?[:=]|\bbearer\s+\S+)",
    re.IGNORECASE,
)
LOG_SCAN_TAIL_BYTES = 128


class RecordError(ValueError):
    """An evidence operation cannot be safely completed."""


def fail(message: str) -> None:
    raise RecordError(message)


def require_secure_openat() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail("platform lacks required O_NOFOLLOW/O_DIRECTORY support")


def normalized_root(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def canonical_parts(root: pathlib.Path, value: pathlib.Path, label: str) -> tuple[str, ...]:
    if value.is_absolute():
        try:
            relative = value.relative_to(root)
        except ValueError:
            fail(f"{label} escapes evidence root")
    else:
        relative = value
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} is not canonical")
    return parts


def open_root(root: pathlib.Path) -> int:
    require_secure_openat()
    parts = root.parts
    if not root.is_absolute() or not parts or parts[0] != os.sep:
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


def open_parent(root_fd: int, parts: tuple[str, ...], create: bool = False) -> int:
    try:
        directory_fd = os.dup(root_fd)
    except OSError as error:
        fail(f"evidence root descriptor is unavailable: {error}")
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                except OSError as error:
                    fail(f"cannot create evidence directory: {error}")
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


def hash_regular_file(root_fd: int, parts: tuple[str, ...]) -> tuple[str, int]:
    parent_fd = open_parent(root_fd, parts)
    descriptor: int | None = None
    try:
        try:
            listed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"log is unavailable: {error}")
        if not stat.S_ISREG(listed.st_mode):
            fail("log is not a regular non-symlink file")
        if listed.st_size < 0 or listed.st_size > MAX_LOG_BYTES:
            fail("log exceeds the size limit")
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            fail(f"log cannot be opened safely: {error}")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != listed.st_dev
            or opened.st_ino != listed.st_ino
            or opened.st_size != listed.st_size
        ):
            fail("log changed while it was opened")
        digest = hashlib.sha256()
        copied = 0
        scan_tail = b""
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > MAX_LOG_BYTES:
                    fail("log exceeds the size limit while reading")
                scan_window = scan_tail + chunk
                if SENSITIVE_LOG_VALUE.search(scan_window) is not None:
                    fail("log contains sensitive content")
                scan_tail = scan_window[-LOG_SCAN_TAIL_BYTES:]
                digest.update(chunk)
        if copied != listed.st_size:
            fail("log changed while it was read")
        return digest.hexdigest(), copied
    except OSError as error:
        fail(f"log cannot be read: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def create_log(root_fd: int, parts: tuple[str, ...]) -> None:
    parent_fd = open_parent(root_fd, parts, create=True)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        except OSError as error:
            fail(f"cannot create log safely: {error}")
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("created log is not a regular file")
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def append_log(root_fd: int, parts: tuple[str, ...], event: str) -> None:
    if EVENT.fullmatch(event) is None:
        fail("log event is not a safe identifier")
    parent_fd = open_parent(root_fd, parts)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(parts[-1], os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as error:
            fail(f"log cannot be opened for append safely: {error}")
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("log is not a regular non-symlink file")
        try:
            write_all(descriptor, (event + "\n").encode("ascii"), "log event")
            try:
                os.fsync(descriptor)
            except OSError as error:
                fail(f"cannot sync log safely: {error}")
        except RecordError:
            try:
                current = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_dev != metadata.st_dev
                    or current.st_ino != metadata.st_ino
                    or current.st_size < metadata.st_size
                ):
                    fail("log changed while its append was rolled back")
                os.ftruncate(descriptor, metadata.st_size)
                os.fsync(descriptor)
            except OSError as error:
                fail(f"cannot roll back log append safely: {error}")
            raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def read_json_under_root(root_fd: int, parts: tuple[str, ...], label: str) -> dict[str, Any]:
    parent_fd = open_parent(root_fd, parts)
    descriptor: int | None = None
    try:
        try:
            listed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            fail(f"{label} is unavailable: {error}")
        if not stat.S_ISREG(listed.st_mode):
            fail(f"{label} is not a regular non-symlink file")
        if listed.st_size < 0 or listed.st_size > 1024 * 1024:
            fail(f"{label} exceeds the size limit")
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd)
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
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) != listed.st_size:
            fail(f"{label} changed while it was read")
    except OSError as error:
        fail(f"{label} cannot be read safely: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} JSON is invalid: {error}")
    if not isinstance(value, dict):
        fail(f"{label} JSON is not an object")
    return value


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or SENSITIVE_KEY.search(key):
                continue
            result[key] = sanitize(item)
        return result
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return "[redacted]" if SENSITIVE_VALUE.search(value) else value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "[redacted]"


def parse_details(raw: str | None) -> dict[str, Any]:
    if raw is None:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"details JSON is invalid: {error}")
    if not isinstance(parsed, dict):
        fail("details JSON must be an object")
    sanitized = sanitize(parsed)
    encoded = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 16 * 1024:
        fail("sanitized details exceed the size limit")
    return sanitized


def write_all(descriptor: int, encoded: bytes, label: str) -> None:
    view = memoryview(encoded)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as error:
            fail(f"cannot write {label} safely: {error}")
        if written < 1:
            fail(f"cannot write {label} safely: short write")
        view = view[written:]


def write_json_under_root(root: pathlib.Path, root_fd: int, parts: tuple[str, ...], record: dict[str, Any]) -> pathlib.Path:
    parent_fd = open_parent(root_fd, parts, create=True)
    descriptor: int | None = None
    try:
        temporary_flag = getattr(os, "O_TMPFILE", None)
        if temporary_flag is None:
            fail("platform lacks required O_TMPFILE support")
        try:
            descriptor = os.open(".", os.O_WRONLY | temporary_flag, 0o600, dir_fd=parent_fd)
        except OSError as error:
            fail(f"cannot create private evidence record safely: {error}")
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("evidence record is not a regular file")
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        write_all(descriptor, encoded, "evidence record")
        os.fsync(descriptor)
        try:
            os.link(
                f"/proc/self/fd/{descriptor}",
                parts[-1],
                dst_dir_fd=parent_fd,
                follow_symlinks=True,
            )
        except FileExistsError:
            fail("evidence record target already exists")
        except OSError as error:
            fail(f"cannot publish evidence record safely: {error}")
        return root.joinpath(*parts)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def require_record_arguments(args: argparse.Namespace) -> None:
    required = ("output", "scenario", "step", "status", "exit_code", "started_at", "finished_at", "log")
    if any(getattr(args, name) is None for name in required):
        fail("record mode requires all record arguments")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--scenario")
    parser.add_argument("--step")
    parser.add_argument("--status", choices=("PASS", "FAIL"))
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--started-at")
    parser.add_argument("--finished-at")
    parser.add_argument("--log", type=pathlib.Path)
    parser.add_argument("--details-json")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--create-log", type=pathlib.Path)
    actions.add_argument("--append-log", type=pathlib.Path)
    actions.add_argument("--verify-record-log", type=pathlib.Path)
    parser.add_argument("--event")
    args = parser.parse_args()

    root_fd: int | None = None
    try:
        root = normalized_root(args.evidence_root)
        require_secure_openat()
        root_fd = open_root(root)
        if args.create_log is not None:
            if args.event is not None:
                fail("--event only applies to --append-log")
            parts = canonical_parts(root, args.create_log, "log path")
            create_log(root_fd, parts)
            print(json.dumps({"action": "create-log", "path": "/".join(parts)}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.append_log is not None:
            if args.event is None:
                fail("--append-log requires --event")
            parts = canonical_parts(root, args.append_log, "log path")
            append_log(root_fd, parts, args.event)
            print(json.dumps({"action": "append-log", "path": "/".join(parts)}, sort_keys=True, separators=(",", ":")))
            return 0
        if args.verify_record_log is not None:
            if args.log is None:
                fail("--verify-record-log requires --log")
            record_parts = canonical_parts(root, args.verify_record_log, "record path")
            log_parts = canonical_parts(root, args.log, "log path")
            record = read_json_under_root(root_fd, record_parts, "record")
            expected = record.get("log_sha256")
            if not isinstance(expected, str) or HASH.fullmatch(expected) is None:
                fail("record log hash is invalid")
            observed, _ = hash_regular_file(root_fd, log_parts)
            if observed != expected:
                fail("record log hash drifted")
            print(json.dumps({"action": "verify-record-log", "status": "verified"}, sort_keys=True, separators=(",", ":")))
            return 0

        require_record_arguments(args)
        assert args.output is not None and args.log is not None
        assert args.scenario is not None and args.step is not None
        assert args.status is not None and args.exit_code is not None
        assert args.started_at is not None and args.finished_at is not None
        if IDENTIFIER.fullmatch(args.scenario) is None or IDENTIFIER.fullmatch(args.step) is None:
            fail("scenario and step must be safe identifiers")
        if not 0 <= args.exit_code <= 255:
            fail("exit code is outside the supported range")
        if (args.status == "PASS" and args.exit_code != 0) or (args.status == "FAIL" and args.exit_code == 0):
            fail("status and exit code semantics are invalid")
        if TIMESTAMP.fullmatch(args.started_at) is None or TIMESTAMP.fullmatch(args.finished_at) is None:
            fail("timestamps must be UTC seconds")
        output_parts = canonical_parts(root, args.output, "output path")
        log_parts = canonical_parts(root, args.log, "log path")
        log_sha256, log_bytes = hash_regular_file(root_fd, log_parts)
        record = {
            "schema": "jjdguard-vm-step-record/v1",
            "scenario": args.scenario,
            "step": args.step,
            "status": args.status,
            "started_at": args.started_at,
            "finished_at": args.finished_at,
            "exit_code": args.exit_code,
            "log_sha256": log_sha256,
            "log_bytes": log_bytes,
            "details": parse_details(args.details_json),
        }
        path = write_json_under_root(root, root_fd, output_parts, record)
    except RecordError as error:
        print(f"[error] record-step rejected: {error}", file=sys.stderr)
        return 2
    finally:
        if root_fd is not None:
            os.close(root_fd)
    print(json.dumps({"path": str(path), "status": args.status}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
