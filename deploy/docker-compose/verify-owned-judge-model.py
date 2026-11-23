#!/usr/bin/env python3
"""Fail closed unless the supplied Judge GGUF is the approved, commercially licensed input."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


LOCK_SCHEMA = "jjdguard-owned-judge-model-lock/v3"
MODEL_ID = "bundled-judge"
# The lock records where the weights really come from: the bundled Judge is
# derived from a named upstream base (JJDGuard LoRA merged in), and both the base
# and the result must carry a commercial license.
MODEL_ORIGIN = "derived"
ALLOWED_LICENSES = frozenset({"apache-2.0", "mit"})
MODEL_FILE = "jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf"


def fail(message: str) -> None:
    raise SystemExit(f"[error] owned Judge model rejected: {message}")


def is_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} does not exist: {path}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"{label} is not a regular non-symlink file: {path}")
    return info


def read_lock(path: Path) -> dict[str, object]:
    regular_file(path, "lock")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"lock is unreadable JSON: {exc}")
    if not isinstance(data, dict):
        fail("lock must be a JSON object")
    if set(data) != {
        "adapter_sha256", "base", "file", "license", "model_id", "origin",
        "schema", "sha256", "size", "training",
    }:
        fail("lock keys do not match the approved schema")
    if data["schema"] != LOCK_SCHEMA or data["model_id"] != MODEL_ID:
        fail("lock schema or model id is not approved")
    if data["origin"] != MODEL_ORIGIN:
        fail("lock origin must record that the model is derived from its base")
    base = data["base"]
    if not isinstance(base, dict) or set(base) != {"license", "repo", "revision"}:
        fail("lock base record is invalid")
    if not isinstance(base["repo"], str) or not base["repo"].strip():
        fail("lock base repository is missing")
    if not is_hex(base["revision"], 40):
        fail("lock base revision must be a full commit id")
    if base["license"] not in ALLOWED_LICENSES:
        fail("lock base license is not approved for commercial delivery")
    if not is_hex(data["adapter_sha256"], 64):
        fail("lock adapter SHA-256 is invalid")
    if not isinstance(data["training"], str) or not data["training"].strip():
        fail("lock training description is missing")
    if data["license"] not in ALLOWED_LICENSES:
        fail("lock license is not approved for commercial delivery")
    if data["file"] != MODEL_FILE:
        fail("lock file name is not approved")
    if not isinstance(data["size"], int) or data["size"] <= 0:
        fail("lock size is invalid")
    if not is_hex(data["sha256"], 64):
        fail("lock SHA-256 is invalid")
    return data


def hash_regular_file(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open model input safely: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail("model input is not a regular file")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        fail("model input changed while being hashed")
    return before.st_size, digest.hexdigest()


def verify(lock_path: Path, input_path: Path) -> None:
    lock = read_lock(lock_path)
    if not input_path.is_absolute():
        fail("model input must be an absolute path")
    if os.path.realpath(input_path) != str(input_path):
        fail("model input must be canonical and contain no symlink")
    regular_file(input_path, "model input")
    if input_path.name != lock["file"]:
        fail("model input file name does not match the approved lock")
    size, digest = hash_regular_file(input_path)
    if size != lock["size"] or digest != lock["sha256"]:
        fail("model input content does not match the approved lock")
    print(f"[ok] bundled Judge model input matches the lock (derived from {lock['base']['repo']}@{lock['base']['revision'][:12]}, {lock['license']})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    verify(Path(args.lock), Path(args.input))


if __name__ == "__main__":
    main()
