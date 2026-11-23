#!/usr/bin/env python3
"""Verify the local Prisma engine input used by the formal offline build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


LOCK_SCHEMA = "jjdguard-release-prisma-engines-lock/v1"
PRISMA_VERSION = "6.19.3"
ARCH_TARGETS = {
    "amd64": {
        "platform": "linux-musl-openssl-3.0.x",
        "origin": "home-local-portal-runtime",
        "source_image": "enterprise-ai-portal:0.2.0-slim",
        "engine_files": (
            "libquery_engine-linux-musl-openssl-3.0.x.so.node",
            "schema-engine-linux-musl-openssl-3.0.x",
        ),
    },
    "arm64": {
        "platform": "linux-musl-arm64-openssl-3.0.x",
        "origin": "home-local-portal-runtime",
        "source_image": "chat-portal/portal-proxy:0.1.0",
        "engine_files": (
            "libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node",
            "schema-engine-linux-musl-arm64-openssl-3.0.x",
        ),
    },
}


def fail(message: str) -> None:
    raise SystemExit(f"[error] Prisma engine input rejected: {message}")


def regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} does not exist: {path}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"{label} is not a regular non-symlink file: {path}")
    return info


def regular_directory(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} does not exist: {path}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail(f"{label} is not a real directory: {path}")
    return info


def hash_regular_file(path: Path, label: str) -> tuple[int, str]:
    regular_file(path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label} safely: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} is not a regular file")
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
        fail(f"{label} changed while being hashed")
    return before.st_size, digest.hexdigest()


def read_lock(path: Path, target_arch: str = "amd64") -> tuple[dict[str, object], str]:
    target = ARCH_TARGETS[target_arch]
    engine_files = target["engine_files"]
    _, lock_sha = hash_regular_file(path, "lock")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"lock is unreadable JSON: {exc}")
    if not isinstance(data, dict):
        fail("lock must be a JSON object")
    if set(data) != {
        "manifest",
        "origin",
        "platform",
        "prisma_version",
        "schema",
        "source_image",
        "source_image_id",
    }:
        fail("lock keys do not match the approved schema")
    if data["schema"] != LOCK_SCHEMA:
        fail("lock schema is not approved")
    if data["prisma_version"] != PRISMA_VERSION:
        fail("lock Prisma version is not approved")
    if data["platform"] != target["platform"]:
        fail("lock platform is not approved")
    if data["origin"] != target["origin"]:
        fail("lock origin is not the approved home runtime")
    if data["source_image"] != target["source_image"]:
        fail("lock source image is not the approved home runtime image")
    if not valid_image_id(str(data["source_image_id"])):
        fail("lock source image ID is invalid")
    manifest = data["manifest"]
    if not isinstance(manifest, list) or len(manifest) != len(engine_files):
        fail("lock manifest length is invalid")
    paths: list[str] = []
    for entry in manifest:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            fail("lock manifest entry shape is invalid")
        path_value = entry["path"]
        size = entry["size"]
        digest = entry["sha256"]
        if not isinstance(path_value, str) or path_value not in engine_files:
            fail("lock manifest path is not approved")
        if not isinstance(size, int) or size <= 0:
            fail("lock manifest size is invalid")
        if not isinstance(digest, str) or len(digest) != 64:
            fail("lock manifest SHA-256 is invalid")
        if any(char not in "0123456789abcdef" for char in digest):
            fail("lock manifest SHA-256 is invalid")
        paths.append(path_value)
    if tuple(sorted(paths)) != tuple(sorted(engine_files)):
        fail("lock manifest paths are incomplete or duplicated")
    return data, lock_sha


def verify(lock_path: Path, input_path: Path, target_arch: str = "amd64") -> dict[str, object]:
    lock, lock_sha = read_lock(lock_path, target_arch)
    engine_files = ARCH_TARGETS[target_arch]["engine_files"]
    if not input_path.is_absolute():
        fail("input directory must be an absolute path")
    if os.path.realpath(input_path) != str(input_path):
        fail("input directory must be canonical and contain no symlink")
    info = regular_directory(input_path, "input directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        fail("input directory must be mode 0700")
    entries = {entry.name: entry for entry in input_path.iterdir()}
    if tuple(sorted(entries)) != tuple(sorted(engine_files)):
        fail("input directory must contain exactly the approved engine files")
    locked = {entry["path"]: entry for entry in lock["manifest"]}
    manifest: list[dict[str, object]] = []
    for name in engine_files:
        size, digest = hash_regular_file(entries[name], f"engine input {name}")
        expected = locked[name]
        if size != expected["size"] or digest != expected["sha256"]:
            fail(f"engine input {name} does not match the approved lock")
        manifest.append({"path": name, "size": size, "sha256": digest})
    manifest.sort(key=lambda item: str(item["path"]))
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "jjdguard-release-prisma-engines/v1",
        "origin": lock["origin"],
        "source_image": lock["source_image"],
        "source_image_id": lock["source_image_id"],
        "approved_lock_sha256": lock_sha,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "manifest": manifest,
    }


def verify_runtime_manifest(
    receipt: dict[str, object], manifest_path: Path, expected_label: str
) -> None:
    regular_file(manifest_path, "runtime engine manifest")
    try:
        lines = manifest_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"runtime engine manifest is unreadable: {exc}")

    expected = receipt["manifest"]
    actual: list[dict[str, object]] = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 3:
            fail("runtime engine manifest entry is malformed")
        path, size_text, digest = fields
        if not size_text.isdecimal() or not digest.isascii():
            fail("runtime engine manifest entry is malformed")
        actual.append({"path": path, "size": int(size_text), "sha256": digest})
    if actual != expected:
        fail(f"runtime engine manifest does not match {expected_label}")


def valid_image_id(value: str) -> bool:
    return (
        value.startswith("sha256:")
        and len(value) == len("sha256:") + 64
        and all(character in "0123456789abcdef" for character in value.removeprefix("sha256:"))
    )


def verify_runtime(
    lock_path: Path, manifest_path: Path, runtime_image: str, runtime_image_id: str,
    target_arch: str = "amd64"
) -> dict[str, object]:
    lock, lock_sha = read_lock(lock_path, target_arch)
    if not runtime_image or runtime_image != runtime_image.strip():
        fail("runtime image is invalid")
    if not valid_image_id(runtime_image_id):
        fail("runtime image ID is invalid")
    expected = {
        "schema": "jjdguard-release-prisma-engines/v1",
        "origin": lock["origin"],
        "source_image": lock["source_image"],
        "source_image_id": lock["source_image_id"],
        "approved_lock_sha256": lock_sha,
        "content_sha256": hashlib.sha256(
            json.dumps(lock["manifest"], sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "manifest": lock["manifest"],
    }
    verify_runtime_manifest(expected, manifest_path, "reviewed lock")
    return {
        "schema": "jjdguard-release-prisma-runtime/v1",
        "origin": lock["origin"],
        "expected_source_image": lock["source_image"],
        "expected_source_image_id": lock["source_image_id"],
        "approved_lock_sha256": lock_sha,
        "runtime_image": runtime_image,
        "runtime_image_id": runtime_image_id,
        "content_sha256": expected["content_sha256"],
        "manifest": expected["manifest"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--target-arch", choices=sorted(ARCH_TARGETS), default="amd64")
    parser.add_argument("--input")
    parser.add_argument("--runtime-manifest")
    parser.add_argument("--runtime-image")
    parser.add_argument("--runtime-image-id")
    args = parser.parse_args()
    if args.input is not None:
        if args.runtime_image is not None or args.runtime_image_id is not None:
            parser.error("--input cannot be combined with runtime image identity")
        receipt = verify(Path(args.lock), Path(args.input), args.target_arch)
        if args.runtime_manifest is not None:
            verify_runtime_manifest(receipt, Path(args.runtime_manifest), "verified receipt")
    else:
        if (
            args.runtime_manifest is None
            or args.runtime_image is None
            or args.runtime_image_id is None
        ):
            parser.error(
                "runtime verification requires --runtime-manifest, --runtime-image, and --runtime-image-id"
            )
        receipt = verify_runtime(
            Path(args.lock),
            Path(args.runtime_manifest),
            args.runtime_image,
            args.runtime_image_id,
            args.target_arch,
        )
    json.dump(receipt, sys.stdout, sort_keys=True, separators=(",", ":"))
    print()


if __name__ == "__main__":
    main()
