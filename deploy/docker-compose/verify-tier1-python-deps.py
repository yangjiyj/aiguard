#!/usr/bin/env python3
"""Verify a local Tier1 Python dependency snapshot without contacting an index."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from email.parser import BytesParser
from pathlib import Path


PROFILES = {
    "tier1": {
        "source_schema": "jjdguard-tier1-python-deps-source/v1",
        "receipt_schema": "jjdguard-tier1-python-deps/v1",
        "source_origin": "home-existing-tier1-image",
        "arm64_source_origin": "home-arm64-python-dependency-image",
        "arm64_source_image": "jjdguard-tier1-python-deps:arm64",
    },
    "security-engine": {
        "source_schema": "jjdguard-security-engine-python-deps-source/v1",
        "receipt_schema": "jjdguard-security-engine-python-deps/v1",
        "source_origin": "home-existing-security-engine-image",
        "arm64_source_origin": "home-arm64-python-dependency-image",
        "arm64_source_image": "jjdguard-security-engine-python-deps:arm64",
    },
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ELF_MACHINE = {"amd64": 62, "arm64": 183}
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\ ]+)")


def fail(message: str) -> None:
    raise SystemExit(f"[error] Tier1 local Python dependencies rejected: {message}")


def normalize_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def require_directory(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        fail(f"{label} must be a real directory: {path}")


def require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail(f"{label} must be a regular file: {path}")


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def load_source_metadata(path: Path, profile: dict[str, str], target_arch: str) -> dict[str, str]:
    require_regular_file(path, "source metadata")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"source metadata is invalid JSON: {exc}")
    expected_keys = {"schema", "origin", "source_image", "source_image_id"}
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("source metadata shape is invalid")
    expected_origin = (
        profile["source_origin"] if target_arch == "amd64"
        else profile["arm64_source_origin"]
    )
    if payload["schema"] != profile["source_schema"] or payload["origin"] != expected_origin:
        fail("source metadata origin is invalid")
    if not isinstance(payload["source_image"], str) or not payload["source_image"].strip():
        fail("source image is invalid")
    if target_arch == "arm64" and payload["source_image"] != profile["arm64_source_image"]:
        fail("ARM64 source image is invalid")
    image_id = payload["source_image_id"]
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        fail("source image ID is invalid")
    if not SHA256_RE.fullmatch(image_id.removeprefix("sha256:")):
        fail("source image ID digest is invalid")
    return payload


def load_requirements(path: Path) -> dict[str, str]:
    require_regular_file(path, "requirements lock")
    expected: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"requirements lock is unreadable: {exc}")
    for line in lines:
        match = REQUIREMENT_RE.match(line)
        if not match:
            continue
        name = normalize_package_name(match.group(1))
        version = match.group(2)
        if name in expected and expected[name] != version:
            fail(f"requirements lock contains conflicting versions for {name}")
        expected[name] = version
    if not expected:
        fail("requirements lock has no pinned packages")
    return expected


def installed_packages(site_packages: Path) -> dict[str, str]:
    require_directory(site_packages, "site-packages directory")
    installed: dict[str, str] = {}
    for metadata_path in sorted(site_packages.glob("*.dist-info/METADATA")):
        require_regular_file(metadata_path, "distribution metadata")
        try:
            metadata = BytesParser().parsebytes(metadata_path.read_bytes())
        except OSError as exc:
            fail(f"distribution metadata is unreadable: {metadata_path}: {exc}")
        raw_name = metadata.get("Name")
        version = metadata.get("Version")
        if not raw_name or not version:
            fail(f"distribution metadata is incomplete: {metadata_path}")
        name = normalize_package_name(raw_name)
        if name in installed:
            fail(f"duplicate installed distribution metadata: {name}")
        installed[name] = version
    return installed


def content_manifest(root: Path) -> list[dict[str, object]]:
    require_directory(root, "dependency snapshot")
    manifest: list[dict[str, object]] = []
    for base, directories, files in os.walk(root, followlinks=False):
        base_path = Path(base)
        for directory in directories:
            child = base_path / directory
            try:
                mode = child.lstat().st_mode
            except FileNotFoundError:
                fail(f"snapshot directory disappeared during verification: {child}")
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                fail(f"snapshot contains an unsafe directory entry: {child}")
        for filename in files:
            child = base_path / filename
            require_regular_file(child, "snapshot file")
            size, digest = sha256_file(child)
            manifest.append(
                {
                    "path": child.relative_to(root).as_posix(),
                    "sha256": digest,
                    "size": size,
                }
            )
    if not manifest:
        fail("dependency snapshot is empty")
    return sorted(manifest, key=lambda item: str(item["path"]))



def verify_native_architecture(site_packages: Path, target_arch: str) -> None:
    expected = ELF_MACHINE[target_arch]
    for path in sorted(site_packages.rglob("*")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            fail(f"dependency file disappeared during architecture check: {path}")
        if not stat.S_ISREG(info.st_mode):
            continue
        try:
            with path.open("rb") as handle:
                header = handle.read(20)
        except OSError as exc:
            fail(f"unable to inspect dependency binary {path}: {exc}")
        if not header.startswith(b"\x7fELF"):
            continue
        if len(header) < 20 or header[5] not in {1, 2}:
            fail(f"dependency ELF header is malformed: {path}")
        byte_order = "little" if header[5] == 1 else "big"
        machine = int.from_bytes(header[18:20], byte_order)
        if machine != expected:
            fail(
                f"dependency ELF architecture mismatch for {path.relative_to(site_packages)}: "
                f"expected {target_arch} e_machine={expected}, actual e_machine={machine}"
            )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILES), default="tier1")
    parser.add_argument("--requirements-lock", required=True, type=Path)
    parser.add_argument("--target-arch", choices=sorted(ELF_MACHINE), default="amd64")
    parser.add_argument("--input", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    profile = PROFILES[args.profile]
    input_root = args.input
    require_directory(input_root, "dependency input")
    if input_root.resolve(strict=True) != input_root:
        fail("dependency input must be canonical")

    source = load_source_metadata(input_root / "source.json", profile, args.target_arch)
    expected = load_requirements(args.requirements_lock)
    actual = installed_packages(input_root / "site-packages")
    verify_native_architecture(input_root / "site-packages", args.target_arch)
    missing = sorted(name for name in expected if name not in actual)
    mismatch = sorted(
        name for name, version in expected.items() if name in actual and actual[name] != version
    )
    if missing:
        fail(f"snapshot is missing locked distributions: {', '.join(missing)}")
    if mismatch:
        details = ", ".join(
            f"{name} expected={expected[name]} actual={actual[name]}" for name in mismatch
        )
        fail(f"snapshot distribution versions differ from lock: {details}")

    manifest = content_manifest(input_root)
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    receipt = {
        "schema": profile["receipt_schema"],
        "origin": source["origin"],
        "source_image": source["source_image"],
        "source_image_id": source["source_image_id"],
        "requirements_lock_sha256": sha256_file(args.requirements_lock)[1],
        "content_sha256": hashlib.sha256(canonical_manifest).hexdigest(),
        "file_count": len(manifest),
        "packages": [
            {"name": name, "version": expected[name]} for name in sorted(expected)
        ],
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
