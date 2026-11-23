#!/usr/bin/env python3
"""Verify that a release bundle has complete, immutable Syft SPDX evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import os
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def fail(message: str) -> None:
    raise SystemExit(f"[error] SBOM index verification failed: {message}")


def load_json(path: pathlib.Path) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"JSON input is not a regular file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON input {path}: {error}")


def safe_relative_path(value: Any, bundle: pathlib.Path) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        fail("SBOM path is invalid")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        fail("SBOM path escapes the bundle")
    target = bundle.joinpath(*relative.parts)
    cursor = bundle
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail("SBOM path contains a symbolic link")
    try:
        target.resolve(strict=True).relative_to(bundle.resolve(strict=True))
    except (FileNotFoundError, ValueError):
        fail("SBOM path escapes or is missing from the bundle")
    if not target.is_file():
        fail("SBOM path is not a regular file")
    return target


def assert_spdx(path: pathlib.Path, label: str) -> None:
    payload = load_json(path)
    if not isinstance(payload, dict):
        fail(f"SPDX document is not an object: {label}")
    if not isinstance(payload.get("spdxVersion"), str) or not payload["spdxVersion"].startswith("SPDX-"):
        fail(f"SPDX version is missing: {label}")
    creation = payload.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, dict) else None
    if (not isinstance(creators, list)
            or "Tool: syft-1.44.0" not in creators):
        fail(f"SPDX creator is not fixed Syft 1.44.0: {label}")
    packages = payload.get("packages")
    if (not isinstance(packages, list) or not packages
            or not all(isinstance(package, dict) for package in packages)):
        fail(f"SPDX package list is empty or invalid: {label}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_reference(
        value: Any, bundle: pathlib.Path, expected_path: str, label: str) -> pathlib.Path:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        fail(f"SBOM reference schema is invalid: {label}")
    if value["path"] != expected_path or not isinstance(value["sha256"], str) or not SHA256_RE.fullmatch(value["sha256"]):
        fail(f"SBOM reference path or hash is invalid: {label}")
    target = safe_relative_path(value["path"], bundle)
    if sha256_file(target) != value["sha256"]:
        fail(f"SBOM hash drifted: {label}")
    assert_spdx(target, label)
    return target


def provenance_images(path: pathlib.Path) -> dict[str, str]:
    payload = load_json(path)
    images = payload.get("images") if isinstance(payload, dict) else None
    if not isinstance(images, list) or not images:
        fail("provenance image list is invalid")
    result: dict[str, str] = {}
    for image in images:
        if not isinstance(image, dict):
            fail("provenance image entry is invalid")
        component, image_id = image.get("component"), image.get("image_id")
        if (not isinstance(component, str) or not COMPONENT_RE.fullmatch(component)
                or not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
                or component in result):
            fail("provenance component or image ID is invalid")
        result[component] = image_id
    return result


def expected_syft_sha256() -> str:
    if os.environ.get("JJD_RELEASE_TESTING") == "1":
        expected = os.environ.get("JJD_TEST_SYFT_SHA256", "")
    else:
        lock = pathlib.Path(__file__).with_name("release-toolchain.lock")
        if not lock.is_file() or lock.is_symlink():
            fail("release toolchain lock is unavailable")
        values = [line.split("=", 1)[1] for line in lock.read_text(encoding="utf-8").splitlines()
                  if line.startswith("syft_binary_sha256=")]
        if len(values) != 1:
            fail("release toolchain lock does not identify fixed Syft")
        expected = values[0]
    if not SHA256_RE.fullmatch(expected):
        fail("fixed Syft hash is invalid")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=pathlib.Path)
    parser.add_argument("--provenance", required=True, type=pathlib.Path)
    parser.add_argument("--index", required=True, type=pathlib.Path)
    args = parser.parse_args()

    bundle = args.bundle
    if not bundle.is_dir() or bundle.is_symlink():
        fail("bundle is not a real directory")
    if args.index.is_symlink():
        fail("SBOM index is a symbolic link")
    try:
        args.index.resolve(strict=True).relative_to(bundle.resolve(strict=True))
    except (FileNotFoundError, ValueError):
        fail("SBOM index is missing or outside the bundle")
    if any(path.is_file() or path.is_symlink() for path in bundle.rglob("SBOM-MISSING.txt")):
        fail("SBOM fallback sentinel is forbidden")

    expected_images = provenance_images(args.provenance)
    index = load_json(args.index)
    if not isinstance(index, dict) or set(index) != {"schema", "syft", "bundle", "images"}:
        fail("SBOM index schema is invalid")
    if index.get("schema") != "jjdguard-release-sbom-index/v1":
        fail("SBOM index schema version is invalid")
    syft = index.get("syft")
    if (not isinstance(syft, dict) or set(syft) != {"version", "binary_sha256"}
            or syft.get("version") != "1.44.0"
            or not isinstance(syft.get("binary_sha256"), str)
            or not SHA256_RE.fullmatch(syft["binary_sha256"])
            or syft["binary_sha256"] != expected_syft_sha256()):
        fail("fixed Syft identity is invalid")
    assert_reference(index.get("bundle"), bundle, "sbom/bundle.spdx.json", "bundle")

    entries = index.get("images")
    if not isinstance(entries, list):
        fail("SBOM image index is invalid")
    observed: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"component", "image_id", "path", "sha256"}:
            fail("SBOM image entry schema is invalid")
        component, image_id = entry["component"], entry["image_id"]
        if (not isinstance(component, str) or component in observed
                or component not in expected_images or image_id != expected_images[component]):
            fail("SBOM image component or image ID drifted")
        expected_path = f"sbom/images/{component}.spdx.json"
        assert_reference({"path": entry["path"], "sha256": entry["sha256"]},
                         bundle, expected_path, component)
        observed[component] = image_id
    if observed != expected_images:
        fail("SBOM image coverage does not exactly match provenance")
    print(f"[ok] SBOM index verified: images={len(observed)} syft=1.44.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
