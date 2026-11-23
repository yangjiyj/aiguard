#!/usr/bin/env python3
"""Fail closed verification of the bytes emitted by ``docker save``."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import tempfile
from typing import Any

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"[error] offline image archive verification failed: {message}")


def load_provenance_module() -> Any:
    path = pathlib.Path(__file__).with_name("verify-image-provenance.py")
    spec = importlib.util.spec_from_file_location("image_provenance", path)
    if spec is None or spec.loader is None:
        fail("unable to load image provenance catalog parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_member_name(name: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        fail("archive contains an unsafe member path")
    return path


def validate_layer_sources(value: Any) -> None:
    if not isinstance(value, dict):
        fail("archive LayerSources is malformed")
    for digest, source in value.items():
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail("archive LayerSources is malformed")
        if not isinstance(source, dict) or set(source) != {"mediaType", "size", "digest"}:
            fail("archive LayerSources is malformed")
        if (source["mediaType"] != "application/vnd.oci.image.layer.v1.tar"
                or type(source["size"]) is not int or source["size"] < 0
                or source["digest"] != digest):
            fail("archive LayerSources is malformed")


def validate_config_matches_inspect(config: dict[str, Any], inspected: dict[str, Any], tag: str) -> None:
    if (config.get("os") != inspected.get("Os")
            or config.get("architecture") != inspected.get("Architecture")
            or config.get("variant") != inspected.get("Variant")
            or config.get("created") != inspected.get("Created")
            or config.get("author") != inspected.get("Author")
            or config.get("config") != inspected.get("Config")):
        fail(f"archive image config drifted for {tag}")
    rootfs = config.get("rootfs")
    inspected_rootfs = inspected.get("RootFS")
    if (not isinstance(rootfs, dict) or not isinstance(inspected_rootfs, dict)
            or rootfs != {"type": inspected_rootfs.get("Type"),
                          "diff_ids": inspected_rootfs.get("Layers")}):
        fail(f"archive image rootfs drifted for {tag}")


def atomic_write_json(path: pathlib.Path, value: Any) -> None:
    if not path.is_file() or path.is_symlink():
        fail("provenance receipt is not a regular file")
    try:
        current = path.stat()
        if current.st_nlink != 1:
            fail("provenance receipt has an unexpected link count")
        mode = stat.S_IMODE(current.st_mode)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                os.fchmod(output.fileno(), mode)
                json.dump(value, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except OSError as error:
        fail(f"unable to update provenance receipt: {error}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--catalog", required=True, type=pathlib.Path)
    parser.add_argument("--receipt", required=True, type=pathlib.Path)
    parser.add_argument("--profile", required=True, choices=("lite", "full"))
    parser.add_argument("--include-chat", required=True, choices=("0", "1"))
    parser.add_argument("--docker-command", default="docker")
    parser.add_argument("--capture-config-digests", action="store_true")
    args = parser.parse_args()

    archive = args.archive
    if not archive.is_file() or archive.is_symlink():
        fail("archive is not a regular gzip file")
    provenance = load_provenance_module()
    rows = provenance.selected_catalog(
        provenance.parse_catalog(args.catalog), args.profile, args.include_chat == "1")
    receipt = provenance.load_json(args.receipt)
    if not isinstance(receipt, dict) or not isinstance(receipt.get("images"), list):
        fail("provenance receipt image list is invalid")
    target_platform = receipt.get("platform")
    if target_platform not in {"linux/amd64", "linux/arm64"}:
        fail("provenance target platform is invalid")
    target_os, target_architecture = target_platform.split("/", 1)
    expected: dict[str, dict[str, Any]] = {}
    for entry in receipt["images"]:
        if not isinstance(entry, dict):
            fail("provenance receipt image entry is invalid")
        tag = entry.get("runtime_tag")
        image_id = entry.get("image_id")
        config_digest = entry.get("oci_config_digest")
        if (not isinstance(tag, str) or not SHA256_RE.fullmatch(str(image_id))
                or not isinstance(config_digest, str) or not SHA256_RE.fullmatch(config_digest)
                or tag in expected):
            fail("provenance receipt runtime tag or config digest is invalid")
        expected[tag] = entry
    expected_tags = {row["runtime_tag"] for row in rows}
    if set(expected) != expected_tags:
        fail("provenance receipt does not exactly cover the selected archive tags")

    try:
        with tarfile.open(archive, mode="r:gz") as payload:
            members: dict[str, list[tarfile.TarInfo]] = {}
            for member in payload:
                safe_member_name(member.name)
                if member.isdir():
                    continue
                if not member.isfile():
                    fail("archive contains a link or special member")
                members.setdefault(member.name, []).append(member)
            manifest_members = members.get("manifest.json", [])
            if len(manifest_members) != 1:
                fail("archive must contain exactly one manifest.json")
            manifest_file = payload.extractfile(manifest_members[0])
            if manifest_file is None:
                fail("archive manifest is unreadable")
            try:
                manifest = json.load(manifest_file)
            except (UnicodeDecodeError, json.JSONDecodeError):
                fail("archive manifest.json is invalid JSON")
            if not isinstance(manifest, list) or not manifest:
                fail("archive manifest.json is not a non-empty array")

            seen_tags: dict[str, tuple[str, str, dict[str, Any]]] = {}
            for item in manifest:
                required_fields = {"Config", "RepoTags", "Layers"}
                allowed_fields = required_fields | {"LayerSources"}
                if (not isinstance(item, dict) or not required_fields.issubset(item)
                        or not set(item).issubset(allowed_fields)):
                    fail("archive manifest entry has unknown or missing fields")
                if "LayerSources" in item:
                    validate_layer_sources(item["LayerSources"])
                config_name, tags, layers = item["Config"], item["RepoTags"], item["Layers"]
                if (not isinstance(config_name, str) or not isinstance(tags, list)
                        or not tags or not isinstance(layers, list)
                        or not all(isinstance(tag, str) and tag for tag in tags)
                        or not all(isinstance(layer, str) for layer in layers)):
                    fail("archive manifest entry is malformed")
                safe_member_name(config_name)
                config_members = members.get(config_name, [])
                if len(config_members) != 1:
                    fail("archive config member is missing or duplicated")
                config_file = payload.extractfile(config_members[0])
                if config_file is None:
                    fail("archive config member is unreadable")
                config_bytes = config_file.read()
                try:
                    config = json.loads(config_bytes)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    fail("archive config JSON is invalid")
                if not isinstance(config, dict):
                    fail("archive config JSON must be an object")
                if config.get("os") != target_os or config.get("architecture") != target_architecture:
                    fail(f"archive image platform drifted for {tags[0]}")
                config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
                for tag in tags:
                    if tag in seen_tags:
                        fail(f"archive runtime tag is duplicated: {tag}")
                    seen_tags[tag] = (config_digest, config_name, config)
    except (OSError, tarfile.TarError) as error:
        fail(f"unable to parse gzip image archive: {error}")

    actual_tags = set(seen_tags)
    missing = sorted(expected_tags - actual_tags)
    if missing:
        fail(f"archive is missing runtime tag: {missing[0]}")
    extra = sorted(actual_tags - expected_tags)
    if extra:
        fail(f"archive contains an extra runtime tag: {extra[0]}")
    captured_digests: dict[str, str] = {}
    docker_command = [args.docker_command]
    for tag in sorted(expected_tags):
        digest, _, config = seen_tags[tag]
        entry = expected[tag]
        inspected = provenance.inspect_image(docker_command, tag, target_platform)
        if inspected.get("Id") != entry["image_id"]:
            fail(f"runtime tag was retargeted during archive export: {tag}")
        if (inspected.get("Os") != target_os
                or inspected.get("Architecture") != target_architecture):
            fail(f"Docker image platform drifted for {tag}")
        validate_config_matches_inspect(config, inspected, tag)
        if args.capture_config_digests:
            entry["oci_config_digest"] = digest
            captured_digests[tag] = digest
        elif digest != entry["oci_config_digest"]:
            fail(f"archive config digest drifted for {tag}")

    if args.capture_config_digests:
        atomic_write_json(args.receipt, receipt)
        print(f"[ok] captured archive OCI config digests: tags={len(captured_digests)}")
    print(f"[ok] offline image archive verified: tags={len(expected_tags)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
