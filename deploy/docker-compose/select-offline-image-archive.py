#!/usr/bin/env python3
"""Materialize one verified Docker image from the bundle's docker-save archive."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import re
import tarfile
from typing import Any

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"[error] offline image selection failed: {message}")


def safe_name(name: Any) -> str:
    if not isinstance(name, str) or not name or "\\" in name:
        fail("archive member name is invalid")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
        fail("archive contains an unsafe member path")
    return name


def read_member(source: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str) -> bytes:
    info = members.get(safe_name(name))
    if info is None or not info.isfile():
        fail("image archive member is missing or not regular")
    stream = source.extractfile(info)
    if stream is None:
        fail("image archive member is unreadable")
    return stream.read()


def write_member(target: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o444
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    target.addfile(info, io.BytesIO(payload))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--config-digest", required=True)
    parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    if not args.archive.is_file() or args.archive.is_symlink():
        fail("source archive is not a regular file")
    if not SHA256_RE.fullmatch(args.config_digest):
        fail("expected OCI config digest is invalid")
    if not args.tag or any(ch.isspace() for ch in args.tag):
        fail("runtime tag is invalid")
    if args.output.exists() or args.output.is_symlink():
        fail("output archive already exists")
    if not args.output.parent.is_dir() or args.output.parent.is_symlink():
        fail("output parent is not a real directory")

    members: dict[str, tarfile.TarInfo] = {}
    try:
        with tarfile.open(args.archive, mode="r:") as source:
            for info in source.getmembers():
                name = safe_name(info.name)
                if info.isdir():
                    continue
                if not info.isfile() or name in members:
                    fail("source archive contains a special or duplicate member")
                members[name] = info
            manifest_bytes = read_member(source, members, "manifest.json")
            try:
                manifest = json.loads(manifest_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError):
                fail("source archive manifest is invalid JSON")
            if not isinstance(manifest, list) or not manifest:
                fail("source archive manifest is empty")

            matches: list[dict[str, Any]] = []
            for item in manifest:
                if not isinstance(item, dict) or not {"Config", "RepoTags", "Layers"}.issubset(item):
                    fail("source archive manifest entry is malformed")
                if not set(item).issubset({"Config", "RepoTags", "Layers", "LayerSources"}):
                    fail("source archive manifest entry contains unknown fields")
                tags = item.get("RepoTags")
                if (not isinstance(tags, list) or not tags
                        or not all(isinstance(tag, str) and tag for tag in tags)
                        or len(set(tags)) != len(tags)):
                    fail("source archive manifest tags are malformed")
                if args.tag in tags:
                    matches.append(item)
            if len(matches) != 1:
                fail("runtime tag does not occur exactly once in source archive")

            item = matches[0]
            config_name = safe_name(item.get("Config"))
            layers = item.get("Layers")
            if not isinstance(layers, list) or not all(isinstance(layer, str) for layer in layers):
                fail("source archive layer list is malformed")
            layer_names = [safe_name(layer) for layer in layers]
            if len(set(layer_names)) != len(layer_names) or config_name in layer_names:
                fail("source archive image members are duplicated")
            config_bytes = read_member(source, members, config_name)
            if "sha256:" + hashlib.sha256(config_bytes).hexdigest() != args.config_digest:
                fail("source archive OCI config digest does not match provenance")
            try:
                config = json.loads(config_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError):
                fail("source archive OCI config is invalid JSON")
            target_os, target_arch = args.platform.split("/", 1)
            if (not isinstance(config, dict) or config.get("os") != target_os
                    or config.get("architecture") != target_arch):
                fail("source archive platform does not match provenance")

            output_manifest = json.dumps([item], separators=(",", ":")).encode("utf-8") + b"\n"
            with tarfile.open(args.output, mode="x", format=tarfile.PAX_FORMAT) as target:
                write_member(target, "manifest.json", output_manifest)
                for name in [config_name, *layer_names]:
                    payload = read_member(source, members, name)
                    write_member(target, name, payload)
    except (OSError, tarfile.TarError) as error:
        fail(f"unable to select image from source archive: {error}")
    print(f"[ok] selected {args.tag} from verified archive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
