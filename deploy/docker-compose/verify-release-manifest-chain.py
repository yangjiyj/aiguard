#!/usr/bin/env python3
"""Fail-closed verifier for the signed offline bundle manifest identity."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"[error] release manifest chain verification failed: {message}")


def load_json(path: pathlib.Path) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"JSON input is not a regular file: {path}")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        fail(f"invalid JSON input {path}: {error}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=pathlib.Path)
    args = parser.parse_args()
    bundle = args.bundle
    if not bundle.is_dir() or bundle.is_symlink() or not re.fullmatch(r"(?:jjdguard|agent-platform)-[A-Za-z0-9._-]+", bundle.name):
        fail("bundle is not a safe offline bundle root")

    manifest_path = bundle / "manifest.json"
    compose_manifest_path = bundle / "deploy/docker-compose/manifest.json"
    source_path = bundle / "release-source.json"
    provenance_path = bundle / "image-provenance.json"
    sbom_path = bundle / "sbom/index.json"
    minimum_path = bundle / "deploy/docker-compose/upgrade-min-data-version"
    manifest = load_json(manifest_path)
    if manifest != load_json(compose_manifest_path):
        fail("root and compose manifests differ")
    required = {
        "schema", "product", "version", "source_revision", "source_tree",
        "image_provenance_sha256", "sbom_index_sha256", "target_arch",
        "bundle_profile", "include_chat", "artifact_stage", "min_data_version",
        "manifest_signature", "built_at", "bundle",
    }
    platform = isinstance(manifest, dict) and manifest.get("product") == "agent-platform"
    platform_keys = {"product_profile", "product_name", "product_version", "product_slug", "agent_kit_sha256"}
    if not isinstance(manifest, dict) or set(manifest) != (required | platform_keys if platform else required):
        fail("manifest keys do not exactly match offline-manifest/v2")
    if (manifest["schema"] != "offline-manifest/v2" or manifest["product"] != ("agent-platform" if platform else "jjdguard-enterprise")
            or manifest["artifact_stage"] != "candidate"
            or manifest["manifest_signature"] not in {"ed25519-domain-v2", "sha256-only"}
            or manifest["bundle"] != bundle.name or manifest["bundle_profile"] not in {"lite", "full"}
            or manifest["include_chat"] not in {"0", "1"} or manifest["target_arch"] not in {"amd64", "arm64", "armv7"}
            or not minimum_path.is_file() or minimum_path.is_symlink()
            or manifest["min_data_version"] != minimum_path.read_text(encoding="utf-8").strip()):
        fail("manifest identity or selection is invalid")
    if platform:
        if (not bundle.name.startswith("agent-platform-") or manifest["product_profile"] != "agent-platform"
                or not isinstance(manifest["product_name"], str)
                or not re.fullmatch(r"[0-9A-Za-z._ -]+", manifest["product_name"])
                or not isinstance(manifest["product_version"], str)
                or not re.fullmatch(r"[0-9A-Za-z.-]+", manifest["product_version"])
                or not isinstance(manifest["product_slug"], str)
                or not re.fullmatch(r"[a-z0-9-]+", manifest["product_slug"])
                or not isinstance(manifest["agent_kit_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["agent_kit_sha256"])):
            fail("platform identity is invalid")
        kit = bundle / "deploy/docker-compose/agent-kit"
        if not kit.is_dir() or kit.is_symlink():
            fail("platform agent-kit is missing")
        digest = hashlib.sha256()
        files = sorted(kit.rglob("*"))
        if not any(path.is_file() and path.name != ".gitkeep" for path in files):
            fail("platform agent-kit has no distributable payload")
        for path in files:
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                fail("unsafe agent-kit member")
            if path.is_file():
                relative = path.relative_to(kit).as_posix().encode("utf-8")
                digest.update(len(relative).to_bytes(4, "big") + relative)
                digest.update(hashlib.sha256(path.read_bytes()).digest())
        if digest.hexdigest() != manifest["agent_kit_sha256"]:
            fail("agent-kit hash mismatch")
    elif not bundle.name.startswith("jjdguard-"):
        fail("gateway bundle root is invalid")
    if not isinstance(manifest["version"], str) or not re.fullmatch(r"[0-9A-Za-z.-]+", manifest["version"]):
        fail("manifest version is invalid")
    if not isinstance(manifest["built_at"], str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", manifest["built_at"]):
        fail("manifest built_at is invalid")
    for key in ("source_revision", "source_tree"):
        if not isinstance(manifest[key], str) or not re.fullmatch(r"[0-9a-f]{40}", manifest[key]):
            fail(f"manifest {key} is invalid")
    for key, path in (("image_provenance_sha256", provenance_path), ("sbom_index_sha256", sbom_path)):
        if (not isinstance(manifest[key], str) or not re.fullmatch(r"[0-9a-f]{64}", manifest[key])
                or not path.is_file() or path.is_symlink() or sha256_file(path) != manifest[key]):
            fail(f"manifest {key} does not match bundled evidence")
    source = load_json(source_path)
    if (not isinstance(source, dict) or set(source) != {"schema", "remote", "source_revision", "source_tree"}
            or source.get("schema") != "jjdguard-release-source/v1"
            or not isinstance(source.get("remote"), str) or not source["remote"]
            or source.get("source_revision") != manifest["source_revision"]
            or source.get("source_tree") != manifest["source_tree"]):
        fail("release source receipt is not bound to the manifest")
    print(f"[ok] release manifest chain verified: revision={manifest['source_revision']} tree={manifest['source_tree']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
