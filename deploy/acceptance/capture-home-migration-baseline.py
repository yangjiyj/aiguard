#!/usr/bin/env python3
"""Validate QGA migration ledgers and bind them into VM acceptance evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import pathlib
import sys
from types import ModuleType


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent


def load_module(name: str, path: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("acceptance helper cannot load its validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--artifact-json", required=True)
    parser.add_argument("--release-json", required=True)
    parser.add_argument("--payload-base64", required=True)
    args = parser.parse_args()

    try:
        indexer = load_module("jjdguard_evidence_index", SCRIPT_DIR / "evidence-index.py")
        promoted = load_module(
            "jjdguard_promoted_release",
            SCRIPT_DIR.parent / "offline-installer" / "verify-promoted-release.py",
        )
        artifact, release = indexer.validate_identity(args.artifact_json, args.release_json)
        payload = base64.b64decode(args.payload_base64, validate=True)
        if not payload or len(payload) > indexer.MAX_FILE_BYTES:
            raise ValueError("migration baseline payload is invalid")
        baseline = json.loads(payload.decode("utf-8"))
        identity = {**artifact, **release}
        promoted.validate_home_migration_baseline(baseline, identity, "VM migration baseline")
        root = indexer.normalized_root(args.evidence_root)
        root_fd = indexer.open_directory(root)
        try:
            output = indexer.write_json(root, root_fd, ("home-migration-baseline.json",), baseline)
        finally:
            indexer.os.close(root_fd)
        encoded = indexer.canonical_json_bytes(baseline)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, SystemExit) as error:
        print(f"[error] migration baseline rejected: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"[error] migration baseline rejected: {error}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "path": str(output),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
