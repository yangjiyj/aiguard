#!/usr/bin/env python3
"""Fail closed unless Portal Proxy authority is present in the release archive."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


EXPECTED_SOURCE = {
    "path": "portal-proxy",
    "dockerfile": "portal-proxy/Dockerfile",
    "build_context": "portal-proxy",
    "lockfile": "portal-proxy/pnpm-lock.yaml",
    "tests": "portal-proxy/test/*.test.ts",
}


def fail(message: str) -> int:
    print(f"[portal-proxy-source][error] {message}", file=sys.stderr)
    return 1


def regular_file(root: Path, relative: str) -> bool:
    candidate = root / relative
    return candidate.is_file() and not candidate.is_symlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-remote", required=True)
    args = parser.parse_args()

    source_root = Path(args.source_root)
    if not source_root.is_dir() or source_root.is_symlink():
        return fail("source root must be a real directory")

    attestation_path = source_root / "portal-proxy/SOURCE-ATTESTATION.json"
    if not attestation_path.is_file() or attestation_path.is_symlink():
        return fail("Portal Proxy source attestation is absent from the release archive")
    try:
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"Portal Proxy source attestation is invalid: {exc}")
    if not isinstance(attestation, dict):
        return fail("Portal Proxy source attestation must be an object")
    if attestation.get("schema") != "jjdguard-portal-proxy-source/v1":
        return fail("Portal Proxy source attestation schema is invalid")

    ownership = attestation.get("ownership")
    if not isinstance(ownership, dict) or ownership.get("license") != "Proprietary":
        return fail("Portal Proxy source ownership is not proprietary")
    for field in ("copyright_holder", "authority"):
        if not isinstance(ownership.get(field), str) or not ownership[field].strip():
            return fail(f"Portal Proxy source ownership is missing {field}")

    authority = attestation.get("current_authoritative_source")
    if not isinstance(authority, dict):
        return fail("Portal Proxy current authority declaration is missing")
    if authority.get("repository") != args.source_remote:
        return fail("Portal Proxy declared repository does not match the release source receipt")
    for field, expected in EXPECTED_SOURCE.items():
        if authority.get(field) != expected:
            return fail(f"Portal Proxy authority field {field} is invalid")

    for relative in (
        "portal-proxy/Dockerfile",
        "portal-proxy/pnpm-lock.yaml",
        "portal-proxy/LICENSE",
    ):
        if not regular_file(source_root, relative):
            return fail(f"Portal Proxy archive is missing required file: {relative}")
    context = source_root / EXPECTED_SOURCE["build_context"]
    if not context.is_dir() or context.is_symlink():
        return fail("Portal Proxy archive build context is invalid")
    tests = [path for path in source_root.glob(EXPECTED_SOURCE["tests"]) if regular_file(source_root, str(path.relative_to(source_root)))]
    if not tests:
        return fail("Portal Proxy archive has no executable source tests")

    print("[ok] Portal Proxy authority matches the release Git archive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
