#!/usr/bin/env python3
"""Materialize hash-pinned public OCR languages into a dependency seed image.

Build-time only; customer runtime and final offline image build need no network.
"""
import argparse
import base64
import hashlib
import json
import urllib.request
from pathlib import Path


def verify_resources(root, lock):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("OCR resource directory missing or unsafe")
    for item in lock["files"]:
        path = root / item["name"]
        if path.is_symlink() or not path.is_file():
            raise ValueError("OCR resource missing: " + item["name"])
        if path.stat().st_size != item["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("OCR resource digest mismatch: " + item["name"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[2] / "apps/security-engine/ocr-resources.lock.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text())
    if args.download:
        args.output.mkdir(parents=True, exist_ok=True)
        if args.output.is_symlink():
            raise ValueError("unsafe output directory")
        for item in lock["files"]:
            target = args.output / item["name"]
            if target.is_file() and not target.is_symlink() and hashlib.sha256(target.read_bytes()).hexdigest() == item["sha256"]:
                continue
            if target.exists() or target.is_symlink():
                raise ValueError("refusing to overwrite non-matching resource")
            with urllib.request.urlopen(item["url"], timeout=60) as response:
                data = response.read()
            # Accept historical blob-API locks when rebuilding an older release.
            if item["url"].startswith("https://api.github.com/repos/"):
                data = base64.b64decode(json.loads(data)["content"], validate=False)
            if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("download digest mismatch")
            target.write_bytes(data)
    verify_resources(args.output, lock)
    print("OCR resources verified: chi_sim, eng, LICENSE")


if __name__ == "__main__":
    main()
