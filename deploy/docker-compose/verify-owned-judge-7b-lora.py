#!/usr/bin/env python3
"""Fail closed unless the supplied 7B Judge GGUF matches the approved lock.

The addon ships the merged judge-v4 model only. The v5 LoRA candidate never
passed promotion (see CHANGELOG), so no adapter file is accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

EXPECTED = {
    "schema": "jjdguard-owned-judge-7b-lock/v2",
    "model_id": "qwen2.5-7b-judge-v4",
    "origin": "user-trained",
}
MODEL_NAME = "judge-v4-Q4_K_M.gguf"

def fail(message):
    raise SystemExit("[error] owned 7B Judge rejected: " + message)

def regular(path, label):
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(label + " missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(label + " is not a regular non-symlink file")

def verify_model(spec, path):
    if not isinstance(spec, dict) or spec.get("file") != MODEL_NAME or path.name != MODEL_NAME:
        fail("model filename does not match lock")
    size, expected = spec.get("size"), spec.get("sha256")
    if type(size) is not int or size <= 0 or not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        fail("model lock metadata invalid")
    if not path.is_absolute() or os.path.realpath(path) != str(path):
        fail("model path must be canonical and absolute")
    regular(path, "model")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for block in iter(lambda: stream.read(1024*1024), b""):
                digest.update(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        fail("model changed during hashing")
    if before.st_size != size or digest.hexdigest() != expected:
        fail("model content does not match lock")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    lock_path = Path(args.lock)
    regular(lock_path, "lock")
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail("lock unreadable: " + str(exc))
    if not isinstance(lock, dict) or set(lock) != {"schema", "model_id", "origin", "model"}:
        fail("lock shape invalid")
    if any(lock[key] != value for key, value in EXPECTED.items()):
        fail("lock identity invalid")
    if not isinstance(lock["model"], dict) or set(lock["model"]) != {"file", "size", "sha256"}:
        fail("model lock shape invalid")
    verify_model(lock["model"], Path(args.model))
    print("[ok] owned 7B judge-v4 Q4 model matches the lock")

if __name__ == "__main__":
    main()
