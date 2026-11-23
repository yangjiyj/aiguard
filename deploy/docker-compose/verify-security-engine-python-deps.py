#!/usr/bin/env python3
from __future__ import annotations
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

script_dir = Path(__file__).resolve().parent
input_root = Path(sys.argv[sys.argv.index("--input") + 1])
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--ocr-resources-lock", type=Path, default=script_dir.parents[1] / "apps/security-engine/ocr-resources.lock.json")
args, remaining = parser.parse_known_args()
lock_path = args.ocr_resources_lock
spec = importlib.util.spec_from_file_location("ocr_resources", script_dir / "prepare-security-ocr-resources.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.verify_resources(input_root / "site-packages/jjdguard_ocr_data", json.loads(lock_path.read_text()))
except (ValueError, OSError) as exc:
    raise SystemExit("[error] security-engine OCR dependencies rejected: " + str(exc))
os.execv(sys.executable, [sys.executable, str(script_dir / "verify-tier1-python-deps.py"), "--profile", "security-engine", *remaining])
