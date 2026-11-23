"""Capability readiness is distinct from process liveness and never enables policy."""
from __future__ import annotations
import importlib.util
import json
import sys
import os
import tempfile
import hashlib
import time
from pathlib import Path
from app import feature_flags as ff
from app.ocr import tessdata_path

_capability_cache = None


def _probe_capability():
    global _capability_cache
    key = str(tessdata_path())
    now = time.monotonic()
    if _capability_cache and _capability_cache[0] == key and now - _capability_cache[1] < 20:
        return _capability_cache[2]
    missing = []
    try:
        import pypdf
        _ = pypdf.PdfReader
    except (ImportError, OSError):
        missing.append("pypdf")
    try:
        from PIL import Image
        _ = Image.open
        import tesserocr
        tesserocr.tesseract_version()
    except (ImportError, OSError, ValueError, RuntimeError):
        missing.append("ocr_native_runtime")
    try:
        lock = json.loads((Path(__file__).resolve().parent.parent / "ocr-resources.lock.json").read_text())
        for item in lock["files"]:
            path = tessdata_path() / item["name"]
            if path.is_symlink() or path.stat().st_size != item["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                raise ValueError("resource_digest")
    except (OSError, ValueError, KeyError):
        missing.append("ocr_resources_unverified")
    _capability_cache = (key, now, missing)
    return missing


def file_detection_readiness() -> dict:
    enabled = ff.is_enabled(ff.ENV_FILE_CONTENT_DLP)
    pdf_available = importlib.util.find_spec("pypdf") is not None
    image_available = importlib.util.find_spec("PIL") is not None
    ocr_available = importlib.util.find_spec("tesserocr") is not None
    languages = [lang for lang in ("chi_sim", "eng") if (tessdata_path() / (lang + ".traineddata")).is_file()]
    missing = list(_probe_capability())
    if not pdf_available:
        missing.append("pypdf")
    if not image_available:
        missing.append("Pillow")
    if not ocr_available:
        missing.append("tesserocr")
    if len(languages) != 2:
        missing.append("ocr_languages")
    store_root = os.getenv("SECURITY_SCAN_STORE_DIR", "").strip()
    store_available = False
    if store_root:
        try:
            from app.scan_store import ScanStore, ScanStoreError
            ScanStore(store_root).ensure_root()
            with tempfile.TemporaryFile(dir=store_root) as probe:
                probe.write(b"readiness")
                probe.flush()
            store_available = True
        except (OSError, ValueError, RuntimeError, ScanStoreError):
            missing.append("scan_store_unwritable")
    available = not missing
    return {
        "ready": not enabled or available,
        "file_content_dlp": {"enabled": enabled, "available": available, "status": ("ready" if available else "unavailable") if enabled else "disabled"},
        "scan_store": {"configured": bool(store_root), "available": store_available},
        "pdf": {"available": pdf_available},
        "ocr": {"available": image_available and ocr_available and len(languages) == 2 and not any(item.startswith("ocr_") for item in missing), "languages": languages, "backend": "tesserocr-cpu"},
        "missing": sorted(set(missing)),
    }


if __name__ == "__main__":
    state = file_detection_readiness()
    print(json.dumps(state, sort_keys=True))
    strict = "--require-enabled" in sys.argv
    sys.exit(0 if state["ready"] and (not strict or state["file_content_dlp"]["enabled"]) else 1)
