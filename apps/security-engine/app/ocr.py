"""Offline CPU OCR. No runtime downloads; every failure has an explicit status."""
from __future__ import annotations
import io
import os
import sysconfig
from pathlib import Path
from app.file_text_extractor import ExtractionResult, _ExtractionError, _run_with_timeout

MAX_OCR_IMAGE_BYTES = max(1, int(os.getenv("SECURITY_OCR_MAX_IMAGE_BYTES", str(8 * 1024 * 1024))))
MAX_OCR_PIXELS = max(1, int(os.getenv("SECURITY_OCR_MAX_PIXELS", "25000000")))
OCR_TIMEOUT_SEC = max(0.1, float(os.getenv("SECURITY_OCR_TIMEOUT_SEC", "15")))
MAX_OCR_FRAMES = max(1, int(os.getenv("SECURITY_OCR_MAX_FRAMES", "10")))


def tessdata_path() -> Path:
    return Path(os.getenv("SECURITY_OCR_TESSDATA_DIR") or (Path(sysconfig.get_path("purelib")) / "jjdguard_ocr_data"))


def _ocr_with_tesseract(image_bytes: bytes) -> str:
    # Executed inside an isolated, killable parsing process, including PDF images.
    if len(image_bytes) > MAX_OCR_IMAGE_BYTES:
        raise _ExtractionError("ocr_oversized")
    os.environ.setdefault("OMP_THREAD_LIMIT", "1")
    try:
        from PIL import Image
        from tesserocr import PyTessBaseAPI, PSM, OEM
    except (ImportError, OSError) as exc:
        raise _ExtractionError("ocr_dependency_missing") from exc
    data_dir = tessdata_path()
    if not all((data_dir / (lang + ".traineddata")).is_file() for lang in ("chi_sim", "eng")):
        raise _ExtractionError("ocr_languages_missing")
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            if image.width * image.height > MAX_OCR_PIXELS:
                raise _ExtractionError("ocr_pixel_limit")
            if getattr(image, "n_frames", 1) > MAX_OCR_FRAMES:
                raise _ExtractionError("ocr_frame_limit")
            texts = []
            with PyTessBaseAPI(path=str(data_dir), lang="chi_sim+eng", oem=OEM.LSTM_ONLY, psm=PSM.AUTO) as api:
                for frame in range(getattr(image, "n_frames", 1)):
                    image.seek(frame)
                    if image.width * image.height > MAX_OCR_PIXELS:
                        raise _ExtractionError("ocr_pixel_limit")
                    api.SetImage(image.convert("RGB"))
                    texts.append(api.GetUTF8Text().strip())
            return "\n".join(filter(None, texts))
    except _ExtractionError:
        raise
    except Exception as exc:
        raise _ExtractionError("ocr_parse_failed") from exc


def extract_image_text(image_bytes: bytes) -> ExtractionResult:
    result = ExtractionResult(real_type="image")
    try:
        parsed = _run_with_timeout(_ocr_with_tesseract, image_bytes, OCR_TIMEOUT_SEC)
        from app.file_text_extractor import _ParsedText
        if isinstance(parsed, _ParsedText):
            result.text = parsed.text
            result.incomplete_reasons = parsed.incomplete_reasons
            result.truncated = "truncated" in parsed.incomplete_reasons
        else:
            result.text = parsed
        if not result.text:
            result.incomplete_reasons.append("ocr_no_text")
        from app.file_text_extractor import _truncate
        result.text, truncated = _truncate(result.text)
        result.truncated = result.truncated or truncated
        if result.truncated:
            result.incomplete_reasons.append("truncated")
        result.extracted_chars = len(result.text)
    except _ExtractionError as exc:
        if str(exc) == "timeout":
            result.timeout = True
        else:
            result.error = str(exc)
    return result


def _ocr_image_bytes(image_bytes: bytes) -> str:
    result = extract_image_text(image_bytes)
    if result.text:
        return result.text
    # Compatibility for installations that already supplied the old optional
    # backends. Never download models in a customer request.
    try:
        parsed = _run_with_timeout(_legacy_ocr, image_bytes, OCR_TIMEOUT_SEC)
        return parsed if isinstance(parsed, str) else parsed.text
    except _ExtractionError:
        return ""


def _legacy_ocr(image_bytes: bytes) -> str:
    from PIL import Image
    with Image.open(io.BytesIO(image_bytes)) as image:
        if image.width * image.height > MAX_OCR_PIXELS:
            raise _ExtractionError("ocr_pixel_limit")
        try:
            import easyocr
            import numpy as np
            reader = easyocr.Reader(["ch_sim", "en"], gpu=False, download_enabled=False)
            return "\n".join(reader.readtext(np.array(image.convert("RGB")), detail=0, paragraph=True))
        except (ImportError, OSError, RuntimeError):
            import pytesseract
            return str(pytesseract.image_to_string(image, lang="chi_sim+eng", timeout=OCR_TIMEOUT_SEC)).strip()


def extract_ocr_text_from_context(context) -> str:
    """Legacy API hook; enabled DLP uses the structured engine bridge instead."""
    import base64
    if not isinstance(context, dict) or not isinstance(context.get("attachments"), list):
        return ""
    texts = []
    limit = max(1, int(os.getenv("SECURITY_OCR_MAX_ATTACHMENTS", "3")))
    for item in context["attachments"][:limit]:
        if not isinstance(item, dict) or not str(item.get("content_type", "")).lower().startswith("image/"):
            continue
        try:
            encoded = item.get("data_base64", "")
            if len(encoded) > (MAX_OCR_IMAGE_BYTES + 2) // 3 * 4:
                continue
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            continue
        text = _ocr_image_bytes(data)
        if text:
            texts.append("[ocr] " + text)
    return "\n".join(texts)
