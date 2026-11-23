"""Coverage is a security contract, including partial extraction and real files."""
import base64
import io
import zipfile
import pytest
from app import feature_flags as ff
from app import file_text_extractor as extractor
from app.file_content_dlp_bridge import extract_textual_attachment_content
from tests.test_file_content_dlp import _make_docx, _make_text_pdf


def archive(**members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def attachment(data, name="report.txt"):
    return {"attachments": [{"file_name": name, "data_base64": base64.b64encode(data).decode()}]}


def test_truncation_is_explicit_and_keeps_detectable_prefix(monkeypatch):
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setattr(extractor, "MAX_TEXT_CHARS", 17)
    text, findings = extract_textual_attachment_content(attachment(b"phone 13812345678" + b"normal" * 20))
    assert "13812345678" in text
    assert any(f.category == "file_content_incomplete" and "truncated" in f.redacted_evidence for f in findings)


def test_zip_scans_nested_office_pdf_and_text():
    raw = archive(**{"normal.txt": "normal", "secret.docx": _make_docx(["客户手机 13812345678"]), "proof.pdf": _make_text_pdf("secret 13912345678")})
    result = extractor.extract_attachment_text("zip", raw)
    assert "13812345678" in result.text
    assert "13912345678" in result.text
    assert result.complete


def test_zip_skipped_member_is_partial_even_with_readable_text():
    result = extractor.extract_attachment_text("zip", archive(**{"normal.txt": "normal", "legacy.doc": b"\xd0\xcf\x11\xe0" + bytes(30)}))
    assert "normal" in result.text
    assert not result.complete
    assert "unsupported_member" in result.incomplete_reasons


def test_archive_recursion_is_bounded(monkeypatch):
    monkeypatch.setattr(extractor, "MAX_ARCHIVE_DEPTH", 1)
    # Direct worker invocation preserves the test's explicit budget across platforms.
    result = extractor._extract_zip_archive(archive(**{"nested.zip": archive(**{"deeper.zip": archive(**{"secret.txt": "secret"})})}))
    assert "archive_depth" in result.incomplete_reasons


def test_corrupt_office_xml_cannot_succeed_with_other_valid_parts():
    result = extractor.extract_attachment_text("docx", archive(**{"word/document.xml": "<broken", "word/header1.xml": '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:t>normal</w:t></w:hdr>'}))
    assert not result.complete


def test_parser_admission_and_execution_share_one_deadline(monkeypatch):
    import time
    class SlowSemaphore:
        def acquire(self, timeout):
            time.sleep(0.12)
            return True
        def release(self):
            pass
    monkeypatch.setattr(extractor, "_parse_semaphore", SlowSemaphore())
    started = time.monotonic()
    with pytest.raises(extractor._ExtractionError, match="timeout"):
        extractor._run_with_timeout(_sleep_parser, b"", 0.15)
    assert time.monotonic() - started < 0.4


def _sleep_parser(data):
    import time
    time.sleep(0.3)
    return "late"


def test_readiness_reports_disabled_capability(monkeypatch):
    from app.file_readiness import file_detection_readiness
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "false")
    readiness = file_detection_readiness()
    assert readiness["file_content_dlp"]["enabled"] is False
    assert readiness["file_content_dlp"]["status"] == "disabled"


def test_ocr_missing_dependency_is_explicit(monkeypatch):
    from app import ocr
    monkeypatch.setenv("SECURITY_OCR_TESSDATA_DIR", "/missing/tessdata")
    result = ocr.extract_image_text(b"invalid")
    assert not result.complete
    assert result.error


def test_legacy_ocr_still_scans_when_dlp_disabled(monkeypatch):
    from app import ocr
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "false")
    monkeypatch.setattr(ocr, "_ocr_image_bytes", lambda data: "合成手机 13812345678")
    context = attachment(b"fixture", "image.png")
    context["attachments"][0]["content_type"] = "image/png"
    assert "13812345678" in ocr.extract_ocr_text_from_context(context)


def test_incomplete_file_preserves_audit_only_policy(monkeypatch):
    from app.detectors.engine import SecurityEngine
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setattr(extractor, "MAX_TEXT_CHARS", 8)
    engine = SecurityEngine()
    engine.audit_only = True
    result = engine.check_input("partial-audit", "normal", context=attachment(b"normal " * 10))
    assert result.action != "block"
    assert any(f.category == "file_content_incomplete" for f in result.raw_findings)


def test_enabled_readiness_rejects_missing_languages(monkeypatch):
    from app.file_readiness import file_detection_readiness
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setenv("SECURITY_OCR_TESSDATA_DIR", "/missing/languages")
    result = file_detection_readiness()
    assert not result["ready"]
    assert not result["ocr"]["available"]


def test_embedded_office_image_is_explicit_until_extracted():
    result = extractor.extract_attachment_text("docx", archive(**{"word/document.xml": '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:t>normal</w:t></w:document>', "word/media/image1.png": b"image"}))
    assert not result.complete
    assert "office_embedded_content" in result.incomplete_reasons


def test_pdf_page_budget_is_explicit(monkeypatch):
    from pypdf import PdfWriter, PdfReader
    source = PdfReader(io.BytesIO(_make_text_pdf("normal")))
    writer = PdfWriter()
    writer.add_page(source.pages[0])
    writer.add_page(source.pages[0])
    data = io.BytesIO()
    writer.write(data)
    monkeypatch.setattr(extractor, "MAX_PDF_PAGES", 1)
    result = extractor._extract_text_pdf(data.getvalue())
    assert "page_limit" in result.incomplete_reasons


def test_xlsx_formula_cached_string_is_not_skipped():
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    raw = archive(**{"xl/worksheets/sheet1.xml": f'<worksheet xmlns="{ns}"><sheetData><row><c t="str"><v>客户手机 13812345678</v></c></row></sheetData></worksheet>'})
    result = extractor.extract_attachment_text("xlsx", raw)
    assert "13812345678" in result.text
    assert result.complete


def _oversized_parser(data):
    return "x" * (extractor.MAX_TEXT_CHARS + 100)


def test_child_truncates_before_sending_body_over_ipc():
    result = extractor._run_with_timeout(_oversized_parser, b"", 5)
    assert isinstance(result, extractor._ParsedText)
    assert len(result.text) == extractor.MAX_TEXT_CHARS
    assert "truncated" in result.incomplete_reasons


def test_ocr_retains_child_truncation_status(monkeypatch):
    from app import ocr
    monkeypatch.setattr(ocr, "_run_with_timeout", lambda *args: extractor._ParsedText("prefix", ["truncated"]))
    result = ocr.extract_image_text(b"fixture")
    assert result.text == "prefix"
    assert result.truncated and not result.complete


def test_readiness_checks_real_scan_store_write(monkeypatch, tmp_path):
    from app import file_readiness
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setenv("SECURITY_SCAN_STORE_DIR", str(tmp_path / "store"))
    result = file_readiness.file_detection_readiness()
    assert result["scan_store"] == {"configured": True, "available": True}
    assert not list((tmp_path / "store").iterdir())


def test_unwritable_store_is_not_ready(monkeypatch, tmp_path):
    from app import file_readiness
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setenv("SECURITY_SCAN_STORE_DIR", str(blocked / "store"))
    result = file_readiness.file_detection_readiness()
    assert not result["ready"]
    assert "scan_store_unwritable" in result["missing"]
