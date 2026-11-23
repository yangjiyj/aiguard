"""Real synthetic PNG, Unicode PDF and scanned PDF, through the DLP engine."""
from pathlib import Path
import base64
import pytest
from app import feature_flags as ff
from app.detectors.engine import SecurityEngine
from app.file_text_extractor import extract_attachment_text
from app.file_readiness import file_detection_readiness
from app.ocr import extract_image_text

ROOT = Path(__file__).parent / "fixtures/file_detection"


def test_real_chinese_pdf_uses_font_mapping():
    result = extract_attachment_text("pdf", (ROOT / "chinese-phone.pdf").read_bytes())
    assert "合成测试客户手机" in result.text
    assert "13812345678" in result.text
    assert result.complete


@pytest.mark.parametrize("name", ["chinese-phone.png", "scanned-chinese-phone.pdf"])
def test_real_ocr_reads_synthetic_chinese_and_digits(name):
    raw = (ROOT / name).read_bytes()
    result = extract_image_text(raw) if name.endswith("png") else extract_attachment_text("pdf", raw)
    assert result.complete, result
    assert "13812345678" in result.text
    assert "手机" in result.text


@pytest.mark.parametrize("name", ["chinese-phone.png", "chinese-phone.pdf", "scanned-chinese-phone.pdf"])
@pytest.mark.parametrize("audit_only", [False, True])
def test_enabled_file_dlp_detects_actual_file_through_engine(monkeypatch, name, audit_only):
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    readiness = file_detection_readiness()
    assert readiness["ready"], readiness
    engine = SecurityEngine()
    engine.audit_only = audit_only
    result = engine.check_input("synthetic-file", "普通业务说明", context={"attachments": [{"file_name": name, "content_type": "image/png" if name.endswith("png") else "application/pdf", "data_base64": base64.b64encode((ROOT / name).read_bytes()).decode()}]})
    assert any(f.category == "phone_cn" for f in result.raw_findings)
    # 未绑定阻断策略的内置检测在附件正文里同样只告警（不再因"来自附件"升级为阻断）。
    assert result.action == "audit"
