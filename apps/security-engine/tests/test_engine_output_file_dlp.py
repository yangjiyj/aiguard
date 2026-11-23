import base64
import pytest
from app import feature_flags
from app.detectors.engine import SecurityEngine


def context(text):
    return {"attachments": [{"file_name": "report.txt", "content_type": "text/plain", "data_base64": base64.b64encode(text.encode()).decode()}]}


def engine(monkeypatch, audit=False):
    feature_flags.apply_overrides({})
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", str(audit).lower())
    return SecurityEngine()


@pytest.mark.parametrize("body", [None, "File attached"])
def test_output_scans_text_attachment_and_marks_provenance(monkeypatch, body):
    result = engine(monkeypatch).check_output("output-file", body, context("API credential=AKIAIOSFODNN7EXAMPLE"))
    findings = [f for f in result.findings if f.type == "secret"]
    assert findings and all(f.content_source == "file_attachment" for f in findings)
    assert all(f.attachment_index == 0 for f in findings)
    assert result.action != "mask", "masked text cannot sanitize transmitted attachment bytes"


def test_output_file_scanning_obeys_audit_only(monkeypatch):
    result = engine(monkeypatch, audit=True).check_output("audit-file", None, context("API credential=AKIAIOSFODNN7EXAMPLE"))
    assert any(f.type == "secret" for f in result.findings)
    assert result.action == "audit"


def test_output_records_file_parser_failure(monkeypatch):
    instance = engine(monkeypatch)
    import app.file_content_dlp_bridge as bridge
    failure = bridge._parse_failure_finding({}, 0, "timeout", "file-test-timeout")
    monkeypatch.setattr(bridge, "extract_textual_attachment_content", lambda *args: ("", [failure]))
    result = instance.check_output("failed-file", None, context("ordinary"))
    assert any(f.rule_id == "file-test-timeout" for f in result.findings)
    # 2.9.22：解析失败本身一直是 audit；原先的 block 来自 report.txt 被当未知类型写死拦截，
    # 现在未知类型缺省告警放行，整体为 audit。
    assert result.action == "audit"


def test_parse_failure_rule_name_matches_recorded_action():
    # r2922 复核：解析失败的实际动作是 audit（放行并记录），规则名不能写“阻断”。
    import app.file_content_dlp_bridge as bridge
    for reason in ("timeout", "encrypted", "corrupt", "incomplete"):
        failure = bridge._parse_failure_finding({"file_name": "report.pdf"}, 0, reason, "file-content-" + reason)
        assert failure.action == "audit"
        assert "阻断" not in failure.rule_name
        assert "阻断" not in failure.matched_text_preview
