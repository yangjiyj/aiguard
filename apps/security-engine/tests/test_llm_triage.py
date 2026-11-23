from app.detectors.engine import SecurityFinding
from app.detectors.triage import (
    build_triage_payload,
    default_needs_review,
    parse_triage_response,
    redact_context,
)


def test_parse_triage_response_accepts_valid_json():
    parsed = parse_triage_response(
        '{"verdict":"likely_false_positive","risk_level":"low","confidence":0.82,'
        '"reason":"字段说明","evidence_summary":"命中字段名","suggested_action":"create_exception",'
        '"report_text":"建议保留审计"}'
    )

    assert parsed["verdict"] == "likely_false_positive"
    assert parsed["risk_level"] == "low"
    assert parsed["confidence"] == 0.82
    assert parsed["suggested_action"] == "create_exception"


def test_parse_triage_response_extracts_json_from_extra_text():
    parsed = parse_triage_response(
        '研判如下：{"verdict":"confirmed_risk","risk_level":"high","confidence":1.3,'
        '"reason":"真实密钥","evidence_summary":"命中 token","suggested_action":"escalate",'
        '"report_text":"需要升级"}谢谢'
    )

    assert parsed["verdict"] == "confirmed_risk"
    assert parsed["confidence"] == 1.0


def test_parse_triage_response_malformed_returns_needs_review():
    parsed = parse_triage_response("not json")

    assert parsed["verdict"] == "needs_review"
    assert parsed["risk_level"] == "medium"
    assert parsed["suggested_action"] == "review"


def test_parse_triage_response_invalid_values_are_normalized():
    parsed = parse_triage_response(
        '{"verdict":"allow","risk_level":"severe","confidence":-2,'
        '"reason":"","evidence_summary":"","suggested_action":"ignore","report_text":""}'
    )

    assert parsed["verdict"] == "needs_review"
    assert parsed["risk_level"] == "medium"
    assert parsed["confidence"] == 0.0
    assert parsed["suggested_action"] == "review"
    assert parsed["reason"]


def test_default_needs_review_contains_reason():
    parsed = default_needs_review("模型输出无法解析")

    assert parsed["verdict"] == "needs_review"
    assert "模型输出无法解析" in parsed["reason"]


def test_redact_context_uses_masked_preview_for_custom_rule_and_limits_context():
    finding = SecurityFinding(
        type="custom",
        category="customer_sensitive_data",
        severity="high",
        matched_text_preview="星河** (sha256:abcd1234)",
        redacted_evidence="星河计划",  # 2.9.19：自定义规则的可读显示，AI 复核不采用
        rule_id="rule_customer_keyword",
        rule_name="客户项目代号",
        rule_type="keyword",
    )
    content = "前文" + "x" * 1400 + "星河计划" + "后文"

    redacted = redact_context(content, finding)

    assert "星河**" in redacted["evidence"]
    assert "星河计划" not in redacted["context"]
    assert len(redacted["context"]) <= 1200


def test_redact_context_uses_real_span_when_masked_preview_cannot_be_found():
    target = "TARGET-CLAUSE"
    content = "A" * 2400 + target + "B" * 300
    start = content.index(target)
    finding = SecurityFinding(
        type="data_leak",  # 自定义规则的复核证据取打码预览（二者相同）；这条要测的是 redacted_evidence 与预览不同时按真实位置定位
        category="customer_sensitive_data",
        severity="high",
        matched_text_preview="TARG****AUSE",
        redacted_evidence="<MASKED>",
        rule_id="rule_late",
        matched_location=f"content[{start}:{start + len(target)}]",
    )

    redacted = redact_context(content, finding)

    assert redacted["anchor_status"] == "resolved"
    assert redacted["offset_unit"] == "unicode_codepoint"
    assert "<MASKED>" in redacted["context"]
    assert target not in redacted["context"]
    assert not redacted["context"].startswith("A" * 1000)


def test_redact_context_anchors_the_requested_repeated_occurrence():
    target = "repeat-me"
    content = "FIRST|" + target + "|" + "x" * 1500 + "|SECOND|" + target + "|END"
    start = content.rindex(target)
    finding = SecurityFinding(
        type="custom",
        category="customer_sensitive_data",
        severity="high",
        matched_text_preview="re****me",
        redacted_evidence="<MASKED>",
        rule_id="rule_repeat",
        matched_location=f"content[{start}:{start + len(target)}]",
    )

    redacted = redact_context(content, finding)

    assert redacted["anchor_status"] == "resolved"
    assert "SECOND" in redacted["context"]
    assert "FIRST" not in redacted["context"]
    assert target not in redacted["context"]


def test_redact_context_span_uses_unicode_codepoint_offsets():
    prefix = ("中文🙂" * 500) + "|附近|"
    target = "敏感片段"
    content = prefix + target + "|结尾"
    start = len(prefix)
    finding = SecurityFinding(
        type="custom",
        category="customer_sensitive_data",
        severity="high",
        matched_text_preview="敏感**",
        redacted_evidence="<MASKED>",
        rule_id="rule_unicode",
        matched_location=f"content[{start}:{start + len(target)}]",
    )

    redacted = redact_context(content, finding)

    assert redacted["anchor_status"] == "resolved"
    assert redacted["offset_unit"] == "unicode_codepoint"
    assert "附近" in redacted["context"]
    assert target not in redacted["context"]


def test_redact_context_reports_out_of_bounds_span():
    finding = SecurityFinding(
        type="custom",
        category="customer_sensitive_data",
        severity="high",
        matched_text_preview="missing",
        redacted_evidence="<MASKED>",
        rule_id="rule_invalid_span",
        matched_location="content[100:120]",
    )

    redacted = redact_context("short content", finding)

    assert redacted["anchor_status"] == "out_of_bounds"
    assert redacted["offset_unit"] == "unicode_codepoint"
    assert len(redacted["context"]) <= 1200
