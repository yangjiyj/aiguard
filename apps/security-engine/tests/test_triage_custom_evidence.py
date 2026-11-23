from app.detectors.triage import build_triage_payload
import json

CONTENT = "患者病案号：BA00123456 已归档"
START = CONTENT.index("BA00123456")
LOCATION = f"content[{START}:{START + 10}]"


def _finding(rule_type, as_dict=False):
    values = dict(
        type="custom" if rule_type != "builtin" else "pii", category="uncatalogued_category", severity="high",
        rule_id="r1", rule_type=rule_type, matched_location=LOCATION, confidence=0.9,
        redacted_evidence="BA00123456", matched_text_preview="BA****56 (sha256:deadbeef)",
    )
    if as_dict:
        return values
    from app.detectors.engine import SecurityFinding
    return SecurityFinding(**values)


def test_custom_rule_triage_evidence_stays_masked():
    for rule_type in ("regex", "keyword", "field_name", "secret"):
        for as_dict in (False, True):
            payload = build_triage_payload(CONTENT, _finding(rule_type, as_dict), "input")
            assert payload["context"]["evidence"] == "BA****56 (sha256:deadbeef)", (rule_type, as_dict)
            assert "BA00123456" not in json.dumps(payload, ensure_ascii=False), (rule_type, as_dict)


def test_builtin_triage_evidence_keeps_redacted_evidence():
    for as_dict in (False, True):
        payload = build_triage_payload(CONTENT, _finding("builtin", as_dict), "input")
        assert payload["context"]["evidence"] == "BA00123456"


def _builtin_marker(as_dict=False, category="ssh_private_key"):
    values = dict(
        type="code_config", category=category, severity="critical", rule_id="r2", rule_type="builtin",
        matched_location=LOCATION, confidence=0.9,
        redacted_evidence="-----BEGIN RSA PRIVATE KEY-----（后续正文 300 字已隐藏）",
        matched_text_preview="--****--",
    )
    if as_dict:
        return values
    from app.detectors.engine import SecurityFinding
    return SecurityFinding(**values)


def test_builtin_with_generated_display_uses_masked_preview():
    for as_dict in (False, True):
        payload = build_triage_payload(CONTENT, _builtin_marker(as_dict), "input")
        assert payload["context"]["evidence"] == "--****--", as_dict


def test_builtin_without_doc_keeps_redacted_evidence():
    for as_dict in (False, True):
        payload = build_triage_payload(CONTENT, _builtin_marker(as_dict, "capability_without_doc"), "input")
        assert payload["context"]["evidence"].startswith("-----BEGIN RSA"), as_dict


def test_display_kind_failure_falls_back_to_redacted_evidence(monkeypatch):
    import app.capability_docs as capability_docs

    def broken(category):
        raise capability_docs.CapabilityDocError("坏了")

    monkeypatch.setattr(capability_docs, "display_kind", broken)
    payload = build_triage_payload(CONTENT, _builtin_marker(), "input")
    assert payload["context"]["evidence"].startswith("-----BEGIN RSA")
