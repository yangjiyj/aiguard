import json
from pathlib import Path
import pytest
from app.detectors.engine import SecurityEngine

ROWS = json.loads((Path(__file__).parent / "fixtures/credential_replay/production_tool_messages.json").read_text())
CATEGORIES = {"plain_password", "code_leak_password_in_code", "code_leak_database_url", "openai_key", "env_file", "config_file"}

@pytest.mark.parametrize("row", ROWS, ids=lambda r: r["request_id"])
def test_full_production_tool_messages_are_not_secret_values(row):
    result = SecurityEngine().check_output("replay", row["content"], context={"agent_type":"openai-codex", "access_type":"ai_ide"})
    # This recorded verification command also contains intentional positive
    # controls. Literal controls must remain detectable; references must not.
    hits = [f for f in result.raw_findings if f.category in CATEGORIES]
    if row["request_id"] == "4e1743f4-5201-4723-b10e-45f114ab2f1b":
        assert all("SyntheticPassword42!" in f.raw_evidence or "sk-proj-Q7mR2vW9" in f.raw_evidence for f in hits)
    else:
        assert not hits

@pytest.mark.parametrize("depth", range(5))
@pytest.mark.parametrize("value", ["$ADMIN_PASSWORD", "${ADMIN_PASSWORD}", "${ADMIN_PASSWORD:-}", "<your-password>", "process.env.ADMIN_PASSWORD"])
def test_structured_serialization_does_not_turn_references_into_secrets(depth, value):
    text = 'PASSWORD=' + value + '\nWEB_PORT=8080\n'
    for _ in range(depth): text = json.dumps({"cmd":text}, ensure_ascii=False)
    assert not [f for f in SecurityEngine().check_output("reference", text).raw_findings if f.category in CATEGORIES]

@pytest.mark.parametrize("depth", range(5))
def test_real_literal_in_same_serialized_message_is_still_detected_and_anchored(depth):
    text = 'PASSWORD=${ADMIN_PASSWORD:-}\nPASSWORD=RealSynthetic42!pZ\n'
    for _ in range(depth): text = json.dumps({"cmd":text})
    findings = SecurityEngine().check_output("positive", text).raw_findings
    hits = [f for f in findings if f.category in {"plain_password", "code_leak_password_in_code"}]
    assert hits
    for f in hits:
        start,end = map(int,f.matched_location[8:-1].split(":"))
        assert text[start:end] == f.raw_evidence
        assert "RealSynthetic42!pZ" in f.raw_evidence


def test_literal_candidate_contract_is_not_a_verified_leak():
    result = SecurityEngine().check_output("contract", 'password="RealSynthetic42!pZ"')
    hit = next(f for f in result.findings if f.category == "plain_password")
    assert hit.triage["validation_status"] == "literal_candidate"
    assert hit.triage["credential_validity"] == "unknown"
    assert hit.triage["confidence_kind"] == "heuristic_rule_score"
    assert hit.triage["review_status"] == "not_requested"
    assert hit.redacted_evidence and "RealSynthetic42!pZ" not in hit.redacted_evidence
    assert "尚未验证" in hit.evidence_reason

@pytest.mark.parametrize("depth", range(5))
def test_json_password_fields_use_the_same_value_parser(depth):
    benign = json.dumps({"password":"${PASSWORD}"})
    positive = json.dumps({"password":"RealSynthetic42!pZ"})
    for _ in range(depth):
        benign = json.dumps({"tool":benign})
        positive = json.dumps({"tool":positive})
    engine = SecurityEngine()
    assert not [f for f in engine.check_output("json-ref",benign).raw_findings if f.category in CATEGORIES]
    assert any(f.category in {"plain_password","code_leak_password_in_code"} for f in engine.check_output("json-lit",positive).raw_findings)

@pytest.mark.parametrize("value", [";RealSynthetic42!pZ", ")RealSynthetic42!pZ", ",RealSynthetic42!pZ", "$RealSynthetic42!pZ"])
def test_literal_punctuation_prefix_is_not_a_source_code_exemption(value):
    result=SecurityEngine().check_output("literal", "password='"+value+"'")
    assert any(f.category=="code_leak_password_in_code" for f in result.raw_findings)
