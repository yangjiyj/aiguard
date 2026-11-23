"""Custom replacements and reversible mappings are request-local, never evidence."""
import json
import pytest
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet, RedactionSettings
from app.custom_rules import CompiledRule, CustomRuleSet


def policy(category, replacement, restore=False):
    return CompiledPolicy(
        policy_code=f"test.{category}", policy_id=f"policy-{category}",
        policy_name=category, policy_type="data_leak", scene="data_security",
        severity="high", action="mask", enabled=True, binding_mode="any",
        redaction=RedactionSettings(replacement=replacement, restore_response=restore),
        capabilities=[CompiledPolicyCapability(category=category, supported_stages=["input", "output"], allowed_actions=["audit", "mask", "block"], mask_capable=True)],
    )


def test_distinct_type_replacements_cover_every_match_and_keep_evidence_redacted():
    engine=SecurityEngine()
    engine.load_policies(PolicySet([policy("phone_cn", "[手机号]"), policy("email", "[邮箱]")]))
    result=engine.check_input("request-1", "联系 13800138000 或 13900139000; person@example.com", skip_semantic=True)
    assert result.action=="mask"
    assert result.masked_content.count("[手机号]")==2
    assert "[邮箱]" in result.masked_content
    assert "person@example.com" not in result.masked_content
    assert result.redaction_mapping=={}


def test_reversible_mapping_is_not_in_findings_and_changes_for_each_request():
    engine=SecurityEngine()
    engine.load_policies(PolicySet([policy("phone_cn", "[手机号]", True)]))
    first=engine.check_input("request-1", "电话 13800138000", skip_semantic=True)
    second=engine.check_input("request-2", "电话 13800138000", skip_semantic=True)
    assert set(first.redaction_mapping.values())=={"13800138000"}
    assert set(first.redaction_mapping).isdisjoint(second.redaction_mapping)
    assert "13800138000" not in first.masked_content
    assert "手机号" in first.masked_content
    assert all(token in first.masked_content for token in first.redaction_mapping)
    assert "redaction_mapping" not in json.dumps([f.model_dump() for f in first.findings + first.raw_findings])
    # An unrelated request cannot get any previous restoration value.
    clean=engine.check_input("request-clean", "写一首诗", skip_semantic=True)
    assert clean.redaction_mapping=={}


def test_custom_regex_replacement_and_output_do_not_issue_restore_secrets():
    engine=SecurityEngine()
    engine.load_custom_rules(CustomRuleSet([CompiledRule(rule_id="customer",rule_name="编号",rule_type="regex",category="customer",severity="high",action="mask",enabled=True,regex=r"CUS-\d{5}",scope={"redaction":{"replacement":"[客户编号]","restore_response":True}})]))
    result=engine.check_input("request-custom", "客户 CUS-12345 和 CUS-54321",skip_semantic=True)
    assert set(result.redaction_mapping.values())=={"CUS-12345","CUS-54321"}
    assert "CUS-12345" not in result.masked_content
    output=engine.check_output("request-custom", "CUS-12345")
    assert output.masked_content=="[客户编号]"
    assert output.redaction_mapping=={}


def test_audit_match_is_not_rewritten_by_another_mask_policy():
    engine=SecurityEngine()
    policies=PolicySet([policy("phone_cn", "[手机号]")])
    findings=[SecurityFinding(matched_text_preview="redacted",type="pii",category="phone_cn",severity="high",rule_id="policy-phone_cn",action="mask",matched_location="content[0:11]"),SecurityFinding(matched_text_preview="redacted",type="pii",category="email",severity="high",rule_id="audit-email",action="audit",matched_location="content[12:30]")]
    assert engine._mask_content("13800138000 person@example.com",findings,policies=policies)=="[手机号] person@example.com"


def test_overlapping_rules_rewrite_once_without_scanning_inserted_text():
    engine=SecurityEngine()
    findings=[SecurityFinding(matched_text_preview="redacted",type="custom",category="customer",severity="high",rule_id="whole",rule_type="regex",action="mask",matched_location="content[0:11]"),SecurityFinding(matched_text_preview="redacted",type="custom",category="customer",severity="high",rule_id="part",rule_type="regex",action="mask",matched_location="content[3:8]")]
    assert engine._mask_content("13800138000",findings)=="<MASKED>"


@pytest.mark.parametrize("replacement", ["", "  ", "a\nb", "a\r", "x\x00", "x"*129, "<JJD_phone_reserved>"])
def test_invalid_replacement_fails_rule_pack_validation(replacement):
    with pytest.raises(ValueError):
        RedactionSettings(replacement=replacement)