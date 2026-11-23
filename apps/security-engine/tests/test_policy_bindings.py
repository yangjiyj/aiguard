"""Capability-bound policies execute against real findings, not UI counts."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.detectors.engine import SecurityEngine, SecurityFinding
from app.policy_bindings import (
    CompiledPolicy,
    CompiledPolicyCapability,
    PolicySet,
    SubjectBinding,
)
from app.principal_context import PrincipalContext


def capability(category: str, *, stages=None, mask_capable=False):
    actions = ["audit", "mask", "block"] if mask_capable else ["audit", "block"]
    return CompiledPolicyCapability(
        category=category,
        supported_stages=stages or ["input", "output"],
        allowed_actions=actions,
        mask_capable=mask_capable,
    )


def policy(
    code: str,
    action: str,
    *capabilities: CompiledPolicyCapability,
    enabled: bool = True,
    binding_mode: str = "any",
    scene: str = "data_leak",
    subject_binding: SubjectBinding | None = None,
):
    return CompiledPolicy(
        policy_code=code,
        policy_id=f"id.{code}",
        policy_name=f"name {code}",
        policy_type="scene_policy",
        scene=scene,
        action=action,
        enabled=enabled,
        binding_mode=binding_mode,
        capabilities=list(capabilities),
        subject_binding=subject_binding,
    )


def test_subject_binding_uses_or_within_dimension_and_and_across_dimensions():
    bound = policy(
        "p.bound",
        "block",
        capability("phone_cn"),
        subject_binding=SubjectBinding(
            tenant_ids=["tenant-a"],
            project_ids=["app-a", "app-b"],
            protocols=["openai"],
        ),
    )
    principal = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        project_id="app-b",
        application_id="app-b",
        protocol="openai",
        identity_source="api_key",
        trust_level="key_bound",
        key_id="key-a",
    )
    matched = PolicySet([bound]).apply([finding("phone_cn")], stage="input", principal=principal)
    assert matched[0].policy_code == "p.bound"

    missed = principal.model_copy(update={"protocol": "anthropic"})
    untouched = PolicySet([bound]).apply([finding("phone_cn")], stage="input", principal=missed)
    assert untouched[0].policy_code == ""


def test_unknown_actor_never_matches_actor_or_personnel_department_binding():
    principal = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        key_owner_user_id="owner-a",
        key_owner_department_ids=["dept-owner"],
        key_id="key-a",
        identity_source="api_key",
        trust_level="key_bound",
    )
    actor_bound = policy(
        "p.actor", "block", capability("phone_cn"),
        subject_binding=SubjectBinding(actor_user_ids=["owner-a"]),
    )
    dept_bound = policy(
        "p.dept", "block", capability("phone_cn"),
        subject_binding=SubjectBinding(personnel_department_ids=["dept-owner"]),
    )
    owner_bound = policy(
        "p.owner", "block", capability("phone_cn"),
        subject_binding=SubjectBinding(key_owner_user_ids=["owner-a"]),
    )
    result = PolicySet([actor_bound, dept_bound, owner_bound]).apply(
        [finding("phone_cn")], stage="input", principal=principal
    )
    assert [item.policy_code for item in result] == ["p.owner"]


def test_personnel_department_children_are_explicit_and_subject_miss_cannot_block():
    principal = PrincipalContext(
        schema_version=1, tenant_id="tenant-a", actor_user_id="actor-a",
        actor_department_ids=["dept-child"], actor_department_ancestor_ids=["dept-parent"],
        identity_source="session", trust_level="authenticated",
    )
    exact = policy(
        "p.exact", "block", capability("phone_cn"),
        subject_binding=SubjectBinding(personnel_department_ids=["dept-parent"]),
    )
    raw = finding("phone_cn")
    raw.action = "block"
    missed = PolicySet([exact]).apply([raw], stage="input", principal=principal)
    assert missed[0].policy_code == ""
    assert missed[0].action == "audit"

    descendants = exact.model_copy(update={
        "policy_code": "p.children", "policy_id": "id.p.children",
        "subject_binding": SubjectBinding(
            personnel_department_ids=["dept-parent"],
            personnel_department_include_children=True,
        ),
    })
    matched = PolicySet([descendants]).apply([raw], stage="input", principal=principal)
    assert matched[0].policy_code == "p.children"
    assert matched[0].action == "block"


def test_disabled_subject_miss_does_not_clamp_an_independent_raw_block():
    disabled = policy(
        "p.disabled-bound", "audit", capability("phone_cn"), enabled=False,
        subject_binding=SubjectBinding(project_ids=["other-app"]),
    )
    raw = finding("phone_cn")
    raw.action = "block"
    principal = PrincipalContext(
        schema_version=1, tenant_id="tenant-a", project_id="app-a", application_id="app-a",
        key_id="key-a", identity_source="api_key", trust_level="key_bound",
    )
    result = PolicySet([disabled]).apply([raw], stage="input", principal=principal)
    assert result[0].action == "block"
    assert result[0].policy_code == ""


def test_global_mandatory_policy_is_not_downgraded_by_scoped_subject_miss():
    global_policy = policy("p.global-block", "block", capability("phone_cn"))
    scoped = policy(
        "p.scoped", "audit", capability("phone_cn"),
        subject_binding=SubjectBinding(project_ids=["other-app"]),
    )
    principal = PrincipalContext(
        schema_version=1, tenant_id="tenant-a", project_id="app-a", application_id="app-a",
        key_id="key-a", identity_source="api_key", trust_level="key_bound",
    )
    result = PolicySet([global_policy, scoped]).apply(
        [finding("phone_cn")], stage="input", principal=principal
    )
    assert [item.policy_code for item in result] == ["p.global-block"]
    assert result[0].action == "block"


def test_unbound_policy_remains_global_without_principal():
    result = PolicySet([policy("p.global", "audit", capability("phone_cn"))]).apply(
        [finding("phone_cn")], stage="input"
    )
    assert result[0].policy_code == "p.global"


def finding(
    category: str,
    *,
    rule_id="detector.original",
    severity="critical",
    finding_type="pii",
    rule_type="builtin",
):
    return SecurityFinding(
        type=finding_type,
        category=category,
        severity=severity,
        matched_text_preview="<MASKED>",
        rule_id=rule_id,
        confidence=0.99,
        rule_name="original detector",
        rule_type=rule_type,
        matched_location="content[0:4]",
        redacted_evidence="evidence",
    )


def test_policy_dto_is_strict_and_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CompiledPolicy.model_validate(
            {
                "policy_code": "p.strict",
                "policy_id": "policy.strict",
                "policy_name": "strict",
                "policy_type": "scene_policy",
                "scene": "data_leak",
                "action": "audit",
                "enabled": True,
                "binding_mode": "any",
                "capabilities": [],
                "unexpected": "must-not-be-ignored",
            }
        )


def test_exact_category_only_keeps_suffix_and_stage_mismatch_unchanged():
    policies = PolicySet([
        policy("p.phone", "audit", capability("phone_cn", stages=["input"])),
    ])
    transformed = policies.apply(
        [finding("phone_cn__normalized"), finding("phone_cn", rule_id="output")],
        stage="output",
    )
    assert [item.rule_id for item in transformed] == ["detector.original", "output"]
    assert all(item.policy_code == "" for item in transformed)


def test_multiple_any_policies_are_all_retained_with_original_evidence():
    policies = PolicySet([
        policy("p.audit", "audit", capability("phone_cn")),
        policy("p.block", "block", capability("phone_cn")),
    ])
    original = finding("phone_cn")
    transformed = policies.apply([original], stage="input")

    assert [item.policy_code for item in transformed] == ["p.audit", "p.block"]
    assert [item.source_rule_id for item in transformed] == [
        original.rule_id,
        original.rule_id,
    ]
    assert all(
        item.type == original.type and item.category == original.category
        for item in transformed
    )
    assert all(
        item.redacted_evidence == original.redacted_evidence for item in transformed
    )
    assert all(item.matched_capabilities == ["phone_cn"] for item in transformed)
    assert transformed[0].rule_id == "id.p.audit"
    assert transformed[0].rule_name == "name p.audit"
    assert transformed[0].rule_type == "scene_policy"
    assert transformed[0].policy_scene == "data_leak"


def test_all_binding_requires_every_exact_category_and_preserves_each_evidence():
    conjunction = policy(
        "p.all",
        "block",
        capability("category_a"),
        capability("category_b"),
        binding_mode="all",
    )
    incomplete = finding("category_a")
    incomplete_result = PolicySet([conjunction]).apply(
        [incomplete], stage="input"
    )
    assert len(incomplete_result) == 1
    assert incomplete_result[0].rule_id == incomplete.rule_id
    assert incomplete_result[0].policy_code == ""
    assert incomplete_result[0].action == "audit"
    engine = SecurityEngine()
    engine.audit_only = False
    assert engine._determine_action(incomplete_result) == "audit"

    complete = PolicySet([conjunction]).apply(
        [
            finding("category_a", rule_id="source.a"),
            finding("category_b", rule_id="source.b"),
        ],
        stage="input",
    )
    assert len(complete) == 2
    assert {item.source_rule_id for item in complete} == {"source.a", "source.b"}
    assert all(
        item.matched_capabilities == ["category_a", "category_b"]
        for item in complete
    )
    assert all(item.action == "block" for item in complete)


def test_unbound_finding_is_audited_instead_of_invisibly_enforced():
    conjunction = policy(
        "p.all",
        "block",
        capability("category_a"),
        capability("category_b"),
        binding_mode="all",
    )
    unbound = finding("category_c")

    transformed = PolicySet([conjunction]).apply([unbound], stage="input")

    assert transformed == [unbound]
    engine = SecurityEngine()
    engine.audit_only = False
    assert engine._determine_action(transformed) == "audit"


def test_disabled_policy_suppresses_only_its_exact_applicable_finding():
    policies = PolicySet([
        policy("p.disabled", "audit", capability("phone_cn"), enabled=False),
    ])
    untouched = finding("email", rule_id="email.original")
    assert policies.apply([finding("phone_cn"), untouched], stage="input") == [
        untouched
    ]


def test_policy_audit_is_explicit_and_not_escalated_by_critical_severity():
    engine = SecurityEngine()
    transformed = PolicySet([
        policy("p.audit", "audit", capability("phone_cn")),
    ]).apply([finding("phone_cn", severity="critical")], stage="input")
    assert engine._determine_action(transformed) == "audit"


def test_policy_action_precedence_is_block_then_mask_then_audit():
    engine = SecurityEngine()
    policies = PolicySet([
        policy("p.audit", "audit", capability("phone_cn")),
        policy("p.mask", "mask", capability("phone_cn", mask_capable=True)),
        policy("p.block", "block", capability("phone_cn")),
    ])
    transformed = policies.apply(
        [finding("phone_cn", severity="low")],
        stage="input",
    )
    assert engine._determine_action(transformed) == "block"


def test_generic_observation_cannot_swallow_specific_bound_block():
    engine = SecurityEngine()
    generic = finding(
        "semantic_instruction_override",
        severity="high",
        finding_type="semantic_attack",
        rule_type="semantic",
    )
    generic.action = "allow"
    specific = finding(
        "injection_legal_threat",
        severity="high",
        finding_type="catalog_policy",
    )
    transformed = PolicySet([
        policy("p.legal-threat", "block", capability("injection_legal_threat")),
    ]).apply([generic, specific], stage="input")

    assert any(item.category == "semantic_instruction_override" for item in transformed)
    assert any(
        item.category == "injection_legal_threat" and item.action == "block"
        for item in transformed
    )
    assert engine._determine_action(transformed) == "block"


@pytest.mark.parametrize(
    "semantic_category",
    ["semantic_roleplay", "semantic_instruction_override"],
)
def test_dynamic_semantic_findings_remain_observe_only_when_policy_requests_block(
    semantic_category,
):
    transformed = PolicySet([
        policy("p.semantic", "block", capability(semantic_category)),
    ]).apply(
        [
            finding(
                semantic_category,
                severity="critical",
                finding_type="semantic_attack",
                rule_type="semantic",
            )
        ],
        stage="input",
    )

    assert len(transformed) == 1
    assert transformed[0].policy_code == "p.semantic"
    assert transformed[0].action == "audit"


def test_mixed_roleplay_policy_blocks_static_match_but_not_semantic_opinion():
    mixed = policy(
        "p.roleplay",
        "block",
        capability("keyword_roleplay"),
        capability("semantic_roleplay"),
        binding_mode="any",
    )

    static_result = PolicySet([mixed]).apply(
        [finding("keyword_roleplay")], stage="input"
    )
    semantic_result = PolicySet([mixed]).apply(
        [
            finding(
                "semantic_roleplay",
                finding_type="semantic_attack",
                rule_type="semantic",
            )
        ],
        stage="input",
    )

    assert static_result[0].action == "block"
    assert semantic_result[0].action == "audit"


def test_mask_that_does_not_change_body_is_forwarded_with_alert(monkeypatch):
    engine = SecurityEngine()
    engine.load_policies(PolicySet([
        policy("p.mask", "mask", capability("phone_cn", mask_capable=True)),
    ]))
    monkeypatch.setattr(engine, "_mask_content", lambda content, findings, *args, **kwargs: content)

    result = engine.check_input("req-mask-fallback", "手机号 13800138000")
    assert result.action == "audit"
    assert result.masked_content is None
    assert any(f.triage.get("mask_unavailable") for f in result.findings)


def test_audit_only_is_the_final_clamp_for_policy_block():
    engine = SecurityEngine()
    engine.audit_only = True
    transformed = PolicySet([
        policy("p.block", "block", capability("phone_cn")),
    ]).apply([finding("phone_cn")], stage="input")
    assert engine._determine_action(transformed) == "audit"

def matcher_policy(code: str, *, enabled: bool = True):
    return CompiledPolicy(
        policy_code=code,
        policy_id=f"id.{code}",
        policy_name=f"name {code}",
        policy_type="matcher_policy",
        scene="prompt_injection",
        matcher_rule_id="matcher.source.rule",
        action="audit",
        enabled=enabled,
        binding_mode="any",
        capabilities=[],
    )


def test_matcher_rule_id_replaces_source_finding_with_policy_identity():
    original = finding("custom_category", rule_id="matcher.source.rule")
    transformed = PolicySet([matcher_policy("p.matcher")]).apply(
        [original],
        stage="input",
    )
    assert len(transformed) == 1
    assert transformed[0].policy_code == "p.matcher"
    assert transformed[0].source_rule_id == "matcher.source.rule"
    assert transformed[0].rule_id == "id.p.matcher"
    assert transformed[0].rule_name == "name p.matcher"
    assert transformed[0].rule_type == "matcher_policy"
    assert transformed[0].policy_scene == "prompt_injection"
    assert transformed[0].matched_capabilities == []


@pytest.mark.parametrize(
    "failure_type",
    ["regex_timeout", "custom_scan_incomplete"],
)
def test_runtime_failure_finding_is_recorded_not_enforced(
    failure_type,
):
    """An incomplete scan is an inspection anomaly: the policy binding keeps
    its evidence and identity but it is recorded as audit, never block."""
    timeout = finding(
        f"custom_{failure_type}",
        rule_id="matcher.source.rule",
        severity="critical",
        finding_type=failure_type,
        rule_type="regex",
    )
    timeout.action = "block"
    timeout.triage = {"cannot_downgrade": True, "reason": "regex_timeout"}

    transformed = PolicySet([matcher_policy("p.matcher")]).apply(
        [timeout],
        stage="input",
    )

    assert len(transformed) == 1
    assert transformed[0].policy_code == "p.matcher"
    assert transformed[0].action == "audit"


def test_disabled_matcher_policy_suppresses_its_source_finding():
    original = finding("custom_category", rule_id="matcher.source.rule")
    assert PolicySet([
        matcher_policy("p.matcher.disabled", enabled=False),
    ]).apply([original], stage="input") == []


def test_check_input_uses_agent_stage_for_agent_policy():
    engine = SecurityEngine()
    engine.load_policies(
        PolicySet([
            policy(
                "p.agent.phone",
                "audit",
                capability("phone_cn", stages=["agent"]),
            )
        ])
    )
    result = engine.check_input(
        "req-agent-policy", "手机号 13800138000", semantic_stage="agent"
    )
    assert [item.policy_code for item in result.findings] == ["p.agent.phone"]


def test_go_compiler_wire_fixture_is_consumed_by_strict_engine_dto():
    contract_path = (
        Path(__file__).resolve().parents[3]
        / "deploy"
        / "tests"
        / "fixtures"
        / "compiled_policy_v1.json"
    )
    compiled = CompiledPolicy.model_validate(
        json.loads(contract_path.read_text(encoding="utf-8"))
    )
    transformed = PolicySet([compiled]).apply(
        [finding("phone_cn", severity="high")],
        stage="input",
    )
    assert len(transformed) == 1
    assert transformed[0].policy_code == "contract.scene.phone"
    assert transformed[0].rule_id == "contract_policy_phone"
    assert transformed[0].action == "mask"
def test_subject_binding_model_dimension_matches_principal_model():
    from app.policy_bindings import SubjectBinding

    binding = SubjectBinding(tenant_ids=["tenant-a"], model_ids=["gpt-5.5"])
    matched = binding.match_details(
        PrincipalContext(
            schema_version=1,
            tenant_id="tenant-a",
            model_id="gpt-5.5",
            key_id="key-1",
            identity_source="api_key",
            trust_level="key_bound",
        )
    )
    model_detail = [d for d in matched if d.dimension == "model_ids"][0]
    assert model_detail.matched is True
    assert model_detail.reason == "matched"

    missing = binding.match_details(
        PrincipalContext(
            schema_version=1,
            tenant_id="tenant-a",
            key_id="key-1",
            identity_source="api_key",
            trust_level="key_bound",
        )
    )
    model_detail = [d for d in missing if d.dimension == "model_ids"][0]
    assert model_detail.matched is False
    assert model_detail.reason == "principal_value_missing"


def test_subject_binding_model_dimension_rejects_unlisted_model():
    from app.policy_bindings import SubjectBinding

    binding = SubjectBinding(tenant_ids=["tenant-a"], model_ids=["gpt-5.5"])
    details = binding.match_details(
        PrincipalContext(
            schema_version=1,
            tenant_id="tenant-a",
            model_id="deepseek-v4-flash",
            key_id="key-1",
            identity_source="api_key",
            trust_level="key_bound",
        )
    )
    model_detail = [d for d in details if d.dimension == "model_ids"][0]
    assert model_detail.matched is False
    assert model_detail.reason == "no_configured_value_matched"


def test_bound_finding_takes_policy_severity_and_keeps_detector_severity():
    compiled = CompiledPolicy(
        policy_code="p.sev", policy_id="id.p.sev", policy_name="SQL 注入代码生成",
        policy_type="code_security", scene="code_security", severity="medium", action="audit",
        enabled=True, binding_mode="any", capabilities=[capability("code_sql_injection_generation")],
    )
    finding = SecurityFinding(
        type="catalog_policy", category="code_sql_injection_generation", severity="high",
        rule_id="catalog_code_sql_injection_generation", confidence=0.9, matched_text_preview="x",
    )
    [bound] = PolicySet([compiled]).apply([finding], stage="input")
    assert bound.severity == "medium"
    assert bound.triage["policy_severity"] == "medium"
    assert bound.triage["detector_severity"] == "high"


def test_policy_severity_can_raise_the_detector_level():
    compiled = CompiledPolicy(
        policy_code="p.crit", policy_id="id.p.crit", policy_name="证书/私钥检测",
        policy_type="data_leak", scene="data_leak", severity="critical", action="block",
        enabled=True, binding_mode="any", capabilities=[capability("ssh_private_key")],
    )
    finding = SecurityFinding(
        type="secret", category="ssh_private_key", severity="high",
        rule_id="r", confidence=0.95, matched_text_preview="x",
    )
    [bound] = PolicySet([compiled]).apply([finding], stage="input")
    assert bound.severity == "critical"
    assert bound.triage["detector_severity"] == "high"


def test_policy_without_severity_keeps_detector_level():
    compiled = CompiledPolicy(
        policy_code="p.none", policy_id="id.p.none", policy_name="无级别策略",
        policy_type="data_leak", scene="data_leak", action="audit",
        enabled=True, binding_mode="any", capabilities=[capability("email")],
    )
    finding = SecurityFinding(type="pii", category="email", severity="low", rule_id="r", matched_text_preview="x")
    [bound] = PolicySet([compiled]).apply([finding], stage="input")
    assert bound.severity == "low"
    assert "detector_severity" not in bound.triage


def test_detector_downgraded_finding_is_not_raised_by_policy_severity():
    compiled = CompiledPolicy(
        policy_code="p.cvv", policy_id="id.p.cvv", policy_name="银行卡信息",
        policy_type="data_leak", scene="data_leak", severity="critical", action="audit",
        enabled=True, binding_mode="any", capabilities=[capability("credit_card_cvv")],
    )
    finding = SecurityFinding(
        type="pii", category="credit_card_cvv", severity="medium", rule_id="r", matched_text_preview="x",
        triage={"severity_downgrade_reason": "安全码格式候选，缺少有效卡号佐证"},
    )
    [bound] = PolicySet([compiled]).apply([finding], stage="input")
    assert bound.severity == "medium"
    assert bound.triage["severity_downgrade_reason"] == "安全码格式候选，缺少有效卡号佐证"
    assert bound.triage["policy_severity"] == "critical"
    assert bound.triage["detector_severity"] == "medium"


def _reason_policy(code, severity, category):
    return CompiledPolicy(
        policy_code=code, policy_id=f"id.{code}", policy_name=code,
        policy_type="data_leak", scene="data_leak", severity=severity, action="audit",
        enabled=True, binding_mode="any", capabilities=[capability(category)],
    )


@pytest.mark.parametrize("category,detector,policy_level", [
    ("credit_card_cvv", "medium", "medium"),
    ("credit_card_cvv", "medium", "low"),
    ("genetic_data", "high", "high"),
])
def test_downgrade_reason_dropped_when_policy_not_above_detector(category, detector, policy_level):
    finding = SecurityFinding(
        type="pii", category=category, severity=detector, rule_id="r", matched_text_preview="x",
        triage={"severity_downgrade_reason": "候选"},
    )
    [bound] = PolicySet([_reason_policy("p.r", policy_level, category)]).apply([finding], stage="input")
    assert bound.severity == policy_level
    assert "severity_downgrade_reason" not in bound.triage
    assert "severity_before_downgrade" not in bound.triage
    assert bound.triage["detector_downgrade_reason"] == "候选"


def test_downgrade_reason_pairs_with_severity_before_downgrade():
    finding = SecurityFinding(
        type="pii", category="credit_card_cvv", severity="medium", rule_id="r", matched_text_preview="x",
        triage={"severity_downgrade_reason": "候选"},
    )
    [bound] = PolicySet([_reason_policy("p.c", "critical", "credit_card_cvv")]).apply([finding], stage="input")
    assert bound.severity == "medium"
    assert bound.triage["severity_downgrade_reason"] == "候选"
    assert bound.triage["severity_before_downgrade"] == "critical"


@pytest.mark.parametrize("policy_level", ["critical", "low"])
def test_observe_branch_keeps_policy_and_detector_severity_only_disposition_merged(policy_level):
    compiled = _reason_policy("p.obs", policy_level, "prompt_injection").model_copy(update={"semantic_action": "observe"})
    finding = SecurityFinding(
        type="semantic_attack", category="prompt_injection", severity="medium", rule_id="r", matched_text_preview="x",
        triage={"severity_downgrade_reason": "候选"},
    )
    [bound] = PolicySet([compiled]).apply([finding], stage="input")
    assert bound.counts_as_security_finding is False
    assert bound.triage["disposition"] == "observation"
    assert bound.triage["disposition_reason"] == "policy_semantic_observe"
    assert bound.triage["policy_severity"] == policy_level
    assert bound.triage["detector_severity"] == "medium"
    if policy_level == "critical":
        assert bound.triage["severity_downgrade_reason"] == "候选"
        assert bound.triage["severity_before_downgrade"] == "critical"
    else:
        assert "severity_downgrade_reason" not in bound.triage
        assert bound.triage["detector_downgrade_reason"] == "候选"
