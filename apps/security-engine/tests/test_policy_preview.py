import anyio
import pytest
from fastapi import HTTPException

import app.api.policy_preview as preview_module
from app.policy_bindings import (
    CompiledPolicy,
    CompiledPolicyCapability,
    PolicySet,
    SubjectBinding,
)
from app.principal_context import PrincipalContext


def _principal(**updates):
    values = {
        "schema_version": 1,
        "tenant_id": "tenant-a",
        "project_id": "app-a",
        "application_id": "app-a",
        "application_department_id": "dept-app",
        "key_id": "key-a",
        "protocol": "chat",
        "entry_point": "gateway_api",
        "identity_source": "api_key",
        "trust_level": "key_bound",
        "identity_version": "identity-v7",
    }
    values.update(updates)
    return PrincipalContext(**values)


def _policy(
    code="policy.bound",
    *,
    action="block",
    enabled=True,
    stages=None,
    binding=None,
):
    return CompiledPolicy(
        policy_code=code,
        policy_id="id." + code,
        policy_name=code,
        policy_type="scene_policy",
        scene="data_leak",
        action=action,
        enabled=enabled,
        binding_mode="any",
        capabilities=[
            CompiledPolicyCapability(
                category="phone_cn",
                supported_stages=stages or ["input"],
                allowed_actions=["audit", "mask", "block"],
                mask_capable=True,
            )
        ],
        subject_binding=binding,
    )


def test_subject_binding_diagnostics_are_the_source_of_matches():
    binding = SubjectBinding(
        tenant_ids=["tenant-a"],
        project_ids=["app-a"],
        key_ids=["key-b"],
        protocols=["chat"],
    )

    details = binding.match_details(_principal())

    assert binding.matches(_principal()) is False
    assert {item.dimension: item.matched for item in details} == {
        "tenant_ids": True,
        "project_ids": True,
        "key_ids": False,
        "protocols": True,
    }
    assert next(item for item in details if item.dimension == "key_ids").reason == "no_configured_value_matched"


def test_subject_binding_preview_without_principal_fails_closed():
    binding = SubjectBinding(key_ids=["key-a"], protocols=["chat"])

    details = binding.match_details(None)

    assert binding.matches(None) is False
    assert [item.reason for item in details] == [
        "principal_missing",
        "principal_missing",
    ]


def test_policy_set_preview_without_content_never_invents_a_finding():
    policies = PolicySet([
        _policy(binding=SubjectBinding(key_ids=["key-a"])),
    ])

    preview = policies.preview(stage="input", principal=_principal())

    assert len(preview) == 1
    assert preview[0].matched is True
    assert preview[0].configured_action == "block"
    assert preview[0].effective_action is None
    assert preview[0].conditional_action == "block"
    assert preview[0].requires_finding is True
    assert preview[0].action_basis == "finding_required"
    assert preview[0].stage_capability_categories == ["phone_cn"]
    assert not hasattr(preview[0], "findings")


def test_policy_set_preview_explains_subject_stage_and_disabled_misses():
    policies = PolicySet([
        _policy("policy.subject", binding=SubjectBinding(key_ids=["key-b"])),
        _policy("policy.stage", stages=["output"]),
        _policy("policy.disabled", enabled=False),
    ])

    preview = policies.preview(stage="input", principal=_principal())

    assert [(item.policy_code, item.matched, item.action_basis) for item in preview] == [
        ("policy.subject", False, "subject_not_matched"),
        ("policy.stage", False, "stage_not_supported"),
        ("policy.disabled", False, "policy_disabled"),
    ]
    assert all(item.effective_action is None for item in preview)


def test_matcher_preview_does_not_claim_agent_stage_without_runtime_evidence():
    matcher = CompiledPolicy(
        policy_code="policy.matcher",
        policy_id="id.policy.matcher",
        policy_name="matcher",
        policy_type="custom_rule",
        scene="custom_rules",
        matcher_rule_id="rule.matcher",
        action="audit",
        enabled=True,
        binding_mode="any",
        capabilities=[],
    )

    preview = PolicySet([matcher]).preview(stage="agent", principal=_principal())

    assert preview[0].stage_supported is False
    assert preview[0].matched is False
    assert preview[0].effective_action is None
    assert preview[0].conditional_action is None
    assert preview[0].requires_finding is False
    assert preview[0].action_basis == "stage_not_supported"


def test_matcher_preview_does_not_claim_agent_stage_coverage():
    policy = CompiledPolicy(
        policy_code="policy.matcher",
        policy_id="id.policy.matcher",
        policy_name="matcher",
        policy_type="custom_rule",
        scene="custom_rules",
        matcher_rule_id="rule.matcher",
        action="audit",
        enabled=True,
        binding_mode="any",
        capabilities=[],
    )

    preview = PolicySet([policy]).preview("agent", _principal())

    assert preview[0].stage_supported is False
    assert preview[0].matched is False
    assert preview[0].conditional_action is None
    assert preview[0].effective_action is None
    assert preview[0].action_basis == "stage_not_supported"


@pytest.fixture
def restore_preview_engine():
    engine = preview_module.engine
    saved_policies = engine.policies
    saved_version = engine.rule_pack_version
    try:
        yield engine
    finally:
        engine.policies = saved_policies
        engine.rule_pack_version = saved_version


def test_internal_preview_uses_current_atomic_rule_pack_without_content(
    restore_preview_engine,
    monkeypatch,
):
    monkeypatch.setenv("SECURITY_TENANT_ID", "tenant-a")
    engine = restore_preview_engine
    engine.policies = PolicySet([
        _policy(binding=SubjectBinding(project_ids=["app-a"])),
    ])
    engine.rule_pack_version = "pack-current"
    request = preview_module.PolicyPreviewRequest(
        tenant_id="tenant-a",
        stage="input",
        principal=_principal(),
    )

    response = anyio.run(lambda: preview_module.preview_policies(request))

    assert response.tenant_id == "tenant-a"
    assert response.rule_pack_version == "pack-current"
    assert response.identity_version == "identity-v7"
    assert response.content_evaluated is False
    assert response.policies[0].policy_version
    assert response.policies[0].matched is True


def test_internal_preview_rejects_cross_tenant_principal_before_engine_access(
    monkeypatch,
):
    monkeypatch.setenv("SECURITY_TENANT_ID", "tenant-a")
    request = preview_module.PolicyPreviewRequest(
        tenant_id="tenant-a",
        stage="input",
        principal=_principal(tenant_id="tenant-b"),
    )

    with pytest.raises(HTTPException) as exc:
        anyio.run(lambda: preview_module.preview_policies(request))

    assert exc.value.status_code == 403
