"""/apply-context/ 端点：对 raw_findings 重放 编码降档→内容例外→_determine_action（不重跑正则）。

契约第 2 条：入参 {tenant_id, raw_findings, context:{agent_type, project_id, user_id, content_source, access_type}}；
出参 {findings, action}。
"""
import anyio
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

import app.api.apply_context as apply_context_module
from app.custom_rules import CompiledException, ExceptionSet
from app.policy_bindings import (
    CompiledPolicy,
    CompiledPolicyCapability,
    PolicySet,
)
from app.principal_context import PrincipalContext


def _run(coro):
    return anyio.run(lambda: coro)


def test_model_review_candidate_requires_full_message_reinspection(monkeypatch):
    from dataclasses import replace
    engine = apply_context_module.engine
    runtime = replace(engine.snapshot_semantic_runtime(), fp_suppression_enabled=True, semantic_master_enabled=True)
    monkeypatch.setattr(engine, 'snapshot_semantic_runtime', lambda: runtime)
    request = apply_context_module.ApplyContextRequest(tenant_id='tenant_default', raw_findings=[{
        'type':'catalog_policy', 'category':'prompt_leak_internal_rules', 'severity':'high',
        'rule_id':'catalog_prompt_leak_internal_rules', 'matched_text_preview':'internal rules',
        'matched_location':'content[100:114]',
    }])
    with pytest.raises(HTTPException) as result:
        _run(apply_context_module.apply_context(request))
    assert result.value.status_code == 409
    assert result.value.detail == 'contextual_review_requires_full_input'


@pytest.fixture
def restore_engine_exceptions():
    """临时替换模块级 engine 的内容例外，用例结束后复原（避免污染其它测试）。"""
    engine = apply_context_module.engine
    saved = engine.content_exceptions
    saved_policies = engine.policies
    try:
        yield engine
    finally:
        engine.content_exceptions = saved
        engine.policies = saved_policies


def _raw_custom_block_finding():
 # 与自定义规则命中一致的原始 finding（block，非 ，可被内容例外降级）
    return {
        "type": "custom",
        "category": "sensitive_keyword",
        "severity": "high",
        "matched_text_preview": "<redacted>",
        "rule_id": "rule_kw001",
        "confidence": 0.9,
        "action": "block",
        }


def _raw_aws_finding():
 # 与引擎 _detect_secrets 产出结构一致的原始 finding（AWS access key，critical ）
    return {
        "type": "secret",
        "category": "aws_access_key",
        "severity": "critical",
        "matched_text_preview": "AK****LE",
        "rule_id": "secret_aws_access_key",
        "confidence": 0.99,
        }


def _phone_policy(action: str) -> CompiledPolicy:
    return CompiledPolicy(
        policy_code=f"scene.phone.{action}",
        policy_id=f"policy_phone_{action}",
        policy_name=f"phone {action}",
        policy_type="scene_policy",
        scene="data_leak",
        action=action,
        enabled=True,
        binding_mode="any",
        capabilities=[
            CompiledPolicyCapability(
                category="phone_cn",
                supported_stages=["input"],
                allowed_actions=["audit", "mask", "block"],
                mask_capable=True,
            )
        ],
    )


def _raw_phone_finding() -> dict:
    finding = _raw_aws_finding()
    finding.update({"type": "pii", "category": "phone_cn", "rule_id": "pii_phone"})
    return finding


def test_apply_context_replays_action_from_raw_findings():
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_aws_finding()],
        context={"agent_type": "claude-code", "content_source": "user"},
    )
    resp = _run(apply_context_module.apply_context(req))
    # 未绑定策略的 critical finding 只留审计，不能隐式阻断。
    assert resp.action == "audit"
    assert len(resp.findings) == 1
    assert resp.findings[0].rule_id == "secret_aws_access_key"


def test_apply_context_empty_findings_is_allow():
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default", raw_findings=[], context={},
    )
    resp = _run(apply_context_module.apply_context(req))
    assert resp.action == "allow"
    assert resp.findings == []


def test_apply_context_rejects_cross_tenant_replay_before_loading_policy_state(
    monkeypatch,
):
    monkeypatch.setenv("SECURITY_TENANT_ID", "tenant_a")
    monkeypatch.setattr(
        apply_context_module.engine,
        "snapshot_rule_pack_state",
        lambda: pytest.fail("cross-tenant request reached policy state"),
    )
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_b", raw_findings=[], context={},
    )

    with pytest.raises(HTTPException) as exc_info:
        _run(apply_context_module.apply_context(req))

    assert exc_info.value.status_code == 403


def test_apply_context_accepts_exact_configured_tenant(monkeypatch):
    monkeypatch.setenv("SECURITY_TENANT_ID", "tenant_a")
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_a", raw_findings=[], context={},
    )

    resp = _run(apply_context_module.apply_context(req))

    assert resp.action == "allow"


@pytest.mark.parametrize("tenant_id", ["", " tenant_a", "tenant_a ", "bad tenant"])
def test_apply_context_tenant_id_is_strictly_validated(tenant_id):
    with pytest.raises(ValidationError):
        apply_context_module.ApplyContextRequest(
            tenant_id=tenant_id, raw_findings=[], context={},
        )


def test_apply_context_rejects_unknown_top_level_fields():
    with pytest.raises(ValidationError):
        apply_context_module.ApplyContextRequest.model_validate(
            {
                "tenant_id": "tenant_default",
                "raw_findings": [],
                "context": {},
                "unexpected": True,
            }
        )


@pytest.mark.parametrize(
    "invalid_finding",
    [
        {**_raw_aws_finding(), "confidence": "0.99"},
        {**_raw_aws_finding(), "unexpected": "ignored-before"},
    ],
)
def test_apply_context_strictly_validates_cached_findings(invalid_finding):
    with pytest.raises(ValidationError):
        apply_context_module.ApplyContextRequest.model_validate(
            {
                "tenant_id": "tenant_default",
                "raw_findings": [invalid_finding],
                "context": {},
            }
        )


def test_apply_context_applies_project_scoped_exception(restore_engine_exceptions):
    # 契约第 2 条：context 的 project_id 必须透传给内容例外，命中 project 作用域例外后降档
    engine = restore_engine_exceptions
    engine.content_exceptions = ExceptionSet([
        CompiledException(
            exception_id="e-proj",
            scope_type="project",
            scope_ref="proj_a",
            rule_id="rule_kw001",
            decision="audit",
        ),
    ])
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_custom_block_finding()],
        context={"agent_type": "claude-code", "project_id": "proj_a"},
    )
    resp = _run(apply_context_module.apply_context(req))
    # project 作用域命中 → block 降为 audit，并标注 exception_id
    assert resp.findings[0].exception_id == "e-proj"
    assert resp.findings[0].action == "audit"
    assert resp.action == "audit"


def test_apply_context_skips_project_scoped_exception_on_mismatch(restore_engine_exceptions):
    # 若 context 未带匹配 project_id（如关键字未透传），例外不得生效 → 仍 block
    engine = restore_engine_exceptions
    engine.content_exceptions = ExceptionSet([
        CompiledException(
            exception_id="e-proj",
            scope_type="project",
            scope_ref="proj_a",
            rule_id="rule_kw001",
            decision="audit",
        ),
    ])
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_custom_block_finding()],
        context={"agent_type": "claude-code", "project_id": "proj_b"},
    )
    resp = _run(apply_context_module.apply_context(req))
    assert resp.findings[0].exception_id == ""
    assert resp.findings[0].action == "block"
    assert resp.action == "block"


def test_apply_context_passes_principal_to_key_v1_exception(
    restore_engine_exceptions,
):
    engine = restore_engine_exceptions
    engine.content_exceptions = ExceptionSet([
        CompiledException(
            exception_id="e-key",
            scope_type="key_v1",
            scope_ref="key-a",
            rule_id="rule_kw001",
            decision="audit",
        ),
    ])
    principal = PrincipalContext(
        schema_version=1,
        tenant_id="tenant_default",
        key_id="key-a",
        identity_source="api_key",
        trust_level="key_bound",
    )
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_custom_block_finding()],
        context={},
        principal=principal,
    )

    resp = _run(apply_context_module.apply_context(req))

    assert resp.findings[0].exception_id == "e-key"
    assert resp.findings[0].action == "audit"
    assert resp.action == "audit"


def test_apply_context_rejects_cross_tenant_principal_for_key_v1_exception(
    restore_engine_exceptions,
):
    engine = restore_engine_exceptions
    engine.content_exceptions = ExceptionSet([
        CompiledException(
            exception_id="e-key",
            scope_type="key_v1",
            scope_ref="key-a",
            rule_id="rule_kw001",
            decision="audit",
        ),
    ])
    principal = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-other",
        key_id="key-a",
        identity_source="api_key",
        trust_level="key_bound",
    )
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_custom_block_finding()],
        context={},
        principal=principal,
    )

    resp = _run(apply_context_module.apply_context(req))

    assert resp.findings[0].exception_id == ""
    assert resp.findings[0].action == "block"
    assert resp.action == "block"


def test_apply_context_reapplies_policy_identity_and_explicit_audit(
    restore_engine_exceptions,
):
    engine = restore_engine_exceptions
    engine.policies = PolicySet([_phone_policy("audit")])
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_phone_finding()],
        context={},
    )
    resp = _run(apply_context_module.apply_context(req))
    assert resp.action == "audit"
    assert resp.findings[0].policy_code == "scene.phone.audit"
    assert resp.findings[0].source_rule_id == "pii_phone"


def test_apply_context_keeps_mask_so_callers_fall_back_to_full_scan(
    restore_engine_exceptions,
):
    """Replay has no original text to mask. It must not escalate a configured
    mask to block: callers (gateway, forward proxy) treat "mask" as "run the
    full scan", which performs the real masking."""
    engine = restore_engine_exceptions
    engine.policies = PolicySet([_phone_policy("mask")])
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[_raw_phone_finding()],
        context={},
    )
    resp = _run(apply_context_module.apply_context(req))
    assert resp.action == "mask"


def test_apply_context_drops_stale_invalid_bankcard_and_nested_phone(
    monkeypatch,
):
    engine = apply_context_module.engine
    monkeypatch.setattr(engine, "pii_checksum_enabled", True)
    monkeypatch.setattr(engine, "pii_checksum_drop_invalid", True)
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[
            {
                "type": "custom",
                "category": "pii_bankcard",
                "severity": "high",
                "matched_text_preview": "47************49",
                "rule_id": "rule_g_bankcard",
                "confidence": 0.9,
                "action": "audit",
                "raw_evidence": "4756138564441249",
            },
            {
                "type": "custom",
                "category": "pii_phone",
                "severity": "medium",
                "matched_text_preview": "13*******24",
                "rule_id": "rule_g_phone",
                "confidence": 0.9,
                "action": "audit",
                "raw_evidence": "13856444124",
            },
        ],
        context={
            "agent_type": "claude-code",
            "content_source": "tool_result",
        },
    )

    resp = _run(apply_context_module.apply_context(req))

    assert resp.action == "allow"
    assert resp.findings == []


def test_apply_context_replays_non_user_pii_as_observation(
    monkeypatch, restore_engine_exceptions
):
    engine = restore_engine_exceptions
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.delenv("SECURITY_AUDIT_ONLY", raising=False)
    from app import feature_flags

    feature_flags.apply_overrides({})
    engine.reconfigure_semantic()
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default",
        raw_findings=[
            {
                "type": "custom",
                "category": "pii_email",
                "severity": "medium",
                "matched_text_preview": "te****om",
                "rule_id": "rule_g_email",
                "confidence": 0.95,
                "action": "audit",
                "raw_evidence": "test@example.com",
            }
        ],
        context={
            "agent_type": "unknown-private-model",
            "content_source": "tool_result",
        },
    )

    resp = _run(apply_context_module.apply_context(req))

    assert resp.action == "allow"
    assert len(resp.findings) == 1
    assert resp.findings[0].counts_as_security_finding is False
    assert resp.findings[0].action == "allow"
    assert resp.findings[0].triage["disposition_reason"] == "non_user_context"


# ---- 复审追加：网关、独立代理把“未经扫描的文件引用”命中送来过内容例外 ----

def _raw_file_reference_finding():
    # 与 packages/shared-go/filereference Outcome.ExceptionProbe 同形态。
    return {
        "type": "file",
        "category": "file_id_unverified",
        "severity": "high",
        "rule_id": "file-id-unverified",
        "rule_name": "未经扫描的文件引用",
        "rule_type": "file_reference",
        "action": "block",
        "matched_text_preview": "引用的文件没有安全检测记录",
        "redacted_evidence": "引用的文件没有安全检测记录",
        "evidence_reason": "引用的文件没有安全检测记录",
        "matched_location": "file_reference",
    }


def test_apply_context_applies_rule_exception_to_file_reference_finding(restore_engine_exceptions):
    engine = restore_engine_exceptions
    engine.content_exceptions = ExceptionSet([
        CompiledException(exception_id="e-fref", scope_type="tenant", rule_id="file-id-unverified", decision="audit"),
    ])
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default", raw_findings=[_raw_file_reference_finding()], context={"project_id": "p"},
    )
    resp = _run(apply_context_module.apply_context(req))
    assert [f.exception_id for f in resp.findings] == ["e-fref"]
    assert resp.findings[0].action == "audit"


def test_apply_context_file_reference_finding_without_exception_is_untouched(restore_engine_exceptions):
    engine = restore_engine_exceptions
    engine.content_exceptions = ExceptionSet([
        CompiledException(exception_id="e-other", scope_type="tenant", rule_id="file-id-lookup-failed", decision="audit"),
    ])
    req = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default", raw_findings=[_raw_file_reference_finding()], context={},
    )
    resp = _run(apply_context_module.apply_context(req))
    assert [f.exception_id for f in resp.findings] == [""]
    assert resp.findings[0].action == "block"
