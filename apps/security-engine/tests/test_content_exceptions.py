"""
P2-3 例外（误报豁免）+ 高危纵深防御 —— 引擎运行期单元测试。

纵深防御第 2 层（运行期，对应网关侧严格模式处置）：
- ExceptionSet 按 rule_id 精确豁免：把命中 finding 的 action 降级为 exc.decision，
  并标注 exception_id（finding 仍保留，供安全事件展示「已豁免」，而非丢弃）
- 租户级 catch-all 例外（无 rule_id, scope_type=tenant）豁免 custom/file 维度命中
  即便例外精确指向其 rule_id；也防住编译期拦不到的广域 scope 例外
- 内置检测（pii/secret/code）不属内容例外作用域，不受影响
- decision 只接受 allow/audit（编译期已校验，引擎侧再兜底，绝不收紧/升级）
"""
import pytest
from datetime import datetime, timedelta, timezone

from app.detectors.engine import SecurityFinding
from app.custom_rules import (
    CompiledRule,
    CompiledException,
    CustomRuleSet,
    ExceptionSet,
)
from app.principal_context import PrincipalContext


def _finding(
    rule_id="rule_med001",
    type="custom",
    action="block",
    category="custom_medical_record",
):
    return SecurityFinding(
        type=type,
        category=category,
        severity="high",
        matched_text_preview="<REDACTED>",
        rule_id=rule_id,
        action=action,
        redacted_evidence="<REDACTED>",
    )


def _exc(
    exception_id="exc1",
    scope_type="rule",
    scope_ref="",
    rule_id="rule_med001",
    decision="audit",
    reason="复核确认误报",
    include_children=False,
):
    return CompiledException(
        exception_id=exception_id,
        scope_type=scope_type,
        scope_ref=scope_ref,
        rule_id=rule_id,
        decision=decision,
        reason=reason,
        include_children=include_children,
    )


def _key_principal(key_id="key-a"):
    return PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        key_id=key_id,
        identity_source="api_key",
        trust_level="key_bound",
    )


def _actor_principal(
    department_ids=None,
    ancestor_ids=None,
):
    return PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        actor_user_id="actor-a",
        actor_department_ids=sorted(department_ids or []),
        actor_department_ancestor_ids=sorted(ancestor_ids or []),
        identity_source="session",
        trust_level="authenticated",
    )


def test_exact_exception_matches_policy_source_rule_identity():
    mapped = _finding(rule_id="policy.scene.medical")
    mapped.policy_code = "builtin.medical.record"
    mapped.source_rule_id = "rule_med001"

    result = ExceptionSet([_exc(rule_id="rule_med001")]).apply([mapped])

    assert result[0].rule_id == "policy.scene.medical"
    assert result[0].source_rule_id == "rule_med001"
    assert result[0].action == "audit"
    assert result[0].exception_id == "exc1"


def test_exact_exception_still_matches_policy_identity():
    mapped = _finding(rule_id="policy.scene.medical")
    mapped.policy_code = "builtin.medical.record"
    mapped.source_rule_id = "rule_med001"

    result = ExceptionSet([
        _exc(rule_id="policy.scene.medical"),
    ]).apply([mapped])

    assert result[0].action == "audit"
    assert result[0].exception_id == "exc1"


@pytest.mark.parametrize(
    "category",
    [
        "pii_idcard", "pii_bankcard", "pii_passport", "id_card_cn", "bank_card_cn",
        "openai_key", "ssh_private_key", "private_key", "generic_api_key",
    ],
)
def test_exception_takes_effect_on_identity_and_credential_evidence(category):
    # 2.9.22（设计 D1、5.4）：管理员建的例外一律生效；“不可降级”只约束引擎的自动降级。
    protected = _finding(category=category)
    assert protected.cannot_downgrade() is True

    result = ExceptionSet([_exc()]).apply([protected])

    assert result[0].action == "audit"
    assert result[0].exception_id == "exc1"


def test_exception_takes_effect_on_detector_marked_non_downgradable_finding():
    # 强辱骂、强密级词、编码流量攻击信号由检测器在 triage 里标不可降级，例外照样生效。
    protected = _finding(category="profanity_strong")
    protected.triage = {"cannot_downgrade": True, "cannot_downgrade_reason": "strong"}

    result = ExceptionSet([_exc()]).apply([protected])

    assert result[0].action == "audit"
    assert result[0].exception_id == "exc1"
    # 例外只改动作，不抹掉检测器留下的“不可自动降级”证据。
    assert result[0].cannot_downgrade() is True


def test_exception_apply_source_never_reads_cannot_downgrade():
    # 守门（设计第 7 节第 1 条）：ExceptionSet 的匹配与套用不得读 cannot_downgrade。
    import inspect

    source = inspect.getsource(ExceptionSet.apply) + inspect.getsource(ExceptionSet._match)
    assert "cannot_downgrade" not in source


def test_runtime_ignores_exception_after_its_expiry():
    finding = _finding()
    expired = _exc()
    expired.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()

    result = ExceptionSet([expired]).apply([finding])

    assert result[0].action == "block"
    assert result[0].exception_id == ""


def test_runtime_applies_exception_before_its_expiry():
    finding = _finding()
    active = _exc()
    active.expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    result = ExceptionSet([active]).apply([finding])

    assert result[0].action == "audit"
    assert result[0].exception_id == "exc1"


def test_unknown_scope_fails_closed_even_with_an_exact_rule_id():
    result = ExceptionSet([
        _exc(scope_type="future_scope", rule_id="rule_med001"),
    ]).apply([_finding()])

    assert result[0].action == "block"
    assert result[0].exception_id == ""


def test_key_v1_matches_only_the_stable_principal_key_id():
    exception = _exc(
        scope_type="key_v1",
        scope_ref="key-a",
        rule_id="",
    )

    matched = ExceptionSet([exception]).apply(
        [_finding()],
        principal=_key_principal("key-a"),
        tenant_id="tenant-a",
    )
    missing = ExceptionSet([exception]).apply([_finding()])
    mismatched = ExceptionSet([exception]).apply(
        [_finding()],
        principal=_key_principal("key-b"),
        tenant_id="tenant-a",
    )

    assert matched[0].exception_id == "exc1"
    assert matched[0].action == "audit"
    assert missing[0].exception_id == ""
    assert mismatched[0].exception_id == ""


def test_actor_department_v1_is_exact_by_default():
    exception = _exc(
        scope_type="actor_department_v1",
        scope_ref="dept-parent",
        rule_id="",
    )
    principal = _actor_principal(
        department_ids=["dept-child"],
        ancestor_ids=["dept-parent"],
    )

    ancestor_only = ExceptionSet([exception]).apply(
        [_finding()],
        principal=principal,
        tenant_id="tenant-a",
    )
    exact = ExceptionSet([exception]).apply(
        [_finding()],
        principal=_actor_principal(department_ids=["dept-parent"]),
        tenant_id="tenant-a",
    )

    assert ancestor_only[0].exception_id == ""
    assert exact[0].exception_id == "exc1"


def test_actor_department_v1_includes_descendants_only_when_explicit():
    exception = _exc(
        scope_type="actor_department_v1",
        scope_ref="dept-parent",
        rule_id="",
        include_children=True,
    )
    principal = _actor_principal(
        department_ids=["dept-child"],
        ancestor_ids=["dept-parent"],
    )

    result = ExceptionSet([exception]).apply(
        [_finding()],
        principal=principal,
        tenant_id="tenant-a",
    )

    assert result[0].exception_id == "exc1"
    assert result[0].action == "audit"


def test_actor_department_v1_never_uses_key_owner_or_unknown_actor():
    exception = _exc(
        scope_type="actor_department_v1",
        scope_ref="dept-owner",
        rule_id="",
        include_children=True,
    )
    unknown_actor = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        key_owner_user_id="owner-a",
        key_owner_department_ids=["dept-owner"],
        key_id="key-a",
        identity_source="api_key",
        trust_level="key_bound",
    )

    result = ExceptionSet([exception]).apply(
        [_finding()],
        principal=unknown_actor,
        tenant_id="tenant-a",
    )

    assert result[0].exception_id == ""
    assert result[0].action == "block"


def test_legacy_user_scope_still_uses_context_key_owner_not_actor():
    exception = _exc(
        scope_type="user",
        scope_ref="owner-a",
        rule_id="",
    )
    principal = _actor_principal(department_ids=["dept-a"])

    actor_only = ExceptionSet([exception]).apply(
        [_finding()],
        principal=principal,
    )
    key_owner_context = ExceptionSet([exception]).apply(
        [_finding()],
        user_id="owner-a",
        principal=principal,
    )

    assert actor_only[0].exception_id == ""
    assert key_owner_context[0].exception_id == "exc1"


def test_expired_key_v1_exception_is_rechecked_at_runtime():
    expired = _exc(
        scope_type="key_v1",
        scope_ref="key-a",
        rule_id="",
    )
    expired.expires_at = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()

    result = ExceptionSet([expired]).apply(
        [_finding()],
        principal=_key_principal("key-a"),
        tenant_id="tenant-a",
    )

    assert result[0].exception_id == ""
    assert result[0].action == "block"


def test_key_v1_rejects_unknown_trust_and_cross_tenant_principals():
    exception = _exc(
        scope_type="key_v1",
        scope_ref="key-a",
        rule_id="",
    )
    unknown = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        key_id="key-a",
        identity_source="unknown",
        trust_level="unknown",
    )

    unknown_result = ExceptionSet([exception]).apply(
        [_finding()],
        principal=unknown,
        tenant_id="tenant-a",
    )
    cross_tenant_result = ExceptionSet([exception]).apply(
        [_finding()],
        principal=_key_principal("key-a").model_copy(
            update={"tenant_id": "tenant-b"},
        ),
        tenant_id="tenant-a",
    )

    assert unknown_result[0].exception_id == ""
    assert cross_tenant_result[0].exception_id == ""
