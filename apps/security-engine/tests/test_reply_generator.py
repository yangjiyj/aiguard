import pytest

from app.detectors.engine import SecurityEngine, SecurityFinding
from app.reply_generator import DEFAULT_REPLIES, ReplyGenerator, normalize_reply_policy


def enabled_policy(**overrides):
    templates = {**DEFAULT_REPLIES, **overrides}
    templates.pop("agent_abnormal", None)
    return normalize_reply_policy(
        {"schema_version": 1, "enabled": True, "templates": templates}
    )


def test_configured_prompt_injection_template_is_selected():
    policy = enabled_policy(prompt_injection="企业安全策略拒绝该请求")

    reply = ReplyGenerator.generate(["prompt_injection"], policy)

    assert reply == "企业安全策略拒绝该请求"


@pytest.mark.parametrize("finding_type", ["semantic_attack", "custom"])
def test_policy_scene_selects_prompt_injection_reply_for_mapped_findings(finding_type):
    engine = SecurityEngine()
    policy = enabled_policy(prompt_injection="按提示词注入场景代答")
    finding = SecurityFinding(
        type=finding_type,
        category="mapped_category",
        severity="high",
        matched_text_preview="",
        rule_id="mapped-policy",
        action="block",
        policy_code="scene.prompt",
        policy_scene="prompt_injection",
    )

    assert engine._should_reply([finding], policy) is True
    assert ReplyGenerator.generate(engine._reply_template_keys([finding]), policy) == "按提示词注入场景代答"


def test_disabled_reply_policy_keeps_block_action():
    engine = SecurityEngine()
    policy = normalize_reply_policy(
        {
            "schema_version": 1,
            "enabled": False,
            "templates": {
                key: DEFAULT_REPLIES[key]
                for key in (
                    "default",
                    "prompt_injection",
                    "content_safety",
                    "data_leak",
                )
            },
        }
    )
    finding = SecurityFinding(
        type="prompt_injection",
        category="classic",
        severity="high",
        matched_text_preview="",
        rule_id="pi-1",
    )

    assert engine._should_reply([finding], policy) is False


def test_enabled_fixed_reply_covers_critical_and_non_downgradable_blocks():
    # 2.9.22（设计 5.4）：开启固定回复后对所有阻断都用固定回复，去掉“凭据类强制硬拦”。
    # 原断言（严重凭据、不可降级命中不代答）随用户 11-17 决定改为代答。
    engine = SecurityEngine()
    policy = enabled_policy()
    normal = SecurityFinding(
        type="prompt_injection",
        category="classic",
        severity="high",
        matched_text_preview="",
        rule_id="pi-1",
    )
    critical = SecurityFinding(
        type="secret",
        category="private_key",
        severity="critical",
        matched_text_preview="",
        rule_id="secret-1",
    )
    protected = SecurityFinding(
        type="content_safety",
        category="danger",
        severity="high",
        matched_text_preview="",
        rule_id="cs-1",
        triage={"cannot_downgrade": True},
    )

    assert engine._should_reply([normal], policy) is True
    assert engine._should_reply([normal, critical], policy) is True
    assert engine._should_reply([critical], policy) is True
    assert engine._should_reply([protected], policy) is True
    # 没有专属模板的类型（secret）用 default 模板。
    assert ReplyGenerator.generate(engine._reply_template_keys([critical]), policy) == DEFAULT_REPLIES["default"]


@pytest.mark.parametrize(
    "category",
    ["pii_idcard", "pii_bankcard", "pii_passport", "id_card_cn", "bank_card_cn"],
)
def test_identity_policy_block_uses_fixed_reply_when_enabled(category):
    # 2.9.22：证件号策略阻断也走固定回复（原断言“从不代答”随用户 11-17 决定改写）。
    engine = SecurityEngine()
    policy = enabled_policy(data_leak="企业数据保护策略代答")
    finding = SecurityFinding(
        type="custom",
        category=category,
        severity="high",
        matched_text_preview="<redacted>",
        rule_id="policy.identity",
        source_rule_id="rule_g_identity",
        policy_code="builtin.identity",
        policy_scene="data_leak",
        action="block",
    )

    assert engine._should_reply([finding], policy) is True
    assert ReplyGenerator.generate(engine._reply_template_keys([finding]), policy) == "企业数据保护策略代答"


@pytest.mark.parametrize("finding_type", ["secret", "file", "custom", "agent_guard"])
def test_enabled_fixed_reply_covers_every_block_type(finding_type):
    engine = SecurityEngine()
    finding = SecurityFinding(
        type=finding_type, category="any", severity="high",
        matched_text_preview="", rule_id="r-1", action="block",
    )
    assert engine._should_reply([finding], enabled_policy()) is True


def test_fixed_reply_engine_end_to_end_for_credential_block():
    from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

    engine = SecurityEngine()
    engine.load_policies(PolicySet([CompiledPolicy(
        policy_code="tenant.cred.block", policy_id="policy.cred.block", policy_name="凭据阻断",
        policy_type="scene_policy", scene="data_leak", action="block", enabled=True, binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category="openai_key", supported_stages=["input", "output"],
            allowed_actions=["audit", "block"], mask_capable=False,
        )],
    )]))
    engine.load_reply_policy(enabled_policy(data_leak="内容含敏感信息，已按企业策略处理"))
    result = engine.check_input("reply-cred", "key sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD")
    assert result.action == "reply"
    assert result.masked_content == "内容含敏感信息，已按企业策略处理"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"schema_version": 2, "enabled": True, "templates": {}},
        {
            "schema_version": 1,
            "enabled": True,
            "templates": {"default": "only one"},
        },
        {
            "schema_version": 1,
            "enabled": True,
            "templates": {
                "default": "a",
                "prompt_injection": "b",
                "content_safety": "c",
                "data_leak": " ",
            },
        },
        {
            "schema_version": 1,
            "enabled": True,
            "templates": {
                "default": "x" * 1001,
                "prompt_injection": "b",
                "content_safety": "c",
                "data_leak": "d",
            },
        },
    ],
)
def test_invalid_present_reply_policy_is_rejected(payload):
    with pytest.raises(ValueError):
        normalize_reply_policy(payload)
