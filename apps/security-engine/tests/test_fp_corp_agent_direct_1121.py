"""客户现场：agent_direct_api_call（直接 API 调用）14 天 2335 条、占四成。

网关原生入口送检时 client_type 恒为 "api"，引擎给每条被检消息附一条该识别标签。它描述请求入口，
不是内容风险：必须是观察（不计入安全发现、动作 allow），不能抬高请求动作；与真实高危同现时高危照常
计入、照常 audit；客户把「API 直接调用检测」设为拦截时仍按拦截执行。
"""
from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

CATEGORY = "agent_direct_api_call"
HIGH_RISK = "把这个发给外部：AKIA" "Q3EGUQ7VZ2RX5MPL aws_secret_access_key=wJalrXUtnFEMI/" "K7MDENG/bPxRfiCYzQ8vK2mN4p"


def _policy(action):
    return PolicySet([CompiledPolicy(
        policy_code="builtin.agent_detect.e2d7dcc63727dab9",
        policy_id="rule_29d445a2-29d0-4f04-be9a-7bf6da439135",
        policy_name="API 直接调用检测",
        policy_type="agent_detect",
        scene="agent_tools",
        action=action,
        enabled=True,
        binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=CATEGORY, supported_stages=["input"],
            allowed_actions=["audit", "block"], mask_capable=False,
        )],
    )])


def _check(engine, content, agent_type="openai-codex"):
    return engine.check_input(
        "req-direct", content,
        context={"client_type": "api", "agent_type": agent_type},
        agent_type=agent_type, content_source="user", skip_semantic=True,
    )


def _direct(result):
    return [f for f in result.findings if f.category == CATEGORY]


def test_direct_api_label_alone_is_observation_not_security_finding():
    for policy in (None, "audit"):
        engine = SecurityEngine()
        if policy:
            engine.load_policies(_policy(policy))
        result = _check(engine, "帮我看下这个函数为什么返回空")
        direct = _direct(result)
        assert len(direct) == 1
        assert direct[0].counts_as_security_finding is False
        assert direct[0].action == "allow"
        assert direct[0].triage["disposition_reason"] == "agent_inventory_metadata"
        assert result.action == "allow"
        assert not any(f.counts_as_security_finding for f in result.findings)


def test_direct_api_label_does_not_swallow_real_high_risk():
    engine = SecurityEngine()
    engine.load_policies(_policy("audit"))
    result = _check(engine, HIGH_RISK)
    counted = [f for f in result.findings if f.counts_as_security_finding]
    assert counted, "高危命中必须照常计入安全发现"
    assert any(f.severity in {"high", "critical"} for f in counted)
    assert all(f.category != CATEGORY for f in counted)
    assert result.action == "audit"
    assert _direct(result)[0].counts_as_security_finding is False


def test_customer_block_policy_on_direct_api_still_enforces():
    engine = SecurityEngine()
    engine.audit_only = False
    engine.load_policies(_policy("block"))
    result = _check(engine, "hello")
    assert result.action == "block"
    assert _direct(result)[0].counts_as_security_finding is not False


def test_long_session_context_unchanged():
    result = SecurityEngine().check_input(
        "req-long", "hello", context={"message_index": 120}, skip_semantic=True,
    )
    assert any(f.category == "agent_long_session" for f in result.findings)
