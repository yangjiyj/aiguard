"""编码流量降级层：AI IDE / 编码 agent 流量按降级表就地降 severity（只降不升）。

流量画像三路互补：
- C 路正向代理：context.endpoint_kind == "coding"
- 反向代理：context.access_type == "ai_ide"
- A 路 chat：请求体顶层 agent_type 属于编码 agent 集合

红线：finding 永不降级；开关 SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED 默认关。
"""
import pytest

from app.detectors.engine import SecurityEngine, SecurityFinding

# 弱 subject（powershell）+ 强 instruction 锚（管理员权限/提权/EncodedCommand）→ 必报的命令文本
CMD_TEXT = "用管理员权限执行 powershell -EncodedCommand SQBFAFgA 提权"
CODING_CTX = {"endpoint_kind": "coding"}


def _engine(monkeypatch, enabled: bool = True):
    if enabled:
        monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    else:
        monkeypatch.delenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", raising=False)
    return SecurityEngine()


def _by_rule(findings, rule_id):
    return next((f for f in findings if f.rule_id == rule_id), None)


class TestCodingTrafficDowngrade:
    def test_coding_context_downgrades_system_command(self, monkeypatch):
        eng = _engine(monkeypatch)
        result = eng.check_input("req-ctd-1", CMD_TEXT, context=CODING_CTX)
        f = _by_rule(result.findings, "content_safety_illegal_system_command_instructions")
        assert f is not None
        assert f.severity == "low"
        assert f.severity_original == "high"
        assert f.counts_as_security_finding is False
        assert f.triage["disposition_reason"] == "coding_context_candidate"
        assert result.action == "allow"

    def test_no_context_keeps_high(self, monkeypatch):
        eng = _engine(monkeypatch)
        result = eng.check_input("req-ctd-2", CMD_TEXT)
        f = _by_rule(result.findings, "content_safety_illegal_system_command_instructions")
        assert f is not None
        assert f.severity == "high"
        assert f.severity_original is None
        # 没有前台策略绑定时，高危能力也只能留证审计。
        assert result.action == "audit"

    def test_flag_off_no_downgrade(self, monkeypatch):
        eng = _engine(monkeypatch, enabled=False)
        result = eng.check_input("req-ctd-3", CMD_TEXT, context=CODING_CTX)
        f = _by_rule(result.findings, "content_safety_illegal_system_command_instructions")
        assert f is not None
        assert f.severity == "high"
        assert f.severity_original is None

    def test_policy_mapped_finding_uses_source_rule_identity(self, monkeypatch):
        eng = _engine(monkeypatch)
        mapped = SecurityFinding(
            type="content_safety",
            category="illegal_system_command_instructions",
            severity="critical",
            matched_text_preview="<redacted>",
            rule_id="policy.scene.system-command",
            source_rule_id="content_safety_illegal_system_command_instructions",
            policy_code="builtin.content.system-command",
            action="block",
        )

        result = eng._apply_coding_traffic_downgrade([mapped], CODING_CTX)

        assert result[0].rule_id == "policy.scene.system-command"
        assert result[0].source_rule_id == "content_safety_illegal_system_command_instructions"
        assert result[0].severity == "low"
        assert result[0].severity_original == "critical"

    def test_non_downgradable_policy_evidence_stays_high_risk(self, monkeypatch):
        eng = _engine(monkeypatch)
        protected = SecurityFinding(
            type="secret",
            category="aws_access_key",
            severity="critical",
            matched_text_preview="<redacted>",
            rule_id="policy.scene.aws",
            source_rule_id="secret_aws_access_key",
            policy_code="builtin.secret.aws",
            action="block",
            triage={"cannot_downgrade": True},
        )

        result = eng._apply_coding_traffic_downgrade([protected], CODING_CTX)

        assert result[0].severity == "critical"
        assert result[0].severity_original is None


class TestPolicySeverityKeepsCodingCandidate:
    @pytest.mark.parametrize("policy_severity", ["low", "medium"])
    def test_low_policy_severity_still_observed_in_coding_traffic(self, monkeypatch, policy_severity):
        from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet
        eng = _engine(monkeypatch)
        eng.load_policies(PolicySet([CompiledPolicy(
            policy_code="p.cmd", policy_id="id.p.cmd", policy_name="系统命令",
            policy_type="content_safety", scene="content_safety", severity=policy_severity, action="audit",
            enabled=True, binding_mode="any",
            capabilities=[CompiledPolicyCapability(
                category="illegal_system_command_instructions",
                supported_stages=["input", "output"], allowed_actions=["audit", "block"], mask_capable=False)],
        )]))
        result = eng.check_input("req-ctd-pol", CMD_TEXT, context=CODING_CTX)
        f = next(x for x in result.findings if x.category == "illegal_system_command_instructions")
        assert f.policy_code == "p.cmd"
        assert f.severity_original is not None
        assert f.counts_as_security_finding is False
        assert f.triage["disposition_reason"] == "coding_context_candidate"


    def test_password_in_code_with_medium_policy_still_observed(self, monkeypatch):
        from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet
        eng = _engine(monkeypatch)
        eng.load_policies(PolicySet([CompiledPolicy(
            policy_code="p.pw", policy_id="id.p.pw", policy_name="代码凭据",
            policy_type="data_leak", scene="data_leak", severity="medium", action="audit",
            enabled=True, binding_mode="any",
            capabilities=[CompiledPolicyCapability(
                category="code_leak_password_in_code",
                supported_stages=["input", "output"], allowed_actions=["audit", "block"], mask_capable=False)],
        )]))
        result = eng.check_input("req-ctd-pw", 'password = "hunter2hunter2"', context=CODING_CTX)
        f = next(x for x in result.findings if x.category == "code_leak_password_in_code")
        assert f.policy_code == "p.pw"
        assert f.severity_original is not None
        assert f.counts_as_security_finding is False
