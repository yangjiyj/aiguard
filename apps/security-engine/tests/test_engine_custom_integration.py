"""
P2-1 Layer 2：自定义规则接入 SecurityEngine.check_input 的集成测试。

验证客户 block 规则命中后：
  1) 命中进入统一 findings（带 rule_id / 脱敏 evidence）
  2) 驱动 result.action == "block"（自定义 action 纳入决策）
  3) 空规则集时不破坏既有内置检测（向后兼容）
  4) audit_only 全局降级开关对自定义 block 同样生效（红线：先 audit/alert）

红线：evidence 不得泄漏原文。
"""
import pytest

from app.detectors.engine import SecurityEngine
from app.custom_rules import CompiledRule, CompiledException


def _medical_record_rule() -> CompiledRule:
    return CompiledRule(
        rule_id="rule_med001",
        rule_name="病案号正则",
        rule_type="regex",
        category="custom_medical_record",
        severity="high",
        action="block",
        enabled=True,
        regex=r"病案号[:：]?\s*([A-Za-z]{0,3}\d{6,12})",
    )


class TestCustomRuleIntegration:

    @pytest.mark.parametrize("action", ["allow", "audit", "mask", "block"])
    def test_supported_action_is_preserved_in_finding_and_effective_result(
        self, action
    ):
        engine = SecurityEngine()
        rule = CompiledRule(
            rule_id=f"rule_{action}",
            rule_name=f"runtime {action}",
            rule_type="regex",
            category="custom_runtime_action",
            severity="high",
            action=action,
            enabled=True,
            regex=r"ZZRUNTIME[0-9]+",
        )
        engine.load_custom_rules([rule])

        result = engine.check_input("req-runtime-action", "before ZZRUNTIME123 after")

        finding = next(item for item in result.findings if item.rule_id == rule.rule_id)
        assert finding.action == action
        assert result.action == action
        if action == "mask":
            assert result.masked_content == "before <MASKED> after"
        else:
            assert result.masked_content is None

    def test_block_rule_hit_drives_block_action(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_medical_record_rule()])
        result = engine.check_input("req-1", "患者病案号：BA00123456 已归档")
        assert result.action == "block"
        custom = [f for f in result.findings if f.rule_id == "rule_med001"]
        assert len(custom) == 1
        assert custom[0].type == "custom"
        assert custom[0].action == "block"
        assert custom[0].rule_name == "病案号正则"

    def test_evidence_redacted_in_findings(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_medical_record_rule()])
        result = engine.check_input("req-2", "患者病案号：BA00123456 已归档")
        f = [x for x in result.findings if x.rule_id == "rule_med001"][0]
        assert "BA00123456" not in f.matched_text_preview
        # 2.9.19：命中内容可见。短取值（不足 16 位、前面没有凭据字段名）按“自动”方式原样显示；
        # 旧的“头尾各 2 位 + sha256”打码只保留在 matched_text_preview。
        assert f.redacted_evidence == "BA00123456"
        assert "sha256" not in f.redacted_evidence

    def test_no_custom_rules_preserves_builtin_behavior(self):
        engine = SecurityEngine()
        result = engine.check_input("req-3", "今天天气不错，没有敏感信息")
        assert result.action == "allow"
        assert all(f.type != "custom" for f in result.findings)

    def test_audit_only_downgrades_custom_block(self, monkeypatch):
        monkeypatch.setenv("SECURITY_AUDIT_ONLY", "1")
        engine = SecurityEngine()
        engine.load_custom_rules([_medical_record_rule()])
        result = engine.check_input("req-4", "患者病案号：BA00123456")
        assert result.action == "audit"

    def test_disabled_custom_rule_not_loaded(self):
        rule = _medical_record_rule()
        rule.enabled = False
        engine = SecurityEngine()
        engine.load_custom_rules([rule])
        result = engine.check_input("req-5", "患者病案号：BA00123456")
        assert all(f.rule_id != "rule_med001" for f in result.findings)
        assert result.action == "allow"


def _private_key_rule(action: str = "block") -> CompiledRule:
    """高危规则：私钥外发，命中后保留 high_risk 标记。"""
    return CompiledRule(
        rule_id="rule_pk001",
        rule_name="私钥外发",
        rule_type="regex",
        category="private_key",
        severity="critical",
        action=action,
        enabled=True,
        regex=r"HF-PRIVATE-KEY-[0-9]+",
    )


class TestContentExceptionIntegration:
    """P2-3：例外规则经 SecurityEngine 端到端降级，客户显式动作优先。"""

    def test_exception_downgrades_custom_block_to_audit(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_medical_record_rule()])
        engine.load_content_audit_exceptions(
            [
                CompiledException(
                    exception_id="exc1",
                    scope_type="rule",
                    rule_id="rule_med001",
                    decision="audit",
                    reason="业务确认误报",
                )
            ]
        )
        result = engine.check_input("req-exc-1", "患者病案号：BA00123456 已归档")
        f = [x for x in result.findings if x.rule_id == "rule_med001"][0]
        assert f.action == "audit"
        assert f.exception_id == "exc1"
        assert result.action == "audit"

    def test_no_exception_keeps_block(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_medical_record_rule()])
        engine.load_content_audit_exceptions([])
        result = engine.check_input("req-exc-2", "患者病案号：BA00123456 已归档")
        f = [x for x in result.findings if x.rule_id == "rule_med001"][0]
        assert f.action == "block"
        assert f.exception_id == ""
        assert result.action == "block"

    @pytest.mark.parametrize("category,content", [
        ("openai_key", "部署脚本里的 key：sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
        ("id_card_cn", "身份证号 110101199003077777 用于登记"),
    ])
    def test_exception_releases_policy_blocked_credential_and_identity(self, category, content):
        # 2.9.22（设计 5.4）：凭据、证件号配成阻断后，管理员按命中规则建的例外照样生效。
        from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

        engine = SecurityEngine()
        engine.load_policies(PolicySet([CompiledPolicy(
            policy_code="tenant.cred.block", policy_id="policy.cred.block",
            policy_name="凭据与证件号阻断", policy_type="scene_policy", scene="data_leak",
            action="block", enabled=True, binding_mode="any",
            capabilities=[CompiledPolicyCapability(
                category=category, supported_stages=["input", "output"],
                allowed_actions=["audit", "block"], mask_capable=False,
            )],
        )]))
        blocked = engine.check_input("req-exc-cred-0", content)
        hit = [f for f in blocked.findings if f.policy_code == "tenant.cred.block"]
        assert blocked.action == "block" and hit and hit[0].cannot_downgrade()

        engine.load_content_audit_exceptions([CompiledException(
            exception_id="exc-cred", scope_type="rule", rule_id=hit[0].rule_id,
            decision="audit", reason="测试数据，确认误报",
        )])
        released = engine.check_input("req-exc-cred-1", content)
        exempted = [f for f in released.findings if f.exception_id == "exc-cred"]
        assert released.action == "audit"
        assert exempted and exempted[0].action == "audit"
