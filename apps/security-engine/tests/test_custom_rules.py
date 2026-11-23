"""
P2-1 自定义规则匹配引擎单元测试（方案A：规则编译下发 —— 引擎消费侧）

覆盖范围：
- 客户自定义正则规则命中并产出统一结果模型（rule_id / rule_name / rule_type / action / 脱敏证据 / 命中位置）
- 命中证据必须脱敏，原始敏感值不得完整落入 finding（安全红线）
- 禁用规则不参与匹配
- 干净文本不误报
- ReDoS 灾难性正则在编译期被识别并跳过（坏规则不拖垮整组规则）
"""
import pytest
from app.custom_rules import CompiledRule, CustomRuleSet


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


class TestCustomRegexRule:
    def test_regex_hit_produces_unified_finding(self):
        rs = CustomRuleSet([_medical_record_rule()])
        findings = rs.match("患者病案号：BA00123456 已归档")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "rule_med001"
        assert f.rule_name == "病案号正则"
        assert f.rule_type == "regex"
        assert f.action == "block"
        assert f.severity == "high"
        assert f.category == "custom_medical_record"

    def test_evidence_is_redacted(self):
        """命中证据必须脱敏：原始病案号不得完整出现在 finding 中"""
        rs = CustomRuleSet([_medical_record_rule()])
        f = rs.match("患者病案号：BA00123456 已归档")[0]
        assert "BA00123456" not in f.redacted_evidence
        assert "BA00123456" not in f.matched_text_preview
        assert f.redacted_evidence          # 仍要给出可读的脱敏摘要
        assert f.matched_location           # 命中位置要标注（不含原文）

    def test_admin_evidence_keeps_raw_match_separate_from_redacted_summary(self):
        rs = CustomRuleSet([_medical_record_rule()])
        f = rs.match("患者病案号：BA00123456 已归档")[0]
        assert f.raw_evidence == "BA00123456"
        assert f.redacted_evidence != f.raw_evidence

    def test_disabled_rule_skipped(self):
        rule = _medical_record_rule()
        rule.enabled = False
        rs = CustomRuleSet([rule])
        assert rs.match("患者病案号：BA00123456 已归档") == []

    def test_no_false_positive_on_clean_text(self):
        rs = CustomRuleSet([_medical_record_rule()])
        assert rs.match("今天天气不错，没有任何敏感信息") == []

    def test_passport_rule_rejects_lowercase_identifier_like_token(self):
        rule = CompiledRule(
            rule_id="rule_g_passport",
            rule_name="护照号",
            rule_type="regex",
            category="pii_passport",
            severity="high",
            action="audit",
            enabled=True,
            regex=r"(?<![A-Za-z0-9])[EGPSDK]\d{8}(?![A-Za-z0-9])",
        )
        rs = CustomRuleSet([rule])
        assert rs.match("内部标识 d212345654 不应被当作护照号") == []
        assert len(rs.match("护照号 E12345678")) == 1
        assert rs.match("内部标识 XYE12345678Z9 不应被当作护照号") == []


class TestReDoSGuard:
    def test_catastrophic_pattern_skipped_not_crashing(self):
        """嵌套量词等灾难性回溯正则在编译期被识别并跳过，不影响其它规则"""
        bad = CompiledRule(
            rule_id="rule_bad",
            rule_name="恶意正则",
            rule_type="regex",
            category="custom",
            severity="low",
            action="audit",
            regex=r"(a+)+$",
        )
        rs = CustomRuleSet([bad, _medical_record_rule()])
        assert any(s.rule_id == "rule_bad" for s in rs.skipped)
        assert len(rs.active_rules) == 1
        # 整组不抛异常，正常规则仍可命中
        assert len(rs.match("病案号：AB123456")) == 1
