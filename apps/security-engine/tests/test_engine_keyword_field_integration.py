"""任务 3.6：护栏关键词/字段名匹配器 —— SecurityEngine 端到端集成规格。

镜像 test_engine_custom_integration.py：经 load_custom_rules → check_input 全链路，
验证 keyword/field_name 规则真正命中并参与 action 裁决（不再被静默跳过）。
content 是 check_input 收到的原始文本（不保证 JSON），故 field_name 走文本级键检测。
"""

import pytest

from app.detectors.engine import SecurityEngine
from app.custom_rules import CompiledRule


# 关键词刻意选「玄武网关」这类租户私有代号，而非「绝密」等通用密级标记：
# 后者会被内置 classified_classified_cn(data_leak) 检测器同时命中，data_leak 属
# reply 可降级类型，引擎据 _should_reply 把 block 降级为 reply(优雅拒答)——那样测的
# 是内置检测器而非自定义关键词链路。租户代号让自定义关键词规则成为唯一命中项，
# 既贴合自定义关键词的真实用途(拦内置不认识的租户专有词)，又能严格断言 action=="block"。
def _keyword_rule(action="block"):
    return CompiledRule(
        rule_id="rule_kw001",
        rule_name="违禁关键词",
        rule_type="keyword",
        category="custom_keyword",
        severity="high",
        action=action,
        enabled=True,
        keywords=["玄武网关"],
    )


def _field_name_rule(action="block"):
    return CompiledRule(
        rule_id="rule_fn001",
        rule_name="敏感字段名",
        rule_type="field_name",
        category="custom_field_name",
        severity="high",
        action=action,
        enabled=True,
        field_names=["id_card"],
    )


class TestEngineKeywordFieldIntegration:
    def test_keyword_rule_blocks_via_check_input(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_keyword_rule()])
        result = engine.check_input("req-kw", "本季度玄武网关项目的对接排期已确定")
        assert result.action == "block"
        assert any(
            f.rule_id == "rule_kw001" and f.rule_type == "keyword" and f.type == "custom"
            for f in result.findings
        )

    def test_field_name_rule_blocks_via_check_input(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_field_name_rule()])
        result = engine.check_input("req-fn", '{"name": "张三", "id_card": "310101199001011234"}')
        assert result.action == "block"
        assert any(
            f.rule_id == "rule_fn001" and f.rule_type == "field_name" and f.type == "custom"
            for f in result.findings
        )

    def test_keyword_evidence_redacted_in_findings(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_keyword_rule()])
        result = engine.check_input("req-kw2", "本季度玄武网关项目的对接排期已确定")
        custom = [f for f in result.findings if f.type == "custom"]
        assert custom
        assert all(f.redacted_evidence for f in custom)

    def test_keyword_clean_text_allows(self):
        engine = SecurityEngine()
        engine.load_custom_rules([_keyword_rule()])
        result = engine.check_input("req-clean", "这是一份普通的公开说明文档")
        assert result.action == "allow"
        assert not any(f.type == "custom" for f in result.findings)

    def test_field_name_no_false_positive_substring(self):
        # field_name=键：含子串但非完整键的文本不应被拦截。
        engine = SecurityEngine()
        engine.load_custom_rules([_field_name_rule()])
        result = engine.check_input("req-sub", "my id_card was lost last week")
        assert not any(f.type == "custom" for f in result.findings)

    @pytest.mark.parametrize(
        ("rule_type", "matcher", "content"),
        [
            ("keyword", {"keywords": ["玄武网关"]}, "玄武网关 secret-value"),
            ("field_name", {"field_names": ["password"]}, 'password: "secret-value"'),
        ],
    )
    def test_unsafe_non_regex_mask_is_forwarded_with_alert(
        self, rule_type, matcher, content
    ):
        # model_construct simulates a legacy producer bypassing the strict DTO.
        # A mask the runtime cannot perform is forwarded and alerted, never
        # escalated to block (only a configured block may interrupt traffic).
        unsafe = CompiledRule.model_construct(
            rule_id="rule_unsafe_mask",
            rule_name="unsafe mask",
            rule_type=rule_type,
            category="custom_unsafe_mask",
            severity="high",
            action="mask",
            enabled=True,
            regex=None,
            keywords=matcher.get("keywords"),
            field_names=matcher.get("field_names"),
            scope={},
        )
        engine = SecurityEngine()
        engine.load_custom_rules([unsafe])

        result = engine.check_input("req-unsafe-mask", content)

        assert result.action == "audit"
        assert result.masked_content is None
        assert any(f.triage.get("mask_unavailable") for f in result.findings)
