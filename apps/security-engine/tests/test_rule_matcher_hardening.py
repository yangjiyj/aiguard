"""规则包 matcher 输入规范化与类型契约的纵深测试。"""

import pytest
from pydantic import ValidationError

# 先导入 engine，避免 custom_rules 的既有模块级实例初始化形成循环导入。
from app.detectors import engine as _engine  # noqa: F401
from app.custom_rules import CompiledRule, CustomRuleSet
from app.rule_pack_loader import parse_rule_pack


def _rule(**overrides) -> CompiledRule:
    values = {
        "rule_id": "rule_matcher",
        "rule_name": "matcher 规则",
        "rule_type": "regex",
        "category": "custom",
        "severity": "high",
        "action": "block",
    }
    values.update(overrides)
    return CompiledRule(**values)


def _packed_rule(**overrides) -> dict:
    values = {
        "rule_id": "rule_matcher",
        "rule_name": "matcher 规则",
        "rule_type": "regex",
        "category": "custom",
        "severity": "high",
        "action": "block",
        "regex": "token-[0-9]+",
    }
    values.update(overrides)
    return values


class TestMatcherNormalization:
    def test_regex_is_stripped_before_compilation(self):
        rule = _rule(regex="  token-[0-9]+  ")

        rules = CustomRuleSet([rule])

        assert rule.regex == "token-[0-9]+"
        assert len(rules.active_rules) == 1
        assert len(rules.match("value=token-123")) == 1

    def test_keywords_are_stripped_and_blank_entries_removed(self):
        rule = _rule(
            rule_type="keyword",
            regex=None,
            keywords=["  Alpha  ", "   ", "\tBeta\n"],
        )

        rules = CustomRuleSet([rule])

        assert rule.keywords == ["Alpha", "Beta"]
        assert len(rules.active_rules) == 1
        assert len(rules.match("contains beta here")) == 1

    def test_field_names_are_stripped_and_blank_entries_removed(self):
        rule = _rule(
            rule_type="field_name",
            regex=None,
            field_names=["  id_card  ", "\t", " password\n"],
        )

        rules = CustomRuleSet([rule])

        assert rule.field_names == ["id_card", "password"]
        assert len(rules.active_rules) == 1
        assert len(rules.match('{"password": "redacted"}')) == 1


class TestBlankMatchersAreSkipped:
    def test_whitespace_only_regex_is_skipped(self):
        rule = _rule(regex=" \t\n ")

        rules = CustomRuleSet([rule])

        assert rules.active_rules == []
        assert [item.rule_id for item in rules.skipped] == ["rule_matcher"]

    def test_whitespace_only_keyword_array_is_skipped(self):
        rule = _rule(rule_type="keyword", regex=None, keywords=[" ", "\t"])

        rules = CustomRuleSet([rule])

        assert rules.active_rules == []
        assert [item.rule_id for item in rules.skipped] == ["rule_matcher"]

    def test_whitespace_only_field_name_array_is_skipped(self):
        rule = _rule(rule_type="field_name", regex=None, field_names=[" ", "\n"])

        rules = CustomRuleSet([rule])

        assert rules.active_rules == []
        assert [item.rule_id for item in rules.skipped] == ["rule_matcher"]


class TestRuleTypeMatcherContract:
    def test_regex_type_without_regex_is_not_loaded(self):
        payload = {"rules": [_packed_rule(regex=None, keywords=["token"])]}

        with pytest.raises(ValueError, match="matcher"):
            parse_rule_pack(payload)


@pytest.mark.parametrize("rule_type", ["keyword", "field_name"])
def test_non_regex_matcher_rejects_mask_action(rule_type):
    matcher = (
        {"keywords": ["secret"]}
        if rule_type == "keyword"
        else {"field_names": ["password"]}
    )
    with pytest.raises(ValidationError):
        _rule(rule_type=rule_type, regex=None, action="mask", **matcher)


@pytest.mark.parametrize(
    "invalid",
    [
        {"enabled": "false"},
        {"unexpected_runtime_switch": True},
    ],
)
def test_compiled_rule_rejects_coercion_and_unknown_fields(invalid):
    with pytest.raises(ValidationError):
        CompiledRule.model_validate({**_packed_rule(), **invalid})

def test_keyword_type_without_keywords_is_not_loaded():
    payload = {
        "rules": [
            _packed_rule(rule_type="keyword", regex="token-[0-9]+", keywords=None)
        ]
    }

    with pytest.raises(ValueError, match="matcher"):
        parse_rule_pack(payload)


def test_field_name_type_without_field_names_is_not_loaded():
    payload = {
        "rules": [
            _packed_rule(
                rule_type="field_name",
                regex="token-[0-9]+",
                field_names=["   "],
            )
        ]
    }

    with pytest.raises(ValueError, match="matcher"):
        parse_rule_pack(payload)


def test_unknown_type_is_not_loaded_even_with_a_matcher():
    payload = {
        "rules": [_packed_rule(rule_type="prompt_injection", keywords=["ignore"])]
    }

    with pytest.raises(ValueError, match="matcher"):
        parse_rule_pack(payload)
