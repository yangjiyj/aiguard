r"""任务 3.6：护栏关键词/字段名匹配器（P1-17，支柱⑥）—— CustomRuleSet 单元规格。

现状根因：`CustomRuleSet.__init__` 仅对 rule_type=="regex" 编译，keyword/field_name
直接进 skipped；`match()` 只扫 active_rules → 配的关键词规则被静默跳过（你以为在拦其实没编译）。

设计（串接现有 active_rules / redact_evidence / SecurityFinding 全链路，非新建并行匹配路径）：
在 __init__ 把 keyword/field_name 规则「合成」为 escape 后的字面量正则，复用既有扫描+脱敏+统一 finding。
- keyword 合成 = (?:escape(k)|…) + IGNORECASE（任一子串命中，大小写不敏感，护栏取高召回）。
- field_name 合成 = \b(?:escape(n)|…)["']?\s*[:=] + IGNORECASE（键检测：匹配 `字段名:`/`字段名=`，
  含 JSON "password":、表单 password=、散文 password: x；前导 \b + 尾随分隔符避免
  mypassword/passwordless 误报，区分 field_name=键 与 keyword=裸值）。
合成为字面量正则，本质无 ReDoS，故不套 is_safe_regex 启发式，仅 try/except re.compile 兜语法。
"""

from app.custom_rules import CompiledRule, CustomRuleSet


def _keyword_rule(keywords=None, enabled=True, rule_id="rule_kw001", action="block"):
    return CompiledRule(
        rule_id=rule_id,
        rule_name="违禁关键词",
        rule_type="keyword",
        category="custom_keyword",
        severity="high",
        action=action,
        enabled=enabled,
        keywords=keywords if keywords is not None else ["绝密"],
    )


def _field_name_rule(field_names=None, enabled=True, rule_id="rule_fn001", action="block"):
    return CompiledRule(
        rule_id=rule_id,
        rule_name="敏感字段名",
        rule_type="field_name",
        category="custom_field_name",
        severity="high",
        action=action,
        enabled=enabled,
        field_names=field_names if field_names is not None else ["password"],
    )


class TestCustomKeywordRule:
    def test_keyword_hit_produces_unified_finding(self):
        rs = CustomRuleSet([_keyword_rule(keywords=["绝密"])])
        findings = rs.match("本文件标注为绝密资料，注意保管")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "rule_kw001"
        assert f.rule_name == "违禁关键词"
        assert f.rule_type == "keyword"
        assert f.action == "block"
        assert f.severity == "high"
        assert f.category == "custom_keyword"
        assert f.matched_location

    def test_keyword_case_insensitive(self):
        # 护栏取高召回：关键词匹配大小写不敏感。
        rs = CustomRuleSet([_keyword_rule(keywords=["Confidential"])])
        findings = rs.match("This document is CONFIDENTIAL, handle with care")
        assert len(findings) == 1
        assert findings[0].rule_type == "keyword"

    def test_keyword_multiple_alternatives(self):
        rs = CustomRuleSet([_keyword_rule(keywords=["绝密", "机密", "内部限阅"])])
        assert len(rs.match("此为机密文档")) == 1
        assert len(rs.match("此为内部限阅文档")) == 1
        assert len(rs.match("此为公开文档")) == 0

    def test_keyword_evidence_redacted(self):
        rs = CustomRuleSet([_keyword_rule(keywords=["SECRET_PROJECT_FALCON"])])
        findings = rs.match("代号 SECRET_PROJECT_FALCON 行动即将启动")
        assert len(findings) == 1
        f = findings[0]
        assert "SECRET_PROJECT_FALCON" not in f.redacted_evidence
        assert "SECRET_PROJECT_FALCON" not in f.matched_text_preview
        assert f.redacted_evidence
        assert f.matched_location

    def test_keyword_no_false_positive_on_clean_text(self):
        rs = CustomRuleSet([_keyword_rule(keywords=["绝密"])])
        assert rs.match("这是一份普通的公开说明文档") == []

    def test_keyword_empty_list_skipped(self):
        rule = _keyword_rule(keywords=[])
        rs = CustomRuleSet([rule])
        assert len(rs.active_rules) == 0
        assert any(s.rule_id == "rule_kw001" for s in rs.skipped)
        assert rs.match("任何内容绝密") == []

    def test_disabled_keyword_skipped(self):
        rs = CustomRuleSet([_keyword_rule(keywords=["绝密"], enabled=False)])
        assert len(rs.active_rules) == 0
        assert rs.match("本文件标注为绝密资料") == []


class TestCustomFieldNameRule:
    def test_field_name_json_key_hit(self):
        rs = CustomRuleSet([_field_name_rule(field_names=["password"])])
        findings = rs.match('{"username": "alice", "password": "hunter2"}')
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "rule_fn001"
        assert f.rule_type == "field_name"
        assert f.action == "block"
        assert f.category == "custom_field_name"
        assert f.matched_location

    def test_field_name_form_delimiter(self):
        # 表单/查询串形态：password=...
        rs = CustomRuleSet([_field_name_rule(field_names=["password"])])
        assert len(rs.match("user=alice&password=hunter2&ok=1")) == 1

    def test_field_name_prose_colon(self):
        # 散文形态：id_card: 310101...
        rs = CustomRuleSet([_field_name_rule(field_names=["id_card"], rule_id="rule_fn002")])
        assert len(rs.match("申请人 id_card: 310101199001011234 已登记")) == 1

    def test_field_name_case_insensitive(self):
        rs = CustomRuleSet([_field_name_rule(field_names=["Password"])])
        assert len(rs.match('{"PASSWORD": "x"}')) == 1

    def test_field_name_no_false_positive_on_bare_substring(self):
        # field_name=键（需带分隔符 + 词边界），区别于 keyword=裸值：
        # 以下都不应命中（避免把含子串的普通文本误判为字段出现）。
        rs = CustomRuleSet([_field_name_rule(field_names=["password"])])
        assert rs.match("my password is strong enough") == []   # 无分隔符
        assert rs.match("passwordless login is enabled") == []  # 子串但非完整键
        assert rs.match("mypassword: secret") == []             # 无词边界（前接 my）

    def test_field_name_empty_list_skipped(self):
        rule = _field_name_rule(field_names=[])
        rs = CustomRuleSet([rule])
        assert len(rs.active_rules) == 0
        assert any(s.rule_id == "rule_fn001" for s in rs.skipped)
        assert rs.match('{"password": "x"}') == []
