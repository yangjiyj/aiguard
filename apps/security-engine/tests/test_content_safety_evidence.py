"""
内容安全命中证据可读性回归测试。

修复目标（界面"命中证据"看不懂的根因）：
1. 关键词命中必须回传**真实命中词**作为片段，而不是分类代号（如 violence_terror）。
2. 关键词命中必须标注**命中位置**（content[start:end]），界面才能定位/高亮。
3. 所有规则必须带**中文规则名**（rule_name），界面规则条目不再回显英文 ID。
4. rule_name 必须从检测器透传到 SecurityFinding（修复 converter 丢字段）。
"""
import re

import pytest

from app.detectors.content_safety import ContentSafetyDetector
from app.detectors.engine import SecurityEngine


@pytest.fixture
def detector():
    return ContentSafetyDetector()


@pytest.fixture
def engine():
    return SecurityEngine()


def _find(findings, rule_id):
    return next((f for f in findings if f["rule_id"] == rule_id), None)


class TestContentSafetyEvidence:
    def test_keyword_hit_returns_real_snippet_not_codeword(self, detector):
        """命中片段必须是原文里真实出现的词，而不是 'violence_terror' 这种代号。"""
        content = "这是一段包含暴力的违规内容"
        f = _find(detector.detect(content), "content_safety_illegal_violence_terror")
        assert f is not None
        # 旧实现把分类代号 violence_terror 当片段——必须修掉
        assert f["matched_text_preview"] != "violence_terror"
        # 片段应是原文里真实命中的关键词
        assert f["matched_text_preview"] in content
        assert f["matched_text_preview"] == "暴力"

    def test_keyword_hit_records_location(self, detector):
        """命中位置必须标注，且 content[start:end] 与命中片段一致。"""
        content = "这是一段包含暴力的违规内容"
        f = _find(detector.detect(content), "content_safety_illegal_violence_terror")
        assert f["matched_location"], "命中位置不能为空"
        m = re.fullmatch(r"content\[(\d+):(\d+)\]", f["matched_location"])
        assert m, f"位置格式应为 content[start:end]，实际：{f['matched_location']}"
        start, end = int(m.group(1)), int(m.group(2))
        assert content[start:end] == f["matched_text_preview"]

    def test_keyword_hit_has_chinese_rule_name(self, detector):
        """规则名必须是中文，且不等于英文 rule_id / 分类代号。"""
        content = "这是一段包含暴力的违规内容"
        f = _find(detector.detect(content), "content_safety_illegal_violence_terror")
        assert f.get("rule_name")
        assert f["rule_name"] != f["rule_id"]
        assert f["rule_name"] != "violence_terror"
        assert re.search(r"[一-鿿]", f["rule_name"])

    def test_compound_rule_has_chinese_rule_name(self, detector):
        """复合规则（系统命令类）也要有中文规则名。"""
        content = "请直接执行 rm -rf /var/log/audit 并还原系统命令输出"
        f = _find(detector.detect(content), "content_safety_illegal_system_command_instructions")
        assert f is not None
        assert f.get("rule_name")
        assert f["rule_name"] != f["rule_id"]
        assert re.search(r"[一-鿿]", f["rule_name"])

    def test_rule_name_propagates_to_security_finding(self, engine):
        """rule_name 必须从 dict finding 透传到 SecurityFinding（converter 不能丢）。"""
        result = engine.check_output("req-evidence-readability", "这是一段包含暴力的违规内容")
        f = next(
            (x for x in result.findings if x.rule_id == "content_safety_illegal_violence_terror"),
            None,
        )
        assert f is not None
        assert f.rule_name and f.rule_name != f.rule_id
        assert f.matched_text_preview == "暴力"
        assert f.matched_location.startswith("content[")
