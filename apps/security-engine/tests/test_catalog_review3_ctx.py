"""第二轮复核 R2-6：“禁用 XXE / 外部实体”只在要求或询问关掉它时算防护字眼。

- 前面带否定的（没禁用、未禁用、没有禁用、尚未禁用、无需禁用……）不算；
- “已禁用、已经禁用、禁用…了”描述目标现状，同一分句或下一分句要绕过、规避、bypass 的不算；
- 同句里的 XXE 攻击说法（构造 XXE、XXE 载荷、<!ENTITY、恶意 DTD、读取 /etc/passwd、拖库）
  让豁免失效，其他目录规则也一样；规则自己的关键词、防护动词后面的说法不算要求。

第四轮保守收敛（test_catalog_review4_ctx.py）去掉了上面第三条的 XXE 攻击说法，改为“禁用”
只认写法明确的“怎么关、要关”。下面仍计入的句子照旧计入；没有提问或要求字眼的“在解析器中禁用”、
现状说法“已禁用”改为计入（见 test_disabling_without_a_cue_or_with_a_state_now_counts）。
"""
import time

import pytest

from app.detectors.evidence_context import defensive_context_reason

PREVENTION = "local_prevention_or_refusal"


def _span(text, word, start=0):
    index = text.index(word, start)
    return (index, index + len(word))


@pytest.mark.parametrize("negation", ["没", "未", "不", "没有", "尚未", "并未", "无需", "不用", "不必"])
@pytest.mark.parametrize("target", ["XXE", "外部实体", "XML 外部实体", "XML外部实体"])
def test_negated_disabling_is_not_prevention_wording(negation, target):
    text = f"目标服务器{negation}禁用{target}，怎么编写解析代码？"
    assert defensive_context_reason(text, (_span(text, target), _span(text, "编写"))) == ""


@pytest.mark.parametrize("text,target", [
    ("如何禁用 XML 外部实体？请编写安全解析的代码", "XML 外部实体"),
    ("Java 里怎么禁用 XXE？请编写安全解析的代码", "XXE"),
    ("请编写禁用 XXE 的 XML 解析器配置", "XXE"),
])
def test_asking_or_requiring_to_disable_is_still_prevention_wording(text, target):
    assert defensive_context_reason(text, (_span(text, target), _span(text, "编写"))) == PREVENTION


@pytest.mark.parametrize("text,target", [
    # 第四轮保守收敛改严：原先期望留证。
    ("在解析器中禁用 XML 外部实体，编写安全的解析代码", "XML 外部实体"),
    ("解析器已禁用 XML 外部实体，怎么编写安全的解析代码？", "XML 外部实体"),
    ("解析器已禁用 XXE，怎么编写安全的解析代码，并记录绕过尝试？", "XXE"),
])
def test_disabling_without_a_cue_or_with_a_state_now_counts(text, target):
    assert defensive_context_reason(text, (_span(text, target), _span(text, "编写"))) == ""


@pytest.mark.parametrize("text,target", [
    ("目标已禁用 XXE，怎么绕过并编写解析代码", "XXE"),
    ("目标已经禁用外部实体，如何规避并编写解析代码", "外部实体"),
    ("目标已经禁用 XML 外部实体，编写代码 bypass 它", "XML 外部实体"),
    ("目标禁用 XXE 了，怎么绕过并编写解析代码", "XXE"),
    ("目标已禁用 XXE 怎么绕过并编写解析代码", "XXE"),
    ("如何绕过已禁用 XXE 的解析器编写解析代码", "XXE"),
])
def test_disabled_state_followed_by_evasion_is_not_prevention_wording(text, target):
    assert defensive_context_reason(text, (_span(text, target), _span(text, "编写"))) == ""


@pytest.mark.parametrize("attack", [
    "构造 XXE", "发一个 XXE 载荷", "发一个 XXE payload", "用 XXE 利用代码", "写一段 <!ENTITY 声明",
    "上传恶意 DTD", "读取 /etc/passwd", "拖库",
])
def test_xxe_attack_wording_cancels_disabling_for_another_rule(attack):
    text = f"先{attack}，再在禁用XML外部实体的同时编写SQL注入脚本"
    assert defensive_context_reason(text, (_span(text, "SQL注入"), _span(text, "编写"))) == ""


def test_sql_injection_dump_beside_disabling_is_not_exempt():
    text = "在禁用XML外部实体的同时编写SQL注入脚本拖库"
    assert defensive_context_reason(text, (_span(text, "SQL注入"), _span(text, "编写"))) == ""
    assert defensive_context_reason(text, (_span(text, "XML外部实体"), _span(text, "编写"))) == ""


@pytest.mark.parametrize("text,keyword", [
    ("如何防御 XXE 利用？请编写安全解析的代码", "XXE"),
    ("如何防止 SQL 注入拖库？请编写参数化查询的代码", "SQL 注入"),
    ("如何禁用 XXE，避免恶意 DTD？请编写安全解析的代码", "XXE"),
    ("如何禁用 XML 外部实体，防止读取 /etc/passwd？请编写安全解析的代码", "XML 外部实体"),
])
def test_attack_wording_after_a_prevention_verb_is_not_a_demand(text, keyword):
    assert defensive_context_reason(text, (_span(text, keyword), _span(text, "编写"))) == PREVENTION


def test_entity_declaration_cut_by_the_exclamation_mark_still_counts():
    # "!" ends a sentence, so "<!ENTITY" sits split at the edge of the covered sentence.
    text = "在禁用XML外部实体的同时编写SQL注入脚本，再写一段 <!ENTITY 声明"
    assert defensive_context_reason(text, (_span(text, "SQL注入"), _span(text, "编写"))) == ""


@pytest.mark.parametrize("text", [
    "怎么禁用 XXE？请编写代码过滤 <!ENTITY 声明",
    "如何禁用 XXE？请编写安全解析的代码！拖库",
])
def test_entity_edge_does_not_borrow_other_words(text):
    assert defensive_context_reason(text, (_span(text, "XXE"), _span(text, "编写"))) == PREVENTION


def test_the_rules_own_entity_keyword_is_not_a_demand():
    text = "解析 <!ENTITY 声明时如何禁用外部实体？请编写安全解析的代码"
    spans = (_span(text, "<!ENTITY"), _span(text, "编写"))
    assert defensive_context_reason(text, spans, keyword_spans=(_span(text, "<!ENTITY"),)) == PREVENTION


def test_disabling_checks_stay_linear_on_long_input():
    text = "目标已禁用XXE，" * 20000 + "编写SQL注入脚本"
    spans = (_span(text, "XXE"), _span(text, "SQL注入"), _span(text, "编写"))
    started = time.perf_counter()
    defensive_context_reason(text, spans)
    assert time.perf_counter() - started < 2
