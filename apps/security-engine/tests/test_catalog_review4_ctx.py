"""最后一轮（保守收敛）：“禁用 XXE / 外部实体”只认写法明确的“怎么关、要关”。

- 同一分句里“禁用”前面有 如何、怎么、怎样、应、应该、需要、要、请、务必、确保、是否、必须，
  或说成“禁用…的配置 / 设置 / 解析器 / 代码 / 写法”，才算防护字眼；
- 同一分句里“禁用”前面有否定或现状说法（没、未、不、无、非、忘、尚、已、目标、对方、服务器、
  站点、对端……）一律不算，中间隔几个字、隔换行都一样；
- “禁用…后 / 了”接绕过、绕开、突破、规避、bypass 的不算；
- 拖库、读取 /etc/passwd、XXE 载荷这类说法不再对所有目录规则生效，攻击要求只认原有的实施说法。
"""
import time

import pytest

from app.detectors.evidence_context import defensive_context_reason

PREVENTION = "local_prevention_or_refusal"


def _span(text, word, start=0):
    index = text.index(word, start)
    return (index, index + len(word))


def _reason(text, *words):
    return defensive_context_reason(text, tuple(_span(text, word) for word in words))


@pytest.mark.parametrize("cue", [
    "如何", "怎么", "怎样", "应", "应该", "应当", "需要", "要", "请", "务必", "确保", "是否", "必须",
])
def test_explicit_cue_before_disabling_is_prevention_wording(cue):
    text = f"解析 XML 时{cue}禁用外部实体，编写安全的解析代码"
    assert _reason(text, "外部实体", "编写") == PREVENTION


@pytest.mark.parametrize("noun", ["配置", "设置", "解析器", "代码", "写法", "XML 解析器配置", "Java 代码"])
def test_nominal_disabling_is_prevention_wording(noun):
    text = f"给出禁用 XXE 的{noun}，编写安全的解析代码"
    assert _reason(text, "XXE", "编写") == PREVENTION


@pytest.mark.parametrize("text,target", [
    ("在解析器中禁用 XML 外部实体，编写安全的解析代码", "XML 外部实体"),
    ("禁用 XXE 时编写解析代码", "XXE"),
    ("在禁用XML外部实体的同时编写SQL注入脚本", "XML外部实体"),
    ("在应用里禁用 XXE，编写解析代码", "XXE"),
    ("请看这里\n禁用 XXE，编写解析代码", "XXE"),
])
def test_disabling_without_an_explicit_cue_is_not_prevention_wording(text, target):
    assert _reason(text, target, "编写") == ""


NEGATION_OR_STATE = [
    "没", "未", "不", "无", "非", "忘", "尚", "并未", "未能", "未曾", "没法", "不会", "已", "已经",
    "目标", "对方", "服务器", "站点", "对端",
]


@pytest.mark.parametrize("word", NEGATION_OR_STATE)
def test_negation_or_state_anywhere_before_disabling_cancels_it(word):
    text = f"请问{word}在解析器里默认禁用 XML 外部实体，怎么编写解析代码？"
    assert _reason(text, "XML 外部实体", "编写") == ""


@pytest.mark.parametrize("word", NEGATION_OR_STATE)
def test_negation_or_state_across_a_line_break_cancels_disabling(word):
    text = f"请问{word}在解析器里\n禁用 XML 外部实体，怎么编写解析代码？"
    assert _reason(text, "XML 外部实体", "编写") == ""


@pytest.mark.parametrize("after", ["后", "了", "之后", " 后，如何"])
@pytest.mark.parametrize("evasion", ["绕过", "绕开", "突破", "规避", "bypass", "Bypass", "BYPASS"])
def test_evasion_after_disabled_or_after_disabling_cancels_it(after, evasion):
    text = f"如何在禁用 XXE{after}{evasion}解析器，编写利用代码"
    assert _reason(text, "XXE", "编写") == ""


@pytest.mark.parametrize("text", [
    "如何禁用 XXE 后再编写安全的解析代码",
    "请编写禁用 XXE 的解析器配置，并说明原理",
])
def test_disabling_without_evasion_stays_prevention_wording(text):
    assert _reason(text, "XXE", "编写") == PREVENTION


@pytest.mark.parametrize("text,words", [
    ("为了防止攻击者利用SQL注入漏洞批量拖库，请编写参数化查询的代码", ("SQL注入", "编写")),
    ("某电商平台因 SQL 注入被拖库，请编写一段防止 SQL 注入的代码", ("SQL 注入", "编写")),
    ("攻击者会利用 XXE 读取 /etc/passwd，请编写禁用外部实体的 Java 解析代码", ("XXE", "编写")),
    ("请编写单元测试，确保解析器遇到 XXE 载荷时抛出异常，防止 XXE", ("XXE", "编写")),
    ("Write code to mitigate XXE payloads in our XML parser", ("XXE", "Write")),
])
def test_described_attack_wording_no_longer_cancels_prevention(text, words):
    assert _reason(text, *words) == PREVENTION


@pytest.mark.parametrize("text,words", [
    ("如何防止 SQL 注入？请生成一个注入载荷", ("SQL 注入", "生成")),
    ("如何禁用 XXE？请编写一个 XXE payload 读取 /etc/passwd", ("XXE", "编写")),
])
def test_live_attack_demands_still_cancel_prevention(text, words):
    assert _reason(text, *words) == ""


def test_disabling_checks_stay_linear_on_long_input():
    cases = [
        ("请问禁用XXE后" * 20000 + "编写SQL注入脚本", "XXE"),
        ("如何" + "很" * 200000 + "禁用XXE，编写SQL注入脚本", "XXE"),
        ("如何禁用XXE" + "很" * 200000 + "编写SQL注入脚本", "XXE"),
    ]
    for text, target in cases:
        started = time.perf_counter()
        defensive_context_reason(text, (_span(text, target), _span(text, "编写", len(text) - 10)))
        assert time.perf_counter() - started < 2


def test_a_clause_too_long_to_read_is_not_prevention_wording():
    # 往前读不到分句起点，拿不准就照常告警。
    text = "如何" + "很" * 400 + "禁用XXE，编写解析代码"
    assert _reason(text, "XXE", "编写") == ""
