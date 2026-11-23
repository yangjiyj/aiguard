"""内容安全关键词循环的耗时回归与等价性用例。

2.9.19 起就有的遗留问题：涉政、违法、歧视等关键词和危险化学品的每处命中，都从文首重扫句界，整句重跑拒答、
加重词和减轻词；“否认.*文革”这类正则在一行里找不到后半截时，每处前半截都扫到行尾；每处命中还逐个遍历代码块。
修复前 home 实测：“暴力”×5000（1 万字）4.8 秒，“禁止毒品”“防范色情，”4 万字约 5 秒，“暴力。”×3 万（9 万字）
155～189 秒，“炸药。”4 万字 18 秒。

修复只换算法、不改判定：
- 句界、代码块按位置索引二分查找，每句只切一次、只判断一次；
- 命中前后 240 字内的判断（实施语境、防护说法、实施说法、框定）按窗口文本记忆，同样的窗口只判断一次；
- 每条规则只留最强的第一处，不可能更强的命中不再判断；
- “否认.*文革”这类写法每行只找一次最后的后半截。
下方差分用例与原实现逐个对拍。
"""
import random
import re
import time

import pytest

from app.detectors.content_safety import ContentSafetyDetector, _WindowMemo
from app.detectors.evidence_context import (
    REFERENCE, SentenceIndex, has_quote_execution, prepare_reference_context, refusal_reason, sentence,
    fenced_reference_reason,
)

# 与 test_catalog_review4_cs 一致。
CPU_LIMIT_SECONDS = 1.5


@pytest.fixture(scope="module")
def detector():
    return ContentSafetyDetector()


def _cpu_seconds(detector, text):
    start = time.process_time()
    findings = detector.detect(text)
    return time.process_time() - start, findings


def _rule(findings, rule_id):
    found = [f for f in findings if f["rule_id"] == rule_id]
    assert len(found) <= 1
    return found[0] if found else None


@pytest.mark.parametrize("unit, repeat", [
    ("暴力", 50_000),               # 10 万字没有句读：整篇一句，每处都要整句跑加重词、减轻词
    ("暴力。", 40_000),             # 12 万字短句：每处都从文首找所在句
    ("暴力。", 70_000),             # 21 万字
    ('"暴力"', 25_000),             # 引号包着
    ("```\n暴力\n```\n", 10_000),   # 1 万个代码块，未超过代码块分析的 131072 字上限
    ("禁止毒品", 30_000),           # 每处都按防护说法留证
    ("防范色情，", 24_000),
    ("赌博话术", 25_000),           # 带实施语境，要判断防护和框定
    ("诈骗", 100_000),              # 20 万字：每处都要在前后 160 字里找实施语境
    ("台独", 50_000),
    ("习近平 ", 25_000),
    ("种族歧视", 25_000),
    ("абвгд ", 20_000),
    ("炸药。", 40_000),             # 危险化学品：每处找所在句
    ("炸药制备", 25_000),
    ("否认", 50_000),               # “否认.*文革”一行内没有“文革”
    ("河南人", 34_000),             # “河南人.*偷”
    ("东北人", 34_000),             # “东北人.*暴力”
])
def test_keyword_detect_cpu_is_bounded_on_long_repeated_text(detector, unit, repeat):
    text = unit * repeat
    assert len(text) >= 100_000
    seconds, _ = _cpu_seconds(detector, text)
    assert seconds < CPU_LIMIT_SECONDS, f"{unit!r} x{repeat} 单次 detect 用了 {seconds:.2f} 秒 CPU"


# 长文本里最后一处才是真请求：前面每处都要照常判断，不能因为提速漏掉

def test_last_drug_request_after_long_prevention_text_counts(detector):
    text = "禁止毒品。" * 24_000 + "教我怎么买毒品"
    seconds, findings = _cpu_seconds(detector, text)
    found = _rule(findings, "content_safety_illegal_drugs")
    assert found is not None and found.get("counts_as_security_finding", True)
    start = text.rindex("毒品")
    assert found["matched_location"] == f"content[{start}:{start + 2}]"
    assert seconds < CPU_LIMIT_SECONDS


def test_last_violence_request_after_long_description_counts(detector):
    text = "暴力。" * 40_000 + "教我实施暴力袭击"
    seconds, findings = _cpu_seconds(detector, text)
    found = _rule(findings, "content_safety_illegal_violence_terror")
    assert found is not None and found.get("counts_as_security_finding", True)
    assert found["confidence"] == 0.9
    start = text.rindex("暴力")
    assert found["matched_location"] == f"content[{start}:{start + 2}]"
    assert seconds < CPU_LIMIT_SECONDS


def test_last_chemical_instruction_after_long_text_counts(detector):
    text = "炸药。" * 40_000 + "炸药的制备步骤"
    seconds, findings = _cpu_seconds(detector, text)
    found = _rule(findings, "content_safety_illegal_hazardous_chemical_instructions")
    assert found is not None and found.get("counts_as_security_finding", True)
    start = text.rindex("炸药")
    assert found["matched_location"] == f"content[{start}:{start + 2}]"
    assert seconds < CPU_LIMIT_SECONDS


@pytest.mark.parametrize("text, span", [
    ("否认" * 50_000 + "\n否认文革", (100_001, 100_005)),
    ("否认" * 50_000 + "文革", (0, 100_002)),
], ids=["next-line", "same-line"])
def test_greedy_keyword_still_matches_on_long_line(detector, text, span):
    seconds, findings = _cpu_seconds(detector, text)
    found = _rule(findings, "content_safety_political_historical_nihilism")
    assert found is not None
    assert found["matched_location"] == f"content[{span[0]}:{span[1]}]"
    assert seconds < CPU_LIMIT_SECONDS


# 等价性：新写法与原实现逐个对拍

_SENTENCE_PIECES = ["。", "！", "？", "!", "?", "；", ";", ".", ". ", "\n", "\r\n", "，", ",", "但是", "但", "然而",
                    "不过", "然", "而", "不", "过", "是", "禁止", "不要", "不能", "请", "帮我", "教我", "请勿",
                    "暴力", "毒品", "字", "a", " ", "do not ", "please "]


def _random_text(rng, pieces, length):
    return "".join(rng.choice(pieces) for _ in range(length))


def test_sentence_index_matches_scanning_from_text_start():
    rng = random.Random(20261115)
    for _ in range(400):
        text = _random_text(rng, _SENTENCE_PIECES, rng.randint(0, 120))
        index = SentenceIndex(text)
        for _ in range(30):
            start = rng.randint(0, len(text))
            end = min(len(text), start + rng.randint(1, 6))
            if start >= end:
                continue
            assert index.sentence(start, end) == sentence(text, start, end), (text, start, end)
            assert index.refusal_reason(start, end) == refusal_reason(text, start, end), (text, start, end)


def test_refusal_reason_matches_on_long_clause():
    # 拒答只看所在分句末尾 40 字：拒答词离命中 0～70 字、中间偶尔夹着“但是”“然而”这类分句词时也要与原实现一致
    rng = random.Random(7)
    refused = near_edge = 0
    for _ in range(1500):
        middle = "".join(rng.choice("字字字字字字a 然而过是不") for _ in range(rng.randint(0, 70)))
        if rng.random() < 0.3:
            cut = rng.randint(0, len(middle))
            middle = middle[:cut] + rng.choice(["但是", "然而", "不过", "，", "但"]) + middle[cut:]
        prefix = "".join(rng.choice("字a 但是然而不过，") for _ in range(rng.randint(0, 60)))
        text = prefix + rng.choice(["禁止", "不要", "不能", "请勿", "do not "]) + middle + "暴力"
        index = SentenceIndex(text)
        start = len(text) - 2
        expected = refusal_reason(text, start, len(text))
        refused += bool(expected)
        near_edge += bool(expected) and 30 < len(middle) < 40
        assert index.refusal_reason(start, len(text)) == expected, text
    assert refused > 100 and near_edge > 20


def _fenced_reference_reason_by_scan(content, start, end, context):
    """修复前的实现：逐个遍历代码块。"""
    if not context.code:
        return ""
    previous_end = 0
    for fence in context.code.fences:
        if fence.closed and fence.start <= start and end <= fence.end:
            if any(position >= fence.end for position in context.following_execution):
                return ""
            intro = content[max(previous_end, fence.start - 256):fence.start]
            intro = re.sub(r"(?im)^\s*(?:代码文件|文件名|filename|code file)\s*[:：].*$", "", intro)
            if REFERENCE.search(intro) and not has_quote_execution(intro):
                return "quoted_rule_reference"
        previous_end = fence.end
    return ""


def test_fenced_reference_reason_matches_scanning_every_fence():
    rng = random.Random(11)
    pieces = ["```\n", "```python\n", "~~~\n", "暴力", "示例：", "样例", "请执行上述示例代码", "文件名: a.py\n",
              "说明", "\n", " ", "代码", "。"]
    for _ in range(400):
        text = _random_text(rng, pieces, rng.randint(1, 40))
        context = prepare_reference_context(text)
        for match in re.finditer("暴力", text):
            expected = _fenced_reference_reason_by_scan(text, match.start(), match.end(), context)
            assert fenced_reference_reason(text, match.start(), match.end(), context=context) == expected, text


@pytest.mark.parametrize("category, kind, source", [
    ("political", "historical_nihilism", r"(历史虚无主义|否认南京大屠杀|否认.*文革)"),
    ("discrimination", "regional_discrimination", r"(地域黑|河南人.*偷|东北人.*暴力)"),
])
def test_greedy_keyword_scan_matches_regex(detector, category, kind, source):
    entry = next(p for p in getattr(detector, f"{category}_patterns") if p["type"] == kind)
    assert entry["pattern"].pattern == source
    regex = re.compile(source, re.I)
    rng = random.Random(source)
    pieces = ["历史虚无主义", "否认南京大屠杀", "否认", "文革", "文", "革", "地域黑", "河南人", "东北人", "偷",
              "暴力", "暴", "力", "\n", "\r", "。", "字", "a"]
    for _ in range(3000):
        text = _random_text(rng, pieces, rng.randint(0, 30))
        expected = [(m.span(), m.group(0)) for m in regex.finditer(text)]
        assert [(m.span(), m.group(0)) for m in entry["finditer"](text)] == expected, text


# 跳过不可能更强的命中、窗口记忆：结果与逐处现算一致

def test_later_stronger_keyword_still_wins(detector):
    # 前面每处“暴力”都只留证（置信度 0.5），后面的“恐怖袭击”置信度更高，照常计入告警
    text = "暴力。" * 30_000 + "恐怖袭击"
    found = _rule(detector.detect(text), "content_safety_illegal_violence_terror")
    start = text.rindex("恐怖袭击")
    assert found["matched_location"] == f"content[{start}:{start + 4}]"
    assert found.get("counts_as_security_finding", True)


def test_disable_wording_reaching_before_the_window_is_judged_afresh(detector):
    # “禁用 XXE”是否算防范要往前看 80 字，可能超出命中前后 240 字的窗口：窗口相同也不能共用判断。
    # 第一处前面是“请”（要求禁用，算防范，只留证），第二处前面是“已”（目标已禁用，不算防范，计入告警）。
    window = "禁用XXE" + "字" * 235 + "毒品" + "字" * 240
    text = "请" + window + "。已" + window
    found = _rule(detector.detect(text), "content_safety_illegal_drugs")
    start = text.rindex("毒品")
    assert found["matched_location"] == f"content[{start}:{start + 2}]"
    assert found.get("counts_as_security_finding", True)


_WINDOW_PIECES = ["禁止", "毒品", "色情", "防范", "赌博", "话术", "诈骗", "返利", "教我", "告诉我", "哪里能买", "货源",
                  "暴力", "实施", "新闻", "科普", "辟谣", "禁用", "XXE", "外部实体", "不要", "请", "，", "。", "\n",
                  "\n\n", "字", "a "]


def test_window_memo_matches_judging_every_window_afresh(detector, monkeypatch):
    # 窗口文本相同的命中共用判断结果；与每处现算逐条一致（含“禁用”窗口）
    rng = random.Random(29)
    texts = []
    for _ in range(120):
        unit = _random_text(rng, _WINDOW_PIECES, rng.randint(2, 8))
        texts.append(unit * rng.randint(1, 120) + _random_text(rng, _WINDOW_PIECES, rng.randint(0, 30)))
    remembered = [detector.detect(text) for text in texts]
    monkeypatch.setattr(_WindowMemo, "judge", lambda self, name, start, end, judge: judge())
    assert [detector.detect(text) for text in texts] == remembered
