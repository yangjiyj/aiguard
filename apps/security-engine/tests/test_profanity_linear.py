"""辱骂脏话检测的耗时回归与等价性用例。

2.9.19 起就有的遗留问题：每处命中都从文首找所在句，整句再跑第二人称、转给他人两条正则，白名单区间和
引号也是每处从头逐个比，同一脏话重复上万次时是平方级。修复前 home 实测：“傻逼”2 万字 8.6 秒、
4 万字 31 秒、12 万字 256 秒，“操你妈”12 万字 44 秒。

修复只换算法、不改判定：句界按位置索引查找；白名单区间、引号按起点二分；讨论线索按句缓存；先看有没有
引用或讨论线索，有才查第二人称和转给他人；这两条每句只找一次匹配，每处命中只看命中前后。
下方差分用例与原写法逐个对拍。
"""
import random
import re
import time

import pytest

from app.detectors.content_safety import ContentSafetyDetector
from app.detectors.evidence_context import SentenceIndex, sentence
from app.detectors.profanity import ProfanityDetector, _Hit, _MatchOutside

# 与 test_catalog_review4_cs 一致。
CPU_LIMIT_SECONDS = 1.5
RULE = "content_safety_profanity_abuse"


@pytest.fixture(scope="module")
def detector():
    return ContentSafetyDetector()


@pytest.fixture(scope="module")
def profanity():
    return ProfanityDetector()


def _cpu_seconds(detect, text):
    start = time.process_time()
    findings = detect(text)
    return time.process_time() - start, findings


@pytest.mark.parametrize("unit, repeat", [
    ("傻逼", 50_000),                    # 10 万字没有句读、没有讨论线索
    ("傻逼", 100_000),                   # 20 万字
    ("傻逼。", 40_000),                  # 12 万字短句
    ("脏话：傻逼", 20_000),              # 每处都算讨论，要查同句有没有“你”、有没有“骂某人”
    ("脏话：傻逼  ", 15_000),            # 命中前后夹着空白
    ("脏话：骂傻逼", 17_000),            # “骂”紧挨命中
    ("比如：傻逼，词库", 13_000),        # 举例说法，要看同句有没有讨论线索
    ("“傻逼”这个词是脏话，", 10_000),   # 引号里的讨论，每处都要找所在引号
    ("“傻逼”是脏话，发给张三。", 9_000),
    ("你他妈的 ", 20_000),
    ("操你妈", 34_000),
    ("家畜生产", 25_000),                # 白名单区间和命中一样多
])
def test_profanity_detect_cpu_is_bounded_on_long_repeated_text(detector, unit, repeat):
    text = unit * repeat
    assert len(text) >= 100_000
    seconds, _ = _cpu_seconds(detector.detect, text)
    assert seconds < CPU_LIMIT_SECONDS, f"{unit!r} x{repeat} 单次 detect 用了 {seconds:.2f} 秒 CPU"


# 长文本里每处都要照常判断：计数、第一处、最后一处真骂人都不能因为提速变

def test_last_insult_after_long_discussion_counts(profanity):
    text = "脏话：傻逼。" * 20_000 + "你就是个傻逼"
    seconds, findings = _cpu_seconds(profanity.detect, text)
    assert len(findings) == 1 and findings[0]["counts_as_security_finding"] is True
    start = text.rindex("傻逼")
    assert findings[0]["matched_location"] == f"content[{start}:{start + 2}]"
    assert findings[0]["evidence_reason"] == "强辱骂词直接命中"
    assert seconds < CPU_LIMIT_SECONDS


def test_second_person_at_the_end_of_one_long_sentence_counts_every_hit(profanity):
    text = "脏话：傻逼，" * 20_000 + "你"
    seconds, findings = _cpu_seconds(profanity.detect, text)
    assert len(findings) == 1 and findings[0]["counts_as_security_finding"] is True
    assert findings[0]["matched_location"] == "content[3:5]"
    assert findings[0]["evidence_reason"] == "强辱骂词直接命中，共 20000 处"
    assert seconds < CPU_LIMIT_SECONDS


@pytest.mark.parametrize("tail, counted", [("发给张三。", True), ("。", False)])
def test_forwarding_cancels_quoted_discussion_on_long_text(profanity, tail, counted):
    text = "“傻逼”是脏话，" + tail
    text = text * 9_000
    seconds, findings = _cpu_seconds(profanity.detect, text)
    assert len(findings) == 1 and findings[0]["counts_as_security_finding"] is counted
    assert findings[0]["matched_location"] == "content[1:3]"
    assert findings[0]["evidence_reason"] == ("强辱骂词直接命中，共 9000 处" if counted
                                              else "局部上下文仅支持引用/讨论线索：quoted_profanity_reference")
    assert seconds < CPU_LIMIT_SECONDS


# 等价性：新写法与原写法逐个对拍

_PIECES = ["你", "您", "妳", "骂", "人", "词", "话", "的", "声", "发", "给", "转", "送", "传", "私信", "回复", "张", "三",
           "a", "Z", "1", " ", "  ", "\t", "　", " ", "傻逼", "，", "。", "！", "\n", "：", "“", "”"]


def _random_text(rng, pieces, length):
    return "".join(rng.choice(pieces) for _ in range(length))


def _search_outside_by_slicing(pattern, content, start, end):
    """原写法：所在句去掉这一段、换成空格后再搜。"""
    local, a, b = sentence(content, start, end)
    return bool(pattern.search(local[:a] + " " + local[b:]))


@pytest.mark.parametrize("name, kind", [("second_person_re", "char"), ("forward_re", "head")])
def test_lexicon_patterns_use_the_fast_path(profanity, name, kind):
    # 词表改了这两条写法，这里会失败：快速判断只认词表现有的写法，改写法要一并核对快速判断
    assert _MatchOutside(getattr(profanity.lexicon, name), "", SentenceIndex("")).kind == kind


def _assert_matches_slicing(pattern, seed):
    rng = random.Random(seed)
    pieces = _PIECES + ["脏话：", "比如", "翻译"]
    for _ in range(600):
        text = _random_text(rng, pieces, rng.randint(1, 60))
        outside = _MatchOutside(pattern, text, SentenceIndex(text))
        for _ in range(12):
            start = rng.randint(0, len(text) - 1)
            end = min(len(text), start + rng.randint(1, 4))
            expected = _search_outside_by_slicing(pattern, text, start, end)
            assert outside(start, end) == expected, (text, start, end)


@pytest.mark.parametrize("name", ["second_person_re", "forward_re", "bare_before_re", "cue_re"])
def test_match_outside_span_matches_slicing_the_sentence(profanity, name):
    _assert_matches_slicing(getattr(profanity.lexicon, name), name)


@pytest.mark.parametrize("source", ["[你 ]", "[a-z三]"])
def test_other_character_classes_match_slicing_the_sentence(source):
    # 字符类含空格时，换上去的空格本身就算匹配
    pattern = re.compile(source)
    assert _MatchOutside(pattern, "", SentenceIndex("")).kind == "char"
    _assert_matches_slicing(pattern, source)


def _allowed_by_scanning(lexicon, norm, allow_spans, hit):
    """原写法：逐个比白名单区间。"""
    for a, b in allow_spans:
        if not (a <= hit.start and hit.end <= b):
            continue
        if lexicon.allow_keep_after_re is not None and lexicon.allow_keep_after_re.match(norm[b:b + 8]):
            return True
        if hit.tier == "strong":
            if lexicon.allow_void_re is not None and lexicon.allow_void_re.search(norm[max(0, hit.start - 8):hit.start]):
                continue
            if lexicon.allow_void_after_re is not None and lexicon.allow_void_after_re.match(norm[b:b + 8]):
                continue
        return True
    return False


def test_allow_lookup_matches_scanning_every_span(profanity):
    lexicon = profanity.lexicon
    rng = random.Random(5)
    pieces = ["家畜生", "畜生", "畜生产", "畜生道", "牲畜生", "你", "全家", "滚", "算了", "吧", "病", "产", "废物",
              "废物利用", "垃圾", "垃圾分类", "傻瓜", "傻瓜相机", "字", "，"]
    for _ in range(400):
        norm = _random_text(rng, pieces, rng.randint(1, 40))
        spans = [(m.start(), m.end()) for m in lexicon.allow_re.finditer(norm)]
        allow = profanity._allow_lookup(norm, spans)
        hits = profanity._strong_hits(norm) + profanity._weak_hits(norm)
        hits += [_Hit("strong", s, min(len(norm), s + rng.randint(1, 3)), "strong") for s in range(len(norm))]
        for hit in hits:
            assert allow(hit) == _allowed_by_scanning(lexicon, norm, spans, hit), (norm, hit)
