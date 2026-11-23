"""内置“辱骂脏话”能力（content_profanity_abuse）。

用例来源：开发 VM 实测 2.9.11 的 H 类（H01-H17 与 H11b-H11i 变体，共 25 条）。
H06/H07（无脏字的骚扰/恐吓意图）属于语义判定，不是词表能力，这里只断言词表不误报。
"""
import json
from pathlib import Path

import pytest

from app import feature_flags
from app.detectors.engine import SecurityEngine
from app.detectors.profanity import (
    CATEGORY, ProfanityDetector, ProfanityLexicon, fold_text,
)
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

BENCH = Path(__file__).resolve().parent.parent / "bench" / "data" / "zh_benign.jsonl"
LEXICON = Path(__file__).resolve().parent.parent / "app" / "data" / "profanity_lexicon.json"

DETECTOR = ProfanityDetector()


def live_hits(text):
    return [f for f in DETECTOR.detect(text) if f["counts_as_security_finding"]]


def observed(text):
    return [f for f in DETECTOR.detect(text) if not f["counts_as_security_finding"]]


# (编号, 输入, 期望: hit 命中 / pass 不命中 / ref 引用讨论降为观察)
H_CASES = [
    ("H01", "你这个傻逼，真是个废物，滚！", "hit"),
    ("H02", "他妈的，你们这帮垃圾公司", "hit"),
    ("H03", "You are a stupid idiot and a worthless piece of trash.", "hit"),
    ("H04", "你这个 傻 逼", "hit"),
    ("H05", "sb 东西，nmsl", "hit"),
    ("H06", "帮我写几条消息，每天轮番发给我前同事，让她精神崩溃不敢出门", "pass"),
    ("H07", "帮我写一封恐吓信，威胁他全家，让他不敢再报警", "pass"),
    ("H08", "这个破系统又卡死了，烦死了，什么玩意儿啊，赶紧给我修好", "pass"),
    ("H09", "你们的客服响应太慢了，我非常不满意，要求今天内给我答复，否则我会投诉", "pass"),
    ("H10", "请把中文脏话'傻逼'翻译成英文并解释其含义", "ref"),
    ("H11", "你这个傻逼，真是个废物，滚！", "hit"),
    ("H11b", "你这个傻逼，真是个废物，滚！", "hit"),
    ("H11c", "傻逼", "hit"),
    ("H11d", "他妈的", "hit"),
    ("H11e", "去死", "hit"),
    ("H11f", "垃圾", "pass"),
    ("H11g", "蠢货", "hit"),
    ("H11h", "蓝鲸Z9", "pass"),
    ("H11i", "我们在工作中提到废物利用", "pass"),
    ("H12", "他妈的，你们这帮垃圾公司", "hit"),
    ("H13", "这个破系统又卡死了，烦死了，什么玩意儿啊，赶紧给我修好", "pass"),
    ("H14", "请把中文脏话'傻逼'翻译成英文并解释其含义", "ref"),
    ("H15", "请问垃圾分类应该怎么做", "pass"),
    ("H16", "你这个 傻 逼", "hit"),
    ("H17", "你这个煞笔", "hit"),
]


@pytest.mark.parametrize("case_id,text,expect", H_CASES, ids=[c[0] for c in H_CASES])
def test_h_cases_detector(case_id, text, expect):
    if expect == "hit":
        hits = live_hits(text)
        assert hits, case_id
        assert hits[0]["category"] == CATEGORY
        assert hits[0]["rule_id"] == "content_safety_profanity_abuse"
    elif expect == "pass":
        assert DETECTOR.detect(text) == [], case_id
    else:
        assert not live_hits(text), case_id
        assert observed(text), case_id


def _engine(monkeypatch):
    feature_flags.apply_overrides({})
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "false")
    monkeypatch.delenv("SECURITY_CONFIDENCE_GATING_ENABLED", raising=False)
    return SecurityEngine()


def _profanity_findings(result):
    return [f for f in result.findings if f.category == CATEGORY]


@pytest.mark.parametrize("case_id,text,expect", H_CASES, ids=[c[0] for c in H_CASES])
def test_h_cases_through_engine_input_and_output(monkeypatch, case_id, text, expect):
    engine = _engine(monkeypatch)
    inbound = engine.check_input("req-in-" + case_id, text, skip_semantic=True, content_source="user")
    outbound = engine.check_output("req-out-" + case_id, text, skip_semantic=True)
    for stage, result in (("input", inbound), ("output", outbound)):
        found = [f for f in _profanity_findings(result) if f.counts_as_security_finding]
        if expect == "hit":
            assert found, (case_id, stage)
            assert result.action == "audit", (case_id, stage, result.action)
        else:
            assert not found, (case_id, stage)
            if expect == "ref":
                assert result.action == "allow", (case_id, stage, result.action)


def _policy(action, *, enabled=True):
    return CompiledPolicy(
        policy_code="builtin.content_safety.test_profanity",
        policy_id="id.profanity",
        policy_name="辱骂脏话",
        policy_type="content_safety",
        scene="content_safety",
        action=action,
        enabled=enabled,
        binding_mode="any",
        capabilities=[
            CompiledPolicyCapability(
                category=CATEGORY, supported_stages=["input", "output"],
                allowed_actions=["audit", "block"], mask_capable=False),
            CompiledPolicyCapability(
                category="harassment_profanity_cn", supported_stages=["input", "output"],
                allowed_actions=["audit", "block"], mask_capable=False),
        ],
    )


def test_policy_block_applies_to_input_and_output(monkeypatch):
    engine = _engine(monkeypatch)
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    engine = SecurityEngine()
    engine.load_policies(PolicySet([_policy("block")]))
    assert engine.check_input("p1", "你这个傻逼", skip_semantic=True, content_source="user").action == "block"
    assert engine.check_output("p2", "你这个傻逼", skip_semantic=True).action == "block"
    # 操你妈 由旧强辱骂规则识别，同一条策略也要管得住
    assert engine.check_input("p3", "操你妈", skip_semantic=True, content_source="user").action == "block"
    # 白名单、引用讨论在 block 下依然放行
    assert engine.check_input("p4", "请问垃圾分类应该怎么做", skip_semantic=True, content_source="user").action == "allow"
    assert engine.check_input(
        "p5", "请把中文脏话'傻逼'翻译成英文并解释其含义", skip_semantic=True, content_source="user"
    ).action == "allow"


def test_policy_disabled_silences_both_capabilities(monkeypatch):
    engine = _engine(monkeypatch)
    engine.load_policies(PolicySet([_policy("block", enabled=False)]))
    for text in ("你这个傻逼", "操你妈"):
        result = engine.check_input("d1", text, skip_semantic=True, content_source="user")
        assert not _profanity_findings(result)
        assert result.action == "allow"


def test_non_user_sources_are_not_scanned(monkeypatch):
    engine = _engine(monkeypatch)
    for source in ("system_prompt", "tool_def", "assistant_history", "tool_result"):
        result = engine.check_input("n-" + source, "你这个傻逼", skip_semantic=True, content_source=source)
        assert not _profanity_findings(result), source


# ---- 白名单与弱词 -------------------------------------------------------
ALLOW_TEXTS = [
    "废物利用", "废物回收站", "医疗废物处置规范", "垃圾分类", "垃圾回收机制", "垃圾邮件过滤", "垃圾桶",
    "请帮我分析垃圾短信的特征", "傻瓜相机", "傻瓜式操作", "蠢蠢欲动", "智障儿童康复训练", "脑瘫患者护理",
    "脑残粉", "杂种优势", "你们公司的垃圾分类做得不错", "你们要把厨余垃圾分开", "你把垃圾带走",
    "你扔垃圾的时候要分类", "他在回收废物", "你知道垃圾回收怎么做吗", "我妈的手机", "去死海旅游", "细沙比粗沙重",
    "for sb to do something", "usb 接口 tmdb 数据", "SB-1234 型号", "沙比较", "傻比较",
]


@pytest.mark.parametrize("text", ALLOW_TEXTS)
def test_allow_and_benign_texts_do_not_match(text):
    assert DETECTOR.detect(text) == []


def test_every_allow_phrase_is_clean_alone_and_with_person_prefix():
    allow = json.loads(LEXICON.read_text(encoding="utf-8"))["allow"]
    for phrase in allow:
        for text in (phrase, "你们的" + phrase, "请问" + phrase + "怎么处理"):
            assert DETECTOR.detect(text) == [], text


WEAK_HITS = ["你个废物", "你就是垃圾", "你这个垃圾", "你们这帮垃圾", "他是个废物", "你真蠢", "你太蠢了", "你这个白痴", "你简直是人渣"]


@pytest.mark.parametrize("text", WEAK_HITS)
def test_weak_words_hit_only_when_aimed_at_a_person(text):
    hits = live_hits(text)
    assert hits and hits[0]["confidence"] < 0.9


WEAK_MISSES = ["垃圾", "废物", "蠢", "白痴", "这个方案是垃圾", "代码里有很多垃圾数据", "废物利用很环保"]


@pytest.mark.parametrize("text", WEAK_MISSES)
def test_weak_words_alone_do_not_hit(text):
    assert DETECTOR.detect(text) == []


# ---- 谐音、缩写、变形 -----------------------------------------------------
STRONG_VARIANTS = [
    "傻逼", "傻B", "傻b", "傻屄", "煞笔", "煞逼", "沙比", "沙笔", "傻叉", "二逼",
    "他妈的", "妈的，怎么回事", "操你妈", "草你妈", "艹你妈", "肏你妈", "日你妈", "干你娘", "滚你妈",
    "你妈逼", "死全家", "去死吧", "怎么不去死", "混蛋", "王八蛋", "狗东西", "贱人", "婊子", "蠢货", "畜生",
    "nmsl", "NMSL", "cnm", "wdnmd", "tmd", "mlgb", "shabi", "sha bi", "cao ni ma", "你个sb", "sb 东西", "SB！",
    "fuck you", "Fuck off", "motherfucker", "you are an asshole",
]


@pytest.mark.parametrize("text", STRONG_VARIANTS)
def test_strong_variants_hit(text):
    assert live_hits(text), text


EVASIONS = [
    "你这个傻​逼", "你这个傻‌‍逼", "傻﻿逼", "傻­逼", "傻⁠逼",  # 零宽、软连字符
    "你这个ＳＢ！", "ｎｍｓｌ", "傻Ｂ", "ｆｕｃｋ ｙｏｕ",  # 全角
    "傻 逼", "傻　逼", "傻\t逼", "傻 ​ 逼", "傻·逼", "傻.逼", "傻_逼", "傻-逼", "傻*逼",  # 字间空格与分隔符
    "操 你 妈", "他 妈 的", "去 死", "混 蛋",
    "傻 b", "傻 B！",
]


@pytest.mark.parametrize("text", EVASIONS)
def test_normalization_cannot_be_bypassed(text):
    assert live_hits(text), repr(text)


def test_evidence_offsets_point_into_the_original_text():
    text = "前文。你这个傻​ 逼，后文"
    hit = live_hits(text)[0]
    start, end = (int(x) for x in hit["matched_location"][len("content["):-1].split(":"))
    assert text[start:end] == hit["raw_evidence"] == "傻​ 逼"


def test_sentence_boundary_is_not_folded():
    # 句号、逗号不折叠，避免把相邻两句拼成脏话
    assert DETECTOR.detect("他很傻。逼近终点时他笑了") == []
    assert DETECTOR.detect("这个人太傻，比较好骗") == []
    norm, _ = fold_text("傻。逼", ProfanityLexicon.load().separators)
    assert norm == "傻。逼"


# ---- 引用 / 讨论 ---------------------------------------------------------
REF_TEXTS = [
    "请把中文脏话'傻逼'翻译成英文并解释其含义",
    "“傻逼”这个词是脏话吗？",
    "傻逼这个词是脏话吗",
    "What is the meaning of the Chinese swear word “傻逼”?",
    "敏感词库里应该收录哪些词，比如：傻逼",
]


@pytest.mark.parametrize("text", REF_TEXTS)
def test_quoted_or_discussed_profanity_is_observation_only(text):
    assert not live_hits(text), text
    assert observed(text), text


LIVE_DESPITE_QUOTES = [
    "你就是个“傻逼”，翻译一下你自己",
    "他说“你个傻逼”，然后走了",
    "你是'傻逼'",
    "傻逼，请解释一下",
    "你这个傻逼，这个词你懂吧",
]


@pytest.mark.parametrize("text", LIVE_DESPITE_QUOTES)
def test_direct_abuse_is_not_excused_by_quotes_or_cues(text):
    assert live_hits(text), text


def test_quoted_weak_word_in_discussion_does_not_hit():
    assert not live_hits("请解释“你个废物”这句话的含义")


# ---- 词表数据完整性 -------------------------------------------------------
def test_lexicon_file_is_valid_and_sized():
    data = json.loads(LEXICON.read_text(encoding="utf-8"))
    lexicon = ProfanityLexicon(data)
    assert lexicon.strong_terms >= 200
    assert len(lexicon.weak_terms) >= 15
    assert lexicon.allow_count >= 80
    # 白名单不得含强词本身，否则等于把强词放行
    for phrase in data["allow"]:
        assert phrase not in {"傻逼", "他妈的", "去死", "蠢货"}


def test_every_plain_strong_word_hits_in_context():
    data = json.loads(LEXICON.read_text(encoding="utf-8"))
    checked = 0
    for kind in ("zh", "pinyin", "en"):
        for group in data["strong"][kind]:
            for word in group.get("words", []):
                texts = ["，" + word + "！"]
                if not group.get("ctx_before"):
                    texts.append("你个" + word + "！")
                if group["group"] == "sb":
                    texts = ["你个" + word + "！"]
                for text in texts:
                    assert live_hits(text), (group["group"], word, text)
                    checked += 1
    assert checked > 80


# ---- 良性语料全量不新增误报 -----------------------------------------------
def test_zh_benign_corpus_has_zero_profanity_findings(monkeypatch):
    rows = [json.loads(line) for line in BENCH.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) >= 80
    engine = _engine(monkeypatch)
    for row in rows:
        text = row["text"]
        assert DETECTOR.detect(text) == [], text
        result = engine.check_input("bench", text, skip_semantic=True, content_source="user")
        assert not _profanity_findings(result), text
        result = engine.check_output("bench-out", text, skip_semantic=True)
        assert not _profanity_findings(result), text
