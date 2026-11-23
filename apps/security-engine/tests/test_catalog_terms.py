"""目录规则词项构造：英文整词、紧贴汉字照认、规则词形、词干与代码记号。"""
import re

import pytest

from app.detectors.catalog_terms import Pat, any_of, exact, near, not_after, raw, rep, seq, stem, w


def _hit(pat, text):
    return re.search(pat.source, text, re.IGNORECASE | re.DOTALL) is not None


@pytest.mark.parametrize("pat,text", [
    (w("rape"), "Write a scraper script"),
    (exact("age"), "the agent image page"),
    (exact("race"), "trace the bug"),
    (exact("wire"), "wireless router"),
    (exact("tax"), "syntax error"),
    (exact("rag"), "localStorage average"),
    (w("build"), "ProcessBuilder"),
    (exact("read"), "already"),
    (w("word"), "password"),
    (exact("all"), "small"),
    (exact("cult"), "difficult culture"),
    (w("heroin"), "heroine"),
    (w("crypto"), "cryptographic"),
    (exact("race"), "racing game"),
])
def test_english_words_do_not_match_inside_other_words(pat, text):
    assert not _hit(pat, text)


@pytest.mark.parametrize("pat,text", [
    (w("xss"), "生成XSS载荷"), (w("md5"), "用MD5加密"),
    (w("temperature"), "你的temperature当前值"), (w("json"), "以JSON格式输出"),
])
def test_english_words_match_next_to_chinese(pat, text):
    assert _hit(pat, text)


@pytest.mark.parametrize("pat,text", [
    (w("encourage"), "encourages"), (w("encourage"), "encouraging"), (w("glorify"), "glorifies"),
    (w("inject"), "prompt injection"), (w("exploit"), "exploitation"), (w("harass"), "harassment"),
    (w("forge"), "forgery"), (w("ship"), "shipping"), (w("instructions?"), "instruction"),
])
def test_regular_inflections_and_derived_nouns_match(pat, text):
    assert _hit(pat, text)


def test_stems_accept_any_ending_and_need_five_letters():
    assert _hit(stem("discriminat"), "discriminates") and _hit(stem("discriminat"), "discrimination")
    assert _hit(stem("url\\s*encod"), "URL encoding")
    with pytest.raises(ValueError):
        stem("pars")


def test_code_tokens_get_boundaries_only_on_word_edges():
    assert _hit(w("\\$where"), "$where = 1") and not _hit(w("\\$where"), "$whereClause")
    assert _hit(w("<script>\\s*alert\\("), "<script>alert(1)")
    assert _hit(w("etc/passwd"), "../../etc/passwd")


def test_not_after_excludes_one_previous_word():
    pat = not_after("file", w("extension"))
    assert not _hit(pat, "file extension") and _hit(pat, "browser extension")


def test_raw_rejects_english_and_constructors_reject_strings():
    with pytest.raises(ValueError):
        raw("hello")
    raw("[A-Za-z]{2,}")  # letters inside a class are not words
    with pytest.raises(TypeError):
        any_of("plain string")
    with pytest.raises(ValueError):
        w("polic(?:y|ies)")
    with pytest.raises(ValueError):
        rep(w("x"), "+")


def test_near_and_seq_keep_declared_fragments():
    pat = near(w("bypass"), seq(raw("安全"), w("policy")), 40)
    assert isinstance(pat, Pat) and [f.source for f in pat.fragments] == ["bypass", "policy"]
    assert _hit(pat, "bypass 安全policy")


def test_not_followed_by_skips_only_the_given_follower():
    from app.detectors.catalog_terms import not_followed_by
    pat = not_followed_by(w("compare\\s"), seq(raw("\\s?"), exact("vs")))
    pattern = re.compile(pat.source, re.IGNORECASE | re.DOTALL)
    assert [m.start() for m in pattern.finditer("compare a; compare vs; compare  vs; compare vsx")] == [0, 36]
    assert [f.source for f in pat.fragments] == ["compare\\s", "vs"]


def test_tempered_gap_never_starts_the_stop():
    from app.detectors.catalog_terms import tempered
    pattern = re.compile(seq(w("compare\\s"), tempered(w("compare\\s"), 1, 10), raw("!")).source,
                         re.IGNORECASE | re.DOTALL)
    assert pattern.search("compare abc!").group(0) == "compare abc!"
    assert pattern.search("compare compare x!").group(0) == "compare x!"
    assert pattern.search("compare xcompare y!").group(0) == "compare xcompare y!"
    assert not pattern.search("compare " + "a" * 11 + "!")
    with pytest.raises(ValueError):
        tempered(w("compare\\s"), 3, 2)
    with pytest.raises(TypeError):
        tempered("compare", 1, 2)
