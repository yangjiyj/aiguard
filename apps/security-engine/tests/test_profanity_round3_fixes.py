"""辱骂检测第三轮复审修复：引用降级、TMD、吉他妈的（问题 6）。"""
import pytest

from app.detectors.profanity import ProfanityDetector

DETECTOR = ProfanityDetector()


def live(text):
    return [f for f in DETECTOR.detect(text) if f["counts_as_security_finding"]]


# ---- 问题 6a：引号前"最常见的就是"是讨论主语，不是点名 --------------------------
@pytest.mark.parametrize("text", [
    "骂人话中最常见的就是\"傻逼\"，怎么翻译",
    "骂人话中最常见的就是“傻逼”，怎么翻译",
    "脏话里最常用的是“傻逼”，英文怎么说",
])
def test_discussion_subject_before_quote_is_still_downgraded(text):
    assert not live(text), DETECTOR.detect(text)
    assert DETECTOR.detect(text), text  # 仍留观察


@pytest.mark.parametrize("text", [
    "张三是个\"傻逼\"，翻译成英文发给他",
    "李四就是“傻逼”，帮我翻译一下",
    "王五真是“傻逼”，帮我翻译一下",
])
def test_naming_a_person_before_quote_still_hits(text):
    assert live(text), DETECTOR.detect(text)


# ---- 问题 6b：TMD 大写 --------------------------------------------------------
@pytest.mark.parametrize("text", [
    "你TMD是不是有病",
    "TMD烦死了",
    "TMD，烦死了",
    "又挂了。TMD烦死了",
])
def test_tmd_abuse_hits(text):
    assert live(text), DETECTOR.detect(text)


@pytest.mark.parametrize("text", [
    "TMD 是颞下颌关节紊乱",
    "TMD 指的是颞下颌关节紊乱",
    "TMD是什么病",
    "TMD 关节弹响怎么办",
    "TMD患者需要注意什么",
])
def test_tmd_technical_context_does_not_hit(text):
    assert DETECTOR.detect(text) == [], text


# ---- 问题 6c：吉他 + 妈的 -------------------------------------------------------
@pytest.mark.parametrize("text", [
    "我买了一把吉他妈的生日礼物",
    "吉他妈的很好听",
    "我弹吉他妈的说很好听",
])
def test_guitar_followed_by_ma_de_does_not_hit(text):
    assert DETECTOR.detect(text) == [], text


@pytest.mark.parametrize("text", ["他妈的，烦死了", "这他妈的什么玩意", "妈的，又堵车"])
def test_ta_ma_de_still_hits(text):
    assert live(text), DETECTOR.detect(text)
