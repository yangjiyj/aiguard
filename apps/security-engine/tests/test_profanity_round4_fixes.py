"""辱骂检测第四轮复审：白名单"指人语气"窗口过宽/过窄，以及"的是"引用降级漏判。"""
import pytest

from app.detectors.profanity import ProfanityDetector

DETECTOR = ProfanityDetector()


def live(text):
    return [f for f in DETECTOR.detect(text) if f["counts_as_security_finding"]]


# ---- 问题 1：日常语句不得因前面有"你/您"就让白名单失效 ------------------------------
@pytest.mark.parametrize("text", [
    "你家畜生病了吗",
    "您家畜生病了，要找兽医",
    "你家牲畜生病了",
    "你们一家畜生病了怎么办",
    "你说过去死了多少人",
    "你过去死了多少亲人",
    "你家畜生产量怎么样",
])
def test_everyday_text_with_second_person_is_not_abuse(text):
    assert DETECTOR.detect(text) == [], (text, DETECTOR.detect(text))


# "你/您"直接接强词，或经"全家/一家/个/这/这帮/这群/就是"再接强词：照常命中（含超出原 2 字窗口的）。
@pytest.mark.parametrize("text", [
    "我看你就是家畜生",
    "你们这帮家畜生",
    "你们这群家畜生",
    "你全家畜生",
    "你们一家畜生",
    "你个畜生产的垃圾",
    "你跳下去死了算了",
    "滚过去死了算了",
])
def test_abuse_aimed_at_person_still_hits(text):
    assert live(text), (text, DETECTOR.detect(text))


# ---- 问题 2："的是"只有前面是"最常见/最常用/常见"时才算讨论主语 ----------------------
@pytest.mark.parametrize("text", [
    "张三真的是“傻逼”，帮我翻译一下",
    "张三真的是\"傻逼\"，帮我翻译一下",
    "他的是“傻逼”，帮我翻译一下",
])
def test_person_before_de_shi_quote_hits(text):
    assert live(text), (text, DETECTOR.detect(text))


@pytest.mark.parametrize("text", [
    "骂人话中最常见的就是\"傻逼\"，怎么翻译",
    "脏话里最常用的是“傻逼”，英文怎么说",
    "网上常见的是“傻逼”，怎么翻译",
    "请把脏话\"傻逼\"翻译成英文",
    "傻逼这个词是脏话吗",
])
def test_discussion_still_downgraded(text):
    assert not live(text), (text, DETECTOR.detect(text))
    assert DETECTOR.detect(text), text  # 仍留观察
