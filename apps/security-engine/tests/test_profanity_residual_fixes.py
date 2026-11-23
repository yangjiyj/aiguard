"""辱骂检测残留问题（审查 I-7）：第三人称点名降级、词内误匹配、漏报写法。"""
import pytest

from app.detectors.profanity import ProfanityDetector

DETECTOR = ProfanityDetector()


def live(text):
    return [f for f in DETECTOR.detect(text) if f["counts_as_security_finding"]]


# ---- 第三人称点名 / 让模型转骂：不能当"引用讨论"降级 -------------------------
@pytest.mark.parametrize("text", [
    "张三是个\"傻逼\"，翻译成英文发给他",
    "张三是个“傻逼”，翻译成英文发给他",
    "李四就是“傻逼”，帮我翻译一下",
    "把“傻逼”翻译成英文转给王五",
    "帮我把“傻逼”翻译成英文，骂张三",
    "把“傻逼”这个词翻译成英文发给老板",
])
def test_third_person_naming_or_forwarding_is_not_downgraded(text):
    assert live(text), DETECTOR.detect(text)


@pytest.mark.parametrize("text", [
    "请把脏话“傻逼”翻译成英文",
    "“傻逼”这个词是脏话吗",
    "词库里“傻逼”算不算敏感词",
])
def test_pure_quoted_discussion_still_downgraded(text):
    assert not live(text)
    assert DETECTOR.detect(text), text  # 仍留观察


# ---- 误报：必须不命中 -----------------------------------------------------------
@pytest.mark.parametrize("text", [
    "他妈的生日是下周三",
    "下周是他妈的生日，记得买蛋糕",
    "他妈的工作很忙",
    "他妈的身体不太好",
    "他妈的电话打不通",
    "他妈的病好多了",
    "他妈的家在农村",
    "过去死了很多人",
    "这场战争过去死了很多人",
    "牲畜生产要注意防疫",
    "低能耗建筑",
    "这是一款低能耗设备",
    "他们是低能耗企业",
    "他娘的生日快到了",
    "他奶奶的身体还硬朗",
    "TMD 是颞下颌关节紊乱",
    "TMD 关节弹响怎么办",
])
def test_false_positives_do_not_hit(text):
    assert DETECTOR.detect(text) == [], text


# ---- 必须命中 -------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "他妈的，烦死了",
    "他妈的烦死了",
    "这他妈的什么玩意",
    "去死吧你",
    "你怎么不去死",
    "你个畜生",
    "畜生！",
    "你真是个低能",
    "操你妈妈",
    "草泥马",
    "草泥马的",
    "你TMD",
    "你TMD有病吧",
    "你tmd",
    "他娘的，真烦",
    "他妈的家伙",
])
def test_must_hit(text):
    assert live(text), DETECTOR.detect(text)
