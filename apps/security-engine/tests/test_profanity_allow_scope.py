"""辱骂检测第三轮复审问题 5：白名单只与命中重叠就丢整条命中，造成真实辱骂漏报。"""
import pytest

from app.detectors.profanity import ProfanityDetector

DETECTOR = ProfanityDetector()


def live(text):
    return [f for f in DETECTOR.detect(text) if f["counts_as_security_finding"]]


# ---- 问题 5：白名单要完整覆盖命中，且前面没有指人/骂人语气才生效 ------------------
@pytest.mark.parametrize("text", [
    "你全家畜生",
    "你们一家畜生",
    "你个畜生产的垃圾",
    "你跳下去死了算了",
    "滚过去死了算了",
])
def test_allow_phrase_does_not_excuse_abuse_aimed_at_person(text):
    assert live(text), DETECTOR.detect(text)


@pytest.mark.parametrize("text", [
    "过去死了很多人",
    "牲畜生产",
    "低能耗",
    "他们是低能耗企业",
    "家畜生病了",
    "家畜生病了要及时隔离",
    "你知道过去死了多少人吗",
    "你们的家畜生病了吗",
])
def test_allow_phrase_still_clears_everyday_text(text):
    assert DETECTOR.detect(text) == [], text
