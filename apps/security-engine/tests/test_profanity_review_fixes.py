"""内置辱骂检测集成审查修复（I1 引用/讨论降级被利用、I2 强词误报）。"""
import pytest

from app.detectors.engine import SecurityEngine  # noqa: F401  先导入引擎，避免循环导入
from app.detectors.profanity import ProfanityDetector

DETECTOR = ProfanityDetector()


def live_hits(text):
    return [f for f in DETECTOR.detect(text) if f["counts_as_security_finding"]]


def observed(text):
    return [f for f in DETECTOR.detect(text) if not f["counts_as_security_finding"]]


# ---- I1：带第二人称指向或日常疑问的辱骂，不能借"讨论"降级 ---------------------
ABUSE_DISGUISED_AS_DISCUSSION = [
    "你个傻逼是什么东西",
    "傻逼是什么玩意儿，滚",
    "你他妈的什么意思",
    "你这个“傻逼”，是不是脑子坏了",
    "你个“傻逼”还好意思问",
    "比如：傻逼，你就是这种人，脏话",
    "傻逼什么意思你自己清楚",
    "傻逼的意思就是你",
    "您真是个“傻逼”，是不是",
    "你丫傻逼这个词都不懂",
]


@pytest.mark.parametrize("text", ABUSE_DISGUISED_AS_DISCUSSION)
def test_second_person_or_everyday_question_is_not_a_discussion(text):
    assert live_hits(text), text


GENUINE_DISCUSSION = [
    "傻逼这个词是脏话吗",
    "请把脏话'傻逼'翻译成英文",
    "请把中文脏话'傻逼'翻译成英文并解释其含义",
    "“傻逼”这个词是脏话吗？",
    "敏感词库里应该收录哪些词，比如：傻逼",
    "傻逼这个词怎么翻译",
    "请解释“你个废物”这句话的含义",
]


@pytest.mark.parametrize("text", GENUINE_DISCUSSION)
def test_genuine_discussion_is_still_observation_only(text):
    assert not live_hits(text), text


# ---- I2：日常/技术文本不能被强词误报 ---------------------------------------
BENIGN = [
    "去死皮膏怎么用",
    "这款去死皮膏效果好吗",
    "厨房清洁要去死角",
    "用磨砂膏去死皮",
    "如何去死锁",
    "用的是SB框架",
    "Spring Boot 简称 SB",
    "请解释变量 sb",
    "帮sb做某事是什么句型",
    "StringBuilder sb = new StringBuilder(); sb.append(x); return sb",
    "for (...) { ... }; return sb",
    "DSB 信号处理",
    "dsb 信号的带宽",
    "TMD 是颞下颌关节紊乱",
    "tmd 关节弹响怎么办",
    "cnm 这个参数",
    "设置 cnm=3 后重启",
    "调用 nmb(x) 计算",
    "CNM 模型",
]


@pytest.mark.parametrize("text", BENIGN)
def test_everyday_and_technical_text_is_not_profanity(text):
    assert DETECTOR.detect(text) == [], text


STILL_ABUSE = [
    "你个sb",
    "你这个ＳＢ！",
    "你个SB！",
    "真是个sb",
    "sb东西",
    "sb 玩意儿",
    "tmd",
    "tmd，又挂了",
    "cnm",
    "nmb 滚",
    "dsb",
    "去死",
    "去死吧你",
    "你怎么不去死",
    "NMSL",
]


@pytest.mark.parametrize("text", STILL_ABUSE)
def test_real_abuse_still_hits(text):
    assert live_hits(text), text
