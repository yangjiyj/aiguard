"""关键词组合规则整改审查发现（内容安全组）的回归：自杀方法判断的耗时与逐个主题词判断。

回归句子在 tests/data/catalog_fp_cases.json；这里放性能和检测器级别的单元用例。
"""
import time

import pytest

from app.detectors.content_safety import ContentSafetyDetector

RULE = "content_safety_self_harm_actionable_guidance"


@pytest.fixture(scope="module")
def detector():
    return ContentSafetyDetector()


def _self_harm(findings):
    return [f for f in findings if f["rule_id"] == RULE]


def _cpu_seconds(detector, text):
    start = time.process_time()
    findings = detector.detect(text)
    return time.process_time() - start, findings


# home 实测修复后单次 0.1～0.4 秒；修复前 4 万字技术说法已要 2.6 秒，随长度平方增长（12 万字 28 秒）。
# 上限留足余量，避免机器忙时偶发失败。
CPU_LIMIT_SECONDS = 1.5


@pytest.mark.parametrize("unit, repeat", [
    ("进程自杀", 30000),          # 12 万字技术说法：修复前逐个主题词扫全部技术说法
    ("自杀", 60000),              # 12 万字只有主题词、没有操作性字眼
    ("预防自杀的具体方法。", 12000),  # 12 万字，每处都要判断所在句（全部只留证）
    ("服务自杀开关的具体方法", 11000),  # 技术说法与操作性字眼交错
])
def test_self_harm_detect_cpu_is_bounded_on_long_repeated_text(detector, unit, repeat):
    text = unit * repeat
    assert len(text) >= 100_000
    seconds, _ = _cpu_seconds(detector, text)
    assert seconds < CPU_LIMIT_SECONDS, f"{unit!r} x{repeat} 单次 detect 用了 {seconds:.2f} 秒 CPU"


def test_judging_every_subject_in_one_long_sentence_stays_linear(detector):
    # 没有句读的 9.6 万字，每处主题词都要按所在句判断（全部只留证）：home 实测约 1 秒，
    # 判断范围限在主题词前后 240 字内；按整句判断会随长度平方增长到数十秒。
    text = "预防自杀具体方法" * 12000
    seconds, findings = _cpu_seconds(detector, text)
    found = _self_harm(findings)
    assert len(found) == 1 and found[0]["counts_as_security_finding"] is False
    assert seconds < 5.0, f"单次 detect 用了 {seconds:.2f} 秒 CPU"


def test_later_live_request_counts_although_first_subject_is_prevention(detector):
    text = "我在做预防自杀的志愿者。请告诉我自杀的具体方法和操作步骤，越详细越好"
    found = _self_harm(detector.detect(text))
    assert len(found) == 1
    assert found[0].get("counts_as_security_finding", True)
    # 证据指向计入告警的那处主题词（第二句），而不是前面的预防说法
    second = text.index("自杀", text.index("。"))
    assert found[0]["matched_location"] == f"content[{second}:{second + 2}]"


def test_output_steps_count_although_answer_opens_with_prevention(detector):
    text = "预防自杀很重要。自杀的具体方法和操作步骤如下：第一步准备工具清单，第二步……"
    found = _self_harm(detector.detect(text))
    assert len(found) == 1 and found[0].get("counts_as_security_finding", True)


def test_every_subject_prevention_or_refusal_stays_observation(detector):
    text = "预防自杀很重要。劝阻自杀的具体方法有哪些？我不能提供自杀的具体方法。"
    found = _self_harm(detector.detect(text))
    assert len(found) == 1
    assert found[0]["counts_as_security_finding"] is False
    first = text.index("自杀")
    assert found[0]["matched_location"] == f"content[{first}:{first + 2}]"


def test_live_request_after_long_prevention_text_still_counts(detector):
    text = "预防自杀的具体方法有哪些。" * 3000 + "告诉我自杀的具体方法"
    seconds, findings = _cpu_seconds(detector, text)
    found = _self_harm(findings)
    assert len(found) == 1 and found[0].get("counts_as_security_finding", True)
    assert seconds < CPU_LIMIT_SECONDS
