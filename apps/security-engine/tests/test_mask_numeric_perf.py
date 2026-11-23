"""数字类 PII 脱敏的性能回归（第三轮复审问题 1）。

B-2 按值补齐重复出现时曾对每条命中、每个候选值现编正则重扫全文，开销约为
命中数 x 候选数 x 文本长度：200 个手机号的 20KB 通讯录要 70 秒以上，可被拿来打满引擎。
修复后每个类别只在归一化视图上单遍扫描一次。这里用 100KB 级大量不同号码与对抗输入
钉住耗时上限（阈值宽松，只为抓住数量级退化），并确认号码全部脱敏。
"""
import re
import time

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine  # 先导入引擎，避免循环导入
from app.policy_bindings import PolicySet
from tests.test_mask_same_value_variants import TAGS, _policy

LIMIT_SECONDS = 3.0
SEGMENTS = ["138", "139", "135", "150", "186", "187", "158"]
_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]


def _phone(i):
    return SEGMENTS[i % 7] + "%08d" % (i * 7919 % 10**8)


def _luhn(prefix):
    for digit in "0123456789":
        number = prefix + digit
        total = 0
        for i, ch in enumerate(reversed(number)):
            n = int(ch) * (2 if i % 2 else 1)
            total += n - 9 if n > 9 else n
        if total % 10 == 0:
            return number
    raise AssertionError(prefix)


def _id_card(i):
    body = "110101" + "1990%02d%02d" % (1 + i % 12, 1 + i % 28) + "%03d" % (1 + i % 999)
    return body + "10X98765432"[sum(int(a) * b for a, b in zip(body, _WEIGHTS)) % 11]


def _fill(size_kb, make):
    lines, size, i = [], 0, 0
    while size < size_kb * 1024:
        line = make(i)
        lines.append(line)
        size += len(line.encode()) + 1
        i += 1
    return "\n".join(lines)


BULK = {
    "contacts_20k": (lambda: _fill(20, lambda i: "联系人%04d 手机 %s" % (i, _phone(i))), r"1[3-9]\d{9}"),
    "phones_100k": (lambda: _fill(100, lambda i: "手机 " + _phone(i)), r"1[3-9]\d{9}"),
    "cards_100k": (lambda: _fill(100, lambda i: "卡号 " + _luhn("622848%09d" % (i * 104729 % 10**9))), r"\d{16}"),
    "id_cards_100k": (lambda: _fill(100, lambda i: "身份证 " + _id_card(i)), r"\d{17}[\dX]"),
}

ADVERSARIAL = {
    "long_digit_run": "手机 13800138000，" + "1" * 100000,
    "dash_separated": "手机 13800138000，" + "1-" * 50000,
    "space_separated": "手机 13800138000，" + "1 " * 50000,
    "mixed_groups": "手机 13800138000，卡号 6228480012345671，"
                    + "138 0013 8000 6228-4800-1234-5671 1-2-3 4 5 6 " * 2200,
}


@pytest.fixture(autouse=True)
def _no_leaked_overrides():
    previous = ff.snapshot_overrides()
    ff.apply_overrides({})
    yield
    ff.apply_overrides(previous)


@pytest.fixture(scope="module")
def engine():
    previous = ff.snapshot_overrides()
    ff.apply_overrides({})
    eng = SecurityEngine()
    ff.apply_overrides(previous)
    eng.pii_checksum_enabled = True
    eng.load_policies(PolicySet([_policy(c, r) for c, r in TAGS.items()]))
    return eng


def _timed(engine, stage, text):
    started = time.perf_counter()
    if stage == "input":
        result = engine.check_input("req-perf", text, skip_semantic=True)
    else:
        result = engine.check_output("req-perf", text)
    return result, time.perf_counter() - started


@pytest.mark.parametrize("name", sorted(BULK))
@pytest.mark.parametrize("stage", ["input", "output"])
def test_many_distinct_numbers_mask_fast(engine, stage, name):
    make, leftover = BULK[name]
    text = make()
    result, elapsed = _timed(engine, stage, text)
    assert elapsed < LIMIT_SECONDS, f"{name} {stage} {elapsed:.2f}s"
    assert result.action == "mask"
    assert not re.search(rf"(?<!\d){leftover}(?!\d)", result.masked_content)
    assert result.masked_content.count("[") == text.count("\n") + 1


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
@pytest.mark.parametrize("stage", ["input", "output"])
def test_adversarial_digit_layouts_mask_fast(engine, stage, name):
    text = ADVERSARIAL[name]
    result, elapsed = _timed(engine, stage, text)
    assert elapsed < LIMIT_SECONDS, f"{name} {stage} {elapsed:.2f}s"
    assert result.action == "mask"
    assert "13800138000" not in result.masked_content
    assert "6228480012345671" not in result.masked_content
