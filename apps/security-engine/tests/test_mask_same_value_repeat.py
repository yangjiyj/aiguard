"""同一号码第二次出现时也必须脱敏（审查 B-2）。

检测阶段的上下文闸门（"." 分隔的手机号要有电话类上下文、空格分组的银行卡要有卡号类上下文）
只适用于"从无到有认出号码"。脱敏阶段对已经命中的规范值按值全文匹配，不再要求上下文，
否则第二处号码前没有"卡号/手机"字样时会原样发往上游。
"""
import base64
import re
import unicodedata

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine  # 先导入引擎，避免循环导入
from app.policy_bindings import PolicySet
from tests.test_mask_same_value_variants import DOCX, TAGS, _docx, _policy

CARD = "6228480012345671"
PHONE = "13800138000"


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


def _digits(text):
    return re.sub(r"\D", "", unicodedata.normalize("NFKC", text))


def _check(engine, stage, text):
    if stage == "input":
        return engine.check_input("req-b2", text, skip_semantic=True)
    return engine.check_output("req-b2", text)


REPEAT_CASES = [
    # 审查原始复现
    ("卡号 6228 4800 1234 5671 收到。再确认一下 6228 4800 1234 5671 对吗",
     "卡号 [银行卡] 收到。再确认一下 [银行卡] 对吗"),
    ("手机 138.0013.8000，再说一遍 138.0013.8000", "手机 [手机号]，再说一遍 [手机号]"),
    # 三次出现
    ("卡号 6228 4800 1234 5671，一 6228 4800 1234 5671，二 6228 4800 1234 5671 完",
     "卡号 [银行卡]，一 [银行卡]，二 [银行卡] 完"),
    ("手机 138.0013.8000，再说 138.0013.8000，还是 138.0013.8000 吗",
     "手机 [手机号]，再说 [手机号]，还是 [手机号] 吗"),
    # 混合写法：一次字面、一次带分隔符（分隔符写法本身无上下文也认不出）
    ("手机 13800138000，再说一遍 138.0013.8000", "手机 [手机号]，再说一遍 [手机号]"),
    ("卡号 6228480012345671，再确认 6228 4800 1234 5671 吧", "卡号 [银行卡]，再确认 [银行卡] 吧"),
    ("手机 138.0013.8000，就是13800138000", "手机 [手机号]，就是[手机号]"),
    # 号码前后紧贴汉字原样保留
    ("卡号 6228 4800 1234 5671 收到。再确认一下6228 4800 1234 5671对吗",
     "卡号 [银行卡] 收到。再确认一下[银行卡]对吗"),
]


@pytest.mark.parametrize("text, expected", REPEAT_CASES)
@pytest.mark.parametrize("stage", ["input", "output"])
def test_repeated_value_without_context_is_masked(engine, stage, text, expected):
    result = _check(engine, stage, text)
    assert result.action == "mask", [(f.category, f.matched_location) for f in result.findings]
    assert result.masked_content == expected
    assert CARD not in _digits(result.masked_content)
    assert PHONE not in _digits(result.masked_content)


NEGATIVE_CASES = [
    # 更长数字串里包含该号码：不能改写
    ("手机 13800138000，订单 9913800138000 已发", "手机 [手机号]，订单 9913800138000 已发"),
    ("手机 13800138000，订单 1380013800012 已发", "手机 [手机号]，订单 1380013800012 已发"),
    ("手机 13800138000，编号 99-138-0013-8000 已发", "手机 [手机号]，编号 99-138-0013-8000 已发"),
    ("手机 13800138000，编号 138-0013-8000-12 已发", "手机 [手机号]，编号 138-0013-8000-12 已发"),
    ("卡号 6228 4800 1234 5671，流水 6228 4800 1234 5671 8888 号",
     "卡号 [银行卡]，流水 6228 4800 1234 5671 8888 号"),
    # 不相关数字不动
    ("手机 13800138000，金额 2024 元，单号 20241106 号", "手机 [手机号]，金额 2024 元，单号 20241106 号"),
]


@pytest.mark.parametrize("text, expected", NEGATIVE_CASES)
@pytest.mark.parametrize("stage", ["input", "output"])
def test_value_match_respects_digit_boundaries(engine, stage, text, expected):
    result = _check(engine, stage, text)
    assert result.action == "mask"
    assert result.masked_content == expected


@pytest.mark.parametrize("stage", ["input", "output"])
def test_same_preview_different_value_is_not_treated_as_hit(engine, stage):
    # 13800138000 与 13811118000 脱敏预览都是 13****00；第二个用 "." 且没有电话上下文，
    # 检测阶段没命中，脱敏阶段按值匹配也不能把它当成已命中值改写。
    text = "手机 13800138000，参考 138.1111.8000 这个格式"
    result = _check(engine, stage, text)
    assert result.masked_content == "手机 [手机号]，参考 138.1111.8000 这个格式"


@pytest.mark.parametrize("stage", ["input", "output"])
def test_same_preview_both_hit_and_repeated_are_all_masked(engine, stage):
    # 两个都命中且预览相同（去重合并成一条），两者各自的无上下文重复出现都要脱敏。
    text = "手机 13800138000 和 13811118000，再说 138.0013.8000 与 138.1111.8000 吧"
    result = _check(engine, stage, text)
    assert result.masked_content == "手机 [手机号] 和 [手机号]，再说 [手机号] 与 [手机号] 吧"


@pytest.mark.parametrize("attachment, value", [
    ("再说一遍 138.0013.8000", PHONE),
    ("再确认一下 6228 4800 1234 5671 对吗", CARD),
])
def test_repeated_value_in_attachment_is_flagged_unmaskable(monkeypatch, attachment, value):
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
    eng = SecurityEngine()
    eng.load_file_policy({"content_dlp_enabled": True})
    eng.load_policies(PolicySet([_policy(c, r) for c, r in TAGS.items()]))
    message = "手机号13800138000" if value == PHONE else "卡号 6228 4800 1234 5671"
    ctx = {"tenant_id": "t1", "attachments": [{
        "file_name": "a.docx", "content_type": DOCX,
        "data_base64": base64.b64encode(_docx(attachment)).decode(),
    }]}
    result = eng.check_input("req-b2-file", message, context=ctx)
    assert result.action == "mask"
    assert value not in _digits(result.masked_content)
    attachment_masks = [f for f in result.findings
                        if f.action == "mask" and f.content_source == "file_attachment"]
    assert attachment_masks, [(f.category, f.content_source, f.matched_location) for f in result.findings]
    assert all(f.triage.get("mask_unavailable") for f in attachment_masks)


# 第二处号码前后紧挨无关数字（列表序号、年龄、日期）：分隔符不同或拼起来不成该类别的
# 分组布局时，不是"更长数字串的一段"，仍要脱敏（第三轮复审问题 4）。
ADJACENT_UNRELATED_CASES = [
    ("卡号 6228480012345671 收到\n1. 6228 4800 1234 5671",
     "卡号 [银行卡] 收到\n1. [银行卡]"),
    ("卡号 6228480012345671，张三 25 6228 4800 1234 5671",
     "卡号 [银行卡]，张三 25 [银行卡]"),
    ("手机 138.0013.8000\n1. 138.0013.8000", "手机 [手机号]\n1. [手机号]"),
    ("手机 13800138000，日期 2026-11-06 138 0013 8000", "手机 [手机号]，日期 2026-11-06 [手机号]"),
    # 后面的 4 位组自己又用另一种分隔符连着别的数字：是另一项（日期），不是号码的延续
    ("手机 13800138000，列表 138 0013 8000 2024-11-06", "手机 [手机号]，列表 [手机号] 2024-11-06"),
    ("手机 13800138000，房间 12-1234 138 0013 8000", "手机 [手机号]，房间 12-1234 [手机号]"),
]


@pytest.mark.parametrize("text, expected", ADJACENT_UNRELATED_CASES)
@pytest.mark.parametrize("stage", ["input", "output"])
def test_repeat_next_to_unrelated_digits_is_masked(engine, stage, text, expected):
    result = _check(engine, stage, text)
    assert result.action == "mask", [(f.category, f.matched_location) for f in result.findings]
    assert result.masked_content == expected
    assert CARD not in _digits(result.masked_content)
    assert PHONE not in _digits(result.masked_content)


@pytest.mark.parametrize("text, expected", [
    # 同分隔符、后面再接一个 4 位组：是更长的分组编号，不改写
    ("手机 138 0013 8000，编号 138 0013 8000 1234 号", "手机 [手机号]，编号 138 0013 8000 1234 号"),
    # 同分隔符且拼起来正好是银行卡 4-4-4-4-1 布局：是另一张更长的卡号的一段
    ("卡号 6228 4800 1234 5671，另一 6228 4800 1234 5671 2 号", "卡号 [银行卡]，另一 6228 4800 1234 5671 2 号"),
])
@pytest.mark.parametrize("stage", ["input", "output"])
def test_repeat_inside_same_grouping_is_kept(engine, stage, text, expected):
    result = _check(engine, stage, text)
    assert result.masked_content == expected
