"""统一归一化视图 app/text_normalize.py 的接口契约。"""
import re

import pytest

from app.text_normalize import (
    DIGIT_SEP,
    compact_digits,
    fold_text,
    keyword_view,
    normalize_keyword,
    normalize_view,
    source_span,
)

ZW = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u200e", "\U000e0041", "\ufe0f"]


def test_ascii_is_identity_without_allocating_index():
    view = normalize_view("tel 13800138000")
    assert view.text == view.source
    assert isinstance(view.index, range)
    assert not view.changed


def test_fullwidth_digits_and_letters_fold_to_ascii():
    view = normalize_view("手机 １３８００１３８０００，Ｚ９")
    assert view.text == "手机 13800138000,Z9"
    start = view.text.index("138")
    assert view.source_slice(start, start + 11) == "１３８００１３８０００"


@pytest.mark.parametrize("zw", ZW)
def test_invisible_chars_are_removed_and_span_covers_them(zw):
    source = f"手机 138{zw}0013{zw}8000 请回电"
    view = normalize_view(source)
    assert view.text == "手机 13800138000 请回电"
    start = view.text.index("138")
    s, e = view.source_span(start, start + 11)
    # 原文区间连同中间插入的零宽字符一起覆盖，前后文字不被带入
    assert source[s:e] == f"138{zw}0013{zw}8000"
    assert source[:s] == "手机 " and source[e:] == " 请回电"


def test_leading_and_trailing_invisibles_are_not_pulled_into_span():
    source = "\u200b138\u200b"
    view = normalize_view(source)
    assert view.text == "138"
    assert view.source_span(0, 3) == (1, 4)


def test_expanding_compat_char_maps_whole_char():
    source = "a⑴b"  # 带括号的 1 → "(1)"
    view = normalize_view(source)
    assert view.text == "a(1)b"
    assert view.source_span(1, 4) == (1, 2)
    assert view.source_span(2, 3) == (1, 2)


def test_source_span_helper_matches_method_and_handles_empty():
    view = normalize_view("ａｂｃ")
    assert source_span(view.index, 0, 3, len(view.source)) == view.source_span(0, 3)
    assert view.source_span(1, 1) == (1, 1)
    assert view.source_span(3, 3) == (3, 3)


def test_fold_text_matches_lane_b_contract():
    # 汉字之间的分隔符折叠；英文之间不折叠；返回 (文本, idx) 二元组
    norm, idx = fold_text("你 傻\u200b*逼 吗 a b", " *")
    assert norm == "你傻逼吗 a b"
    assert [idx[i] for i in range(len(norm))] == [0, 2, 5, 7, 8, 9, 10, 11]
    # "傻 b"：汉字后面接独立的 b/x 也折叠
    assert fold_text("傻 b", " ")[0] == "傻b"
    assert fold_text("傻 bc", " ")[0] == "傻 bc"
    ascii_norm, ascii_idx = fold_text("a * b", " *")
    assert ascii_norm == "a * b" and isinstance(ascii_idx, range)


def test_keyword_view_folds_space_next_to_cjk_but_keeps_english_spaces():
    view = keyword_view("项目蓝鲸 Z9的预算 top secret 绝 密")
    assert view.text == "项目蓝鲸Z9的预算top secret绝密"
    assert normalize_keyword("蓝鲸 Ｚ９") == "蓝鲸Z9"
    assert normalize_keyword("top  secret") == "top  secret"
    start = view.text.index("蓝鲸Z9")
    assert view.source_slice(start, start + 4) == "蓝鲸 Z9"


def test_digit_separator_class_is_bounded_and_digit_free():
    pattern = re.compile(rf"\d{{3}}{DIGIT_SEP}\d{{4}}")
    assert pattern.fullmatch("138-0013")
    assert pattern.fullmatch("138 – 0013")
    assert not pattern.fullmatch("138 -  0013")  # 分隔符最多 3 个
    assert compact_digits("6222 0212-3456.7890") == "6222021234567890"
    assert compact_digits("110105 19491231 002x") == "11010519491231002x"


def test_long_text_view_keeps_exact_mapping():
    chunk = "汇款到，卡号６２２２\u200b０２１２。"
    source = chunk * 2000
    view = normalize_view(source)
    assert len(view.index) == len(view.text)
    for i in range(0, len(view.text), 997):
        mapped = view.source[view.index[i]]
        assert normalize_view(mapped).text == view.text[i] or len(normalize_view(mapped).text) > 1


def test_astral_chars_normalize_or_stay_with_exact_mapping():
    # 数学粗体数字 → ASCII；emoji 不变；第 14 平面标签字符删除
    source = "电话\U0001D7CF\U0001D7D1\U0001D7D6\U000E0041 \U0001F600"
    view = normalize_view(source)
    assert view.text == "电话138 \U0001F600"
    assert view.source_slice(2, 5) == "\U0001D7CF\U0001D7D1\U0001D7D6"
    assert view.source_slice(6, 7) == "\U0001F600"
