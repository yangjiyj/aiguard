"""数字类 PII（手机号/身份证/银行卡）的写法变体识别，位置落回原文。

在 ``app.text_normalize.normalize_view`` 的归一化视图上匹配（全角数字、零宽字符已处理），
再按固定分组位置识别分隔符（空格、-、全角空格/横线；"." 见下）与 +86/0086/86 前缀：

- 手机号 3-4-4 分组：``138-0013-8000``、``+86 138 0013 8000``、``008613800138000``；
  不带 + / 00 的裸 86 只在紧贴或横线连接时算国家码（``8613800138000``、``86-138…``），
  ``86 138 0013 8000`` 这种更像数字列表，86 不算进号码；
- 身份证 6-8-4 / 6-4-4-4 分组，末位 X/x（含全角）；
- 银行卡 4-4-4-4(-1~3) 分组，要求卡号/账户类上下文（完整词：卡号、银行卡、账号……，
  "显卡/打卡/卡顿"不算）或 62 开头的 19 位银联格式。

一个号码内各处分隔符必须相同，分组长度必须正好是上面的布局（"1380013 8000"、
"138-0013 8000" 不算）。"." 只在前面有电话类上下文时作手机号分隔符（版本号、构建号多用点），
身份证/银行卡不接受 "."。号码前紧挨"字母/数字 + 横线/点/下划线"（req-、2024-、x_）或
非电话类 key=value（trace_id=）时，是标识符/编号的一段，不当作号码。

空格分组的号码若前后还紧挨着别的数字组（一串数字列表），不当作号码。

只在固定分组位置接受分隔符，不做"删光分隔符再找数字"，避免把相邻的两个无关数字
（日期、版本号、金额列表）拼成一个号码。依赖分隔符、前缀或归一化才识别出来的号码
一律要求结构/校验位有效（不受 SECURITY_PII_CHECKSUM_ENABLED 影响）；字面写法保持原有
判定逻辑不变，由调用方按原开关处理。

手机号紧贴英文字母（``tel13800138000end``）放宽为"前后不是数字"，但所在 ASCII 词里还有
别的数字或下划线（哈希、标识符、``user_138…``）、或两侧字母串过长时仍不算。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.detectors.numeric_context import (
    is_complete_pii_token,
    is_letter_bounded_number,
    non_pii_numeric_spans,
)
from app.detectors.pii_checksum import (
    validate_bank_card,
    validate_id_card_cn,
    validate_phone_cn_segment,
)
from app.text_normalize import DIGIT_SEP as S, NormalizedText, compact_digits, normalize_view

NUMERIC_PII_CATEGORIES = ("phone_cn", "id_card_cn", "bank_card_cn")

# 前后用 \d（含其它脚本数字）判断边界；号码本身只认 ASCII 数字（归一化后全角已是 ASCII）。
_PATTERNS = {
    "phone_cn": re.compile(
        rf"(?<!\d)(?:(?P<cc>(?:\+|00)86){S}|86[-\u2010-\u2015\u2212]?)?(?P<v>1[3-9][0-9]{S}[0-9]{{4}}{S}[0-9]{{4}})(?!\d)"
    ),
    "id_card_cn": re.compile(
        rf"(?<!\d)(?P<v>[0-9]{{6}}{S}[0-9]{{4}}{S}[0-9]{{4}}{S}[0-9]{{3}}[0-9Xx])(?!\d)"
    ),
    "bank_card_cn": re.compile(
        rf"(?<!\d)(?P<v>[0-9]{{4}}(?:{S}[0-9]{{4}}){{3}}(?:{S}[0-9]{{1,3}})?)(?!\d)"
    ),
}
# 带分隔符的银行卡要有卡号/账户类上下文（前 16 字内），或是 62 开头 4-4-4-4-3 的银联
# 19 位格式；否则 "统计 4173 1752 7506 7299 件" 这类 4 位数字表约有 4% 能碰巧过 IIN+Luhn。
_BANK_CONTEXT = re.compile(
    r"(?:卡号|银行卡|储蓄卡|信用卡|借记卡|银联卡|账号|帐号|账户|帐户|户名|开户|收款|汇款|转账|打款|付款"
    r"|\bcard|\bacct|\baccount)",
    re.IGNORECASE,
)
_BANK_CONTEXT_WINDOW = 16
# 空格分组号码前后还紧挨着别的数字组：是一串数字列表，不是一个号码。
_GROUP_BEFORE = re.compile(r"[0-9] +$")
_GROUP_AFTER = re.compile(r" +[0-9]")
_ANY_DIGIT = re.compile(r"[0-9]")
_CONTINUES_GROUPING = re.compile(r"[-.\u2010-\u2015\u2212]?[0-9]")
# \u53f7\u7801\u524d\u7d27\u6328"\u5b57\u6bcd/\u6570\u5b57 + \u8fde\u63a5\u7b26"\uff1areq-138-\u2026\u30012024-139-\u2026\u3001build.138\u2026\uff0c\u662f\u7f16\u53f7/\u6807\u8bc6\u7b26\u7684\u4e00\u6bb5\u3002
_IDENTIFIER_BEFORE = re.compile(r"[A-Za-z0-9][-._\u2010-\u2015\u2212]$")
# key=value\uff1atrace_id=138-0013-8000 \u662f\u65e5\u5fd7\u5b57\u6bb5\uff1bphone=/mobile= \u8fd9\u7c7b\u7535\u8bdd\u5b57\u6bb5\u4ecd\u7b97\u53f7\u7801\u3002
_KEY_VALUE_BEFORE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*$")
_PHONE_KEY = re.compile(r"phone|mobile|tel|cell|contact|msisdn", re.IGNORECASE)
# "." \u4f5c\u624b\u673a\u53f7\u5206\u9694\u7b26\u65f6\u524d\u9762\u8981\u6709\u7535\u8bdd\u7c7b\u4e0a\u4e0b\u6587\uff08\u524d 16 \u5b57\u5185\uff09\u3002
_PHONE_CONTEXT = re.compile(r"(?:\u7535\u8bdd|\u624b\u673a|\u8054\u7cfb|\u81f4\u7535|\u62e8\u6253|\u6765\u7535|\u53f7\u7801|\u70ed\u7ebf|tel|phone|mobile|call)", re.IGNORECASE)
_PREFIX_WINDOW = 24
_SEPARATOR_RUN = re.compile(r"[^0-9Xx]+")
_LAYOUTS = {
    "phone_cn": ((3, 4, 4),),
    "id_card_cn": ((6, 8, 4), (6, 4, 4, 4)),
    "bank_card_cn": ((4, 4, 4, 4), (4, 4, 4, 4, 1), (4, 4, 4, 4, 2), (4, 4, 4, 4, 3)),
}


def _grouping_ok(category: str, raw: str, text: str, start: int) -> bool:
    """\u5206\u7ec4\u53f7\u7801\uff1a\u5206\u9694\u7b26\u4e00\u81f4\u3001\u5206\u7ec4\u957f\u5ea6\u662f\u89c4\u5b9a\u5e03\u5c40\uff1b"." \u53ea\u5728\u6709\u7535\u8bdd\u4e0a\u4e0b\u6587\u7684\u624b\u673a\u53f7\u91cc\u63a5\u53d7\u3002"""
    separators = _SEPARATOR_RUN.findall(raw)
    if len(set(separators)) != 1:
        return False
    if tuple(len(group) for group in _SEPARATOR_RUN.split(raw)) not in _LAYOUTS[category]:
        return False
    if "." in separators[0]:
        return category == "phone_cn" and bool(
            _PHONE_CONTEXT.search(text, max(0, start - _BANK_CONTEXT_WINDOW), start)
        )
    return True


def _identifier_prefixed(text: str, start: int) -> bool:
    """\u53f7\u7801\u524d\u662f\u6807\u8bc6\u7b26/\u7248\u672c/\u7f16\u53f7\u7684\u8fde\u63a5\u7b26\uff0c\u6216\u975e\u7535\u8bdd\u7c7b key=value \u7684\u503c\u3002"""
    before = text[max(0, start - _PREFIX_WINDOW):start]
    if _IDENTIFIER_BEFORE.search(before):
        return True
    key_value = _KEY_VALUE_BEFORE.search(before)
    return bool(key_value and not _PHONE_KEY.search(key_value.group("key")))


@dataclass(frozen=True)
class NumericPiiCandidate:
    """一个数字类 PII 候选。

    category: phone_cn / id_card_cn / bank_card_cn
    start/end: 原文区间（脱敏替换它；含前缀、区间内分隔符与零宽字符）
    value:     规范值（去分隔符与前缀，身份证末位大小写保留）
    variant:   是否依赖归一化/分隔符/前缀才识别（字面写法为 False）
    """

    category: str
    start: int
    end: int
    value: str
    variant: bool


def _valid(category: str, value: str) -> bool:
    if category == "phone_cn":
        return validate_phone_cn_segment(value)
    if category == "id_card_cn":
        return validate_id_card_cn(value)
    return validate_bank_card(value)


def find_numeric_pii(content: str, view: Optional[NormalizedText] = None) -> List[NumericPiiCandidate]:
    """在 content 中找手机号/身份证/银行卡候选（含写法变体），返回原文坐标。

    字面写法（无分隔符、无前缀、原文片段即规范值）沿用原有边界与元数据排除；
    手机号号段结构校验对两种写法都做。身份证/银行卡字面写法不在这里做校验位判定，
    交给调用方按 SECURITY_PII_CHECKSUM_* 开关处理（保持旧行为）。
    """
    if not content:
        return []
    view = view or normalize_view(content)
    text = view.text
    if _ANY_DIGIT.search(text) is None:
        return []
    metadata = non_pii_numeric_spans(text)
    loose_metadata = None
    out: List[NumericPiiCandidate] = []
    for category in NUMERIC_PII_CATEGORIES:
        for match in _PATTERNS[category].finditer(text):
            vs, ve = match.span("v")
            ms, me = match.span()
            raw = text[vs:ve]
            value = compact_digits(raw)
            separated = value != raw
            prefixed = ms != vs
            source_start, source_end = view.source_span(ms, me)
            variant = separated or prefixed or view.source[source_start:source_end] != text[ms:me]
            if separated and _CONTINUES_GROUPING.match(text, me):
                # 138-0013-8000-12：分组还在继续，是别的编号格式
                continue
            if separated and not _grouping_ok(category, raw, text, ms):
                continue
            if (separated or prefixed) and _identifier_prefixed(text, ms):
                # req-138-0013-8000、2024-139-1234-5600、trace_id=138-0013-8000
                continue
            if separated and " " in raw and (
                _GROUP_BEFORE.search(text, max(0, ms - 8), ms) or _GROUP_AFTER.match(text, me)
            ):
                continue
            if separated and category == "bank_card_cn" and not (
                _BANK_CONTEXT.search(text, max(0, ms - _BANK_CONTEXT_WINDOW), ms)
                or (value.startswith("62") and len(value) == 19)
            ):
                continue
            if is_complete_pii_token(text, ms, me):
                if not separated and (vs, ve) in metadata:
                    continue
            elif category == "phone_cn" and not separated and is_letter_bounded_number(text, ms, me):
                if loose_metadata is None:
                    loose_metadata = non_pii_numeric_spans(text, identifiers=False)
                if (vs, ve) in loose_metadata:
                    continue
            else:
                continue
            if (category == "phone_cn" or variant) and not _valid(category, value):
                continue
            out.append(NumericPiiCandidate(category, source_start, source_end, value, variant))
    return out


# 脱敏阶段按值匹配：分隔符只允许出现在该类别规定的分组位置（与 _LAYOUTS 一致）。
_VALUE_BREAKS = {
    category: frozenset(
        sum(layout[:i]) for layout in layouts for i in range(1, len(layout))
    )
    for category, layouts in _LAYOUTS.items()
}
_VALUE_LENGTHS = {category: frozenset(sum(layout) for layout in layouts) for category, layouts in _LAYOUTS.items()}
# 与 DIGIT_SEP 同一组分隔符：空格、-、.、各种横线。
_SEP_SET = frozenset(" -.‐‑‒–—―−")
_MAX_SEP_RUN = 3
_ADJACENT_GROUP_SCAN = 32


def _scan_pattern(category: str, length: int) -> "re.Pattern[str]":
    """该类别某一长度的号码形状（分隔符只在分组位置），零宽前瞻以便逐位置重叠扫描。"""
    breaks = _VALUE_BREAKS[category]
    parts = []
    for i in range(length):
        if i and i in breaks:
            parts.append(S)
        last_id_char = category == "id_card_cn" and i == length - 1
        parts.append("[0-9Xx]" if last_id_char else "[0-9]")
    return re.compile(r"(?<!\d)(?=(" + "".join(parts) + r")(?!\d))")


# 预编译：每个类别每种长度一条，单遍扫描全文；不再按值现编正则（第三轮复审问题 1）。
_SCAN_PATTERNS = {
    category: tuple(_scan_pattern(category, length) for length in sorted(lengths))
    for category, lengths in _VALUE_LENGTHS.items()
}


def _sep_run(text: str, pos: int, before: bool) -> int:
    """从 pos 向前（或向后）吃掉至多 _MAX_SEP_RUN 个分隔符，返回停下的位置；超过上限返回 -1。"""
    j = pos
    if before:
        while j > 0 and pos - j < _MAX_SEP_RUN and text[j - 1] in _SEP_SET:
            j -= 1
        return -1 if j > 0 and text[j - 1] in _SEP_SET else j
    while j < len(text) and j - pos < _MAX_SEP_RUN and text[j] in _SEP_SET:
        j += 1
    return -1 if j < len(text) and text[j] in _SEP_SET else j


def _adjacent_group(text: str, start: int, end: int, before: bool) -> Optional[Tuple[str, str]]:
    """号码前（或后）紧挨的"分隔符 + 数字组"，返回 (分隔符串, 数字组)；没有则 None。

    邻组远端若又用另一种分隔符连着数字（"138 0013 8000 2024-11-06" 的 2024），它属于
    另一项（日期、编号），不算邻组。
    """
    pos = start if before else end
    j = _sep_run(text, pos, before)
    if j < 0 or j == pos:
        return None
    separator = text[j:pos] if before else text[pos:j]
    k = j
    if before:
        while k > 0 and j - k < _ADJACENT_GROUP_SCAN and "0" <= text[k - 1] <= "9":
            k -= 1
        group, far = text[k:j], k
    else:
        while k < len(text) and k - j < _ADJACENT_GROUP_SCAN and "0" <= text[k] <= "9":
            k += 1
        group, far = text[j:k], k
    if not group:
        return None
    f = _sep_run(text, far, before)
    if f >= 0 and f != far:
        far_sep = text[f:far] if before else text[far:f]
        beyond = text[f - 1:f] if before else text[f:f + 1]
        if far_sep != separator and "0" <= beyond <= "9":
            return None
    return separator, group


def _part_of_longer(category: str, raw: str, separator: str, group: str, before: bool) -> bool:
    """紧挨的数字组是否与号码同属一个更长的分组数字串（是则不改写）。

    - 号码本身连写：紧挨"数字 + 连接符"（2024-13800138000、v1.13800138000）是编号的一段；
      隔着空格（列表序号 "1. 13800138000"）不是。
    - 号码带分隔符：邻组分隔符与号码内分隔符不同（"1. 6228 4800…"、"2026-11-06 138 0013 8000"）
      不是同一串。分隔符相同时，拼起来正好是该类别布局（4-4-4-4 再接 1 位）、用 -/. 连成的
      编号（99-138-0013-8000、138-0013-8000-12）、或邻组也有 4 位以上（20 位流水号
      6228 4800 1234 5671 8888）才算更长串的一段；空格隔开的 1-3 位短组（序号、年龄、
      日期尾巴，如 "25 6228 4800…"）是另一项。
    """
    inner = set(_SEPARATOR_RUN.findall(raw))
    if not inner:
        return not any(ch.isspace() for ch in separator)
    if inner != {separator}:
        return False
    layout = tuple(len(part) for part in _SEPARATOR_RUN.split(raw))
    combined = ((len(group),) + layout) if before else (layout + (len(group),))
    if combined in _LAYOUTS[category]:
        return True
    return not separator.isspace() or len(group) >= 4


def find_numeric_values(
    content: str, category: str, values, view: Optional[NormalizedText] = None,
) -> List[Tuple[int, int]]:
    """脱敏用：在 content 中找已命中规范值的全部出现，返回原文区间。

    检测阶段的上下文闸门（"." 手机号要电话上下文、空格分组银行卡要卡号上下文等）只用于
    "认出"号码；值已经确定是敏感号码后，同值的每处出现都要替换，不再要求上下文。
    仍按数字边界判断：前后紧挨数字、或与邻接数字组同属一个更长分组串时不算（见
    ``_part_of_longer``），不会把包含该号码的更长数字串改写。区间只覆盖号码本身。

    在归一化视图上用该类别的预编译形状单遍扫描，每处匹配压成纯数字后查值集合，
    开销与文本长度成线性，与命中数、候选值个数无关。
    """
    if not content or not values:
        return []
    wanted = {value.upper() for value in values if len(value) in _VALUE_LENGTHS[category]}
    if not wanted:
        return []
    view = view or normalize_view(content)
    text = view.text
    if _ANY_DIGIT.search(text) is None:
        return []
    spans: List[Tuple[int, int]] = []
    for pattern in _SCAN_PATTERNS[category]:
        for match in pattern.finditer(text):
            ms, me = match.span(1)
            raw = match.group(1)
            if compact_digits(raw).upper() not in wanted:
                continue
            if any(
                adjacent is not None and _part_of_longer(category, raw, adjacent[0], adjacent[1], before)
                for before in (True, False)
                for adjacent in (_adjacent_group(text, ms, me, before),)
            ):
                continue
            spans.append(view.source_span(ms, me))
    return spans
