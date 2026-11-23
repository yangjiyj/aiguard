"""统一文本归一化视图：检测在归一化文本上做，命中位置映射回原文。

为什么需要
    同一个手机号/身份证/关键字可以换种写法绕过字面匹配：全角数字 ``１３８…``、
    零宽字符隔开 ``138<U+200B>0013…``、字间插空格 ``蓝鲸 Z9``。检测器在"归一化视图"上
    匹配即可识别这些写法；但脱敏和留证必须落到**原文**，所以视图同时保存
    "归一化文本第 i 个字符来自原文第几个字符"的映射。

视图做了什么（逐字符，保证映射精确）
    1. NFKC：全角→半角、兼容字形→标准字形（逐字符做，不跨字符组合）。
    2. 删除不可见字符：Unicode Cf 类（U+200B/200C/200D/2060/FEFF/00AD、双向控制、
       U+E0000 标签字符等）、变体选择符、少量填充字符。
    3. 可选折叠：``fold_text`` 折叠汉字之间的分隔符（车道 B 辱骂词检测用）；
       ``keyword_view`` 折叠紧挨汉字的空白（自定义关键字用）。
    数字分隔符（空格、-、.、全角空格）与 +86/0086/86 前缀不在视图里删除，
    由各数字类 PII 正则按固定分组识别（见 ``DIGIT_SEP``、``compact_digits``），
    避免把两个无关数字拼成一个号码。

映射约定
    ``index[i]`` 是 ``text[i]`` 对应的原文下标（一个原文字符 NFKC 展开成多个字符时，
    这些字符共享同一下标）。归一化区间 ``[s, e)`` 对应原文区间
    ``[index[s], index[e-1] + 1)``：区间内被删掉的零宽字符/分隔符一并包含，区间外的
    不会被带进来。脱敏替换这个原文区间即可，上游不会残留可拼回明文的片段。

性能
    纯 ASCII 文本直接返回恒等视图（``index`` 为 ``range``，不分配列表）。一对一替换
    （全角字母数字/标点、表意空格）用 ``str.translate`` 在 C 层完成，下标仍是恒等 ``range``；
    只有删除（零宽）或一变多（``⑴``）的字符逐个处理并建映射列表。字符表在导入时
    按当前 Python 的 Unicode 表计算一次（约 50ms）。

本模块是纯函数，无全局可变状态（除只读缓存），线程安全。
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Sequence, Tuple

__all__ = [
    "NormalizedText",
    "normalize_view",
    "fold_view",
    "fold_text",
    "keyword_view",
    "normalize_keyword",
    "source_span",
    "is_cjk",
    "is_invisible",
    "DIGIT_SEP",
    "compact_digits",
]

_INVISIBLE_EXTRA = frozenset({0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x180E})
_CHAR_CACHE: Dict[str, str] = {}
_CHAR_CACHE_LIMIT = 20000


def is_cjk(ch: str) -> bool:
    """是否为 CJK 统一汉字（含扩展 A、兼容汉字、扩展 B）。空串返回 False。"""
    if not ch:
        return False
    cp = ord(ch)
    return (0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF
            or 0xF900 <= cp <= 0xFAFF or 0x20000 <= cp <= 0x2A6DF)


def is_invisible(ch: str) -> bool:
    """零宽/格式控制/变体选择符等不可见字符：归一化时直接删除。"""
    cp = ord(ch)
    return (unicodedata.category(ch) == "Cf" or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF or cp in _INVISIBLE_EXTRA)


def _normalized_char(ch: str) -> str:
    """单字符 NFKC；不可见字符返回空串。带有界缓存。"""
    cached = _CHAR_CACHE.get(ch)
    if cached is None:
        if is_invisible(ch):
            cached = ""
        else:
            cached = "".join(c for c in unicodedata.normalize("NFKC", ch) if not is_invisible(c))
        if len(_CHAR_CACHE) < _CHAR_CACHE_LIMIT:
            _CHAR_CACHE[ch] = cached
    return cached


def _char_class(codepoints: List[int]) -> "re.Pattern[str]":
    """BMP 码点编译成字符类，并整体附上非 BMP 区间。

    re 对 BMP 字符类用位图 O(1) 判断；若把第 1/2/14 平面的上百个零散区间也放进去，
    每个字符都要逐个比区间（100KB 中文从 0.5ms 变 5ms）。非 BMP 字符很少，统一交给
    逐字符路径即可（_normalized_char 对不变的字符原样返回）。
    """
    ranges: List[List[int]] = []
    for cp in codepoints:
        if ranges and ranges[-1][1] == cp - 1:
            ranges[-1][1] = cp
        else:
            ranges.append([cp, cp])
    body = "".join(
        re.escape(chr(a)) if a == b else f"{re.escape(chr(a))}-{re.escape(chr(b))}"
        for a, b in ranges
    )
    return re.compile(f"[{body}{chr(0x10000)}-{chr(0x10FFFF)}]+")


def _build_tables() -> Tuple["re.Pattern[str]", "re.Pattern[str]", Dict[int, str]]:
    """预计算"归一化后会变化"的字符，按是否一对一拆成两类。

    - 一对一（全角字母数字、全角标点、表意空格……）：放进 str.translate 表，C 层一次替换，
      下标映射保持恒等；
    - 删除或一变多（零宽、⑴→(1)、ﬁ→fi……）以及全部非 BMP 字符（数学字母数字、
      第 14 平面标签字符等）：编译成字符类，逐字符处理并记录映射。
    """
    unstable: List[int] = []
    irregular: List[int] = []
    one_to_one: Dict[int, str] = {}
    spans = (range(0x80, 0xD800), range(0xE000, 0x10000))
    normalize, category = unicodedata.normalize, unicodedata.category
    for span in spans:
        for cp in span:
            ch = chr(cp)
            # 与 _normalized_char(ch) != ch 等价，内联以缩短导入耗时
            if (normalize("NFKC", ch) != ch or category(ch) == "Cf"
                    or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF
                    or cp in _INVISIBLE_EXTRA):
                unstable.append(cp)
                mapped = _normalized_char(ch)
                if len(mapped) == 1:
                    one_to_one[cp] = mapped
                else:
                    irregular.append(cp)
    return _char_class(unstable), _char_class(irregular), one_to_one


_UNSTABLE_RUN, _IRREGULAR_RUN, _ONE_TO_ONE = _build_tables()
_CHAR_CACHE.clear()


@dataclass(frozen=True)
class NormalizedText:
    """归一化视图。

    属性
        source: 原文。
        text:   归一化文本，检测器在它上面匹配。
        index:  ``index[i]`` 为 ``text[i]`` 的原文下标；恒等视图时是 ``range``。
    """

    source: str
    text: str
    index: Sequence[int]

    @property
    def changed(self) -> bool:
        """视图与原文是否不同（False 时可直接用原文坐标）。"""
        return self.text != self.source

    def source_span(self, start: int, end: int) -> Tuple[int, int]:
        """把归一化区间 ``[start, end)`` 映射为原文区间（含区间内被删的字符）。"""
        return source_span(self.index, start, end, len(self.source))

    def source_slice(self, start: int, end: int) -> str:
        """归一化区间对应的原文片段。"""
        s, e = self.source_span(start, end)
        return self.source[s:e]


def source_span(index: Sequence[int], start: int, end: int, source_len: int) -> Tuple[int, int]:
    """映射函数的独立版本：适用于只拿到 ``(text, index)`` 二元组的调用方。

    空区间映射到其插入点（``end`` 位置对应的原文下标），越界钳到原文长度。
    """
    n = len(index)
    if start >= end:
        point = index[start] if start < n else source_len
        return point, point
    if start < 0 or end > n:
        raise ValueError("span out of normalized range")
    return index[start], index[end - 1] + 1


def _identity(text: str) -> NormalizedText:
    return NormalizedText(text, text, range(len(text)))


def normalize_view(text: str) -> NormalizedText:
    """NFKC + 删除不可见字符，保留到原文的逐字符映射。

    例：原文 "手机 １３８<U+200B>0013" 的视图文本是 "手机 1380013"，
    视图区间 [3, 10) 映射回原文 [3, 11)，即连同零宽字符一起的 "１３８<U+200B>0013"。
    """
    if not text or text.isascii():
        return _identity(text or "")
    if _UNSTABLE_RUN.search(text) is None:
        return _identity(text)
    first = _IRREGULAR_RUN.search(text)
    if first is None:
        # 只有一对一替换：长度不变，下标恒等
        return NormalizedText(text, text.translate(_ONE_TO_ONE), range(len(text)))
    pieces: List[str] = []
    index: List[int] = []
    cursor = 0
    for run in _IRREGULAR_RUN.finditer(text, first.start()):
        start, end = run.span()
        if start > cursor:
            pieces.append(text[cursor:start].translate(_ONE_TO_ONE))
            index.extend(range(cursor, start))
        for position in range(start, end):
            piece = _normalized_char(text[position])
            if piece:
                pieces.append(piece)
                index.extend([position] * len(piece))
        cursor = end
    if cursor < len(text):
        pieces.append(text[cursor:].translate(_ONE_TO_ONE))
        index.extend(range(cursor, len(text)))
    return NormalizedText(text, "".join(pieces), index)


@lru_cache(maxsize=64)
def _separator_run(separators: str) -> "re.Pattern[str]":
    return re.compile("[" + "".join(re.escape(c) for c in separators) + "]+")


def _compose(view: NormalizedText, drops: List[Tuple[int, int]]) -> NormalizedText:
    """从视图中删去若干 ``[s, e)`` 区间（视图坐标，升序不重叠），映射随之收缩。"""
    if not drops:
        return view
    text, index = view.text, view.index
    pieces: List[str] = []
    new_index: List[int] = []
    cursor = 0
    for start, end in drops:
        pieces.append(text[cursor:start])
        new_index.extend(index[cursor:start])
        cursor = end
    pieces.append(text[cursor:])
    new_index.extend(index[cursor:])
    return NormalizedText(view.source, "".join(pieces), new_index)


def fold_view(text: str, separators: str) -> NormalizedText:
    """归一化后，再删除"夹在两个汉字之间"的分隔符串。

    规则与车道 B（辱骂词）原 ``fold_text`` 完全一致：分隔符串前一个字符是汉字，
    且后一个字符是汉字，或是后面不接字母数字的 ``b/B/x/X``（"傻 b"、"妈 x"）时折叠；
    句末标点和换行由调用方不放进 ``separators`` 即可保留。
    """
    view = normalize_view(text)
    if not separators or view.text.isascii():
        return view
    norm = view.text
    n = len(norm)
    drops: List[Tuple[int, int]] = []
    for run in _separator_run(separators).finditer(norm):
        i, j = run.span()
        prev = norm[i - 1] if i else ""
        nxt = norm[j] if j < n else ""
        if prev and is_cjk(prev) and nxt and (
            is_cjk(nxt) or (nxt in "bBxX" and (j + 1 >= n or not norm[j + 1].isalnum()))
        ):
            drops.append((i, j))
    return _compose(view, drops)


def fold_text(text: str, separators: str) -> Tuple[str, Sequence[int]]:
    """车道 B ``profanity.fold_text`` 的直接替换：返回 ``(归一化文本, idx)``。

    ``idx[i]`` 是归一化文本第 i 个字符对应的原文下标；命中 ``[s, e)`` 的原文区间为
    ``[idx[s], idx[e-1] + 1)``。
    """
    view = fold_view(text, separators)
    return view.text, view.index


_WS_RUN = re.compile(r"\s+")


def keyword_view(text: str) -> NormalizedText:
    """自定义关键字匹配视图：归一化 + 折叠紧挨汉字的空白。

    空白串任一侧是汉字就删除（"绝密 项目"→"绝密项目"，"蓝鲸 Z9"→"蓝鲸Z9"）；
    两侧都不是汉字（英文单词之间）保留原样，不改变 "top secret" 的语义。
    关键字本身用 ``normalize_keyword`` 做同样处理后再匹配。
    """
    view = normalize_view(text)
    norm = view.text
    if norm.isascii():
        return view
    n = len(norm)
    drops: List[Tuple[int, int]] = []
    for run in _WS_RUN.finditer(norm):
        i, j = run.span()
        if (i and is_cjk(norm[i - 1])) or (j < n and is_cjk(norm[j])):
            drops.append((i, j))
    return _compose(view, drops)


def normalize_keyword(keyword: str) -> str:
    """关键字的归一化形式（与 ``keyword_view`` 对正文的处理一致）。"""
    return keyword_view(keyword).text


# 数字类 PII 分组之间允许的分隔符（归一化视图里：全角空格已成为空格，全角横线
# 已成为 ASCII 横线）。只在固定分组位置出现，长度有界，与 \d 不相交，不会回溯爆炸。
DIGIT_SEP = r"[ \-.\u2010-\u2015\u2212]{0,3}"
_NON_ID_CHARS = re.compile(r"[^0-9Xx]")


def compact_digits(value: str) -> str:
    """去掉号码中的分隔符，得到规范值（身份证末位 X/x 保留）。"""
    return _NON_ID_CHARS.sub("", value)
