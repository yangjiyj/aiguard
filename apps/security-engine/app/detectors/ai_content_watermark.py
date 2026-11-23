"""
JJDGuard 自家 AI 生成内容水印的格式识别。

网关在交付层给门户回复追加零宽水印帧（见 packages/shared-go/aicontentlabel）。员工把带水印的
回复贴回输入时，零宽字符检测不应把它当成隐写攻击。这里只识别格式完整的帧：两个 U+2063 起点、
84 个数据符号（U+200B U+200C U+200D U+2060）、一个 U+2064 终点，格式字节为 0 或 1。
引擎不持有密钥，不校验 HMAC；伪造一个格式正确的帧只能藏 20 字节固定结构的数据，帧外的零宽字符照旧检测。
"""
from typing import List, Tuple

_MARK = chr(0x2063)  # INVISIBLE SEPARATOR，两个连写为帧起点
_END = chr(0x2064)  # INVISIBLE PLUS，帧终点
# 2 位符号 0..3：ZERO WIDTH SPACE、ZERO WIDTH NON-JOINER、ZERO WIDTH JOINER、WORD JOINER。
_SYMBOLS = {chr(0x200B): 0, chr(0x200C): 1, chr(0x200D): 2, chr(0x2060): 3}
_PAYLOAD_BYTES = 21
_DATA_SYMBOLS = _PAYLOAD_BYTES * 4
FRAME_CHARS = 2 + _DATA_SYMBOLS + 1


def _decode_at(text: str, start: int) -> bool:
    """start 处是否是一个格式完整的帧（start 指向第一个起点符号）。"""
    end = start + FRAME_CHARS
    if end > len(text) or text[start] != _MARK or text[start + 1] != _MARK or text[end - 1] != _END:
        return False
    first = 0
    for i in range(_DATA_SYMBOLS):
        value = _SYMBOLS.get(text[start + 2 + i])
        if value is None:
            return False
        if i < 4:
            first = (first << 2) | value
    return first in (0, 1)


def find_watermark_spans(text: str) -> List[Tuple[int, int]]:
    """返回所有格式完整的水印帧的字符区间 [start, end)，按出现顺序。"""
    spans: List[Tuple[int, int]] = []
    if not text or _MARK not in text:
        return spans
    pos = 0
    while True:
        idx = text.find(_MARK + _MARK, pos)
        if idx < 0:
            return spans
        if _decode_at(text, idx):
            spans.append((idx, idx + FRAME_CHARS))
            pos = idx + FRAME_CHARS
        else:
            pos = idx + 1


def strip_watermarks(text: str) -> str:
    """去掉所有格式完整的水印帧。"""
    spans = find_watermark_spans(text)
    if not spans:
        return text
    parts = []
    last = 0
    for start, end in spans:
        parts.append(text[last:start])
        last = end
    parts.append(text[last:])
    return "".join(parts)
