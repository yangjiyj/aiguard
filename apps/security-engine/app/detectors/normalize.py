"""文本归一化与多编码解码，用于解码后重扫，对抗变形绕过。

纯函数；解码失败/二进制载荷一律跳过，不抛异常。
"""
from __future__ import annotations

import base64
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

# 零宽与软连字符 -> 删除
_ZERO_WIDTH = {
    0x200B: None, 0x200C: None, 0x200D: None, 0x200E: None, 0x200F: None,
    0xFEFF: None, 0x00AD: None, 0x2060: None,
}

# 常见同形字 -> ASCII（西里尔/希腊 -> 拉丁）
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "А": "A", "Е": "E",
    "О": "O", "Р": "P", "С": "C", "Х": "X",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "υ": "u",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}


@dataclass
class DecodedPayload:
    method: str
    text: str


def normalize_text(text: str) -> str:
    if not text:
        return text
    stripped = text.translate(_ZERO_WIDTH)
    folded = stripped.translate(_HOMOGLYPH_TABLE)
    return unicodedata.normalize("NFKC", folded)


def _is_mostly_printable(text: str, threshold: float = 0.8) -> bool:
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t ")
    return printable / len(text) >= threshold


_RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_RE_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_RE_UNICODE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}")
_RE_URL = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")


def decode_payloads(text: str) -> list[DecodedPayload]:
    if not text:
        return []
    out: list[DecodedPayload] = []

    for m in _RE_BASE64.findall(text):
        if len(m) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(m, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_mostly_printable(decoded):
            out.append(DecodedPayload("base64", decoded))

    for m in _RE_HEX.findall(text):
        try:
            decoded = bytes.fromhex(m.replace("\\x", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_mostly_printable(decoded):
            out.append(DecodedPayload("hex", decoded))

    for m in _RE_UNICODE.findall(text):
        try:
            decoded = m.encode().decode("unicode_escape")
        except (UnicodeDecodeError, ValueError):
            continue
        if _is_mostly_printable(decoded):
            out.append(DecodedPayload("unicode", decoded))

    for m in _RE_URL.findall(text):
        decoded = urllib.parse.unquote(m)
        if decoded != m and _is_mostly_printable(decoded):
            out.append(DecodedPayload("url", decoded))

    return out
