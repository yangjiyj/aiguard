"""小语种占比判定：区别于"出现即命中"，按 Unicode 区块字符占比路由。

纯函数。命中返回占比最高且 >= 阈值的脚本信号，否则 None。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

RATIO_THRESHOLD = 0.30
_MIN_ALPHA = 8

_SCRIPTS = {
    "arabic": re.compile(r"[\u0600-\u06FF\u0750-\u077F]"),
    "cyrillic": re.compile(r"[\u0400-\u04FF]"),
    "tibetan": re.compile(r"[\u0F00-\u0FFF]"),
    "mongolian": re.compile(r"[\u1800-\u18AF]"),
    "uyghur_kazakh": re.compile(r"[ئات-غف-ي]"),
    "thai": re.compile(r"[\u0E00-\u0E7F]"),
    "devanagari": re.compile(r"[\u0900-\u097F]"),
}


@dataclass
class LowResourceSignal:
    script: str
    ratio: float
    preview: str
    route_to_judge: bool = True


def detect_low_resource(text: str):
    if not text:
        return None
    alpha = [c for c in text if c.isalpha()]
    if len(alpha) < _MIN_ALPHA:
        return None

    best_script = None
    best_ratio = 0.0
    for script, pattern in _SCRIPTS.items():
        count = sum(1 for c in alpha if pattern.match(c))
        ratio = count / len(alpha)
        if ratio > best_ratio:
            best_ratio = ratio
            best_script = script

    if best_script is None or best_ratio < RATIO_THRESHOLD:
        return None
    return LowResourceSignal(
        script=best_script, ratio=best_ratio, preview=text[:32]
    )
