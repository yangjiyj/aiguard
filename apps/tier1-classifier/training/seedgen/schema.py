"""标注行 schema 契约（纯 stdlib，合成器/清洗器/合并器共用）。

对齐 spec §5A 与 bench 数据集：label∈{benign,attack}，attack 必带真实
category（对齐 semantic.py 的 _CATEGORY_CN 4 类 key），benign 用 "none"。
"""
from __future__ import annotations

CATEGORIES = {
    "semantic_jailbreak",
    "semantic_roleplay",
    "semantic_instruction_override",
    "semantic_exfil_induce",
}
LABELS = {"benign", "attack"}
SOURCES = {"seed", "distill", "correction"}


class RowError(ValueError):
    """标注行不合契约。"""


def validate_row(row: dict) -> None:
    text = row.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RowError(f"text 必须为非空字符串: {row!r}")
    label = row.get("label")
    if label not in LABELS:
        raise RowError(f"label 必须 ∈ {LABELS}: {label!r}")
    source = row.get("source")
    if source not in SOURCES:
        raise RowError(f"source 必须 ∈ {SOURCES}: {source!r}")
    category = row.get("category")
    if label == "attack":
        if category not in CATEGORIES:
            raise RowError(f"attack 行 category 必须 ∈ {CATEGORIES}: {category!r}")
    else:
        if category != "none":
            raise RowError(f"benign 行 category 必须为 'none': {category!r}")
