"""近重去重（纯 stdlib，CI 可跑）。

字符 bigram 集合 Jaccard 相似度，按 label 分桶内去近重，保留首见。
spec §5A 的 embedding 近重去重在 B 组训练管线落地；此处为无 embedder 环境
的等价启发式，给种子集质量把关，防同义改写撑虚召回/精度。
"""
from __future__ import annotations

from typing import List, Tuple


def _bigrams(text: str) -> set:
    s = "".join(text.split())  # 去空白，按字符切
    if len(s) < 2:
        return {s} if s else set()
    return {s[i:i + 2] for i in range(len(s) - 1)}


def jaccard_bigrams(a: str, b: str) -> float:
    ga, gb = _bigrams(a), _bigrams(b)
    if not ga and not gb:
        return 1.0
    inter = len(ga & gb)
    union = len(ga | gb)
    return inter / union if union else 0.0


def dedup_rows(rows: List[dict], *, threshold: float = 0.9) -> Tuple[List[dict], int]:
    """同 label 桶内去近重；返回 (保留行, 丢弃数)。相似度 >= threshold 视为近重。"""
    kept: List[dict] = []
    removed = 0
    by_label: dict = {}
    for row in rows:
        bucket = by_label.setdefault(row["label"], [])
        if any(jaccard_bigrams(row["text"], k) >= threshold for k in bucket):
            removed += 1
            continue
        bucket.append(row["text"])
        kept.append(row)
    return kept, removed
