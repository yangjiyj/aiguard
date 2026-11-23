"""检测能力说明目录：每个检测能力“具体匹配什么”、示例和显示方式。

唯一来源是 app/data/capability_docs/*.json。控制面用的副本由
deploy/maintenance/gen_capability_docs.py 生成，测试保证两份一致。
规格：docs/superpowers/specs/2026-11-14-hit-visibility-design.md 4.8。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Dict, Mapping, Optional, Tuple

from app.detectors.hit_display import DISPLAY_KINDS

DOCS_DIR = (Path(__file__).parent / "data" / "capability_docs").resolve()
CHECKS = frozenset({"input", "output", "none"})
FIELDS = frozenset({"category", "display", "matches", "hit_examples", "miss_examples", "judged_by_ai", "check"})
MAX_MATCHES_CHARS = 200
MAX_EXAMPLE_CHARS = 300


class CapabilityDocError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilityDoc:
    category: str
    display: str
    matches: str
    hit_examples: Tuple[str, ...]
    miss_examples: Tuple[str, ...]
    judged_by_ai: bool
    check: str


def _text(value, label: str, source: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > max_chars:
        raise CapabilityDocError(f"{source}: {label} 需为 1–{max_chars} 字、首尾无空白的非空字符串")
    return value


def _examples(entry: Mapping, key: str, source: str, low: int, high: int) -> Tuple[str, ...]:
    values = entry.get(key)
    if not isinstance(values, list) or not (low <= len(values) <= high):
        raise CapabilityDocError(f"{source}: {entry.get('category')} 的 {key} 需要 {low}–{high} 条")
    for value in values:
        _text(value, f"{entry.get('category')} 的 {key} 每条", source, MAX_EXAMPLE_CHARS)
    if len(set(values)) != len(values):
        raise CapabilityDocError(f"{source}: {entry.get('category')} 的 {key} 有重复示例")
    return tuple(values)


def _parse_entry(entry, source: str) -> CapabilityDoc:
    if not isinstance(entry, dict):
        raise CapabilityDocError(f"{source}: 条目需为对象")
    extra = sorted(set(entry) - FIELDS)
    missing = sorted(FIELDS - set(entry))
    if extra or missing:
        raise CapabilityDocError(f"{source}: 字段不符，多出 {extra}，缺少 {missing}")
    category = _text(entry["category"], "category", source, 200)
    display = entry["display"]
    if not isinstance(display, str) or display not in DISPLAY_KINDS:
        raise CapabilityDocError(f"{source}: {category} 的 display 取值无效")
    matches = _text(entry["matches"], f"{category} 的 matches", source, MAX_MATCHES_CHARS)
    judged = entry["judged_by_ai"]
    check = entry["check"]
    if not isinstance(check, str) or check not in CHECKS:
        raise CapabilityDocError(f"{source}: {category} 的 check 取值无效")
    if not isinstance(judged, bool) or (judged and check != "none"):
        raise CapabilityDocError(f"{source}: {category} 的 check 与 judged_by_ai 不一致")
    hits = _examples(entry, "hit_examples", source, 1, 3)
    misses = _examples(entry, "miss_examples", source, 0 if check == "none" else 1, 2)
    if set(hits) & set(misses):
        raise CapabilityDocError(f"{source}: {category} 的同一示例不能同时在 hit_examples 和 miss_examples 里（重复）")
    return CapabilityDoc(category, display, matches, hits, misses, judged, check)


def parse_docs(files: Mapping[str, str]) -> Dict[str, CapabilityDoc]:
    """files：文件名 → JSON 文本（每个文件是条目数组）。"""
    docs: Dict[str, CapabilityDoc] = {}
    for name in sorted(files):
        try:
            entries = json.loads(files[name])
        except ValueError as error:
            raise CapabilityDocError(f"{name}: JSON 语法错误：{error}") from error
        if not isinstance(entries, list):
            raise CapabilityDocError(f"{name}: 顶层需为数组")
        for entry in entries:
            doc = _parse_entry(entry, name)
            if doc.category in docs:
                raise CapabilityDocError(f"{name}: {doc.category} 重复出现")
            docs[doc.category] = doc
    return docs


@lru_cache(maxsize=1)
def load_capability_docs() -> Mapping[str, CapabilityDoc]:
    return MappingProxyType(parse_docs({path.name: path.read_text(encoding="utf-8") for path in DOCS_DIR.glob("*.json")}))


def display_kind(category: str) -> Optional[str]:
    doc = load_capability_docs().get(category or "")
    return doc.display if doc else None
