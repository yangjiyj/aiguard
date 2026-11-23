"""把契约标注行转 bench 数据集格式并去重追加（扩充已有 40 条 seed）。

bench 格式：攻击 {text,label:1,category}；良性 {text,label:0}（无 category）。
追加时按 text 对已有文件去重，绝不破坏 test_bench_dataset.py 的 no-dup 守卫。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

from .schema import validate_row


def to_bench_rows(rows: List[dict]) -> Tuple[List[dict], List[dict]]:
    jb: List[dict] = []
    bn: List[dict] = []
    for r in rows:
        validate_row(r)
        if r["label"] == "attack":
            jb.append({"text": r["text"], "label": 1, "category": r["category"]})
        else:
            bn.append({"text": r["text"], "label": 0})
    return jb, bn


def _existing_texts(path: Path) -> set:
    if not path.exists():
        return set()
    out = set()
    for ln in path.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            out.add(json.loads(ln)["text"])
    return out


def append_to_bench(rows: List[dict], jb_path: Path, bn_path: Path) -> Tuple[int, int]:
    jb_path, bn_path = Path(jb_path), Path(bn_path)
    jb_new, bn_new = to_bench_rows(rows)

    # 全局去重：no-dup 守卫（test_bench_dataset.py::test_no_duplicate_texts）是对
    # zh_jailbreak + zh_benign 合并后查重，故 seen 必须跨两文件统一。否则同一条 text
    # 同时以 attack/benign 出现（矛盾标签的脏数据），per-file 去重会双写出跨文件重复。
    seen = _existing_texts(jb_path) | _existing_texts(bn_path)

    def _append(path: Path, items: List[dict]) -> int:
        added = 0
        with path.open("a", encoding="utf-8") as f:
            for it in items:
                if it["text"] in seen:
                    continue
                seen.add(it["text"])
                f.write(json.dumps(it, ensure_ascii=False) + "\n")
                added += 1
        return added

    return _append(jb_path, jb_new), _append(bn_path, bn_new)
