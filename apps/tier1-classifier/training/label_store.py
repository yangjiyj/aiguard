"""tier1_labels 标签存储（v1 后端=本地 SQLite，Phase 2 同 schema 映射 postgres）。

契约表: tier1_labels(id INTEGER PK, text, label, category, source, created_at)
label∈{benign,attack}; source∈{seed,distill,correction}。
category 契约（复用 seedgen/schema.py 单一真源，add() 内强制）:
  attack 行 category 必须 ∈ CATEGORIES（semantic.py 4 类 key）；benign 行 category 必须 == "none"。
接口: add(text,label,category,source) / iter()->rows(dict) / count()。
add() 按 text 幂等去重（先写为准）：同文本已在库则跳过、返回既有 id，不新增行，
  防 Phase 2 飞轮直写累积重复/矛盾标签（校验仍在去重之前 fail-closed）。
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Iterator, Dict, Any

from .seedgen.schema import CATEGORIES, LABELS, SOURCES

# 单一真源复用 schema.py，避免与合成器/清洗器契约漂移。
# 保留旧名 VALID_* 供既有调用方/测试，指向同一对象。
VALID_LABELS = LABELS
VALID_SOURCES = SOURCES
VALID_CATEGORIES = CATEGORIES

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tier1_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    label TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""


class LabelStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def add(self, text: str, label: str, category: str, source: str) -> int:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text 不能为空")
        if label not in VALID_LABELS:
            raise ValueError(f"label 必须属于 {VALID_LABELS}，得到 {label!r}")
        if source not in VALID_SOURCES:
            raise ValueError(f"source 必须属于 {VALID_SOURCES}，得到 {source!r}")
        if not isinstance(category, str) or not category:
            raise ValueError("category 不能为空（良性用 'none'）")
        # 按 label 分支强制 category 契约（对齐 seedgen/schema.py），
        # 拒绝脏训练数据沉默落库（fail-closed）。
        if label == "attack":
            if category not in VALID_CATEGORIES:
                raise ValueError(
                    f"attack 行 category 必须属于 {VALID_CATEGORIES}，得到 {category!r}"
                )
        else:  # benign
            if category != "none":
                raise ValueError(
                    f"benign 行 category 必须为 'none'，得到 {category!r}"
                )
        created_at = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self._db_path)
        try:
            # RFIX-3(a) 按 text 去重（先写为准）：同文本已在库则跳过、返回既有 id，
            # 不新增第二行。防 Phase 2 飞轮直写累积重复/矛盾标签。
            # 校验在前（见上），故此处只对已通过校验的干净行做幂等短路——
            # 脏行仍在校验阶段 fail-closed，绝不被“重复”悄悄放过。
            existing = conn.execute(
                "SELECT id FROM tier1_labels WHERE text = ? LIMIT 1", (text,)
            ).fetchone()
            if existing is not None:
                return int(existing[0])
            cur = conn.execute(
                "INSERT INTO tier1_labels(text,label,category,source,created_at) "
                "VALUES (?,?,?,?,?)",
                (text, label, category, source, created_at),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    def iter(self) -> Iterator[Dict[str, Any]]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            for row in conn.execute(
                "SELECT id,text,label,category,source,created_at "
                "FROM tier1_labels ORDER BY id"
            ):
                yield dict(row)
        finally:
            conn.close()

    def count(self) -> int:
        conn = sqlite3.connect(self._db_path)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM tier1_labels").fetchone()[0])
        finally:
            conn.close()
