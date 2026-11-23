"""种子集装配 CLI（spec §5A/§6）：合成 → 清洗 → 去重 → 产标注 JSONL。

LLM 可注入（mock/真），开源集清洗结果合入，近重去重后写 source=seed 的标注行。
v1 目标几百~上千条；attack/benign 均衡 + 难负样本足（由 synth BENIGN_SPECS 保证）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

from .synth import Synthesizer, LLMClient
from .opensource import map_records
from .dedup import dedup_rows
from .schema import validate_row


def assemble_seed(*, llm: LLMClient, per_attack: int, per_benign: int,
                  opensource: List[Tuple[str, list]], out_path: Path,
                  dedup_threshold: float = 0.9) -> int:
    rows = list(Synthesizer(llm=llm).synthesize(
        per_attack=per_attack, per_benign=per_benign))
    for source, records in opensource:
        res = map_records(source, records)
        rows.extend(res.rows)
    rows, _removed = dedup_rows(rows, threshold=dedup_threshold)
    for r in rows:
        validate_row(r)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(rows)
