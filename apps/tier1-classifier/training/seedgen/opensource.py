"""开源中文安全集清洗映射（spec §5A）。

把外部原始记录映射到本契约 {text,label,category,source=seed}。
每个开源集一个 mapper（来源声明 + 字段映射规则）。不可映射记录显式丢弃并计数。
来源（需各自遵守其许可，仅用于厂商侧离线训练，不进 git）：
  - safety_prompts: 清华 Safety-Prompts（不安全类→attack）
  - cvalues: CValues（safe→benign）
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .schema import validate_row

# Safety-Prompts 的不安全类型 → 本 4 类 category 的粗映射
_SAFETY_TYPE_TO_CATEGORY = {
    "Crimes_And_Illegal_Activities": "semantic_jailbreak",
    "Role_Play_Instruction": "semantic_roleplay",
    "Goal_Hijacking": "semantic_instruction_override",
    "Prompt_Leaking": "semantic_exfil_induce",
}
_DEFAULT_ATTACK_CATEGORY = "semantic_jailbreak"


@dataclass
class CleanResult:
    rows: List[dict] = field(default_factory=list)
    dropped: int = 0


def _map_safety_prompts(rec: dict) -> Optional[dict]:
    text = (rec.get("prompt") or "").strip()
    if not text:
        return None
    category = _SAFETY_TYPE_TO_CATEGORY.get(
        rec.get("type"), _DEFAULT_ATTACK_CATEGORY)
    return {"text": text, "label": "attack",
            "category": category, "source": "seed"}


def _map_cvalues(rec: dict) -> Optional[dict]:
    text = (rec.get("prompt") or "").strip()
    if not text:
        return None
    is_safe = rec.get("label") == "safe"
    if is_safe:
        return {"text": text, "label": "benign",
                "category": "none", "source": "seed"}
    return {"text": text, "label": "attack",
            "category": _DEFAULT_ATTACK_CATEGORY, "source": "seed"}


SOURCE_MAPPERS: Dict[str, Callable[[dict], Optional[dict]]] = {
    "safety_prompts": _map_safety_prompts,
    "cvalues": _map_cvalues,
}


def map_records(source: str, records: List[dict]) -> CleanResult:
    mapper = SOURCE_MAPPERS[source]  # 未知 source → KeyError（不静默）
    res = CleanResult()
    for rec in records:
        row = mapper(rec)
        if row is None:
            res.dropped += 1
            continue
        try:
            validate_row(row)
        except Exception:
            res.dropped += 1
            continue
        res.rows.append(row)
    return res
