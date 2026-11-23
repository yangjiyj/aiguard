"""把种子标注 JSONL（text/label/category，label 为 1/0）摄取进 LabelStore。

约定：label 1→"attack"，0→"benign"；source 一律 "seed"；
良性缺 category 或非法 category → "none"。同文本去重（按 text，含库内已有行，跨批不重复落库）。
复用 apps/security-engine/bench/data/ 的 zh_jailbreak.jsonl + zh_benign.jsonl。

容错（本职是面对外部/众包脏数据，单行脏数据不得中止整批摄取）：
  - 非法 JSON 行 → 跳过并计 skipped_bad_json；
  - label 无法解析为整数（None/字符串标签/空串等）→ 跳过并计 skipped_invalid_label；
  - attack 行 category 缺失或非法（不在 4 类合法集内）→ 跳过并计 skipped_invalid_category，
    不把它伪造成 'none' 喂给 fail-closed 的 LabelStore.add（那会抛错炸掉整批）。
  良性行缺/非法 category 仍归一为 'none'（良性 category 契约就是 'none'）。
跳过计数写入可选的 stats dict（不传则静默跳过，happy-path 返回值不变）。
"""
from __future__ import annotations

import json
from typing import Iterable, Optional, Dict

from training.label_store import LabelStore

_VALID_CATS = {
    "semantic_jailbreak",
    "semantic_roleplay",
    "semantic_instruction_override",
    "semantic_exfil_induce",
}


def _normalize_category(cat, label: Optional[str] = None) -> str:
    """归一 category。

    benign 行无条件归一为 'none'（benign 契约就是 category=='none'，
    任何残留攻击类 category 都丢弃）——否则把残留攻击类原样喂给
    fail-closed 的 LabelStore.add 会抛 "benign 行 category 必须为 'none'"
    中止整批摄取。attack/未知 label 行：合法 4 类保留，否则 'none'。
    """
    if label == "benign":
        return "none"
    return cat if isinstance(cat, str) and cat in _VALID_CATS else "none"


def _parse_label(raw) -> Optional[str]:
    """把 label 字段解析为 'attack'/'benign'；无法解析为整数则返回 None（视为脏行）。

    缺省（键不存在）按 0→benign 处理；显式给了无法解析的脏值（None/'attack'/''
    等）则返回 None 让调用方跳过，不让一条脏标签炸掉整批摄取。
    """
    try:
        return "attack" if int(raw) == 1 else "benign"
    except (TypeError, ValueError):
        return None


def ingest_seed_jsonl(
    paths: Iterable[str],
    store: LabelStore,
    stats: Optional[Dict[str, int]] = None,
) -> int:
    # RFIX-3(b) 去重扩展到“库内已有行”，而非仅单次调用内 per-call 去重：
    # 预载已入库文本，跨批摄取重叠文本不重复落库、added 只计真正新增。
    # （LabelStore.add 本身也按 text 幂等去重，这里额外过滤是为让 added
    #  计数真实反映“新增条数”而非把库内已有行也算进去。）
    seen: set[str] = {row["text"] for row in store.iter()}
    added = 0
    skipped_bad_json = 0
    skipped_invalid_label = 0
    skipped_invalid_category = 0
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    skipped_bad_json += 1
                    continue
                if not isinstance(obj, dict):
                    skipped_bad_json += 1
                    continue
                text = obj.get("text", "")
                if not isinstance(text, str) or not text.strip() or text in seen:
                    continue
                label = _parse_label(obj.get("label", 0))
                if label is None:
                    skipped_invalid_label += 1
                    continue
                category = _normalize_category(obj.get("category"), label)
                # 对称拦截 / 归一，避免脏行触发 fail-closed 的 store.add 中止整批：
                #   - attack 行 category 必须 ∈ 4 类合法集；缺/非法已归一成 'none'，
                #     而 'none' 对 attack 行非法 → 跳过并计 skipped_invalid_category；
                #   - benign 行残留的攻击类 category 已被 _normalize_category 强制
                #     归一为 'none'（benign 契约就是 'none'），无需跳过、不丢数据。
                if label == "attack" and category == "none":
                    skipped_invalid_category += 1
                    continue
                store.add(text, label, category, "seed")
                seen.add(text)
                added += 1
    if stats is not None:
        stats["skipped_bad_json"] = skipped_bad_json
        stats["skipped_invalid_label"] = skipped_invalid_label
        stats["skipped_invalid_category"] = skipped_invalid_category
    return added
