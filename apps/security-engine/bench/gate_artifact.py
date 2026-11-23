"""bench 门产物：从 run_bench.run() 的 report 抽出 retrain 可消费的门结论。

spec §6：bench 不过线 → 不出不达标基线模型。retrain 训完融合 ONNX 后调 bench →
extract_gate_artifact 固化 {PASS/FAIL + low/high 阈值初值 + 召回/良性误升级} →
assert_release_allowed：FAIL 抛 GateNotPassedError（retrain 阻断），PASS 回传阈值初值。

纯 stdlib，门逻辑不在此重算（复用 metrics.decision_gate 的结论）；
capacity_multiplier 沿用 None（灰区 0 时）保证严格合法 JSON。
"""
from __future__ import annotations

import json
from typing import Dict, Optional, Tuple


class GateNotPassedError(RuntimeError):
    """bench 门未过线 → retrain 阻断，不出不达标基线模型。"""


def extract_gate_artifact(report: Dict) -> Dict:
    """从 bench report 抽门产物（retrain / 打包消费）。"""
    best = report["best"]
    gate = report["gate"]
    return {
        "scope": "tier1_routing_diagnostic",
        "end_to_end_passed": False,
        "passed": bool(gate["passed"]),
        "low_threshold": best["low"],
        "high_threshold": best["high"],
        "cascade_recall": best["cascade_recall_with_gray"],
        "benign_false_escalation_rate": best["benign_false_escalation_rate"],
        "gray_zone_rate": best["gray_zone_rate"],
        "capacity_multiplier": gate.get("capacity_multiplier"),
        "reason": gate.get("reason", ""),
        "fallback": gate.get("fallback"),
    }


def assert_release_allowed(artifact: Dict) -> Tuple[float, float]:
    """门 PASS → 回传 (low, high) 阈值初值；FAIL → 抛，retrain 阻断。"""
    if not artifact.get("passed"):
        fb = artifact.get("fallback") or "tier1_finetune"
        raise GateNotPassedError(
            f"bench 门未过线（{artifact.get('reason', '')}）→ 不出基线模型，"
            f"fallback={fb}（调种子/换 embedder 重训后复测）。"
        )
    return artifact["low_threshold"], artifact["high_threshold"]


def write_gate_artifact(artifact: Dict, path: str) -> None:
    """严格 JSON 落盘（allow_nan=False，杜绝 Infinity/NaN 非法字面量）。"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, ensure_ascii=False, indent=2, allow_nan=False)
