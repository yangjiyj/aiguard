"""Offline admission-recall gate for the Tier-1 cascade.

Why this exists
---------------
`SECURITY_TIER1_LOW_THRESHOLD=0.0` (the live control-plane value) disables the
legacy cascade: every window goes to the judge. The obvious cost fix is "skip
low-score windows that have no admission cue". That is NOT safe with the
current deterministic signals.

Measured on the bundled labelled corpus (bench/data/zh_jailbreak.jsonl and
zh_benign.jsonl), with a worst-case Tier-1 that scores every sample low:

    signal                     attack admitted / 80   benign signalled / 82
    admission_cues                     16 (20.0%)            2
    instruction_evidence               16 (20.0%)            2
    indirect_instruction_signal        12 (15.0%)            2
    explicit exfil anchors              8 (10.0%)            1
    MCP poison patterns                15 (18.8%)           15
    union of all of the above          35 (43.8%)           17

So cue-based skipping would silently drop at least 56% of labelled jailbreaks
before the judge ever sees them. That violates the "no recall regression" red
line. The cascade guard therefore stays OFF unless an offline corpus gate
proves that the deterministic pre-filters admit every labelled attack.

This module measures that lower bound. It does NOT claim to measure end-to-end
recall: that needs the real Tier-1 model and the live judge. A passing gate is
a necessary condition, not a sufficient one. The acceptance replay on the
64C + GPU host remains mandatory before the default can be switched.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Callable, Optional

from app.detectors.cascade_signals import admission_cues, instruction_evidence

_CORPUS_DIR = Path(__file__).resolve().parents[1] / "bench" / "data"
_REQUIRED_RECALL = 1.0
_cache_lock = threading.Lock()
_cached: Optional[dict] = None


def _signals(text: str) -> bool:
    """Union of every high-precision pre-filter available before the judge."""
    if admission_cues(text) or instruction_evidence(text):
        return True
    try:
        from app.detectors.prompt_injection import indirect_instruction_signal
        if indirect_instruction_signal(text):
            return True
    except Exception:
        pass
    try:
        from app.detectors.semantic import _has_explicit_exfil_signal
        if _has_explicit_exfil_signal(text):
            return True
    except Exception:
        pass
    try:
        from app.detectors.agent_guard import _POISON_PATTERNS
        if any(pattern.search(text) for pattern in _POISON_PATTERNS):
            return True
    except Exception:
        pass
    return False


def _load(name: str) -> list:
    path = _CORPUS_DIR / name
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("text"), str):
            rows.append(row)
    return rows


def corpus_texts() -> dict:
    """Labelled texts for offline cost measurement; no model or judge needed."""
    return {
        "attacks": [row["text"] for row in _load("zh_jailbreak.jsonl")],
        "benign": [row["text"] for row in _load("zh_benign.jsonl")],
    }


def evaluate_corpus(*, signal: Optional[Callable[[str], bool]] = None) -> dict:
    """Admission-level recall / FP / judge-call comparison for three policies."""
    detector = signal or _signals
    attacks = _load("zh_jailbreak.jsonl")
    benign = _load("zh_benign.jsonl")
    attack_admitted = sum(1 for row in attacks if detector(row["text"]))
    benign_admitted = sum(1 for row in benign if detector(row["text"]))
    n_attack, n_benign = len(attacks), len(benign)
    recall = attack_admitted / n_attack if n_attack else 0.0
    fp_rate = benign_admitted / n_benign if n_benign else 0.0
    total = n_attack + n_benign
    return {
        "attack_samples": n_attack,
        "benign_samples": n_benign,
        "attack_admitted_by_prefilters": attack_admitted,
        "benign_admitted_by_prefilters": benign_admitted,
        "admission_recall_lower_bound": round(recall, 4),
        "admission_false_positive_upper_bound": round(fp_rate, 4),
        # legacy @ low=0.0: every window goes to the judge (baseline = 100% recall).
        "judge_calls_legacy_low_0": total,
        "judge_calls_cue_skipping": attack_admitted + benign_admitted,
        "judge_call_reduction": round(1 - (attack_admitted + benign_admitted) / total, 4) if total else 0.0,
        "required_recall": _REQUIRED_RECALL,
        "guard_allowed": n_attack > 0 and recall >= _REQUIRED_RECALL,
    }


def recall_gate() -> dict:
    global _cached
    with _cache_lock:
        if _cached is None:
            _cached = evaluate_corpus()
        return dict(_cached)


def guard_activation(*, low_threshold: float, policy: str,
                     requested: Optional[bool] = None) -> tuple:
    """Return (active, reason, gate_metrics). Never active without a passing gate."""
    if requested is None:
        requested = os.getenv("SECURITY_SEMANTIC_CASCADE_GUARD", "").strip().lower() in (
            "1", "true", "yes", "on", "enabled")
    if low_threshold >= 0.05:
        return False, "legacy_cascade_active", None
    if policy != "coverage_v2":
        return False, "coverage_v2_not_enabled", None
    if not requested:
        return False, "guard_not_requested", recall_gate()
    gate = recall_gate()
    if not gate["guard_allowed"]:
        return False, "cascade_guard_recall_below_baseline", gate
    return True, "guard_active", gate


def reset_gate() -> None:
    global _cached
    with _cache_lock:
        _cached = None
