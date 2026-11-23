import json

import pytest

from bench import gate_artifact as ga


def _report(passed, low=0.2, high=0.8, recall=0.95, benign_esc=0.05, gray=0.1):
    """构造一份与 run_bench.run() 同结构的最小 report。"""
    return {
        "counts": {"total": 82, "attack": 40, "benign": 42, "failopen_dropped": 0},
        "best": {
            "low": low, "high": high,
            "tier1_recall_high": recall, "cascade_recall_with_gray": recall,
            "benign_false_escalation_rate": benign_esc,
            "gray_zone_rate": gray, "precision_high": 0.9,
        },
        "gate": {
            "passed": passed,
            "reason": "ok" if passed else "recall 0.500 < 0.9",
            "capacity_multiplier": (None if gray == 0 else 1.0 / gray),
            "gray_zone_rate": gray,
            **({} if passed else {"fallback": "tier1_finetune"}),
        },
    }


def test_extract_artifact_pass_carries_thresholds():
    art = ga.extract_gate_artifact(_report(True, low=0.25, high=0.85))
    assert art["passed"] is True
    assert art["low_threshold"] == 0.25
    assert art["high_threshold"] == 0.85
    assert art["cascade_recall"] == pytest.approx(0.95)
    assert art["benign_false_escalation_rate"] == pytest.approx(0.05)
    assert art["fallback"] is None


def test_extract_artifact_fail_carries_fallback():
    art = ga.extract_gate_artifact(_report(False, recall=0.5))
    assert art["passed"] is False
    assert art["fallback"] == "tier1_finetune"


def test_artifact_is_strict_json_serializable_no_gray():
    art = ga.extract_gate_artifact(_report(True, gray=0.0))
    assert art["capacity_multiplier"] is None
    dumped = json.dumps(art, ensure_ascii=False, allow_nan=False)
    assert "Infinity" not in dumped and "NaN" not in dumped


def test_assert_release_allowed_blocks_on_fail():
    """门 FAIL → 不放行：retrain 据此阻断，绝不出不达标基线模型。"""
    bad = ga.extract_gate_artifact(_report(False, recall=0.5))
    with pytest.raises(ga.GateNotPassedError) as ei:
        ga.assert_release_allowed(bad)
    assert "tier1_finetune" in str(ei.value)


def test_assert_release_allowed_passes_on_pass():
    good = ga.extract_gate_artifact(_report(True))
    # 不抛，回传阈值初值供 retrain 写进模型 config / env 默认参考
    low, high = ga.assert_release_allowed(good)
    assert (low, high) == (0.2, 0.8)


def test_write_gate_artifact_roundtrip(tmp_path):
    art = ga.extract_gate_artifact(_report(True))
    p = tmp_path / "gate.json"
    ga.write_gate_artifact(art, str(p))
    back = json.loads(
        p.read_text(encoding="utf-8"),
        parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)),
    )
    assert back["passed"] is True and back["low_threshold"] == 0.2
