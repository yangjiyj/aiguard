import json
import pytest
from bench import metrics


def test_confusion_counts_basic():
    # scores=攻击概率；阈值 0.5 时：>=0.5 判攻击
    y_true = [1, 1, 0, 0]
    scores = [0.9, 0.3, 0.6, 0.1]
    cm = metrics.confusion_at(y_true, scores, threshold=0.5)
    assert cm == {"tp": 1, "fn": 1, "fp": 1, "tn": 1}


def test_recall_precision():
    y_true = [1, 1, 1, 0, 0]
    scores = [0.9, 0.8, 0.2, 0.7, 0.1]
    r = metrics.recall_at(y_true, scores, threshold=0.5)
    p = metrics.precision_at(y_true, scores, threshold=0.5)
    assert r == pytest.approx(2 / 3)   # 3 攻击命中 2
    assert p == pytest.approx(2 / 3)   # 3 判正里 2 真


def test_recall_precision_no_positive_edges():
    # 无正样本预测时 precision 定义为 1.0（不罚没误报）；无正样本真值时 recall 1.0
    assert metrics.precision_at([0, 0], [0.1, 0.2], 0.5) == 1.0
    assert metrics.recall_at([0, 0], [0.1, 0.2], 0.5) == 1.0


def test_gray_zone_rate():
    # Tier-1 只分流：所有 p>=low 都升级 3B；high 仅保留为兼容配置。
    scores = [0.1, 0.3, 0.5, 0.85, 0.9, 0.2, 0.8]
    rate = metrics.gray_zone_rate(scores, low=0.2, high=0.8)
    # p>=0.2：除 0.1 外均升级裁判 → 6/7
    assert rate == pytest.approx(6 / 7)


def test_cascade_recall_counts_high_band_plus_gray_assumed_caught():
    """Tier-1 高分段召回只作分类器诊断，不直接判风险。
    cascade_recall_with_gray 统计所有 p>=low 的攻击覆盖，假定升级 3B 后抓住。"""
    y_true = [1, 1, 1, 0]
    scores = [0.9, 0.5, 0.1, 0.85]
    only_high = metrics.cascade_recall(y_true, scores, high=0.8)
    with_gray = metrics.cascade_recall_with_gray(y_true, scores, low=0.2, high=0.8)
    assert only_high == pytest.approx(1 / 3)   # 高分段诊断：仅 0.9
    assert with_gray == pytest.approx(2 / 3)   # 0.9 与 0.5 都送 3B


def test_benign_false_escalation_rate():
    """良性误升级率 = 良性样本里 p>=low（会触发 3B）的比例。"""
    y_true = [0, 0, 0, 0]
    scores = [0.1, 0.25, 0.05, 0.9]
    rate = metrics.benign_false_escalation_rate(y_true, scores, low=0.2)
    assert rate == pytest.approx(2 / 4)  # 0.25 和 0.9


def test_sweep_thresholds_returns_grid():
    y_true = [1, 1, 0, 0]
    scores = [0.9, 0.6, 0.3, 0.1]
    rows = metrics.sweep_thresholds(
        y_true, scores,
        lows=[0.2, 0.3], highs=[0.7, 0.8],
    )
    # 每个 (low,high) 组合一行，含关键指标
    assert len(rows) == 4
    keys = set(rows[0])
    assert {"low", "high", "tier1_recall_high", "cascade_recall_with_gray",
            "benign_false_escalation_rate", "gray_zone_rate"} <= keys


def test_decision_gate_pass():
    # 召回>=0.9 且良性误升级率<=阈值 → 过线
    res = metrics.decision_gate(
        cascade_recall_with_gray=0.95,
        benign_false_escalation_rate=0.15,
        gray_zone_rate=0.2,
        recall_min=0.9,
        benign_escalation_max=0.30,
    )
    assert res["passed"] is True
    assert res["capacity_multiplier"] == pytest.approx(1 / 0.2)  # 1/灰区率


def test_decision_gate_fail_triggers_fallback():
    res = metrics.decision_gate(
        cascade_recall_with_gray=0.7,   # 召回不够
        benign_false_escalation_rate=0.1,
        gray_zone_rate=0.2,
        recall_min=0.9,
        benign_escalation_max=0.30,
    )
    assert res["passed"] is False
    assert res["fallback"] == "tier1_finetune"  # 写明 fallback 入口
    assert "recall" in res["reason"]


def test_decision_gate_capacity_multiplier_zero_gray():
    res = metrics.decision_gate(
        cascade_recall_with_gray=0.95, benign_false_escalation_rate=0.1,
        gray_zone_rate=0.0, recall_min=0.9, benign_escalation_max=0.30,
    )
    # 灰区 0 → 3B 完全不调，容量无上界（理论）。归一为 None 而非 math.inf，
    # 否则 json.dumps 产出非法字面量 Infinity，机读交付物 bench-result.json 会被严格解析器拒绝。
    assert res["capacity_multiplier"] is None
    # 兜底：整个 gate dict 必须可严格序列化（allow_nan=False 不抛错）
    json.dumps(res, allow_nan=False)
