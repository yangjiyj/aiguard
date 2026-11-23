import json
from pathlib import Path
import pytest
from bench import run_bench

DATA_DIR = Path(__file__).resolve().parent.parent / "bench" / "data"


def _fake_scorer(score_by_label1=0.9, score_by_label0=0.05):
    """按真值给分的 fake scorer：攻击→高分、良性→低分（模拟"完美"分类器）。"""
    class _S:
        def __init__(self):
            self.latencies_ms = []
        def score_texts(self, texts):
            # 不知道真值，这里用文本→分映射由调用方在 run() 里 zip；
            # 为可控，run() 接收 scorer.score_texts(texts) 顺序与 y_true 对齐
            raise NotImplementedError
    return _S()


def test_percentile_helper():
    assert run_bench.percentile([10, 20, 30, 40], 50) == pytest.approx(25.0)
    assert run_bench.percentile([5], 99) == 5.0
    assert run_bench.percentile([], 50) == 0.0


def test_run_computes_report_with_injected_scores(monkeypatch):
    """注入一个按顺序返回预设分数的 scorer，验证报告结构与判定门联动。"""
    y_true_order = []

    class SeqScorer:
        def __init__(self, mapping):
            self.mapping = mapping
            self.latencies_ms = [12.0, 13.0, 11.0, 14.0]
        def score_texts(self, texts):
            return [self.mapping[t] for t in texts]

    # 用真实数据集前 2 攻击 + 前 2 良性构造确定性输入
    rows = run_bench.load_dataset(DATA_DIR)
    atk = [r for r in rows if r["label"] == 1][:2]
    ben = [r for r in rows if r["label"] == 0][:2]
    subset = atk + ben
    mapping = {atk[0]["text"]: 0.95, atk[1]["text"]: 0.5, ben[0]["text"]: 0.05, ben[1]["text"]: 0.1}
    scorer = SeqScorer(mapping)

    report = run_bench.run(
        rows=subset, scorer=scorer,
        lows=[0.2], highs=[0.8],
        recall_min=0.9, benign_escalation_max=0.30,
    )
    assert "best" in report and "sweep" in report and "latency_ms" in report and "gate" in report
    assert report["counts"] == {"total": 4, "attack": 2, "benign": 2, "failopen_dropped": 0}
    # 0.95>high 直出 + 0.5 灰区升级 → with_gray 召回=1.0；良性 0.05/0.1 都 <low → 误升级 0
    assert report["best"]["cascade_recall_with_gray"] == pytest.approx(1.0)
    assert report["gate"]["passed"] is True
    assert report["latency_ms"]["p50"] > 0


def test_load_dataset_merges_both_files():
    rows = run_bench.load_dataset(DATA_DIR)
    labels = {r["label"] for r in rows}
    assert labels == {0, 1}
    assert len(rows) >= 80  # 越狱+良性各 >=40


def test_run_drops_failopen_nan():
    import math

    class NanScorer:
        latencies_ms = [1.0, 1.0]
        def score_texts(self, texts):
            return [0.9, math.nan]

    rows = [{"text": "a", "label": 1}, {"text": "b", "label": 0}]
    report = run_bench.run(rows=rows, scorer=NanScorer(), lows=[0.2], highs=[0.8],
                           recall_min=0.9, benign_escalation_max=0.30)
    assert report["counts"]["failopen_dropped"] == 1
    assert report["counts"]["total"] == 2


def test_run_all_failopen_gates_fail():
    """全样本 fail-open（每条都 NaN）→ 0 条有效样本，判定门必须 FAIL 而非误判 PASS。
    退化输入决不能产出『PASS, ship it』（fail-open 的错误方向）。"""
    import math

    class AllNanScorer:
        latencies_ms = [1.0, 1.0]
        def score_texts(self, texts):
            return [math.nan, math.nan]

    rows = [{"text": "a", "label": 1}, {"text": "b", "label": 0}]
    report = run_bench.run(rows=rows, scorer=AllNanScorer(), lows=[0.2], highs=[0.8],
                           recall_min=0.9, benign_escalation_max=0.30)
    assert report["counts"]["failopen_dropped"] == 2
    assert report["gate"]["passed"] is False
    assert "no_valid_samples" in report["gate"]["reason"]
    # FAIL 时必须指明 fallback 入口
    assert report["gate"]["fallback"] == "tier1_finetune"


def test_run_excessive_failopen_gates_fail():
    """有效样本占比过低（丢弃率 > 阈值）→ 判定门 FAIL（统计无意义）。"""
    import math

    class MostlyNanScorer:
        latencies_ms = [1.0, 1.0, 1.0, 1.0, 1.0]
        def score_texts(self, texts):
            # 5 条只剩 1 条有效（丢弃率 80% > 50% 阈值）
            return [0.95, math.nan, math.nan, math.nan, math.nan]

    rows = [
        {"text": "a", "label": 1},
        {"text": "b", "label": 0},
        {"text": "c", "label": 0},
        {"text": "d", "label": 0},
        {"text": "e", "label": 0},
    ]
    report = run_bench.run(rows=rows, scorer=MostlyNanScorer(), lows=[0.2], highs=[0.8],
                           recall_min=0.9, benign_escalation_max=0.30)
    assert report["counts"]["failopen_dropped"] == 4
    assert report["gate"]["passed"] is False
    assert "failopen" in report["gate"]["reason"]


def test_report_json_is_strict_valid_when_no_gray_zone(tmp_path):
    """裁判升级率为 0 时 capacity_multiplier 不能序列化成非法 JSON 字面量 Infinity。
    bench-result.json 是机读交付物，jq/Go/严格 JS 解析器必须能读。"""
    class NoGrayScorer:
        latencies_ms = [1.0, 1.0]
        def score_texts(self, texts):
            return [0.05, 0.05]  # 两条都 <low → 不升级 3B

    rows = [{"text": "a", "label": 1}, {"text": "b", "label": 0}]
    report = run_bench.run(rows=rows, scorer=NoGrayScorer(), lows=[0.2], highs=[0.8],
                           recall_min=0.9, benign_escalation_max=0.30)
    assert report["best"]["gray_zone_rate"] == 0.0
    # capacity_multiplier 在裁判升级率为 0 时归一为 None（合法 JSON）而非 inf
    assert report["gate"]["capacity_multiplier"] is None
    # 严格序列化：allow_nan=False 不得抛错，输出不含 Infinity/NaN 字面量
    dumped = json.dumps(report, ensure_ascii=False, allow_nan=False)
    assert "Infinity" not in dumped
    assert "NaN" not in dumped
    # 往返：用 parse_constant 捕获非法常量，证明确实是严格 JSON
    json.loads(
        dumped,
        parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)),
    )


def test_main_writes_strict_json(tmp_path, monkeypatch):
    """main() 经 --json-out 落盘的文件必须是严格合法 JSON（端到端覆盖序列化路径）。"""
    out = tmp_path / "bench-result.json"

    class NoGrayScorer:
        latencies_ms = [1.0, 1.0]
        def score_texts(self, texts):
            return [0.95, 0.05]

    rows = [{"text": "a", "label": 1}, {"text": "b", "label": 0}]
    monkeypatch.setattr(run_bench, "load_dataset", lambda _d: rows)
    monkeypatch.setattr(run_bench, "_build_scorer", lambda _a: NoGrayScorer())

    # 默认阈值网格(0.1-0.3 / 0.7-0.9)下，0.95/0.05 也全无灰区 → 触发 inf 路径
    rc = run_bench.main(["--mode", "onnx", "--json-out", str(out)])
    assert rc in (0, 2)
    text = out.read_text(encoding="utf-8")
    assert "Infinity" not in text
    # 严格 reparse 成功（捕获非法常量则抛错）
    json.loads(text, parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))


def test_build_scorer_fused_mode_constructs_fused_onnx_scorer():
    """--mode fused → 构造 FusedOnnxScorer，指向融合 model.onnx。"""
    from bench.scorers import FusedOnnxScorer

    args = run_bench.argparse.Namespace(
        mode="fused", model="/models/tier1-fused/model.onnx",
        tokenizer="", threads=1, url="", token="", timeout=5.0,
    )
    scorer = run_bench._build_scorer(args)
    assert isinstance(scorer, FusedOnnxScorer)
    assert scorer.model_path == "/models/tier1-fused/model.onnx"


def test_main_fused_mode_passes_gate_with_injected_scorer(tmp_path, monkeypatch):
    """fused 模式经 main() 端到端走判定门：注入「完美」分类器 → 召回 1.0、
    良性误升级 0 → 门 PASS → 退出码 0，并产 low/high 阈值初值。"""
    out = tmp_path / "fused-bench.json"

    class PerfectScorer:
        latencies_ms = [10.0, 11.0, 12.0, 13.0]
        def score_texts(self, texts):
            # 真值由 rows 顺序决定：前 2 攻击给高分、后 2 良性给低分
            return [0.95, 0.95, 0.02, 0.02]

    rows = [
        {"text": "a1", "label": 1}, {"text": "a2", "label": 1},
        {"text": "b1", "label": 0}, {"text": "b2", "label": 0},
    ]
    monkeypatch.setattr(run_bench, "load_dataset", lambda _d: rows)
    monkeypatch.setattr(run_bench, "_build_scorer", lambda _a: PerfectScorer())

    rc = run_bench.main(
        ["--mode", "fused", "--model", "/models/tier1-fused/model.onnx",
         "--json-out", str(out)]
    )
    assert rc == 0  # 门 PASS
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["gate"]["passed"] is True
    # 产出 low/high 阈值初值（喂给 SECURITY_TIER1_{LOW,HIGH}_THRESHOLD）
    assert "low" in report["best"] and "high" in report["best"]
    assert report["best"]["cascade_recall_with_gray"] >= 0.9


def test_main_fused_mode_fails_gate_when_recall_low(tmp_path, monkeypatch):
    """fused 模式：分类器漏召回（攻击给低分）→ 门 FAIL → 退出码 2 + fallback 入口。
    不达标模型决不放行（不出不达标基线）。"""
    out = tmp_path / "fused-bad.json"

    class WeakScorer:
        latencies_ms = [10.0, 11.0, 12.0, 13.0]
        def score_texts(self, texts):
            # 两条攻击都给 0.05（<所有 low）→ 召回 0 → 必 FAIL
            return [0.05, 0.05, 0.02, 0.02]

    rows = [
        {"text": "a1", "label": 1}, {"text": "a2", "label": 1},
        {"text": "b1", "label": 0}, {"text": "b2", "label": 0},
    ]
    monkeypatch.setattr(run_bench, "load_dataset", lambda _d: rows)
    monkeypatch.setattr(run_bench, "_build_scorer", lambda _a: WeakScorer())

    rc = run_bench.main(
        ["--mode", "fused", "--model", "/models/tier1-fused/model.onnx",
         "--json-out", str(out)]
    )
    assert rc == 2  # 门 FAIL → 退出码 2
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["gate"]["passed"] is False
    assert report["gate"]["fallback"] == "tier1_finetune"
