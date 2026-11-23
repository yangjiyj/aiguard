"""P2-1 回归：check-triage 开闸前性能加固（judge 去重广播 + 总预算截断 + 端点线程池化）。

红线不变量（本文件同时守护）：
- 去重/预算只减少 judge 调用次数，绝不产生新的 likely_false_positive——
  triage 只能来自 judge 明确产出（广播的是同身份 judge 结果的副本）。
- 预算用尽 → 剩余 finding 无 triage（fail-open，不压制不藏证）。
- _eligible 过滤 / Tier-1 门控 / 失败 fail-open 语义与既有测试（test_check_triage.py）一致。
"""
import inspect

import pytest

from app import triage_service
from app.detectors.engine import SecurityEngine


def _finding(ftype="prompt_injection", rule_id="pi_rule", location="input", preview="p"):
    return {
        "type": ftype, "category": "x", "severity": "high",
        "matched_text_preview": preview, "rule_id": rule_id,
        "rule_name": "规则", "rule_type": "builtin", "confidence": 0.6,
        "matched_location": location, "redacted_evidence": "证据", }


def _judge_conn():
    return {"url": "http://127.0.0.1:8091/v1/chat/completions", "model": "m",
            "api_key": "k", "timeout": 6.0}


_LFP = {"verdict": "likely_false_positive", "risk_level": "low",
        "confidence": 0.9, "reason": "字段名误报"}


# ---------------- 去重 + 广播 ----------------


def test_same_identity_judged_once_and_broadcast(monkeypatch):
    """同身份只分两轮独立 judge，结果广播回全组。"""
    called = {"n": 0}

    def _judge(payload, **kw):
        called["n"] += 1
        return dict(_LFP)

    monkeypatch.setattr(triage_service, "judge_triage", _judge)
    findings = [
        _finding(rule_id="pi_rule", location="input", preview="第一处"),
        _finding(rule_id="pi_rule", location="input", preview="第二处"),
        _finding(rule_id="pi_rule", location="output", preview="第三处"),
    ]
    out = triage_service.apply_check_triage(
        "今天天气不错", findings,
        tier1_score=lambda c: 0.05, low_threshold=0.2, judge=_judge_conn(),
    )
    # 两个身份组，每组两轮 → 4 次（同身份不按 finding 数量重复）。
    assert called["n"] == 4
    # 同身份两个 finding 都拿到广播结果
    assert out[0]["triage"]["verdict"] == "likely_false_positive"
    assert out[1]["triage"]["verdict"] == "likely_false_positive"
    assert out[2]["triage"]["verdict"] == "likely_false_positive"


def test_broadcast_copies_are_independent(monkeypatch):
    """广播出去的是副本：改一个 finding 的 triage 不影响同组其它 finding。"""
    monkeypatch.setattr(triage_service, "judge_triage", lambda payload, **kw: dict(_LFP))
    findings = [_finding(preview="a"), _finding(preview="b")]
    out = triage_service.apply_check_triage(
        "x", findings, tier1_score=lambda c: 0.05, low_threshold=0.2, judge=_judge_conn(),
    )
    assert out[0]["triage"] is not out[1]["triage"]
    out[0]["triage"]["verdict"] = "confirmed_risk"
    assert out[1]["triage"]["verdict"] == "likely_false_positive"


def test_different_identities_judged_separately(monkeypatch):
    """不同 rule_id 不合并，各自完成两轮 judge。"""
    called = {"n": 0}
    monkeypatch.setattr(triage_service, "judge_triage",
                        lambda payload, **kw: called.__setitem__("n", called["n"] + 1) or dict(_LFP))
    findings = [_finding(rule_id="r1"), _finding(rule_id="r2")]
    triage_service.apply_check_triage(
        "x", findings, tier1_score=lambda c: 0.05, low_threshold=0.2, judge=_judge_conn(),
    )
    assert called["n"] == 4


def test_group_judge_failure_fail_open_does_not_block_other_groups(monkeypatch):
    """某组 judge 抛异常 → 该组全组无 triage（不压制），其余组照常。"""
    def _judge(payload, **kw):
        if payload["finding"]["rule_id"] == "r_bad":
            raise RuntimeError("boom")
        return dict(_LFP)

    monkeypatch.setattr(triage_service, "judge_triage", _judge)
    findings = [
        _finding(rule_id="r_bad", preview="a"),
        _finding(rule_id="r_bad", preview="b"),
        _finding(rule_id="r_ok"),
    ]
    out = triage_service.apply_check_triage(
        "x", findings, tier1_score=lambda c: 0.05, low_threshold=0.2, judge=_judge_conn(),
    )
    assert "triage" not in out[0] and "triage" not in out[1]
    assert out[2]["triage"]["verdict"] == "likely_false_positive"


# ---------------- 总预算截断 ----------------


def test_budget_exhausted_stops_remaining_judges(monkeypatch):
    """预算用尽即停：未判的 finding 无 triage（fail-open，不压制）。"""
    now = {"t": 0.0}
    called = {"n": 0}

    def _judge(payload, **kw):
        called["n"] += 1
        now["t"] += 5.0  # 每次 judge 耗 5 秒
        return dict(_LFP)

    monkeypatch.setattr(triage_service, "judge_triage", _judge)
    findings = [_finding(rule_id="r1"), _finding(rule_id="r2"), _finding(rule_id="r3")]
    out = triage_service.apply_check_triage(
        "x", findings, tier1_score=lambda c: 0.05, low_threshold=0.2, judge=_judge_conn(),
        total_budget_seconds=8.0, clock=lambda: now["t"],
    )
    # t=0 开始 r1 的两轮复核（→10s）；t=10≥8 停止后续组，r2/r3 不判
    assert called["n"] == 2
    assert out[0]["triage"]["verdict"] == "likely_false_positive"
    assert "triage" not in out[1]
    assert "triage" not in out[2]


def test_budget_counts_tier1_time(monkeypatch):
    """预算从函数入口起算：Tier-1 打分耗时也计入，入口即超则一次 judge 都不发。"""
    now = {"t": 0.0}
    called = {"n": 0}
    monkeypatch.setattr(triage_service, "judge_triage",
                        lambda payload, **kw: called.__setitem__("n", called["n"] + 1) or dict(_LFP))

    def _slow_tier1(content):
        now["t"] += 9.0  # Tier-1 已把 8s 预算烧穿
        return 0.05

    out = triage_service.apply_check_triage(
        "x", [_finding()], tier1_score=_slow_tier1, low_threshold=0.2, judge=_judge_conn(),
        total_budget_seconds=8.0, clock=lambda: now["t"],
    )
    assert called["n"] == 0
    assert "triage" not in out[0]


def test_budget_nonpositive_means_unlimited(monkeypatch):
    """预算 ≤0 = 不限（运维退路，恢复无预算旧行为），全部照判。"""
    now = {"t": 0.0}
    called = {"n": 0}

    def _judge(payload, **kw):
        called["n"] += 1
        now["t"] += 100.0
        return dict(_LFP)

    monkeypatch.setattr(triage_service, "judge_triage", _judge)
    findings = [_finding(rule_id="r1"), _finding(rule_id="r2"), _finding(rule_id="r3")]
    out = triage_service.apply_check_triage(
        "x", findings, tier1_score=lambda c: 0.05, low_threshold=0.2, judge=_judge_conn(),
        total_budget_seconds=0.0, clock=lambda: now["t"],
    )
    assert called["n"] == 6
    assert all(f["triage"]["verdict"] == "likely_false_positive" for f in out)


def test_disagreement_is_needs_review_and_never_suppressed(monkeypatch):
    """两轮结论不一致时必须 fail-open，不能生成 likely_false_positive。"""
    verdicts = iter(["likely_false_positive", "confirmed_risk"])

    def _judge(payload, **kw):
        return {
            "verdict": next(verdicts),
            "risk_level": "low",
            "confidence": 0.9,
            "reason": "独立复核",
        }

    monkeypatch.setattr(triage_service, "judge_triage", _judge)
    out = triage_service.apply_check_triage(
        "今天天气不错", [_finding()], tier1_score=lambda c: 0.05,
        low_threshold=0.2, judge=_judge_conn(),
    )
    triage = out[0]["triage"]
    assert triage["verdict"] == "needs_review"
    assert triage["review_state"] == "needs_review"
    assert triage["judge_passes"] == 2
    assert triage["judge_agreement"] is False


def test_unavailable_second_pass_is_needs_review_and_never_suppressed(monkeypatch):
    """第二轮不可用时不能沿用第一轮 FP 结论。"""
    calls = {"n": 0}

    def _judge(payload, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return dict(_LFP)
        return None

    monkeypatch.setattr(triage_service, "judge_triage", _judge)
    out = triage_service.apply_check_triage(
        "今天天气不错", [_finding()], tier1_score=lambda c: 0.05,
        low_threshold=0.2, judge=_judge_conn(),
    )
    triage = out[0]["triage"]
    assert triage["verdict"] == "needs_review"
    assert triage["judge_passes"] == 1
    assert triage["judge_agreement"] is False


# ---------------- 引擎接线（env → 服务） ----------------


def test_engine_budget_default_is_8s(monkeypatch):
    monkeypatch.delenv("SECURITY_TRIAGE_TOTAL_BUDGET_SECONDS", raising=False)
    e = SecurityEngine()
    assert e._triage_total_budget == 8.0


def test_engine_budget_env_override(monkeypatch):
    monkeypatch.setenv("SECURITY_TRIAGE_TOTAL_BUDGET_SECONDS", "3.5")
    e = SecurityEngine()
    assert e._triage_total_budget == 3.5


def test_engine_passes_budget_to_service(monkeypatch):
    monkeypatch.setenv("SECURITY_FP_SUPPRESSION_ENABLED", "true")
    monkeypatch.setenv("SECURITY_TRIAGE_TOTAL_BUDGET_SECONDS", "2.5")
    e = SecurityEngine()
    captured = {}

    def _fake_apply(content, findings, **kw):
        captured.update(kw)
        return findings

    monkeypatch.setattr(triage_service, "apply_check_triage", _fake_apply)
    e.check_triage("rid", "x", [_finding()])
    assert captured["total_budget_seconds"] == 2.5


# ---------------- 端点线程池化 ----------------


def test_endpoint_is_plain_def_not_coroutine():
    """check-triage 端点必须是普通 def（FastAPI 自动进线程池），
    否则内部同步 urllib（tier1/judge）会锁死事件循环、拖垮 /check-input 主链。"""
    from app.api import check_triage as mod
    assert not inspect.iscoroutinefunction(mod.check_triage)
