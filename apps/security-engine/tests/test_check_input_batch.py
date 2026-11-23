"""
/check-input/batch 真并发 + 整体预算超时降级（P1-B 模块 2a proxy 路径配套）
"""
import threading
import time

import anyio

import app.api.check_input as check_input_module
from app.api.check_input import CheckInputRequest, check_input_batch
from app.bounded_work import BoundedWorkPool
from app.detectors.engine import SecurityCheckResult, SecurityFinding


def _run(coro):
    return anyio.run(lambda: coro)


def _result(request_id: str) -> SecurityCheckResult:
    return SecurityCheckResult(request_id=request_id, findings=[], action="allow", masked_content=None)


def test_batch_empty_returns_empty():
    assert _run(check_input_batch([])) == []


def test_batch_runs_checks_concurrently(monkeypatch):
    """三条请求各自阻塞在 Barrier 上，只有真并发才能三方齐到、全部放行。"""
    monkeypatch.setenv("SECURITY_BATCH_ITEM_CONCURRENCY", "3")
    pool = BoundedWorkPool("batch-conc-test", workers=4, capacity=8)
    monkeypatch.setattr(check_input_module, "_INPUT_POOL", pool)
    barrier = threading.Barrier(3, timeout=5)

    def fake_check(**kwargs):
        barrier.wait()
        return _result(kwargs["request_id"])

    monkeypatch.setattr(check_input_module.engine, "check_input", fake_check)
    reqs = [CheckInputRequest(request_id=f"r{i}", content=f"c{i}") for i in range(3)]
    out = _run(check_input_batch(reqs))
    assert [r.request_id for r in out] == ["r0", "r1", "r2"]
    assert all(r.action == "allow" for r in out)


def test_batch_budget_timeout_returns_per_item_incomplete(monkeypatch):
    import json
    from fastapi.responses import JSONResponse
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", "0.05")
    calls = []
    def fake_check(**kwargs):
        calls.append(kwargs)
        time.sleep(0.15)
        return _result(kwargs["request_id"])
    monkeypatch.setattr(check_input_module.engine, "check_input", fake_check)
    reqs = [CheckInputRequest(request_id=f"r{i}", content=f"c{i}") for i in range(2)]
    out = _run(check_input_batch(reqs))
    assert isinstance(out, JSONResponse) and out.status_code == 207
    results = json.loads(out.body)
    assert [r["request_id"] for r in results] == ["r0", "r1"]
    assert all(r["inspection_status"] == "incomplete" for r in results)
    assert not any(c["request_id"].endswith("-batch-flat") for c in calls)


def test_batch_budget_env_invalid_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", "not-a-number")
    assert check_input_module._batch_budget_seconds() == 18.0


def test_batch_surfaces_detector_and_triage_budget_incomplete(monkeypatch):
    import json
    from fastapi.responses import JSONResponse

    def fake_check(**kwargs):
        return SecurityCheckResult(
            request_id=kwargs["request_id"],
            action="audit",
            findings=[SecurityFinding(
                type="engine_runtime",
                category="engine_scan_incomplete",
                severity="low",
                matched_text_preview="scan incomplete",
                rule_id="runtime",
                action="audit",
                counts_as_security_finding=False,
                triage={
                    "review_status": "incomplete",
                    "review_reason": "triage_total_budget_exhausted",
                },
            )],
        )

    monkeypatch.setattr(check_input_module.engine, "check_input", fake_check)
    out = _run(check_input_batch([
        CheckInputRequest(request_id="incomplete", content="content"),
    ]))

    assert isinstance(out, JSONResponse) and out.status_code == 207
    result = json.loads(out.body)[0]
    assert result["inspection_status"] == "incomplete"
    assert result["inspection_reason"] == "triage_total_budget_exhausted"


def test_batch_larger_than_pool_capacity_waits_without_false_overflow(monkeypatch):
    pool = BoundedWorkPool("batch-test", workers=2, capacity=2)
    monkeypatch.setattr(check_input_module, "_INPUT_POOL", pool)
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", "2")
    active = 0
    maximum = 0
    lock = threading.Lock()

    def fake_check(**kwargs):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        try:
            time.sleep(0.01)
            return _result(kwargs["request_id"])
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(check_input_module.engine, "check_input", fake_check)
    reqs = [CheckInputRequest(request_id=f"queued-{i}", content=f"c{i}") for i in range(10)]

    out = _run(check_input_batch(reqs))

    assert [item.request_id for item in out] == [f"queued-{i}" for i in range(10)]
    assert maximum == 2
    assert pool.snapshot()["rejected"] == 0


def _track_concurrency(monkeypatch, pool):
    monkeypatch.setattr(check_input_module, "_INPUT_POOL", pool)
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", "5")
    state = {"active": 0, "max": 0}
    lock = threading.Lock()

    def fake_check(**kwargs):
        with lock:
            state["active"] += 1
            state["max"] = max(state["max"], state["active"])
        try:
            time.sleep(0.03)
            return _result(kwargs["request_id"])
        finally:
            with lock:
                state["active"] -= 1

    monkeypatch.setattr(check_input_module.engine, "check_input", fake_check)
    return state


def _batch(n):
    return [CheckInputRequest(request_id=f"r{i}", content=f"c{i}") for i in range(n)]


def test_batch_item_concurrency_default_is_two(monkeypatch):
    monkeypatch.delenv("SECURITY_BATCH_ITEM_CONCURRENCY", raising=False)
    state = _track_concurrency(monkeypatch, BoundedWorkPool("t", workers=8, capacity=32))
    out = _run(check_input_batch(_batch(12)))
    assert len(out) == 12 and all(r.inspection_status == "completed" for r in out)
    assert state["max"] <= 2


def test_batch_item_concurrency_env_override(monkeypatch):
    monkeypatch.setenv("SECURITY_BATCH_ITEM_CONCURRENCY", "4")
    state = _track_concurrency(monkeypatch, BoundedWorkPool("t", workers=8, capacity=32))
    _run(check_input_batch(_batch(16)))
    assert 2 < state["max"] <= 4


def test_batch_item_concurrency_one(monkeypatch):
    monkeypatch.setenv("SECURITY_BATCH_ITEM_CONCURRENCY", "1")
    state = _track_concurrency(monkeypatch, BoundedWorkPool("t", workers=8, capacity=32))
    _run(check_input_batch(_batch(6)))
    assert state["max"] == 1


def test_batch_item_concurrency_capped_by_pool_capacity(monkeypatch):
    monkeypatch.setenv("SECURITY_BATCH_ITEM_CONCURRENCY", "50")
    pool = BoundedWorkPool("t", workers=3, capacity=3)
    state = _track_concurrency(monkeypatch, pool)
    out = _run(check_input_batch(_batch(20)))
    assert state["max"] <= 3
    assert all(r.inspection_status == "completed" for r in out)
    assert pool.snapshot()["rejected"] == 0


def test_batch_item_concurrency_invalid_falls_back(monkeypatch, caplog):
    import logging
    for bad in ("abc", "0", "-3", "nan", "2.5"):
        monkeypatch.setenv("SECURITY_BATCH_ITEM_CONCURRENCY", bad)
        pool = BoundedWorkPool("t", workers=8, capacity=32)
        monkeypatch.setattr(check_input_module, "_INPUT_POOL", pool)
        with caplog.at_level(logging.WARNING):
            assert check_input_module._batch_item_concurrency() == 2, bad
    assert "SECURITY_BATCH_ITEM_CONCURRENCY" in caplog.text
