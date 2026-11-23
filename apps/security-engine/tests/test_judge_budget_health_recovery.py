import concurrent.futures
import threading
import time
import pytest
from app.detectors import llm_judge as lj, semantic as sem
from app.api import check_input as api


def test_recent_success_does_not_hide_low_window_completion():
    url = "https://judge.example/v1/chat/completions"
    lj._reset_breakers()
    try:
        for index in range(20):
            ok = index >= 8
            lj._record_semantic_judge_window(url, success=ok, timed_out=not ok, latency_ms=100)
        lj._record_semantic_judge_attempt(url, True)
        health = lj.get_semantic_judge_health(url)
        assert health["window_successes"] == 12
        assert health["operational"] is False
        assert health["breaker_open"] is False
    finally:
        lj._reset_breakers()


def test_healthy_window_recovers_when_old_timeouts_expire(monkeypatch):
    url = "https://judge.example/v1/chat/completions"
    lj._reset_breakers()
    now = [1000.0]
    monkeypatch.setattr(lj.time, "monotonic", lambda: now[0])
    try:
        for _ in range(5):
            lj._record_semantic_judge_window(url, success=False, timed_out=True, latency_ms=100)
        lj._record_semantic_judge_attempt(url, True)
        assert lj.get_semantic_judge_health(url)["operational"] is False
        now[0] += 301
        for _ in range(20):
            lj._record_semantic_judge_window(url, success=True, timed_out=False, latency_ms=10)
        # Recovery requires a fresh fully parsed semantic result after expiration.
        lj._record_semantic_judge_attempt(url, True)
        assert lj.get_semantic_judge_health(url)["operational"] is True
    finally:
        lj._reset_breakers()


def test_request_window_limit_leaves_shared_workers_for_other_requests(monkeypatch):
    monkeypatch.setenv("SECURITY_SEMANTIC_REQUEST_PARALLELISM", "2")
    d = sem.SemanticDetector(url="http://judge/", model="m", api_key="", op_timeout=1, total_timeout=3)
    lock = threading.Lock()
    active = peak = 0
    def inspect(bounds):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(.01)
        with lock:
            active -= 1
        return [{"type": "fixture", "index": bounds[0]}]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        monkeypatch.setattr(sem, "_WINDOW_WORKERS", 8)
        monkeypatch.setattr(sem, "_WINDOW_EXECUTOR", pool)
        monkeypatch.setattr(sem, "_WINDOW_CAPACITY", threading.BoundedSemaphore(8))
        plan = [(i, i+1) for i in range(16)]
        results = list(d._window_results(plan, inspect, time.monotonic()+2, "input", lambda b:b))
    assert len(results) == len(plan)
    assert [r[0] for r in results] == plan
    assert peak == 2


def test_batch_budget_leaves_transport_headroom_and_preserves_explicit_deadlines(monkeypatch):
    monkeypatch.delenv("SECURITY_BATCH_BUDGET_SECONDS", raising=False)
    monkeypatch.setenv("SECURITY_INPUT_BUDGET_SECONDS", "30")
    assert api._batch_budget_seconds() == 18
    monkeypatch.setenv("SECURITY_INPUT_BUDGET_SECONDS", "10")
    assert api._batch_budget_seconds() == 10
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", "2")
    assert api._batch_budget_seconds() == 2


@pytest.mark.parametrize("successes, expected", [(19, True), (18, False), (20, True)])
def test_window_health_boundary_is_95_percent(successes, expected):
    url = "https://judge.example/v1/chat/completions"
    lj._reset_breakers()
    try:
        for i in range(20):
            lj._record_semantic_judge_window(url, success=i < successes, timed_out=i >= successes, latency_ms=100)
        lj._record_semantic_judge_attempt(url, True)
        assert lj.get_semantic_judge_health(url)["operational"] is expected
    finally:
        lj._reset_breakers()
