import threading
import time

from app.bounded_work import execution_budget
from app.detectors import semantic as sem
from app.detectors.llm_judge import SemanticOpinion


def detector():
    return sem.SemanticDetector(url="http://judge/", model="m", api_key="", op_timeout=1, total_timeout=3)


def test_long_tool_result_covers_tail_with_bounded_parallelism(monkeypatch):
    monkeypatch.setenv("SECURITY_SEMANTIC_MAX_WINDOWS", "128")
    d = detector()
    active = peak = calls = 0
    lock = threading.Lock()
    def judge(content, deadline, **kwargs):
        nonlocal active, peak, calls
        with lock:
            active += 1
            peak = max(peak, active)
            calls += 1
        time.sleep(.005)
        with lock:
            active -= 1
        attack = "TAIL_ATTACK" in content
        return SemanticOpinion("malicious" if attack else "benign", "semantic_jailbreak" if attack else "none", .9, "fixture")
    monkeypatch.setattr(d, "_judge_with_deadline", judge)
    content = "".join(f"line-{i:05d} ordinary diagnostic output; " for i in range(1000)) + "TAIL_ATTACK"
    out = d.detect(content, "input", content_source="tool_result")
    assert not any(f.get("type") == "semantic_telemetry" for f in out)
    assert any(f.get("category") == "semantic_jailbreak" and f["triage"]["window_end"] == len(content) for f in out)
    assert calls > 32
    assert 1 < peak <= sem._WINDOW_WORKERS


def test_exhausted_orchestration_capacity_falls_back_without_queue(monkeypatch):
    gate = threading.BoundedSemaphore(1)
    gate.acquire()
    monkeypatch.setattr(sem, "_WINDOW_CAPACITY", gate)
    class NoSubmissions:
        def submit(self, *args):
            raise AssertionError("must not queue without capacity")
    monkeypatch.setattr(sem, "_WINDOW_EXECUTOR", NoSubmissions())
    d = detector()
    monkeypatch.setattr(d, "_judge_with_deadline", lambda *a, **k: SemanticOpinion("benign", "none", .9, "fixture"))
    assert d.detect("".join(f"{i:04d}" for i in range(1200)), "input") == []
    assert not gate.acquire(blocking=False)
    gate.release()


def test_parent_cancellation_remains_incomplete_for_parallel_windows(monkeypatch):
    d = detector()
    cancelled = threading.Event()
    def judge(*args, **kwargs):
        cancelled.set()
        return SemanticOpinion("benign", "none", .9, "late")
    monkeypatch.setattr(d, "_judge_with_deadline", judge)
    with execution_budget(time.monotonic()+3, cancelled):
        out = d.detect("".join(f"{i:04d}" for i in range(1200)), "input")
    assert any(f.get("type") == "semantic_telemetry" for f in out)
    assert not d._window_cache


def test_slow_first_window_does_not_idle_other_slots_and_results_stay_ordered():
    d = detector()
    fifth_started = threading.Event()
    plan = [(i, i+1) for i in range(8)]
    def inspect(bounds):
        if bounds[0] == 0:
            assert fifth_started.wait(1), "a completed slot must start the fifth window before the first finishes"
        if bounds[0] == 4:
            fifth_started.set()
        return [{"type":"fixture", "index":bounds[0]}]
    rows = list(d._window_results(plan, inspect, time.monotonic()+2, "input", lambda bounds:bounds))
    assert [bounds for bounds, result in rows] == plan
    assert [result[0]["index"] for bounds, result in rows] == list(range(8))
