import concurrent.futures
import threading
import time
from app.detectors import semantic as sem
from app.detectors.llm_judge import SemanticOpinion


def make_detector():
    return sem.SemanticDetector(url="http://judge/", model="m", api_key="", op_timeout=1, total_timeout=3)


def test_same_window_concurrent_requests_share_one_inference(monkeypatch):
    d = make_detector()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def judge(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(1)
        return SemanticOpinion("benign", "none", .9, "fixture")
    monkeypatch.setattr(d, "_judge_with_deadline", judge)
    def invoke():
        return d._judge_window("same evidence", time.monotonic()+2, source="tool_result", context={}, priority="normal")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke)
        assert entered.wait(1)
        second = pool.submit(invoke)
        time.sleep(.04)
        release.set()
        assert first.result().verdict == second.result().verdict == "benign"
    assert len(calls) == 1


def test_short_waiter_cannot_cancel_shared_owner_or_fabricate_completion(monkeypatch):
    d = make_detector()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def judge(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(1)
        return SemanticOpinion("malicious", "semantic_jailbreak", .95, "fixture")
    monkeypatch.setattr(d, "_judge_with_deadline", judge)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(d._judge_window, "same evidence", time.monotonic()+2, source="tool_result", context={}, priority="normal")
        assert entered.wait(1)
        waiter = pool.submit(d._judge_window, "same evidence", time.monotonic()+.03, source="tool_result", context={}, priority="normal")
        try:
            assert waiter.result(timeout=.2) is sem._TIMEOUT
        finally:
            release.set()
        assert owner.result().verdict == "malicious"
    assert len(calls) == 1


def test_failed_owner_does_not_poison_the_next_attempt(monkeypatch):
    d = make_detector()
    outcomes = iter([sem._TIMEOUT, SemanticOpinion("benign", "none", .9, "fixture")])
    monkeypatch.setattr(d, "_judge_with_deadline", lambda *a, **k: next(outcomes))
    kwargs = dict(source="tool_result", context={}, priority="normal")
    assert d._judge_window("same", time.monotonic()+1, **kwargs) is sem._TIMEOUT
    assert d._judge_window("same", time.monotonic()+1, **kwargs).verdict == "benign"
