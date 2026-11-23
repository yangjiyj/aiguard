import concurrent.futures
import threading
import time
from app.detectors import semantic as sem

def test_busy_judge_does_not_consume_tier1_capacity(monkeypatch):
    release=threading.Event()
    executor=concurrent.futures.ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(sem, "_EXECUTOR", executor)
    monkeypatch.setattr(sem, "_CAPACITY", threading.BoundedSemaphore(1))
    future=sem._submit_bounded(release.wait, 1)
    class Tier1:
        def classify(self, content): return (0.1, "benign")
    detector=sem.SemanticDetector(url="http://example.invalid", model="m", api_key="test",
                                  op_timeout=1, total_timeout=.2,
                                  tier1_enabled=True, tier1_client=Tier1())
    try:
        assert detector._tier1_with_deadline("normal", time.monotonic()+.2) == (0.1, "benign")
    finally:
        release.set()
        future.result(timeout=2)
        executor.shutdown()
