"""Transient saturation must not lose a verdict when a slot soon becomes free."""
import concurrent.futures
import threading
import time

from app.detectors import semantic as sem
from app.bounded_work import execution_budget


def test_regular_request_can_recover_a_busy_slot(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    monkeypatch.setattr(sem, "_EXECUTOR", executor)
    timer = threading.Timer(.03, capacity.release)
    timer.start()
    try:
        future = sem._submit_bounded(lambda: "classified", private_priority=False,
                                     private_deadline=time.monotonic()+1, private_op_timeout=.1)
        assert isinstance(future, concurrent.futures.Future)
        assert future.result(timeout=1) == "classified"
    finally:
        timer.join()
        executor.shutdown()


def test_regular_request_preserves_inference_budget(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    called = []
    start = time.monotonic()
    result = sem._submit_bounded(lambda: called.append(True), private_priority=False,
                                 private_deadline=start+.1, private_op_timeout=.2)
    assert result is sem._DEFERRED
    assert time.monotonic()-start < .08
    assert not called


def test_saturated_wait_queue_rejects_without_unbounded_wait(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    waiters = threading.BoundedSemaphore(1)
    waiters.acquire()
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    monkeypatch.setattr(sem, "_JUDGE_WAITERS", waiters)
    start = time.monotonic()
    result = sem._submit_bounded(lambda: None, private_deadline=start+1,
                                 private_op_timeout=.1)
    assert result is sem._DEFERRED
    assert time.monotonic()-start < .08


def test_cancellation_during_admission_releases_waiter_without_call(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    waiters = threading.BoundedSemaphore(1)
    cancelled = threading.Event()
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    monkeypatch.setattr(sem, "_JUDGE_WAITERS", waiters)
    called = []
    timer = threading.Timer(.03, cancelled.set)
    timer.start()
    start = time.monotonic()
    try:
        with execution_budget(start+2, cancelled):
            result = sem._submit_bounded(lambda: called.append(True),
                                         private_deadline=start+2, private_op_timeout=.1)
        assert result is sem._TIMEOUT
        assert not called
        assert time.monotonic()-start < .3
        assert waiters.acquire(blocking=False)
        waiters.release()
    finally:
        timer.join()


def test_socket_timeout_recomputed_after_regular_admission(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    monkeypatch.setattr(sem, "_EXECUTOR", executor)
    timer = threading.Timer(.05, capacity.release)
    timer.start()
    try:
        future = sem._submit_bounded(lambda timeout: timeout, timeout=2,
                                     private_deadline=time.monotonic()+.3,
                                     private_op_timeout=.1)
        assert isinstance(future, concurrent.futures.Future)
        assert 0 < future.result(timeout=1) < .28
    finally:
        timer.join()
        executor.shutdown()


def test_full_regular_wait_queue_cannot_exclude_high_priority(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    waiters = threading.BoundedSemaphore(1)
    waiters.acquire()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    monkeypatch.setattr(sem, "_JUDGE_WAITERS", waiters)
    monkeypatch.setattr(sem, "_EXECUTOR", executor)
    timer = threading.Timer(.03, capacity.release)
    timer.start()
    try:
        future = sem._submit_bounded(lambda: "priority", private_priority=True,
                                     private_deadline=time.monotonic()+1, private_op_timeout=.1)
        assert isinstance(future, concurrent.futures.Future)
        assert future.result(timeout=1) == "priority"
        assert not waiters.acquire(blocking=False)
    finally:
        timer.join()
        executor.shutdown()
