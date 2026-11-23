"""A full global judge budget queues like a full process semaphore.

Before, a full process semaphore waited up to the queue budget while a full
*global* budget deferred at once: as soon as a second replica existed, a short
burst became ``judge_capacity_deferred`` (an incomplete verdict) that a single
process would have absorbed.
"""
import threading
import time

import pytest

from app import coordination as coord
from app.detectors import semantic


class _LeaseState:
    def __init__(self, limit):
        self.limit = limit
        self.held = set()
        self.lock = threading.Lock()

    def lease_acquire(self, consumer, key, limit, member, ttl_ms):
        with self.lock:
            if len(self.held) >= min(limit, self.limit):
                return False
            self.held.add(member)
            return True

    def lease_release(self, consumer, key, member):
        with self.lock:
            self.held.discard(member)
            return True


@pytest.fixture
def full_budget(monkeypatch):
    monkeypatch.setenv("SECURITY_SHARED_STATE_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setattr(semantic, "_CAPACITY", threading.BoundedSemaphore(8))
    monkeypatch.setattr(semantic, "_JUDGE_QUEUE_WAIT", 1.0)
    monkeypatch.setattr(semantic, "_JUDGE_REGULAR_QUEUE_WAIT", 1.0)
    budget = coord.GlobalJudgeBudget(state=_LeaseState(1), limit=1)
    monkeypatch.setattr(semantic, "global_judge_budget", lambda: budget)
    holder = budget.acquire()
    assert holder, "the fixture must hold the only global lease"
    yield budget, holder
    budget.release(holder)


def _submit(**kwargs):
    started = time.monotonic()
    result = semantic._submit_bounded(lambda: "judged", **kwargs)
    return result, time.monotonic() - started


def test_a_burst_waits_for_the_global_budget(full_budget):
    budget, holder = full_budget
    threading.Timer(0.3, budget.release, args=(holder,)).start()
    result, elapsed = _submit(private_deadline=time.monotonic() + 5, private_op_timeout=1.0)
    assert result not in (semantic._DEFERRED, semantic._OVERFLOW, semantic._TIMEOUT)
    assert result.result(timeout=2) == "judged"
    assert elapsed >= 0.25


def test_the_wait_is_bounded_and_then_defers(full_budget):
    result, elapsed = _submit(private_deadline=time.monotonic() + 5, private_op_timeout=1.0)
    assert result is semantic._DEFERRED
    assert 0.8 <= elapsed < 2.5


def test_priority_work_that_never_gets_budget_overflows(full_budget):
    result, elapsed = _submit(private_priority=True, private_deadline=time.monotonic() + 5,
                              private_op_timeout=1.0)
    assert result is semantic._OVERFLOW
    assert elapsed < 2.5


def test_calls_without_a_parent_budget_still_fail_fast(full_budget):
    result, elapsed = _submit()
    assert result is semantic._DEFERRED
    assert elapsed < 0.2
