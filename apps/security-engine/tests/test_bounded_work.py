import asyncio
import threading
import time
import pytest
from app.bounded_work import BoundedWorkPool, WorkUnavailable, positive_number

def test_capacity_is_retained_for_timed_out_running_work():
    pool=BoundedWorkPool("capacity-test", 1, 1)
    release=threading.Event()
    started=threading.Event()
    def work():
        started.set()
        release.wait(2)
    async def run():
        with pytest.raises(WorkUnavailable, match="timeout"):
            await pool.run(work, deadline=time.monotonic()+.04)
        assert started.is_set()
        with pytest.raises(WorkUnavailable, match="capacity_overflow"):
            pool.submit(lambda: None, deadline=time.monotonic()+1)
    try:
        asyncio.run(run())
    finally:
        release.set()
        pool._executor.shutdown()
    assert pool.snapshot()["in_flight"] == 0

def test_expired_queued_request_never_executes():
    pool=BoundedWorkPool("deadline-test", 1, 2)
    release=threading.Event()
    ran=[]
    first=pool.submit(release.wait, 2, deadline=time.monotonic()+3)
    second=pool.submit(lambda: ran.append(True), deadline=time.monotonic()+.02)
    try:
        time.sleep(.04)
        release.set()
        first.result(timeout=1)
        with pytest.raises(WorkUnavailable, match="timeout"):
            second.result(timeout=1)
        assert ran == []
    finally:
        release.set()
        pool._executor.shutdown()

def test_invalid_instance_budgets_fall_back(monkeypatch):
    for value in ("nan", "inf", "-1", "0", "bad"):
        monkeypatch.setenv("TEST_BUDGET", value)
        assert positive_number("TEST_BUDGET", 2) == 2
