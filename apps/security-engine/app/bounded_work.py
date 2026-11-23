"""Bounded blocking work outside the ASGI event loop.

Capacity includes running and queued work. A timeout cancels queued work; running
calls retain their capacity until they finish, so timeout storms cannot bypass
the process resource limit.
"""
from __future__ import annotations
import asyncio
import concurrent.futures
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import math
import os
import threading
import time


def positive_number(name, default, integer=False):
    try:
        value = int(os.getenv(name, str(default))) if integer else float(os.getenv(name, str(default)))
        return value if math.isfinite(value) and value > 0 else default
    except (TypeError, ValueError, OverflowError):
        return default


class WorkUnavailable(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ExecutionBudget:
    deadline: float
    cancelled: threading.Event


_budget = ContextVar("security_execution_budget", default=None)


def effective_deadline(deadline):
    """Restrict a stage budget to its parent request, with no payload fields."""
    budget = _budget.get()
    if budget is None:
        return deadline
    if budget.cancelled.is_set():
        return min(deadline, time.monotonic())
    return min(deadline, budget.deadline)


def check_work_budget(deadline=None):
    budget = _budget.get()
    if budget is not None:
        if budget.cancelled.is_set():
            raise WorkUnavailable("canceled")
        deadline = min(deadline, budget.deadline) if deadline is not None else budget.deadline
    if deadline is not None and time.monotonic() >= deadline:
        raise WorkUnavailable("timeout")


@contextmanager
def execution_budget(deadline, cancelled=None):
    parent = _budget.get()
    if parent is not None:
        deadline = min(deadline, parent.deadline)
        cancelled = parent.cancelled
    state = ExecutionBudget(deadline, cancelled if cancelled is not None else threading.Event())
    token = _budget.set(state)
    try:
        yield state
    finally:
        _budget.reset(token)


def wait_for_work_future(future, deadline):
    """Stop waiting cooperatively; running work keeps its own capacity slot."""
    deadline = effective_deadline(deadline)
    while True:
        try:
            check_work_budget(deadline)
        except WorkUnavailable:
            future.cancel()
            raise
        remaining = deadline - time.monotonic()
        try:
            return future.result(timeout=max(0, min(.05, remaining)))
        except concurrent.futures.TimeoutError:
            if future.done():
                raise



class BoundedWorkPool:
    def __init__(self, name, workers, capacity):
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix=name)
        self.capacity = max(workers, capacity)
        self._slots = threading.BoundedSemaphore(self.capacity)
        self._lock = threading.Lock()
        self._active = 0
        self._submitted = 0
        self._rejected = 0
        self._expired = 0

    @classmethod
    def from_env(cls, prefix, workers, capacity):
        count = positive_number(prefix + "_WORKERS", workers, integer=True)
        limit = positive_number(prefix + "_CAPACITY", capacity, integer=True)
        return cls(prefix.lower(), count, limit)

    def submit(self, fn, *args, deadline, **kwargs):
        deadline = effective_deadline(deadline)
        check_work_budget(deadline)
        parent = _budget.get()
        cancelled = parent.cancelled if parent is not None else threading.Event()
        if not self._slots.acquire(blocking=False):
            with self._lock:
                self._rejected += 1
            raise WorkUnavailable("capacity_overflow")
        with self._lock:
            self._active += 1
            self._submitted += 1

        def work():
            with execution_budget(deadline, cancelled):
                try:
                    check_work_budget()
                except WorkUnavailable:
                    with self._lock:
                        self._expired += 1
                    raise
                return fn(*args, **kwargs)

        def complete(_future):
            with self._lock:
                self._active -= 1
            self._slots.release()

        try:
            future = self._executor.submit(work)
        except Exception:
            complete(None)
            raise
        future._work_cancelled = cancelled
        future.add_done_callback(complete)
        return future

    async def run(self, fn, *args, deadline, **kwargs):
        future = self.submit(fn, *args, deadline=deadline, **kwargs)
        wrapped = asyncio.wrap_future(future)
        try:
            return await asyncio.wait_for(wrapped, timeout=max(0, deadline - time.monotonic()))
        except asyncio.TimeoutError as exc:
            future._work_cancelled.set()
            future.cancel()
            with self._lock:
                self._expired += 1
            raise WorkUnavailable("timeout") from exc
        except asyncio.CancelledError:
            future._work_cancelled.set()
            future.cancel()
            raise

    def snapshot(self):
        with self._lock:
            return {"in_flight": self._active, "submitted": self._submitted,
                    "rejected": self._rejected, "expired": self._expired}
