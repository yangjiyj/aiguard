"""Behaviour that only a real server can show: the Lua scripts and GETEX.

Opt-in so nobody points the suite at a server they care about by accident:

    JJD_TEST_VALKEY_URL=redis://:password@127.0.0.1:16398/3 python -m pytest tests/test_shared_state_real_valkey.py

Every key carries a unique prefix and is left to expire (no FLUSHDB).
"""
import os
import threading
import time
import uuid

import pytest

from app import shared_state as ss

URL = os.getenv("JJD_TEST_VALKEY_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="set JJD_TEST_VALKEY_URL to run against a real valkey")


@pytest.fixture
def backend():
    return ss.ValkeyBackend(URL, timeout=1.0)


@pytest.fixture
def key():
    return "jjd-test:%s" % uuid.uuid4().hex


def test_a_fast_clock_cannot_evict_a_live_lease(backend, key, monkeypatch):
    # Every replica shares the server's clock; a node whose own clock runs 40 s fast
    # used to evict a 30 s lease another node was still holding.
    assert backend.lease_acquire(key, 1, "holder", 30000) is True
    real = time.time
    with monkeypatch.context() as patched:
        patched.setattr(ss.time, "time", lambda: real() + 40)
        assert backend.lease_acquire(key, 1, "intruder", 30000) is False
    assert backend.lease_count(key, 30000) == 1


def test_a_slow_clock_cannot_keep_an_expired_lease_alive(backend, key, monkeypatch):
    assert backend.lease_acquire(key, 1, "holder", 300) is True
    time.sleep(0.5)
    real = time.time
    with monkeypatch.context() as patched:
        patched.setattr(ss.time, "time", lambda: real() - 40)
        assert backend.lease_acquire(key, 1, "next", 300) is True


def test_reentering_a_held_lease_at_the_cap_succeeds_and_refreshes(backend, key):
    assert backend.lease_acquire(key, 1, "m", 600) is True
    time.sleep(0.4)
    assert backend.lease_acquire(key, 1, "m", 600) is True
    time.sleep(0.4)
    assert backend.lease_count(key, 600) == 1


def test_the_cap_holds_under_concurrency(backend, key):
    granted = []

    def worker(index):
        local = ss.ValkeyBackend(URL, timeout=2.0)
        granted.append(local.lease_acquire(key, 50, "m%d" % index, 30000))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(200)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert granted.count(True) == 50


def test_getex_reads_and_slides_the_ttl(backend, key):
    backend.set(key, b"v", 600)
    time.sleep(0.4)
    assert backend.getex(key, 600) == b"v"
    time.sleep(0.4)
    assert backend.getex(key, 600) == b"v"
    time.sleep(0.8)
    assert backend.get(key) is None
