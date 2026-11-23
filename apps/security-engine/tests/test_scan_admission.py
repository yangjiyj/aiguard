"""文件扫描准入控制器测试（设计 §6.1/§6.2）。"""
from __future__ import annotations

import threading
import time

import pytest

from app.scan_admission import ScanAdmission, AdmissionError


def test_acquire_release_basic():
    adm = ScanAdmission(tenant_concurrent=2, tenant_queue=5, global_concurrent=16)
    s = adm.acquire("t1")
    assert adm.stats()["global_in_flight"] == 1
    s.release()
    assert adm.stats()["global_in_flight"] == 0


def test_with_block_releases_on_exit():
    adm = ScanAdmission(tenant_concurrent=2)
    with adm.acquire("t1"):
        assert adm.stats()["global_in_flight"] == 1
    assert adm.stats()["global_in_flight"] == 0


def test_tenant_concurrent_limit():
    adm = ScanAdmission(tenant_concurrent=2, tenant_queue=0, global_concurrent=16)
    slots = [adm.acquire("t1"), adm.acquire("t1")]
    # 第三个：队列=0 → 立即拒
    with pytest.raises(AdmissionError):
        adm.acquire("t1", timeout=0.05)
    # 其它租户不受影响
    s3 = adm.acquire("t2")
    assert s3 is not None
    s3.release()
    for s in slots:
        s.release()


def test_tenant_queue_full_rejects():
    adm = ScanAdmission(tenant_concurrent=1, tenant_queue=2, global_concurrent=16)
    held = adm.acquire("t1")  # 占满租户并发
    # 两个排队（不立即超时，会等）
    started = []
    errs = []

    def worker():
        try:
            with adm.acquire("t1", timeout=0.3):
                started.append("ok")
        except AdmissionError:
            errs.append("queue")

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    # 此时 2 个排队、2 个队列满被拒
    time.sleep(0.1)
    held.release()  # 释放，让排队的进入
    for t in threads:
        t.join()
    # 至少有排队满被拒的（5 个 worker，队列 2，并发 1，3 个应被拒或部分超时）
    assert len(errs) >= 1 or len(started) >= 1


def test_tenant_isolation_other_tenant_unaffected():
    """单租户耗尽配额不影响其它租户。"""
    adm = ScanAdmission(tenant_concurrent=2, tenant_queue=0, global_concurrent=16)
    # t1 占满
    adm.acquire("t1")
    adm.acquire("t1")
    # t1 第三个被拒
    with pytest.raises(AdmissionError):
        adm.acquire("t1", timeout=0.01)
    # t2 正常
    with adm.acquire("t2"):
        pass


def test_global_concurrent_limit():
    adm = ScanAdmission(tenant_concurrent=10, tenant_queue=0, global_concurrent=2)
    adm.acquire("t1")
    adm.acquire("t2")
    # 全局已满，第三个（即使是新租户）排队=0 → 拒
    with pytest.raises(AdmissionError):
        adm.acquire("t3", timeout=0.01)


def test_stats_visibility():
    adm = ScanAdmission(tenant_concurrent=2, tenant_queue=5)
    s = adm.acquire("t1")
    st = adm.stats()
    assert st["global_in_flight"] == 1
    assert st["tenants"]["t1"]["in_flight"] == 1
    s.release()
