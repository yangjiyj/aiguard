"""受限扫描临时区测试（设计 §4/§8）。"""
from __future__ import annotations

import hashlib
import os
import threading

import pytest

from app.scan_store import ScanStore, ScanStoreError


def _stream(data: bytes, chunk: int = 64):
    for i in range(0, len(data), chunk):
        yield data[i:i + chunk]


def test_receive_stream_computes_size_and_sha256(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    body = b"hello world document body " * 100
    obj = store.receive_stream("tenant_a", "req_1", _stream(body), "text/plain", "note.txt")
    assert obj.size == len(body)
    assert obj.sha256 == hashlib.sha256(body).hexdigest()
    # 文件名不参与路径（路径里只有 object_id.blob）
    assert "note.txt" not in obj.path
    assert obj.path.endswith(".blob")
    # 可读回
    assert store.read_bytes(obj.object_id, "tenant_a") == body


def test_receive_stream_rejects_oversized_and_removes_partial(tmp_path):
    store = ScanStore(str(tmp_path / "scan"), deploy_max_file_bytes=100)
    body = b"x" * 400
    with pytest.raises(ScanStoreError):
        store.receive_stream("tenant_a", "req_1", _stream(body), "text/plain", "big.bin")
    # 临时区里不应残留文件
    files = [f for f in os.listdir(store._root)] if os.path.isdir(store._root) else []
    assert files == []


def test_tenant_isolation(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    obj = store.receive_stream("tenant_a", "req_1", _stream(b"secret"), "text/plain", "a.txt")
    # tenant_b 读不到 tenant_a 的对象
    with pytest.raises(ScanStoreError):
        store.get(obj.object_id, "tenant_b")
    with pytest.raises(ScanStoreError):
        store.read_bytes(obj.object_id, "tenant_b")
    # tenant_a 正常
    assert store.read_bytes(obj.object_id, "tenant_a") == b"secret"


def test_consume_deletes_immediately(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    obj = store.receive_stream("tenant_a", "req_1", _stream(b"data"), "text/plain")
    assert os.path.exists(obj.path)
    store.consume(obj.object_id, "tenant_a")
    assert not os.path.exists(obj.path)
    # 再读 not_found
    with pytest.raises(ScanStoreError):
        store.get(obj.object_id, "tenant_a")
    n, bytes_ = store.stats()
    assert n == 0 and bytes_ == 0


def test_reap_expired_removes_ttl_objects(tmp_path):
    clock = {"t": 0.0}
    store = ScanStore(str(tmp_path / "scan"), ttl_seconds=60, now_fn=lambda: clock["t"])
    clock["t"] = 1000.0
    obj = store.receive_stream("tenant_a", "req_1", _stream(b"x"), "text/plain")
    assert os.path.exists(obj.path)
    # 未过期
    assert store.reap_expired() == 0
    # 推进时钟超过 TTL
    clock["t"] = 1000.0 + 61
    removed = store.reap_expired()
    assert removed == 1
    assert not os.path.exists(obj.path)


def test_high_watermark_rejects_new_writes(tmp_path):
    # 水位=40：写一个 40 字节对象后 total=40，达到水位 → 第二次写被拒
    store = ScanStore(str(tmp_path / "scan"), high_watermark_bytes=40)
    store.receive_stream("t", "r1", _stream(b"a" * 40), "text/plain")
    with pytest.raises(ScanStoreError) as exc:
        store.receive_stream("t", "r2", _stream(b"b" * 40), "text/plain")
    assert "watermark" in str(exc.value)


def test_invalid_object_id_rejected(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    with pytest.raises(ScanStoreError):
        store.get("../../../etc/passwd", "t")
    with pytest.raises(ScanStoreError):
        store.get("not-real", "t")


def test_object_id_random_and_unpredictable(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    o1 = store.receive_stream("t", "r1", _stream(b"a"), "text/plain")
    o2 = store.receive_stream("t", "r2", _stream(b"a"), "text/plain")
    # 同内容不同 object_id（不可预测）
    assert o1.object_id != o2.object_id
    assert o1.sha256 == o2.sha256


def test_concurrent_writes_thread_safe(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    results = []
    def worker(i):
        try:
            store.receive_stream(f"t{i}", f"r{i}", _stream(b"x" * 100), "text/plain")
            results.append("ok")
        except Exception:
            results.append("err")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == "ok" for r in results)
    n, _ = store.stats()
    assert n == 10


def test_root_must_be_absolute(tmp_path):
    with pytest.raises(ScanStoreError):
        ScanStore("relative/path")


def test_second_worker_can_read_and_consume_object(tmp_path):
    root = str(tmp_path / "scan")
    worker_a = ScanStore(root)
    worker_b = ScanStore(root)
    obj = worker_a.receive_stream(
        "tenant_a", "req_1", _stream(b"shared worker bytes"), "text/plain"
    )

    assert worker_b.read_bytes(obj.object_id, "tenant_a") == b"shared worker bytes"
    worker_b.consume(obj.object_id, "tenant_a")

    assert not os.path.exists(obj.path)
    with pytest.raises(ScanStoreError):
        worker_a.get(obj.object_id, "tenant_a")


def test_second_worker_reaper_does_not_delete_active_object(tmp_path):
    clock = {"t": 1000.0}
    root = str(tmp_path / "scan")
    worker_a = ScanStore(root, ttl_seconds=60, now_fn=lambda: clock["t"])
    worker_b = ScanStore(root, ttl_seconds=60, now_fn=lambda: clock["t"])
    obj = worker_a.receive_stream("tenant_a", "req_1", _stream(b"active"))

    assert worker_b.reap_expired() == 0
    assert worker_b.read_bytes(obj.object_id, "tenant_a") == b"active"


def test_second_worker_reaper_removes_expired_object_and_metadata(tmp_path):
    clock = {"t": 1000.0}
    root = str(tmp_path / "scan")
    worker_a = ScanStore(root, ttl_seconds=60, now_fn=lambda: clock["t"])
    worker_b = ScanStore(root, ttl_seconds=60, now_fn=lambda: clock["t"])
    obj = worker_a.receive_stream("tenant_a", "req_1", _stream(b"expired"))
    meta_path = os.path.join(root, obj.object_id + ".meta.json")
    assert os.path.exists(meta_path)

    clock["t"] += 61
    assert worker_b.reap_expired() == 1
    assert not os.path.exists(obj.path)
    assert not os.path.exists(meta_path)
    with pytest.raises(ScanStoreError):
        worker_a.get(obj.object_id, "tenant_a")


def test_scan_service_reaper_initializes_configured_store(tmp_path, monkeypatch):
    from app.scan_service import ScanService

    root = str(tmp_path / "configured-scan")
    monkeypatch.setenv("SECURITY_SCAN_STORE_DIR", root)
    service = ScanService()

    assert service._store is None
    assert service.reap_all() == 0
    assert service._store is not None
    assert os.path.isdir(root)
