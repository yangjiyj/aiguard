"""临时文件即焚 + 孤儿清理测试（设计 §6.3/§15）。"""
from __future__ import annotations

import os

import pytest

from app.scan_store import ScanStore, ScanStoreError


def _stream(data: bytes, chunk: int = 64):
    for i in range(0, len(data), chunk):
        yield data[i:i + chunk]


def test_temp_file_permission_0600(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    obj = store.receive_stream("t", "r", _stream(b"hello world"), "text/plain", "a.txt")
    mode = os.stat(obj.path).st_mode & 0o777
    assert mode == 0o600, f"file mode {oct(mode)} want 0o600"


def test_root_dir_permission_tight(tmp_path):
    root = str(tmp_path / "scan")
    store = ScanStore(root)
    store.ensure_root()
    mode = os.stat(root).st_mode & 0o777
    assert mode == 0o700, f"dir mode {oct(mode)} want 0o700"


def test_reap_disk_orphans_preserves_active_object_from_other_worker(tmp_path):
    """新 worker 不得把另一 worker 刚写入的活动对象当成孤儿删除。"""
    store = ScanStore(str(tmp_path / "scan"))
    obj = store.receive_stream("t", "r", _stream(b"data"), "text/plain")
    assert os.path.exists(obj.path)
    store2 = ScanStore(str(tmp_path / "scan"))
    store2.ensure_root()
    removed = store2.reap_disk_orphans()
    assert removed == 0
    assert store2.read_bytes(obj.object_id, "t") == b"data"


def test_reap_expired_calls_disk_orphan_cleanup(tmp_path):
    """reap_expired 清理超过 TTL 且无元数据的真实磁盘残片。"""
    store = ScanStore(str(tmp_path / "scan"))
    obj = store.receive_stream("t", "r", _stream(b"data"), "text/plain")
    orphan = os.path.join(store._root, "x" * 32 + ".blob")
    with open(orphan, "wb") as f:
        f.write(b"orphan")
    os.utime(orphan, (0, 0))
    removed = store.reap_expired()
    assert removed == 1
    assert os.path.exists(obj.path)
    assert not os.path.exists(orphan)


def test_reap_disk_orphans_skips_non_blob(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    store.ensure_root()
    # 非 .blob 文件不碰（README 等）
    other = os.path.join(store._root, "README")
    with open(other, "w") as f:
        f.write("keep me")
    store.reap_disk_orphans()
    assert os.path.exists(other)


def test_high_watermark_after_orphan_cleanup(tmp_path):
    """孤儿清理后高水位恢复（孤儿不占额度）。"""
    root = str(tmp_path / "scan")
    store = ScanStore(root, high_watermark_bytes=40)
    first = store.receive_stream("t", "r1", _stream(b"a" * 40), "text/plain")
    # 模拟在元数据提交前崩溃，并让残片超过 TTL。
    meta = os.path.join(root, first.object_id + ".meta.json")
    os.remove(meta)
    os.utime(first.path, (0, 0))

    store2 = ScanStore(root, high_watermark_bytes=40)
    store2.ensure_root()
    assert store2.reap_disk_orphans() == 1
    obj = store2.receive_stream("t", "r2", _stream(b"b" * 40), "text/plain")
    assert os.path.exists(obj.path)


def test_consume_removes_file(tmp_path):
    store = ScanStore(str(tmp_path / "scan"))
    obj = store.receive_stream("t", "r", _stream(b"x"), "text/plain")
    store.consume(obj.object_id, "t")
    assert not os.path.exists(obj.path)


def test_failed_receive_removes_partial(tmp_path):
    store = ScanStore(str(tmp_path / "scan"), deploy_max_file_bytes=10)
    with pytest.raises(ScanStoreError):
        store.receive_stream("t", "r", _stream(b"x" * 100), "text/plain", "big.bin")
    files = [f for f in os.listdir(store._root) if f.endswith(".blob")] if os.path.isdir(store._root) else []
    assert files == []
