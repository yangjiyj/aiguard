"""检测结果缓存测试（设计 §6.4）。"""
from __future__ import annotations

from app.scan_result_cache import ScanResultCache, cache_key


def test_put_then_get_hit():
    c = ScanResultCache(max_entries=10, ttl_seconds=100)
    c.put("t1", "pv1", "eb1", "sha1", "docx", "block", [{"category": "phone_cn"}], now=10.0)
    e = c.get("t1", "pv1", "eb1", "sha1", "docx", now=11.0)
    assert e is not None
    assert e.action == "block"
    assert e.findings[0]["category"] == "phone_cn"


def test_version_change_invalidates():
    """规则或引擎版本变化后旧缓存不复用（键含版本）。"""
    c = ScanResultCache()
    c.put("t1", "pv1", "eb1", "sha1", "docx", "block", [], now=1.0)
    # policy 版本变 → miss
    assert c.get("t1", "pv2", "eb1", "sha1", "docx", now=1.0) is None
    # engine 版本变 → miss
    assert c.get("t1", "pv1", "eb2", "sha1", "docx", now=1.0) is None
    # 原版本 → hit
    assert c.get("t1", "pv1", "eb1", "sha1", "docx", now=1.0) is not None


def test_tenant_isolation():
    c = ScanResultCache()
    c.put("t1", "pv", "eb", "sha", "docx", "block", [], now=1.0)
    assert c.get("t2", "pv", "eb", "sha", "docx", now=1.0) is None


def test_ttl_expiry():
    c = ScanResultCache(ttl_seconds=10)
    c.put("t1", "pv", "eb", "sha", "docx", "block", [], now=100.0)
    assert c.get("t1", "pv", "eb", "sha", "docx", now=109.0) is not None
    assert c.get("t1", "pv", "eb", "sha", "docx", now=120.0) is None


def test_lru_eviction():
    c = ScanResultCache(max_entries=2)
    c.put("t1", "pv", "eb", "sha1", "docx", "block", [], now=1.0)
    c.put("t1", "pv", "eb", "sha2", "docx", "block", [], now=1.0)
    c.put("t1", "pv", "eb", "sha3", "docx", "block", [], now=1.0)
    # sha1 被淘汰
    assert c.get("t1", "pv", "eb", "sha1", "docx", now=1.0) is None
    assert c.get("t1", "pv", "eb", "sha2", "docx", now=1.0) is not None
    assert c.get("t1", "pv", "eb", "sha3", "docx", now=1.0) is not None


def test_missing_version_not_cached():
    c = ScanResultCache()
    c.put("t1", "", "eb", "sha", "docx", "block", [], now=1.0)
    c.put("t1", "pv", "", "sha", "docx", "block", [], now=1.0)
    c.put("t1", "pv", "eb", "", "docx", "block", [], now=1.0)
    assert c.size() == 0


def test_cache_key_stable():
    k1 = cache_key("t1", "pv", "eb", "sha", "docx")
    k2 = cache_key("t1", "pv", "eb", "sha", "docx")
    assert k1 == k2
    k3 = cache_key("t1", "pv", "eb", "sha", "pdf")
    assert k1 != k3


def test_no_raw_content_stored():
    """缓存只存结论+findings，不存原文件或完整正文。CacheEntry 字段无 content/raw 字段。"""
    from app.scan_result_cache import CacheEntry
    fields = CacheEntry.__dataclass_fields__
    for forbidden in ("content", "raw", "text", "body"):
        assert forbidden not in fields, f"CacheEntry 不应含 {forbidden} 字段"
