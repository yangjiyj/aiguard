"""文件内容 DLP 检测结果缓存（设计 §6.4）。

键 = tenant + policy_version + engine_version + sha256。
只存结论（action）、findings（脱敏）、版本，绝不存原文件或完整正文。
规则或引擎版本变化后旧缓存不复用（键含版本）。

进程内 LRU，有界条目数与 TTL；多进程部署下各自缓存（可接受：命中率换简单，
且文件 sha256 命中即同内容，重复检测成本低）。
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, List, Optional

from app.shared_state import (
    SharedState, SharedStateUnavailable, get_shared_state,
    json_bytes, parse_json, record_degradation,
)

DEFAULT_MAX_ENTRIES = int(os.getenv("SECURITY_SCAN_RESULT_CACHE_MAX", "10000"))
DEFAULT_TTL_SECONDS = int(os.getenv("SECURITY_SCAN_RESULT_CACHE_TTL", str(30 * 60)))


def cache_key(
    tenant_id: str,
    policy_version: str,
    engine_build: str,
    sha256: str,
    real_type: str,
) -> str:
    """构造稳定缓存键。real_type 纳入键（同字节不同声明类型提取逻辑不同）。"""
    raw = f"{tenant_id}|{policy_version}|{engine_build}|{sha256}|{real_type}"
    return "fcdlp:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class CacheEntry:
    action: str
    findings: List[Any]  # 脱敏后的 findings（不含完整正文）
    policy_version: str
    engine_build: str
    created_at: float


class ScanResultCache:
    """DLP result cache. Shared mode stores only verdicts, never file content.

    A valkey outage is a pure performance degradation (cache miss -> rescan),
    never an inspection bypass; it is recorded with impact=performance.
    """

    _CONSUMER = "scan_result_cache"

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 *, shared_state: Optional[SharedState] = None,
                 shared: Optional[bool] = None) -> None:
        self._max = max(1, int(max_entries))
        self._ttl = max(1, int(ttl_seconds))
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, CacheEntry]" = OrderedDict()
        if shared is None:
            shared = bool(os.getenv("SECURITY_SHARED_STATE_URL", "").strip())
        self._shared = bool(shared)
        self._state: Optional[SharedState] = (
            shared_state or get_shared_state() if self._shared else None
        )

    @property
    def shared(self) -> bool:
        return self._shared

    @staticmethod
    def _shared_key(raw_key: str) -> str:
        return "fcdlp:shared:" + raw_key

    def get(
        self,
        tenant_id: str,
        policy_version: str,
        engine_build: str,
        sha256: str,
        real_type: str,
        now: float,
    ) -> Optional[CacheEntry]:
        key = cache_key(tenant_id, policy_version, engine_build, sha256, real_type)
        if self._shared:
            try:
                raw = self._state.get(self._CONSUMER, self._shared_key(key),
                                      impact="performance")
            except SharedStateUnavailable:
                record_degradation(self._CONSUMER, "get",
                                   "scan_result_cache_shared_state_unavailable",
                                   impact="performance")
                return None
            data = parse_json(raw, {})
            if not isinstance(data, dict) or not data:
                return None
            if time.time() > float(data.get("expires_at", 0) or 0):
                return None
            return CacheEntry(
                action=str(data.get("action", "")),
                findings=list(data.get("findings") or []),
                policy_version=str(data.get("policy_version", "")),
                engine_build=str(data.get("engine_build", "")),
                created_at=time.monotonic(),
            )
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if (now - entry.created_at) > self._ttl:
                # 过期
                self._store.pop(key, None)
                return None
            # LRU 提到末尾
            self._store.move_to_end(key)
            return entry

    def put(
        self,
        tenant_id: str,
        policy_version: str,
        engine_build: str,
        sha256: str,
        real_type: str,
        action: str,
        findings: List[Any],
        now: float,
    ) -> None:
        # 只缓存有结论且版本齐全的结果；缺版本不缓存（避免命中错版本）
        if not policy_version or not engine_build or not sha256:
            return
        key = cache_key(tenant_id, policy_version, engine_build, sha256, real_type)
        if self._shared:
            payload = json_bytes({
                "action": action,
                "findings": list(findings),
                "policy_version": policy_version,
                "engine_build": engine_build,
                "expires_at": time.time() + self._ttl,
            })
            try:
                self._state.set(self._CONSUMER, self._shared_key(key), payload,
                                self._ttl * 1000, impact="performance")
            except SharedStateUnavailable:
                record_degradation(self._CONSUMER, "put",
                                   "scan_result_cache_shared_state_unavailable",
                                   impact="performance")
            return
        with self._lock:
            self._store[key] = CacheEntry(
                action=action,
                findings=list(findings),
                policy_version=policy_version,
                engine_build=engine_build,
                created_at=now,
            )
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def invalidate(self) -> None:
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._store)
