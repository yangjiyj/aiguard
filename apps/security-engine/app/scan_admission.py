"""文件扫描准入控制器（设计 §6.1/§6.2）。

职责：在文件扫描服务接收大文件前，检查租户配额、全局容量与队列长度。
- 单租户并发扫描权重上限（默认 2）：同一租户同时进行的扫描数有界；
- 单租户等待队列上限（默认 5）：排队中的请求有界，超限立即拒绝；
- 全局扫描容量上限：跨租户总并发有界，防止单租户耗尽资源；
- 单租户资源耗尽不得影响其它租户的普通文字请求（文字请求不进本控制器）。

失败语义：配额耗尽 / 队列满 / 全局满 → 抛 AdmissionError，调用方只拒绝该文件上传，
绝不拖垮普通文字请求（普通文字请求不走准入控制器）。

权重模型：本期按文件数计权（每个扫描权重=1），设计 §6.1 提及的"按成本计权"留待
后续按文件类型分级（小型 Office 权重最低、大型 PDF/压缩包更高）。默认值见 DEFAULT_*。
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

from app.shared_state import (
    SharedState, SharedStateUnavailable, get_shared_state, record_degradation,
)

DEFAULT_TENANT_CONCURRENT = int(os.getenv("SECURITY_SCAN_ADMIT_TENANT_CONCURRENT", "2"))
DEFAULT_TENANT_QUEUE = int(os.getenv("SECURITY_SCAN_ADMIT_TENANT_QUEUE", "5"))
DEFAULT_GLOBAL_CONCURRENT = int(os.getenv("SECURITY_SCAN_ADMIT_GLOBAL_CONCURRENT", "16"))


class AdmissionError(Exception):
    """准入被拒（tenant_quota / tenant_queue / global_quota）。"""


@dataclass
class _TenantState:
    in_flight: int = 0
    queued: int = 0


class ScanAdmission:
    """Tenant/global admission. Shared mode uses leased ZSET slots in valkey.

    A valkey outage is fail-closed for NEW file scans: an unenforceable global
    quota must not silently become a per-process quota. The rejection reason is
    recorded as a detection-impact degradation so it shows up in audit/health.
    """

    _CONSUMER = "scan_admission"

    def __init__(
        self,
        tenant_concurrent: int = DEFAULT_TENANT_CONCURRENT,
        tenant_queue: int = DEFAULT_TENANT_QUEUE,
        global_concurrent: int = DEFAULT_GLOBAL_CONCURRENT,
        *, shared_state: Optional[SharedState] = None,
        shared: Optional[bool] = None,
    ) -> None:
        self._tenant_concurrent = max(1, int(tenant_concurrent))
        self._tenant_queue = max(0, int(tenant_queue))
        self._global_concurrent = max(1, int(global_concurrent))
        self._lock = threading.Lock()
        self._tenants: dict[str, _TenantState] = {}
        self._global_in_flight = 0
        if shared is None:
            shared = bool(os.getenv("SECURITY_SHARED_STATE_URL", "").strip())
        self._shared = bool(shared)
        self._state: Optional[SharedState] = (
            shared_state or get_shared_state() if self._shared else None
        )
        self._lease_ttl_ms = max(1000, int(os.getenv(
            "SECURITY_SCAN_ADMIT_LEASE_MS", "120000")))

    @property
    def shared(self) -> bool:
        return self._shared

    @staticmethod
    def _tenant_key(tenant_id: str) -> str:
        return "scan:admit:tenant:" + hashlib.sha256(tenant_id.encode()).hexdigest()

    def _degrade(self, op: str) -> None:
        record_degradation(self._CONSUMER, op,
                           "scan_admission_shared_state_unavailable",
                           impact="detection")

    def _release_quietly(self, key: str, member: str, op: str) -> None:
        """Best-effort ZREM. Members are unique random tokens, so removing one that is
        not there is harmless -- and a lease the server committed but whose reply never
        arrived (client timeout) must not stay behind until its TTL."""
        try:
            self._state.lease_release(self._CONSUMER, key, member)
        except SharedStateUnavailable:
            self._degrade(op)

    def _acquire_shared(self, tenant_id: str, timeout: Optional[float]):
        """Return a member token, or raise AdmissionError. Leases expire on crash."""
        member = secrets.token_hex(16)
        global_key = "scan:admit:global"
        tenant_key = self._tenant_key(tenant_id)
        queue_key = "scan:admit:queue:" + hashlib.sha256(tenant_id.encode()).hexdigest()
        deadline = None if timeout is None else (time.monotonic() + timeout)
        queued = False
        try:
            while True:
                try:
                    if not self._state.lease_acquire(
                            self._CONSUMER, global_key, self._global_concurrent,
                            member, self._lease_ttl_ms):
                        got_global = False
                    else:
                        got_global = True
                    if got_global:
                        if self._state.lease_acquire(
                                self._CONSUMER, tenant_key,
                                self._tenant_concurrent, member + ":t",
                                self._lease_ttl_ms):
                            return member
                        self._state.lease_release(self._CONSUMER, global_key, member)
                except SharedStateUnavailable:
                    self._degrade("acquire")
                    # Either lease may have been committed before the failure (a client
                    # timeout after the server applied the ZADD, or the tenant lease
                    # failing after the global one was granted): give both back now
                    # instead of holding two slots until the TTL.
                    self._release_quietly(global_key, member, "release")
                    self._release_quietly(tenant_key, member + ":t", "release")
                    raise AdmissionError("shared_state_unavailable")
                if not queued:
                    try:
                        if not self._state.lease_acquire(
                                self._CONSUMER, queue_key,
                                max(1, self._tenant_queue), member + ":q",
                                self._lease_ttl_ms):
                            raise AdmissionError("tenant_queue_full")
                        queued = True
                    except SharedStateUnavailable:
                        self._degrade("acquire_queue")
                        self._release_quietly(queue_key, member + ":q", "release_queue")
                        raise AdmissionError("shared_state_unavailable")
                if deadline is not None and time.monotonic() >= deadline:
                    raise AdmissionError("tenant_concurrent_timeout")
                time.sleep(0.01)
        finally:
            if queued:
                self._release_quietly(queue_key, member + ":q", "release_queue")

    def _release_shared(self, tenant_id: str, member: str) -> None:
        # Two independent releases: the first failing must not leave the tenant lease behind.
        self._release_quietly("scan:admit:global", member, "release")
        self._release_quietly(self._tenant_key(tenant_id), member + ":t", "release")

    def acquire(self, tenant_id: str, timeout: Optional[float] = None) -> "ScanSlot":
        """申请一个扫描槽位。队列满或配额耗尽且无法在 timeout 内获得 → AdmissionError。

        普通文字请求绝不调用本方法，因此不会被准入拒绝影响。
        """
        if not tenant_id:
            raise AdmissionError("tenant_id_required")
        if self._shared:
            member = self._acquire_shared(tenant_id, timeout)
            return ScanSlot(self, tenant_id, member=member)
        deadline = None if timeout is None else (time.monotonic() + timeout)
        # 入队检查
        with self._lock:
            st = self._tenants.setdefault(tenant_id, _TenantState())
            # 租户并发未满 → 直接占槽
            if st.in_flight < self._tenant_concurrent and self._global_in_flight < self._global_concurrent:
                st.in_flight += 1
                self._global_in_flight += 1
                return ScanSlot(self, tenant_id)
            # 否则入队等待（队列有界）
            if st.queued >= self._tenant_queue:
                raise AdmissionError("tenant_queue_full")
            st.queued += 1
        # 排队轮询（有界等待）
        acquired = False
        while True:
            with self._lock:
                if st.in_flight < self._tenant_concurrent and self._global_in_flight < self._global_concurrent:
                    st.in_flight += 1
                    self._global_in_flight += 1
                    st.queued = max(0, st.queued - 1)
                    acquired = True
                    break
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        if not acquired:
            with self._lock:
                st.queued = max(0, st.queued - 1)
            raise AdmissionError("tenant_concurrent_timeout")
        return ScanSlot(self, tenant_id)

    def _release(self, tenant_id: str, member: str = "") -> None:
        if self._shared:
            if member:
                self._release_shared(tenant_id, member)
            return
        with self._lock:
            st = self._tenants.get(tenant_id)
            if st is not None:
                st.in_flight = max(0, st.in_flight - 1)
            self._global_in_flight = max(0, self._global_in_flight - 1)

    def stats(self) -> dict:
        if self._shared:
            return {
                "mode": "shared",
                "tenant_concurrent_limit": self._tenant_concurrent,
                "tenant_queue_limit": self._tenant_queue,
                "global_concurrent_limit": self._global_concurrent,
            }
        with self._lock:
            return {
                "global_in_flight": self._global_in_flight,
                "tenant_concurrent_limit": self._tenant_concurrent,
                "tenant_queue_limit": self._tenant_queue,
                "global_concurrent_limit": self._global_concurrent,
                "tenants": {
                    tid: {"in_flight": s.in_flight, "queued": s.queued}
                    for tid, s in self._tenants.items()
                },
            }


class ScanSlot:
    """RAIDI 扫描槽位：with 语句退出即释放。"""

    def __init__(self, admission: ScanAdmission, tenant_id: str,
                 member: str = "") -> None:
        self._admission = admission
        self._tenant_id = tenant_id
        self._member = member
        self._released = False

    def __enter__(self) -> "ScanSlot":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._admission._release(self._tenant_id, self._member)
