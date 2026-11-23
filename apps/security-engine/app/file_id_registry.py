"""两阶段文件协议的检测结果注册表（设计 §10）。

关联键 = tenant + subject + provider + file_id（四元组）。
- 上传检测后记录 verdict（allow / audit / block / quarantine / pending）；
- 后续请求引用 file_id 时查询：
  - allow → 可使用；
  - block → 拒绝；
  - quarantine → 拒绝（转审批）；
  - pending（未完成）→ 拒绝（等待或拒绝，调用方决定）；
  - 找不到可信关联 → NOT_FOUND，调用方不得标成"已检测通过"。

进程内 LRU + TTL。security-engine 是唯一检测点，三入口都通过它查询 → 跨入口共享同一注册表。
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Literal, Optional, Tuple

from app.shared_state import (
    SharedState, SharedStateUnavailable, get_shared_state,
    json_bytes, parse_json, record_degradation,
)

DEFAULT_MAX_ENTRIES = int(os.getenv("SECURITY_FILEID_REGISTRY_MAX", "50000"))
DEFAULT_TTL_SECONDS = int(os.getenv("SECURITY_FILEID_REGISTRY_TTL", str(60 * 60)))  # 1h

Verdict = Literal["allow", "audit", "block", "quarantine", "pending"]


def registry_key(tenant: str, subject: str, provider: str, file_id: str) -> str:
    raw = f"{tenant}|{subject}|{provider}|{file_id}"
    return "fid:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class VerdictEntry:
    verdict: Verdict
    sha256: str
    policy_version: str
    engine_build: str
    hit_categories: tuple
    created_at: float
    # Shared state uses wall-clock expiry (valkey PX owns the TTL). Local mode
    # keeps the historical monotonic created_at comparison.
    expires_at: float = 0.0


@dataclass
class BindingTokenEntry:
    tenant: str
    subject: str
    provider: str
    sha256: str
    verdict: Verdict
    policy_version: str
    engine_build: str
    created_at: float


class FileIDVerdictRegistry:
    """Verdict registry with an optional valkey-backed shared mode.

    ``shared_state`` injection is the multi-process seam: two registry objects
    sharing one SharedState see one global verdict table. When the shared
    backend is unavailable, lookups fail closed (``not_found``) and every
    degradation is recorded in the shared-state audit ring; an unknown verdict
    is never converted into "allow".
    """

    _CONSUMER = "file_id_registry"

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 *, shared_state: Optional[SharedState] = None,
                 shared: Optional[bool] = None) -> None:
        self._max = max(1, int(max_entries))
        self._ttl = max(1, int(ttl_seconds))
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, VerdictEntry]" = OrderedDict()
        self._bindings: "OrderedDict[str, BindingTokenEntry]" = OrderedDict()
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
    def _token_key(token: str) -> str:
        return "bind:" + hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _shared_verdict_key(raw_key: str) -> str:
        return "fid:verdict:" + raw_key

    @staticmethod
    def _shared_binding_key(raw_key: str) -> str:
        return "fid:token:" + raw_key

    def _degrade(self, op: str) -> None:
        record_degradation(self._CONSUMER, op,
                           "file_id_registry_shared_state_unavailable",
                           impact="detection",
                           node_id=self._state.node_id if self._state else "")

    def issue_binding_token(
        self,
        tenant: str,
        subject: str,
        provider: str,
        sha256: str,
        verdict: Verdict,
        policy_version: str = "",
        engine_build: str = "",
        now: Optional[float] = None,
    ) -> str:
        """Issue an opaque, one-time token for a completed byte scan.

        The raw token is returned only to the trusted gateway. The registry
        stores only its digest and the exact tenant/subject/provider/hash
        scope, so a client-supplied file_id cannot create a trusted verdict.
        """
        if not tenant or not sha256 or verdict not in ("allow", "audit", "block", "quarantine", "pending"):
            return ""
        if now is None:
            now = time.monotonic()
        token = secrets.token_urlsafe(32)
        key = self._token_key(token)
        if self._shared:
            entry = BindingTokenEntry(
                tenant=tenant, subject=subject, provider=provider,
                sha256=sha256, verdict=verdict, policy_version=policy_version,
                engine_build=engine_build, created_at=time.time(),
            )
            payload = json_bytes({
                "tenant": entry.tenant, "subject": entry.subject,
                "provider": entry.provider, "sha256": entry.sha256,
                "verdict": entry.verdict, "policy_version": entry.policy_version,
                "engine_build": entry.engine_build,
            })
            try:
                ok = self._state.set_if_absent(
                    self._CONSUMER, self._shared_binding_key(key),
                    payload, self._ttl * 1000, impact="detection")
            except SharedStateUnavailable:
                self._degrade("issue_binding_token")
                return ""
            return token if ok else ""
        with self._lock:
            self._bindings[key] = BindingTokenEntry(
                tenant=tenant,
                subject=subject,
                provider=provider,
                sha256=sha256,
                verdict=verdict,
                policy_version=policy_version,
                engine_build=engine_build,
                created_at=now,
            )
            self._bindings.move_to_end(key)
            while len(self._bindings) > self._max:
                self._bindings.popitem(last=False)
        return token

    def bind_scanned_file(
        self,
        tenant: str,
        subject: str,
        provider: str,
        token: str,
        file_id: str,
        now: Optional[float] = None,
    ) -> bool:
        """Consume a token exactly once and bind the real upstream file_id."""
        if not tenant or not file_id or not token:
            return False
        if now is None:
            now = time.monotonic()
        key = self._token_key(token)
        if self._shared:
            try:
                raw = self._state.take(self._CONSUMER, self._shared_binding_key(key))
            except SharedStateUnavailable:
                self._degrade("bind_scanned_file")
                return False
            data = parse_json(raw, {})
            if not isinstance(data, dict) or not data:
                return False
            if (data.get("tenant"), data.get("subject"), data.get("provider")) != (
                    tenant, subject, provider):
                return False
            return self._write_shared(
                registry_key(tenant, subject, provider, file_id),
                data.get("verdict", "pending"), data.get("sha256", ""),
                data.get("policy_version", ""), data.get("engine_build", ""),
                (),
            )
        with self._lock:
            entry = self._bindings.get(key)
            if entry is None:
                return False
            if (now - entry.created_at) > self._ttl:
                self._bindings.pop(key, None)
                return False
            if (entry.tenant, entry.subject, entry.provider) != (tenant, subject, provider):
                return False
            self._bindings.pop(key, None)

        # Consume is atomic under the token lock; record after releasing it to
        # avoid recursive locking while preserving one-time semantics.
        self.record(
            tenant=tenant,
            subject=subject,
            provider=provider,
            file_id=file_id,
            verdict=entry.verdict,
            sha256=entry.sha256,
            policy_version=entry.policy_version,
            engine_build=entry.engine_build,
            now=now,
        )
        return True

    def record(
        self,
        tenant: str,
        subject: str,
        provider: str,
        file_id: str,
        verdict: Verdict,
        sha256: str = "",
        policy_version: str = "",
        engine_build: str = "",
        hit_categories: Tuple[str, ...] = (),
        now: Optional[float] = None,
    ) -> None:
        if not tenant or not file_id:
            return
        if not isinstance(verdict, str) or verdict not in ("allow", "audit", "block", "quarantine", "pending"):
            return
        if now is None:
            now = time.monotonic()
        key = registry_key(tenant, subject, provider, file_id)
        if self._shared:
            return self._write_shared(key, verdict, sha256, policy_version,
                                      engine_build, hit_categories)
        with self._lock:
            self._store[key] = VerdictEntry(
                verdict=verdict,  # type: ignore[arg-type]
                sha256=sha256,
                policy_version=policy_version,
                engine_build=engine_build,
                hit_categories=tuple(hit_categories),
                created_at=now,
            )
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def _write_shared(self, key: str, verdict: Verdict, sha256: str,
                      policy_version: str, engine_build: str,
                      hit_categories: Tuple[str, ...]) -> bool:
        """Persist a verdict; never cache it locally when the write fails."""
        payload = json_bytes({
            "verdict": verdict, "sha256": sha256,
            "policy_version": policy_version, "engine_build": engine_build,
            "hit_categories": list(hit_categories),
            "expires_at": time.time() + self._ttl,
        })
        try:
            self._state.set(self._CONSUMER, self._shared_verdict_key(key),
                            payload, self._ttl * 1000, impact="detection")
        except SharedStateUnavailable:
            self._degrade("record")
            return False
        return True

    def lookup(
        self,
        tenant: str,
        subject: str,
        provider: str,
        file_id: str,
        now: Optional[float] = None,
    ) -> Tuple[str, Optional[VerdictEntry]]:
        """返回 (status, entry)。status: 'allow' | 'block' | 'pending' | 'not_found'。

        业务判定：
        - 已记录 allow/audit → 'allow'（可使用，audit 视同放行但留痕）
        - 已记录 block/quarantine → 'block'（拒绝）
        - 已记录 pending → 'pending'（未完成）
        - 找不到/过期 → 'not_found'（不得标通过）
        """
        if not tenant or not file_id:
            return ("not_found", None)
        if now is None:
            now = time.monotonic()
        key = registry_key(tenant, subject, provider, file_id)
        if self._shared:
            try:
                raw = self._state.get(self._CONSUMER, self._shared_verdict_key(key))
            except SharedStateUnavailable:
                # Fail closed: an unreadable verdict is never an inspected allow.
                self._degrade("lookup")
                return ("not_found", None)
            data = parse_json(raw, {})
            if not isinstance(data, dict) or not data:
                return ("not_found", None)
            if time.time() > float(data.get("expires_at", 0) or 0):
                return ("not_found", None)
            entry = VerdictEntry(
                verdict=data.get("verdict", "pending"),
                sha256=data.get("sha256", ""),
                policy_version=data.get("policy_version", ""),
                engine_build=data.get("engine_build", ""),
                hit_categories=tuple(data.get("hit_categories") or ()),
                created_at=time.monotonic(),
                expires_at=float(data.get("expires_at", 0) or 0),
            )
            if entry.verdict in ("allow", "audit"):
                return ("allow", entry)
            if entry.verdict in ("block", "quarantine"):
                return ("block", entry)
            return ("pending", entry)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return ("not_found", None)
            if (now - entry.created_at) > self._ttl:
                self._store.pop(key, None)
                return ("not_found", None)
            self._store.move_to_end(key)
        if entry.verdict in ("allow", "audit"):
            return ("allow", entry)
        if entry.verdict in ("block", "quarantine"):
            return ("block", entry)
        return ("pending", entry)

    def size(self) -> int:
        # Shared entries live in valkey and expire by TTL; -1 means "not local".
        if self._shared:
            return -1
        with self._lock:
            return len(self._store)

    def purge(self) -> None:
        # Test-only helper. Shared entries are never bulk-deleted: doing so
        # would invalidate verdicts belonging to other processes. They expire
        # by TTL instead.
        with self._lock:
            self._store.clear()
            self._bindings.clear()
