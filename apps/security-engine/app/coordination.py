"""Cross-process coordination built on app.shared_state.

Three things must be global once security-engine runs more than one worker:

* circuit-breaker ``open`` state, so one worker's backend failures short-circuit
  every worker instead of each worker re-probing a dead judge for 30 seconds;
* the judge concurrency budget, so ``JUDGE_CAPACITY * workers`` cannot exceed
  what the GPU-side vLLM can actually serve;
* judge window opinion cache, so repeated tool results hit one shared cache.

Everything here is opt-in: with ``SECURITY_SHARED_STATE_URL`` unset the helpers
are inert and the existing single-process behaviour is unchanged.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from typing import Optional

from app.shared_state import (
    SharedState, SharedStateUnavailable, get_shared_state,
    json_bytes, parse_json, record_degradation,
)

DEFAULT_GLOBAL_JUDGE_CONCURRENCY = 96


def coordination_enabled() -> bool:
    return bool(os.getenv("SECURITY_SHARED_STATE_URL", "").strip())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SharedBreakerState:
    """Publish/observe breaker-open state without replacing the local breaker.

    The local breaker keeps its half-open probe semantics. This layer only adds
    a shared "open until <wall clock>" marker, which is read on every call. A
    successful call clears the marker. A valkey outage is recorded as a
    capacity-impact degradation (visible in health/inspection_reason) and falls
    back to the local breaker; it never silently hides a published open state.
    """

    _CONSUMER = "circuit_breaker"

    def __init__(self, state: Optional[SharedState] = None) -> None:
        self._state = state or get_shared_state()
        self._enabled = coordination_enabled()

    @staticmethod
    def _key(identity: str) -> str:
        return "breaker:open:" + _digest(str(identity))

    @property
    def enabled(self) -> bool:
        return self._enabled

    def is_open(self, identity: str) -> bool:
        if not self._enabled:
            return False
        try:
            raw = self._state.get(self._CONSUMER, self._key(identity),
                                  impact="capacity")
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "is_open",
                               "breaker_shared_state_unavailable",
                               impact="capacity")
            # Unknown global breaker state must not be treated as "known closed".
            # Callers keep their local breaker, and the degradation is audited.
            return False
        data = parse_json(raw, {})
        if not isinstance(data, dict):
            return False
        return time.time() < float(data.get("open_until", 0) or 0)

    def publish_open(self, identity: str, cooldown: float) -> None:
        if not self._enabled:
            return
        try:
            self._state.set(self._CONSUMER, self._key(identity),
                            json_bytes({"open_until": time.time() + max(0.0, cooldown)}),
                            int(max(0.0, cooldown) * 1000) or 1000,
                            impact="capacity")
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "publish_open",
                               "breaker_shared_state_unavailable",
                               impact="capacity")

    def clear(self, identity: str) -> None:
        if not self._enabled:
            return
        try:
            self._state.delete(self._CONSUMER, self._key(identity),
                               impact="capacity")
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "clear",
                               "breaker_shared_state_unavailable",
                               impact="capacity")

    def snapshot(self) -> dict:
        return {"enabled": self._enabled, "mode": self._state.mode,
                "consumer": self._CONSUMER}


_BREAKER: Optional[SharedBreakerState] = None
_BREAKER_LOCK = threading.Lock()


def breaker_state() -> SharedBreakerState:
    global _BREAKER
    with _BREAKER_LOCK:
        if _BREAKER is None:
            _BREAKER = SharedBreakerState()
        return _BREAKER


class SharedWindowOpinionCache:
    """Shared verdict cache. Keys are digests; raw text is never stored."""

    _CONSUMER = "judge_window_cache"

    def __init__(self, state: Optional[SharedState] = None,
                 ttl_seconds: float = 60.0) -> None:
        self._state = state or get_shared_state()
        self._enabled = coordination_enabled()
        self._ttl_ms = int(max(1.0, ttl_seconds) * 1000)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @staticmethod
    def _key(digest: bytes) -> str:
        return "judge:opinion:" + digest.hex()

    def get(self, digest: bytes):
        if not self._enabled:
            return None
        try:
            raw = self._state.get(self._CONSUMER, self._key(digest),
                                  impact="performance")
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "get",
                               "judge_window_cache_shared_state_unavailable",
                               impact="performance")
            return None
        data = parse_json(raw, {})
        if not isinstance(data, dict) or not data:
            return None
        if time.time() > float(data.get("expires_at", 0) or 0):
            return None
        return tuple(data.get("opinion") or ()) or None

    def put(self, digest: bytes, opinion) -> None:
        if not self._enabled:
            return
        try:
            self._state.set(self._CONSUMER, self._key(digest),
                            json_bytes({"opinion": list(opinion),
                                        "expires_at": time.time() + self._ttl_ms / 1000.0}),
                            self._ttl_ms, impact="performance")
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "put",
                               "judge_window_cache_shared_state_unavailable",
                               impact="performance")


class GlobalJudgeBudget:
    """Leased global concurrency budget for judge calls.

    ``SECURITY_JUDGE_GLOBAL_CONCURRENCY`` (default 96) is a hard cross-process
    ceiling. Each call takes one lease with a TTL, so a dead worker cannot leak
    capacity. When valkey is unavailable the budget degrades to the existing
    per-process semaphore and the degradation is audited; it never fails open
    silently.
    """

    _CONSUMER = "judge_global_budget"
    _KEY = "judge:global:inflight"

    def __init__(self, state: Optional[SharedState] = None,
                 limit: Optional[int] = None, lease_ms: Optional[int] = None) -> None:
        self._state = state or get_shared_state()
        self._enabled = coordination_enabled()
        try:
            self.limit = max(1, int(limit if limit is not None else os.getenv(
                "SECURITY_JUDGE_GLOBAL_CONCURRENCY",
                str(DEFAULT_GLOBAL_JUDGE_CONCURRENCY))))
        except ValueError:
            self.limit = DEFAULT_GLOBAL_JUDGE_CONCURRENCY
        self._lease_ms = max(1000, int(lease_ms or os.getenv(
            "SECURITY_JUDGE_GLOBAL_LEASE_MS", "30000")))

    @property
    def enabled(self) -> bool:
        return self._enabled

    def acquire(self) -> Optional[str]:
        """Return an opaque lease id, or None when the global budget is full."""
        if not self._enabled:
            return ""
        member = secrets.token_hex(16)
        try:
            ok = self._state.lease_acquire(self._CONSUMER, self._KEY,
                                           self.limit, member, self._lease_ms)
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "acquire",
                               "judge_global_budget_unavailable",
                               impact="capacity")
            # The lease may have been committed before the reply was lost; a ghost would
            # hold one of the 96 slots until its TTL.
            try:
                self._state.lease_release(self._CONSUMER, self._KEY, member)
            except SharedStateUnavailable:
                pass
            return ""  # explicit, audited degradation to the local semaphore
        return member if ok else None

    def release(self, member: str) -> None:
        if not self._enabled or not member:
            return
        try:
            self._state.lease_release(self._CONSUMER, self._KEY, member)
        except SharedStateUnavailable:
            record_degradation(self._CONSUMER, "release",
                               "judge_global_budget_unavailable",
                               impact="capacity")

    def in_flight(self) -> int:
        if not self._enabled:
            return -1
        try:
            return self._state.lease_count(self._CONSUMER, self._KEY,
                                           ttl_ms=self._lease_ms)
        except SharedStateUnavailable:
            return -2

    def snapshot(self) -> dict:
        return {
            "enabled": self._enabled,
            "limit": self.limit,
            "mode": self._state.mode,
            "in_flight": self.in_flight(),
            "lease_ms": self._lease_ms,
        }


_BUDGET: Optional[GlobalJudgeBudget] = None
_BUDGET_LOCK = threading.Lock()


def global_judge_budget() -> GlobalJudgeBudget:
    global _BUDGET
    with _BUDGET_LOCK:
        if _BUDGET is None:
            _BUDGET = GlobalJudgeBudget()
        return _BUDGET


def reset_coordination() -> None:
    """Test seam: drop memoised singletons after replacing shared state."""
    global _BUDGET, _BREAKER
    with _BUDGET_LOCK:
        _BUDGET = None
    with _BREAKER_LOCK:
        _BREAKER = None
