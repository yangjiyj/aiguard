"""Cross-process shared state for security-engine, backed by the existing valkey service.

Why this module exists
----------------------
The engine used to keep breakers, caches, the file_id verdict registry, the MCP
tool-definition pins, judge capacity and scan admission in process-local dicts.
That is correct for one uvicorn worker and silently wrong as soon as
``SECURITY_ENGINE_WEB_CONCURRENCY`` or ``deploy.replicas`` is greater than one.

Deployment contract
-------------------
* ``SECURITY_SHARED_STATE_URL``  -- e.g. ``redis://:password@redis:6379/3``.
  Empty (the default) keeps the legacy in-process backend so single-process
  installations and the whole existing test suite behave exactly as before.
* ``SECURITY_SHARED_STATE_PREFIX`` -- default ``jjd:se:``. All keys are hashed
  or operator-supplied identifiers; **never** raw inspected content.
* ``SECURITY_SHARED_STATE_TIMEOUT`` -- per-command socket timeout, default 0.05s.
* ``SECURITY_SHARED_STATE_REQUIRED`` -- when true, startup selfcheck refuses to
  boot with a local backend. Compose sets it for multi-worker deployments.

No third-party dependency is used: the product ships as an offline bundle, so a
small RESP2 client is included here instead of adding ``redis`` to
requirements.txt. The backend interface is deliberately tiny so tests can share
one in-memory backend between two engine instances, or run two real OS
processes against a test RESP server.

Failure policy
--------------
Every backend failure is recorded in a bounded, process-wide audit ring and is
visible through ``snapshot()`` and ``drain_reasons()``. Consumers must choose a
documented policy: fail closed (never turn an unknown into an allow), or an
explicit degradation whose reason reaches ``semantic_status`` /
``inspection_reason``. There is no silent fallback.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import urllib.parse
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_PREFIX = "jjd:se:"
DEFAULT_TIMEOUT = 0.05
_AUDIT_LIMIT = 256

# impact=detection means a consumer could not prove an inspection invariant.
# Those reasons are promoted into inspection_reason / semantic_status by the
# API layer. capacity/performance degradations stay observable but do not turn
# an otherwise complete inspection into a 503.
_IMPACTS = ("detection", "capacity", "performance")


class SharedStateUnavailable(RuntimeError):
    """A shared-state operation failed; the caller must apply its documented policy."""


class _Audit:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: Deque[dict] = deque(maxlen=_AUDIT_LIMIT)
        self._counts: Dict[str, int] = {}
        self._total = 0

    def record(self, *, consumer: str, op: str, impact: str, reason: str,
               node_id: str = "") -> None:
        if impact not in _IMPACTS:
            impact = "detection"
        event = {
            "ts": round(time.time(), 3),
            "consumer": consumer,
            "op": op,
            "impact": impact,
            "reason": reason,
            "node_id": node_id,
        }
        with self._lock:
            self._events.append(event)
            self._counts[reason] = self._counts.get(reason, 0) + 1
            self._total += 1
        logger.warning("shared_state degraded consumer=%s op=%s impact=%s reason=%s",
                       consumer, op, impact, reason)

    def events(self, limit: int = 32) -> list:
        with self._lock:
            return list(self._events)[-max(0, limit):]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "events_total": self._total,
                "counts": dict(self._counts),
                "recent": list(self._events)[-8:],
            }

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._counts.clear()
            self._total = 0


AUDIT = _Audit()


def record_degradation(consumer: str, op: str, reason: str,
                       *, impact: str = "detection", node_id: str = "") -> None:
    """Public hook for consumers that degrade without a backend exception."""
    AUDIT.record(consumer=consumer, op=op, impact=impact, reason=reason, node_id=node_id)


def drain_reasons(*, impact: Optional[str] = None,
                  max_age_s: Optional[float] = 30.0) -> list:
    """Distinct recent degradation reasons promoted into audit fields.

    Bounded by age so a transient valkey blip does not mark every subsequent
    request incomplete forever; a persistent outage keeps re-recording.
    """
    wanted = ("detection", "capacity") if impact is None else (impact,)
    cutoff = None if max_age_s is None else time.time() - max_age_s
    return sorted({e["reason"] for e in AUDIT.events(limit=_AUDIT_LIMIT)
                   if e["impact"] in wanted
                   and (cutoff is None or e["ts"] >= cutoff)})


def read_env_int(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return max(minimum, default)


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------

class MemoryBackend:
    """Single-process backend. Semantics match the valkey backend exactly.

    Tests intentionally share one instance of this object between two engine
    objects to prove that no consumer keeps hidden process-local state.
    """

    name = "local"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values: Dict[str, tuple] = {}          # key -> (bytes, expiry_monotonic|None)
        self._counters: Dict[str, tuple] = {}        # key -> (int, expiry)
        self._leases: Dict[str, Dict[str, float]] = {}  # key -> {member: expiry_wall}

    @staticmethod
    def _expired(entry) -> bool:
        return entry[1] is not None and entry[1] <= time.monotonic()

    def ping(self) -> bool:
        return True

    def set_if_absent(self, key: str, value: bytes, ttl_ms: int) -> bool:
        now = time.monotonic()
        with self._lock:
            entry = self._values.get(key)
            if entry is not None and not self._expired(entry):
                return False
            self._values[key] = (bytes(value), now + ttl_ms / 1000.0)
            return True

    def get(self, key: str) -> Optional[bytes]:
        with self._lock:
            entry = self._values.get(key)
            if entry is None:
                return None
            if self._expired(entry):
                self._values.pop(key, None)
                return None
            return entry[0]

    def getex(self, key: str, ttl_ms: int) -> Optional[bytes]:
        """Atomically read and push the expiry out (GETEX PX): a sliding TTL."""
        with self._lock:
            entry = self._values.get(key)
            if entry is None:
                return None
            if self._expired(entry):
                self._values.pop(key, None)
                return None
            self._values[key] = (entry[0], time.monotonic() + ttl_ms / 1000.0)
            return entry[0]

    def set(self, key: str, value: bytes, ttl_ms: int) -> None:
        with self._lock:
            self._values[key] = (bytes(value), time.monotonic() + ttl_ms / 1000.0)

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._counters.pop(key, None)
            self._leases.pop(key, None)

    def take(self, key: str) -> Optional[bytes]:
        """Atomically read and remove (one-time binding tokens)."""
        with self._lock:
            entry = self._values.pop(key, None)
        if entry is None or self._expired(entry):
            return None
        return entry[0]

    def increment(self, key: str, ttl_ms: int) -> int:
        now = time.monotonic()
        with self._lock:
            entry = self._counters.get(key)
            if entry is None or self._expired(entry):
                self._counters[key] = (1, now + ttl_ms / 1000.0)
                return 1
            value = entry[0] + 1
            self._counters[key] = (value, entry[1])
            return value

    def counter(self, key: str) -> int:
        with self._lock:
            entry = self._counters.get(key)
            if entry is None or self._expired(entry):
                return 0
            return entry[0]

    def lease_acquire(self, key: str, limit: int, member: str, ttl_ms: int) -> bool:
        now = time.time()
        with self._lock:
            holders = self._leases.setdefault(key, {})
            for name, expiry in list(holders.items()):
                if expiry <= now:
                    del holders[name]
            if member in holders:
                holders[member] = now + ttl_ms / 1000.0
                return True
            if len(holders) >= limit:
                return False
            holders[member] = now + ttl_ms / 1000.0
            return True

    def lease_release(self, key: str, member: str) -> None:
        with self._lock:
            holders = self._leases.get(key)
            if holders is not None:
                holders.pop(member, None)

    def lease_count(self, key: str, ttl_ms: int = 60000) -> int:
        now = time.time()
        with self._lock:
            holders = self._leases.get(key, {})
            for name, expiry in list(holders.items()):
                if expiry <= now:
                    del holders[name]
            return len(holders)

    def close(self) -> None:
        return None


# Lua scripts are executed atomically by valkey. The leading marker is also how
# the in-repo test RESP server dispatches them (no Lua interpreter in tests).
_LUA_INCR = "-- jjd:se:incr\nlocal v = redis.call('INCR', KEYS[1])\nif v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end\nreturn v"
# Time comes from the server (TIME), never from the caller: every replica shares one
# clock that way, so a node whose clock runs fast cannot evict a lease another node
# still holds. ARGV[1] (the caller's clock) is kept for wire compatibility and ignored.
# TIME followed by writes needs Valkey / Redis >= 5 (script effects replication).
_LUA_LEASE_ACQUIRE = (
    "-- jjd:se:lease_acquire\n"
    "local t = redis.call('TIME')\n"
    "local now = tonumber(t[1]) + tonumber(t[2]) / 1000000\n"
    "redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - tonumber(ARGV[2]) / 1000)\n"
    "if redis.call('ZSCORE', KEYS[1], ARGV[4]) then\n"
    "  redis.call('ZADD', KEYS[1], now, ARGV[4])\n"
    "  redis.call('PEXPIRE', KEYS[1], ARGV[2])\n"
    "  return 1\n"
    "end\n"
    "if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then return 0 end\n"
    "redis.call('ZADD', KEYS[1], now, ARGV[4])\n"
    "redis.call('PEXPIRE', KEYS[1], ARGV[2])\n"
    "return 1"
)
_LUA_COUNTER = (
    "-- jjd:se:counter\n"
    "local t = redis.call('TIME')\n"
    "local now = tonumber(t[1]) + tonumber(t[2]) / 1000000\n"
    "redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - tonumber(ARGV[2]) / 1000)\n"
    "return redis.call('ZCARD', KEYS[1])"
)
_LUA_TAKE = (
    "-- jjd:se:take\n"
    "local v = redis.call('GET', KEYS[1])\n"
    "if v then redis.call('DEL', KEYS[1]) end\n"
    "return v"
)


class _RESP2:
    """Minimal thread-safe RESP2 client (AUTH/SELECT/EVAL/SET/GET/... only)."""

    def __init__(self, host: str, port: int, password: str, db: int,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._host = host
        self._port = port
        self._password = password
        self._db = db
        self._timeout = timeout
        self._local = threading.local()

    @staticmethod
    def _encode(args) -> bytes:
        out = [b"*" + str(len(args)).encode() + b"\r\n"]
        for arg in args:
            if isinstance(arg, str):
                raw = arg.encode("utf-8")
            elif isinstance(arg, (bytes, bytearray)):
                raw = bytes(arg)
            else:
                raw = str(arg).encode("utf-8")
            out.append(b"$" + str(len(raw)).encode() + b"\r\n" + raw + b"\r\n")
        return b"".join(out)

    def _read_line(self, fp) -> bytes:
        line = fp.readline()
        if not line:
            raise ConnectionError("valkey closed connection")
        if not line.endswith(b"\r\n"):
            raise ConnectionError("truncated RESP reply")
        return line[:-2]

    def _recv(self, fp):
        line = self._read_line(fp)
        marker, body = line[:1], line[1:]
        if marker == b"+":
            return body.decode("utf-8", "replace")
        if marker == b"-":
            raise RuntimeError(body.decode("utf-8", "replace"))
        if marker == b":":
            return int(body)
        if marker == b"$":
            size = int(body)
            if size < 0:
                return None
            data = fp.read(size)
            if len(data) != size:
                raise ConnectionError("short bulk reply")
            fp.read(2)
            return data
        if marker == b"*":
            count = int(body)
            if count < 0:
                return None
            return [self._recv(fp) for _ in range(count)]
        raise ConnectionError("unknown RESP marker %r" % marker)

    def _connect(self):
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        sock.settimeout(self._timeout)
        fp = sock.makefile("rb")
        try:
            if self._password:
                sock.sendall(self._encode(("AUTH", self._password)))
                self._recv(fp)
            if self._db:
                sock.sendall(self._encode(("SELECT", self._db)))
                self._recv(fp)
        except Exception:
            fp.close()
            sock.close()
            raise
        return sock, fp

    def command(self, *args) -> Any:
        sock = getattr(self._local, "sock", None)
        fp = getattr(self._local, "fp", None)
        if sock is None:
            sock, fp = self._connect()
            self._local.sock = sock
            self._local.fp = fp
        try:
            sock.sendall(self._encode(args))
            return self._recv(fp)
        except Exception:
            self.close_thread()
            raise

    def close_thread(self) -> None:
        sock = getattr(self._local, "sock", None)
        fp = getattr(self._local, "fp", None)
        self._local.sock = None
        self._local.fp = None
        try:
            if fp is not None:
                fp.close()
        finally:
            if sock is not None:
                sock.close()


class ValkeyBackend:
    """Shared backend over the existing valkey service."""

    name = "valkey"

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("redis", "rediss"):
            raise ValueError("SECURITY_SHARED_STATE_URL must use redis://")
        if not parsed.hostname:
            raise ValueError("SECURITY_SHARED_STATE_URL missing host")
        self._db = int(parsed.path.lstrip("/") or "0")
        self._client = _RESP2(
            parsed.hostname,
            parsed.port or 6379,
            urllib.parse.unquote(parsed.password or ""),
            self._db,
            timeout,
        )
        self._lua = {
            "incr": _LUA_INCR,
            "lease_acquire": _LUA_LEASE_ACQUIRE,
            "counter": _LUA_COUNTER,
        }

    def _eval(self, script: str, key: str, *args) -> Any:
        return self._client.command("EVAL", script, 1, key, *args)

    def ping(self) -> bool:
        return self._client.command("PING") == "PONG"

    def set_if_absent(self, key: str, value: bytes, ttl_ms: int) -> bool:
        reply = self._client.command("SET", key, value, "PX", ttl_ms, "NX")
        return reply == "OK"

    def get(self, key: str) -> Optional[bytes]:
        return self._client.command("GET", key)

    def getex(self, key: str, ttl_ms: int) -> Optional[bytes]:
        # Read and push the expiry out in one atomic round trip (Valkey / Redis >= 6.2,
        # which is what the shipped valkey service is).
        return self._client.command("GETEX", key, "PX", ttl_ms)

    def set(self, key: str, value: bytes, ttl_ms: int) -> None:
        self._client.command("SET", key, value, "PX", ttl_ms)

    def delete(self, key: str) -> None:
        self._client.command("DEL", key)

    def take(self, key: str) -> Optional[bytes]:
        return self._eval(_LUA_TAKE, key)

    def increment(self, key: str, ttl_ms: int) -> int:
        return int(self._eval(_LUA_INCR, key, ttl_ms))

    def counter(self, key: str) -> int:
        reply = self._client.command("GET", key)
        return int(reply) if reply is not None else 0

    def lease_acquire(self, key: str, limit: int, member: str, ttl_ms: int) -> bool:
        now = time.time()
        return bool(self._eval(_LUA_LEASE_ACQUIRE, key, now, ttl_ms, limit, member))

    def lease_release(self, key: str, member: str) -> None:
        self._client.command("ZREM", key, member)

    def lease_count(self, key: str, ttl_ms: int = 60000) -> int:
        # Clean expired holders first: ZCARD alone would over-count under
        # continuous traffic, where PEXPIRE keeps the key alive indefinitely.
        return int(self._eval(_LUA_COUNTER, key, time.time(), ttl_ms))

    def close(self) -> None:
        self._client.close_thread()


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------

class SharedState:
    """Prefixed, audited shared-state operations with an explicit health state."""

    def __init__(self, backend=None, *, prefix: str = DEFAULT_PREFIX,
                 node_id: str = "", required: bool = False) -> None:
        self._backend = backend if backend is not None else _default_backend()
        self.prefix = prefix or DEFAULT_PREFIX
        self.node_id = node_id or os.getenv("SECURITY_NODE_ID", "")
        self.required = bool(required)
        self._lock = threading.Lock()
        self._healthy = True
        self._failures = 0
        self._last_error = ""

    @property
    def mode(self) -> str:
        return self._backend.name

    @property
    def healthy(self) -> bool:
        with self._lock:
            return self._healthy

    def _key(self, key: str) -> str:
        return self.prefix + key

    def _run(self, consumer: str, op: str, impact: str, fn: Callable[[Any], Any]):
        try:
            value = fn(self._backend)
        except Exception as exc:
            reason = "shared_state_unavailable:%s" % consumer
            with self._lock:
                self._healthy = False
                self._failures += 1
                self._last_error = "%s: %s" % (type(exc).__name__, str(exc)[:120])
            AUDIT.record(consumer=consumer, op=op, impact=impact, reason=reason,
                         node_id=self.node_id)
            raise SharedStateUnavailable(reason) from exc
        with self._lock:
            self._healthy = True
        return value

    # -- primitives ---------------------------------------------------------
    def set_if_absent(self, consumer: str, key: str, value: bytes, ttl_ms: int,
                      *, impact: str = "detection") -> bool:
        k = self._key(key)
        return self._run(consumer, "set_if_absent", impact,
                         lambda b: b.set_if_absent(k, value, ttl_ms))

    def get(self, consumer: str, key: str, *, impact: str = "detection") -> Optional[bytes]:
        k = self._key(key)
        return self._run(consumer, "get", impact, lambda b: b.get(k))

    def getex(self, consumer: str, key: str, ttl_ms: int, *,
              impact: str = "detection") -> Optional[bytes]:
        """Read and slide the TTL in one operation, so refreshing costs no extra round trip."""
        k = self._key(key)
        return self._run(consumer, "getex", impact, lambda b: b.getex(k, ttl_ms))

    def set(self, consumer: str, key: str, value: bytes, ttl_ms: int,
            *, impact: str = "performance") -> None:
        k = self._key(key)
        self._run(consumer, "set", impact, lambda b: b.set(k, value, ttl_ms))

    def delete(self, consumer: str, key: str, *, impact: str = "performance") -> None:
        k = self._key(key)
        self._run(consumer, "delete", impact, lambda b: b.delete(k))

    def take(self, consumer: str, key: str, *, impact: str = "detection") -> Optional[bytes]:
        k = self._key(key)
        return self._run(consumer, "take", impact, lambda b: b.take(k))

    def increment(self, consumer: str, key: str, ttl_ms: int,
                  *, impact: str = "detection") -> int:
        k = self._key(key)
        return self._run(consumer, "increment", impact, lambda b: b.increment(k, ttl_ms))

    def counter(self, consumer: str, key: str, *, impact: str = "detection") -> int:
        k = self._key(key)
        return self._run(consumer, "counter", impact, lambda b: b.counter(k))

    def lease_acquire(self, consumer: str, key: str, limit: int, member: str,
                      ttl_ms: int, *, impact: str = "capacity") -> bool:
        k = self._key(key)
        return self._run(consumer, "lease_acquire", impact,
                         lambda b: b.lease_acquire(k, limit, member, ttl_ms))

    def lease_release(self, consumer: str, key: str, member: str,
                      *, impact: str = "capacity") -> None:
        k = self._key(key)
        self._run(consumer, "lease_release", impact, lambda b: b.lease_release(k, member))

    def lease_count(self, consumer: str, key: str, *, ttl_ms: int = 60000,
                    impact: str = "capacity") -> int:
        k = self._key(key)
        return self._run(consumer, "lease_count", impact,
                         lambda b: b.lease_count(k, ttl_ms))

    def ping(self) -> bool:
        """Startup probe; does not record a degradation (callers log/alert)."""
        return bool(self._backend.ping())

    def snapshot(self) -> dict:
        with self._lock:
            healthy, failures, last_error = self._healthy, self._failures, self._last_error
        return {
            "mode": self.mode,
            "healthy": healthy,
            "required": self.required,
            "node_id": self.node_id,
            "prefix": self.prefix,
            "failures": failures,
            "last_error": last_error,
            "audit": AUDIT.snapshot(),
        }

    def close(self) -> None:
        self._backend.close()


def _default_backend():
    url = os.getenv("SECURITY_SHARED_STATE_URL", "").strip()
    if not url:
        return MemoryBackend()
    return ValkeyBackend(url, timeout=float(os.getenv(
        "SECURITY_SHARED_STATE_TIMEOUT", str(DEFAULT_TIMEOUT))) or DEFAULT_TIMEOUT)


_state: Optional[SharedState] = None
_state_lock = threading.Lock()


def get_shared_state() -> SharedState:
    """Process-wide singleton. Tests may replace it with ``set_shared_state``."""
    global _state
    with _state_lock:
        if _state is None:
            _state = SharedState(
                required=os.getenv("SECURITY_SHARED_STATE_REQUIRED", "").strip().lower()
                in ("1", "true", "yes", "on")
            )
        return _state


def set_shared_state(state: Optional[SharedState]) -> None:
    global _state
    with _state_lock:
        _state = state


def shared_state_snapshot() -> dict:
    return get_shared_state().snapshot()


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True, default=str).encode("utf-8")


def parse_json(raw: Optional[bytes], default=None):
    if raw is None:
        return default
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        return default
