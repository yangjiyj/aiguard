"""Detection counters for /metrics, /health and the service-health console.

Two scopes are reported and never mixed:

* ``local``  - this uvicorn worker, kept for per-process debugging.
* ``cluster`` - the sum over all workers/replicas, stored in the shared valkey
  service as five fixed-window counters (current + previous 5-minute bucket).
  When valkey is unavailable the cluster block is ``None`` (unknown), never a
  fake zero, and the outage is audited with impact=performance so it never
  turns into a silent detection bypass.

``effective`` is what the console displays: cluster numbers when available,
process-local numbers otherwise. C2 acceptance numbers are
``judge_calls_per_request_avg`` and ``fingerprint_hit_rate``.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Optional

from app.shared_state import SharedStateUnavailable, get_shared_state

_WINDOW = 4096
_BUCKET_SECONDS = 300
_CLUSTER_TTL_MS = (_BUCKET_SECONDS * 2 + 60) * 1000
_MAX_FLUSH_PER_FIELD = 1000
_CONSUMER = "detection_metrics"
_FIELDS = (
    "judge_calls",
    "requests",
    "window_cache_hits",
    "fingerprint_checks",
    "fingerprint_reuse",
)


def _bucket_key(bucket: int, field: str) -> str:
    return "metrics:v1:%d:%s" % (bucket, field)


def _clamp(value, ceiling: int = 10000) -> int:
    try:
        return min(ceiling, max(0, int(value)))
    except (TypeError, ValueError, OverflowError):
        return 0


class _Counters:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._judge_calls = 0
        self._window_cache_hits = 0
        self._requests: deque = deque(maxlen=_WINDOW)
        self._fingerprint_reuse = 0
        self._fingerprint_checks = 0
        self._pending = {field: 0 for field in _FIELDS}

    def _bump(self, field: str, n: int) -> None:
        n = _clamp(n)
        if not n:
            return
        with self._lock:
            if field == "judge_calls":
                self._judge_calls += n
            elif field == "window_cache_hits":
                self._window_cache_hits += n
            self._pending[field] += n

    def record_judge_call(self, n: int = 1) -> None:
        self._bump("judge_calls", n)

    def record_window_cache_hit(self, n: int = 1) -> None:
        self._bump("window_cache_hits", n)

    def record_request(self, *, judge_calls: int = 0,
                       fingerprint_reuse: bool = False) -> None:
        """One semantic cascade finished. Fingerprint stats come from the
        gateway's advisory batch headers, not from here (only the gateway
        knows which segments were reused), so the legacy flag is a no-op."""
        with self._lock:
            self._requests.append(_clamp(judge_calls))
            self._pending["requests"] += 1
        self.flush_shared()

    def record_fingerprint_batch(self, checks, hits) -> None:
        """Gateway-reported per-message-segment fingerprint outcome.

        Clamped and hits<=checks: these arrive on an HTTP header and must not
        be able to poison the health dashboard.
        """
        checks, hits = _clamp(checks), _clamp(hits)
        hits = min(hits, checks)
        with self._lock:
            self._fingerprint_checks += checks
            self._fingerprint_reuse += hits
            self._pending["fingerprint_checks"] += checks
            self._pending["fingerprint_reuse"] += hits
        self.flush_shared()

    def flush_shared(self) -> None:
        """Publish buffered deltas to valkey, at most once per completed call."""
        with self._lock:
            pending = {k: v for k, v in self._pending.items() if v > 0}
            self._pending = {field: 0 for field in _FIELDS}
        if not pending:
            return
        state = get_shared_state()
        if state.mode != "valkey":
            return
        bucket = int(time.time()) // _BUCKET_SECONDS
        for field, count in pending.items():
            key = _bucket_key(bucket, field)
            for _ in range(min(count, _MAX_FLUSH_PER_FIELD)):
                try:
                    state.increment(_CONSUMER, key, _CLUSTER_TTL_MS,
                                    impact="performance")
                except SharedStateUnavailable:
                    # Metrics only: no detection decision depends on this.
                    # state.increment already recorded an audited degradation.
                    break

    def snapshot(self) -> dict:
        with self._lock:
            total_calls = self._judge_calls
            cache_hits = self._window_cache_hits
            requests = list(self._requests)
            checks = self._fingerprint_checks
            reuse = self._fingerprint_reuse
        n = len(requests)
        return {
            "judge_calls_total": total_calls,
            "judge_window_cache_hits_total": cache_hits,
            "requests_observed": n,
            "judge_calls_per_request_avg": round(sum(requests) / n, 4) if n else 0.0,
            "judge_calls_per_request_max": max(requests) if n else 0,
            "fingerprint_checks": checks,
            "fingerprint_reuse_hits": reuse,
            "fingerprint_hit_rate": round(reuse / checks, 4) if checks else 0.0,
        }

    def reset(self) -> None:
        with self._lock:
            self._judge_calls = 0
            self._window_cache_hits = 0
            self._requests.clear()
            self._fingerprint_reuse = 0
            self._fingerprint_checks = 0
            self._pending = {field: 0 for field in _FIELDS}


COUNTERS = _Counters()


def cluster_snapshot() -> Optional[dict]:
    """Cluster-wide rolling window, or None when there is no shared backend."""
    state = get_shared_state()
    if state.mode != "valkey":
        return None
    bucket = int(time.time()) // _BUCKET_SECONDS
    totals = {field: 0 for field in _FIELDS}
    for current in (bucket - 1, bucket):
        for field in _FIELDS:
            try:
                totals[field] += state.counter(
                    _CONSUMER, _bucket_key(current, field), impact="performance")
            except SharedStateUnavailable:
                return None
    requests = totals["requests"]
    checks = totals["fingerprint_checks"]
    return {
        "window_seconds": _BUCKET_SECONDS * 2,
        "judge_calls_total": totals["judge_calls"],
        "judge_window_cache_hits_total": totals["window_cache_hits"],
        "requests_observed": requests,
        "judge_calls_per_request_avg": (
            round(totals["judge_calls"] / requests, 4) if requests else 0.0),
        "fingerprint_checks": checks,
        "fingerprint_reuse_hits": totals["fingerprint_reuse"],
        "fingerprint_hit_rate": (
            round(totals["fingerprint_reuse"] / checks, 4) if checks else 0.0),
    }


def snapshot_metrics() -> dict:
    COUNTERS.flush_shared()
    local = COUNTERS.snapshot()
    cluster = cluster_snapshot()
    source = cluster or local
    effective = {
        "judge_calls_per_request_avg": source["judge_calls_per_request_avg"],
        "judge_calls_per_request_max": source.get("judge_calls_per_request_max"),
        "fingerprint_hit_rate": source["fingerprint_hit_rate"],
        "requests_observed": source["requests_observed"],
        "window_seconds": source.get("window_seconds", "process_lifetime"),
    }
    return {
        **local,
        "scope": "cluster" if cluster else "process",
        "cluster": cluster,
        "effective": effective,
        "fingerprint_stats_source": "gateway_batch_headers",
    }
