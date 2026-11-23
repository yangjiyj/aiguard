"""Effective deployment profile for /health, /metrics and startup selfcheck.

``engine-resource-autotune.sh`` writes the resolved profile and the effective
values into the environment. Nothing here re-detects CPU: startup must report
exactly what the deployment installed, including operator overrides.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_RESOLVED_KEYS = (
    ("web_concurrency", "ENGINE_RESOURCE_EFFECTIVE_WEB_CONCURRENCY", "SECURITY_ENGINE_WEB_CONCURRENCY"),
    ("input_workers", "ENGINE_RESOURCE_EFFECTIVE_INPUT_WORKERS", "SECURITY_INPUT_WORKERS"),
    # These describe the tier1 container, not the engine. The old
    # SECURITY_TIER1_WORKERS / SECURITY_TIER1_THREADS mirrors were display-only
    # and let /health claim 4x4 while the sidecar really ran 1x1; they are gone.
    ("tier1_workers", "ENGINE_RESOURCE_EFFECTIVE_TIER1_WORKERS", "TIER1_WORKERS"),
    ("tier1_threads", "ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS", "TIER1_THREADS"),
    ("tier1_inference_workers", "ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS",
     "TIER1_INFERENCE_WORKERS"),
    ("tier1_inference_capacity", "ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY",
     "TIER1_INFERENCE_CAPACITY"),
    ("tier1_max_inflight", "ENGINE_RESOURCE_EFFECTIVE_TIER1_MAX_INFLIGHT", "SECURITY_TIER1_MAX_INFLIGHT"),
    ("judge_workers", "ENGINE_RESOURCE_EFFECTIVE_JUDGE_WORKERS", "SECURITY_JUDGE_WORKERS"),
    ("judge_capacity", "ENGINE_RESOURCE_EFFECTIVE_JUDGE_CAPACITY", "SECURITY_JUDGE_CAPACITY"),
    ("judge_global_concurrency", "ENGINE_RESOURCE_EFFECTIVE_JUDGE_GLOBAL_CONCURRENCY",
     "SECURITY_JUDGE_GLOBAL_CONCURRENCY"),
)


def _first(*names: str) -> str:
    for name in names:
        raw = os.getenv(name, "").strip()
        if raw:
            return raw
    return ""


def effective_profile() -> dict:
    return {
        key: _first(resolved, real)
        for key, resolved, real in _RESOLVED_KEYS
    }


def resource_profile() -> dict:
    return {
        "profile": os.getenv("ENGINE_RESOURCE_PROFILE", "manual").strip(),
        "resolved": os.getenv("ENGINE_RESOURCE_PROFILE_RESOLVED", "").strip() or "unset",
        "detected_cpus": os.getenv("ENGINE_RESOURCE_DETECTED_CPUS", "").strip(),
        "detected_mem_mb": os.getenv("ENGINE_RESOURCE_DETECTED_MEM_MB", "").strip(),
        "cpu_source": os.getenv("ENGINE_RESOURCE_DETECTED_CPU_SOURCE", "").strip(),
        "judge_budget_status": os.getenv("ENGINE_RESOURCE_JUDGE_BUDGET_STATUS", "").strip(),
        "tier1_concurrency_status":
            os.getenv("ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS", "").strip() or "unknown",
        # Persisted by tier1-scale.sh --apply and restored by every upgrade path.
        # "single" means the base compose file with one replica; cpu/gpu means the
        # matching overlay plus TIER1_REPLICAS replicas. The replica count is the
        # configured topology, not a live count: the tier1 probe below resolves
        # Compose DNS and therefore describes one replica at a time.
        "tier1_replicas": os.getenv("TIER1_REPLICAS", "").strip() or "1",
        "tier1_scale_mode": os.getenv("TIER1_SCALE_MODE", "").strip() or "single",
        "effective": effective_profile(),
    }


def node_id_or_default(value: str = "") -> str:
    """Single source of truth for the engine node identity.

    An explicit operator value is authoritative (single-instance installs pin
    a stable id and must not get a pid suffix appended). A blank value derives
    hostname#pid, so uvicorn workers and Compose replicas never overwrite each
    other in the control-plane pull-status / runtime ledgers.
    """
    explicit = str(value or "").strip()
    if explicit:
        return explicit[:128]
    try:
        host = socket.gethostname().strip()
    except OSError:
        host = ""
    host = host or "unknown-host"
    suffix = "#%d" % os.getpid()
    return host[:128 - len(suffix)] + suffix


def default_node_id() -> str:
    """Node identity from deployment configuration."""
    return node_id_or_default(os.getenv("SECURITY_NODE_ID", ""))


_TIER1_LIVE_TTL = 15.0
_TIER1_LIVE_TIMEOUT = 0.25
_TIER1_LIVE_LOCK = threading.Lock()
_TIER1_LIVE_CACHE = {"at": 0.0, "value": {}}
_TIER1_LIVE_FIELDS = (
    "execution_provider", "onnx_provider", "threads", "batch_windows",
    # S1: the sidecar reports the pool it really runs with. Without these the
    # engine could not tell an overlay-pinned 2x16 from the autotuned 8x256.
    "inference_workers", "inference_capacity", "uvicorn_workers",
)


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def _tier1_health_url() -> str:
    raw = os.getenv("SECURITY_TIER1_URL", "").strip()
    parsed = urllib.parse.urlparse(raw) if raw else None
    if parsed is None or not parsed.hostname:
        return ""
    netloc = parsed.hostname
    if parsed.port:
        netloc = "%s:%d" % (parsed.hostname, parsed.port)
    return urllib.parse.urlunparse(((parsed.scheme or "http").lower(), netloc, "/health", "", "", ""))


def _capacity_matches_profile(reported: dict):
    """Compare the sidecar's real pool with the autotuned profile.

    ``None`` means there is nothing to compare: tier1 disabled, probe down, no
    autotuned value in the environment, or a sidecar image too old to report its
    pool at all (the tier1 image is not rebuilt for every release, so that is common
    and says nothing about the deployment). ``False`` is reserved for the real
    finding: the deployment claims one pool and runs another -- the exact shape of
    the 2x16 vs 8x256 incident. The console shows ``None`` as "not obtained" and
    ``False`` as "no", so the two must not be mixed.
    """
    expected_workers = _first("ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS",
                              "TIER1_INFERENCE_WORKERS")
    expected_capacity = _first("ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY",
                               "TIER1_INFERENCE_CAPACITY")
    if not expected_workers or not expected_capacity:
        return None
    actual_workers = reported.get("inference_workers")
    actual_capacity = reported.get("inference_capacity")
    if actual_workers is None or actual_capacity is None:
        return None
    try:
        return (int(actual_workers) == int(expected_workers)
                and int(actual_capacity) == int(expected_capacity))
    except (TypeError, ValueError):
        return False


def tier1_runtime() -> dict:
    """What the tier1 container itself reports, cached to keep /health cheap.

    Operators need the real sidecar numbers: threads, execution provider and how
    many windows one session.run takes. A short TTL keeps /health and /metrics
    from probing per request, and an unreachable sidecar only flips ``reachable``
    instead of failing the engine's own health.

    Limitation: the probe goes through the Compose service DNS name, so with
    several replicas it answers from whichever one the resolver picks. Everything
    here describes a single replica; the fleet size is ``TIER1_REPLICAS`` in .env
    (reported as ``resource_profile.tier1_replicas``) and is not measured.
    """
    if not _truthy("SECURITY_TIER1_ENABLED"):
        # Not probed, so "reachable" is unknown rather than "no": the console shows
        # False as "Tier-1 probe reachable: no", which reads as a failure on a host
        # that simply has tier1 switched off.
        return {"probed": False, "reachable": None, "capacity_matches_profile": None}
    now = time.monotonic()
    with _TIER1_LIVE_LOCK:
        if _TIER1_LIVE_CACHE["value"] and now - _TIER1_LIVE_CACHE["at"] < _TIER1_LIVE_TTL:
            return dict(_TIER1_LIVE_CACHE["value"])
    value: dict = {"probed": True, "reachable": False, "capacity_matches_profile": None}
    url = _tier1_health_url()
    if url:
        try:
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=_TIER1_LIVE_TIMEOUT) as response:
                body = json.loads(response.read(65536).decode("utf-8"))
            if isinstance(body, dict):
                value["reachable"] = True
                value["model_loaded"] = bool(body.get("model_loaded"))
                runtime = body.get("runtime")
                if isinstance(runtime, dict):
                    for key in _TIER1_LIVE_FIELDS:
                        if runtime.get(key) is not None:
                            value[key] = runtime[key]
                value["capacity_matches_profile"] = _capacity_matches_profile(value)
        except (urllib.error.URLError, OSError, ValueError):
            value = {"probed": True, "reachable": False, "capacity_matches_profile": None}
    with _TIER1_LIVE_LOCK:
        _TIER1_LIVE_CACHE["at"] = now
        _TIER1_LIVE_CACHE["value"] = value
    return dict(value)


def reset_tier1_runtime_cache() -> None:
    with _TIER1_LIVE_LOCK:
        _TIER1_LIVE_CACHE["at"] = 0.0
        _TIER1_LIVE_CACHE["value"] = {}


def cascade_warnings(low_threshold: float | None = None,
                     policy: str | None = None) -> list:
    """Operator-visible warnings; these are raised, never silently corrected."""
    from app import feature_flags as ff

    warnings: list = []
    # The same accessors the detector uses: a value pushed by the control plane
    # lives in the feature-flag overrides, not in os.environ, so reading the
    # environment here never saw the value that actually disabled the cascade.
    try:
        low = float(low_threshold if low_threshold is not None else ff.get_float(
            ff.ENV_TIER1_LOW_THRESHOLD, ff.DEFAULT_TIER1_LOW_THRESHOLD))
    except (TypeError, ValueError):
        low = ff.DEFAULT_TIER1_LOW_THRESHOLD
    active_policy = (policy or ff.get_str(ff.ENV_SEMANTIC_CASCADE_POLICY, "legacy")).strip().lower()
    if low < 0.05:
        warnings.append(
            "tier1_cascade_disabled: tier1_low_threshold<0.05 sends every window to the judge"
        )
        if active_policy != "coverage_v2":
            warnings.append(
                "tier1_cascade_guard_off: set SECURITY_SEMANTIC_CASCADE_POLICY=coverage_v2 "
                "to restore a bounded cascade without losing cue-bearing windows"
            )
    return warnings


def runtime_snapshot() -> dict:
    from app.cascade_recall_gate import recall_gate
    from app.coordination import global_judge_budget
    from app.detection_metrics import snapshot_metrics
    from app.shared_state import drain_reasons, shared_state_snapshot
    return {
        "node_id": default_node_id(),
        "resource_profile": resource_profile(),
        "tier1_runtime": tier1_runtime(),
        "cascade_warnings": cascade_warnings(),
        "cascade_guard": recall_gate(),
        "shared_state": shared_state_snapshot(),
        "judge_global_budget": global_judge_budget().snapshot(),
        "degradation_reasons": drain_reasons(),
        "metrics": snapshot_metrics(),
    }
