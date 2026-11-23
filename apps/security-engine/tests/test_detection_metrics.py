"""C2 acceptance metrics: judge calls/request and fingerprint reuse hit rate."""
import asyncio
import os

import pytest

from app import detection_metrics as dm
from app import shared_state as ss
from app.api import check_input as ci
from app.runtime_profile import default_node_id, node_id_or_default


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SECURITY_SHARED_STATE_URL", raising=False)
    monkeypatch.delenv("SECURITY_NODE_ID", raising=False)
    ss.AUDIT.clear()
    ss.set_shared_state(None)
    dm.COUNTERS.reset()
    yield
    ss.AUDIT.clear()
    ss.set_shared_state(None)
    dm.COUNTERS.reset()


class _ClusterBackend(ss.MemoryBackend):
    """Valkey-shaped mode without a server: shared across two engine objects."""

    name = "valkey"


def _shared(backend=None) -> ss.SharedState:
    state = ss.SharedState(backend or _ClusterBackend(), prefix="jjd:se:test:")
    ss.set_shared_state(state)
    return state


# --- node identity ---------------------------------------------------------

def test_blank_node_id_is_hostname_pid_and_explicit_id_is_authoritative():
    blank = node_id_or_default("")
    assert blank.endswith("#%d" % os.getpid())
    assert len(blank) <= 128
    assert node_id_or_default("engine-a") == "engine-a"
    assert node_id_or_default("  engine-a  ") == "engine-a"
    assert node_id_or_default("x" * 300) == "x" * 128


def test_explicit_security_node_id_is_never_given_a_pid_suffix(monkeypatch):
    monkeypatch.setenv("SECURITY_NODE_ID", "security-engine:primary")
    assert default_node_id() == "security-engine:primary"


def test_rule_pack_handshake_uses_the_same_pid_scoped_identity():
    from app.rule_pack_loader import RulePackConfig
    blank = RulePackConfig(base_url="http://cp", token="t", node_id="")
    assert blank.node_id == node_id_or_default("")
    pinned = RulePackConfig(base_url="http://cp", token="t", node_id="engine-a")
    assert pinned.node_id == "engine-a"


# --- process-local counters ------------------------------------------------

def test_local_counters_report_judge_per_request_and_hit_rate():
    dm.COUNTERS.record_judge_call(2)
    dm.COUNTERS.record_request(judge_calls=2)
    dm.COUNTERS.record_judge_call()
    dm.COUNTERS.record_request(judge_calls=1)
    dm.COUNTERS.record_window_cache_hit()
    dm.COUNTERS.record_fingerprint_batch(10, 8)
    s = dm.COUNTERS.snapshot()
    assert s["judge_calls_total"] == 3
    assert s["judge_calls_per_request_avg"] == 1.5
    assert s["judge_calls_per_request_max"] == 2
    assert s["judge_window_cache_hits_total"] == 1
    assert s["fingerprint_checks"] == 10
    assert s["fingerprint_reuse_hits"] == 8
    assert s["fingerprint_hit_rate"] == 0.8


def test_fingerprint_stats_are_clamped_and_hits_never_exceed_checks():
    dm.COUNTERS.record_fingerprint_batch("garbage", 99)
    dm.COUNTERS.record_fingerprint_batch(2, 99)
    assert dm.COUNTERS.snapshot()["fingerprint_checks"] == 2
    assert dm.COUNTERS.snapshot()["fingerprint_reuse_hits"] == 2
    dm.COUNTERS.record_fingerprint_batch(-5, -5)
    assert dm.COUNTERS.snapshot()["fingerprint_checks"] == 2


# --- cluster-wide aggregation ---------------------------------------------

def test_cluster_scope_aggregates_two_workers_without_double_counting():
    _shared()
    worker_a, worker_b = dm._Counters(), dm._Counters()
    worker_a.record_fingerprint_batch(10, 8)
    worker_b.record_fingerprint_batch(10, 2)
    worker_a.record_judge_call(1)
    worker_a.record_request(judge_calls=1)
    worker_b.record_judge_call(2)
    worker_b.record_request(judge_calls=2)

    cluster = dm.cluster_snapshot()
    assert cluster["judge_calls_total"] == 3
    assert cluster["requests_observed"] == 2
    assert cluster["judge_calls_per_request_avg"] == 1.5
    assert cluster["fingerprint_checks"] == 20
    assert cluster["fingerprint_reuse_hits"] == 10
    assert cluster["fingerprint_hit_rate"] == 0.5
    assert cluster["window_seconds"] == 600

    exposed = dm.snapshot_metrics()
    assert exposed["scope"] == "cluster"
    assert exposed["effective"]["judge_calls_per_request_avg"] == 1.5
    assert exposed["effective"]["fingerprint_hit_rate"] == 0.5
    assert exposed["fingerprint_stats_source"] == "gateway_batch_headers"


def test_without_valkey_metrics_fall_back_to_process_scope():
    dm.COUNTERS.record_request(judge_calls=2)
    exposed = dm.snapshot_metrics()
    assert exposed["scope"] == "process"
    assert exposed["cluster"] is None
    assert exposed["effective"]["judge_calls_per_request_avg"] == 2.0


def test_valkey_outage_is_unknown_and_only_a_performance_degradation():
    class DeadBackend(_ClusterBackend):
        def counter(self, key):
            raise OSError("valkey down")

        def increment(self, key, ttl_ms):
            raise OSError("valkey down")

    _shared(DeadBackend())
    assert dm.cluster_snapshot() is None
    assert dm.snapshot_metrics()["scope"] == "process"
    events = ss.AUDIT.events(limit=64)
    assert events
    assert all(event["impact"] == "performance" for event in events)
    assert "shared_state_unavailable:detection_metrics" in [
        event["reason"] for event in events]
    # A metrics outage must never be reported as a detection/capacity skip.
    assert ss.drain_reasons() == []


# --- gateway -> engine advisory headers ------------------------------------

def test_batch_endpoint_records_gateway_fingerprint_headers(monkeypatch):
    async def fake_inspect(request, deadline, mode):
        return ci.CheckInputResponse(
            request_id=request.request_id, findings=[], action="allow",
            latency_ms=0, inspection_status="completed")

    monkeypatch.setattr(ci, "_inspect", fake_inspect)
    request = ci.CheckInputRequest(request_id="r1", content="hello")
    asyncio.run(ci.check_input_batch([request], "10", "7"))
    s = dm.COUNTERS.snapshot()
    assert s["fingerprint_checks"] == 10
    assert s["fingerprint_reuse_hits"] == 7
    assert s["fingerprint_hit_rate"] == 0.7


def test_batch_endpoint_ignores_malformed_fingerprint_headers(monkeypatch):
    async def fake_inspect(request, deadline, mode):
        return ci.CheckInputResponse(
            request_id=request.request_id, findings=[], action="allow",
            latency_ms=0, inspection_status="completed")

    monkeypatch.setattr(ci, "_inspect", fake_inspect)
    request = ci.CheckInputRequest(request_id="r1", content="hello")
    results = asyncio.run(ci.check_input_batch([request], "garbage", "999"))
    assert len(results) == 1
    assert results[0].inspection_status == "completed"
    assert dm.COUNTERS.snapshot()["fingerprint_checks"] == 0


def test_empty_batch_still_records_all_segments_reused(monkeypatch):
    async def never_called(request, deadline, mode):
        raise AssertionError("no items should be inspected")

    monkeypatch.setattr(ci, "_inspect", never_called)
    results = asyncio.run(ci.check_input_batch([], "12", "12"))
    assert results == []
    assert dm.COUNTERS.snapshot()["fingerprint_hit_rate"] == 1.0
