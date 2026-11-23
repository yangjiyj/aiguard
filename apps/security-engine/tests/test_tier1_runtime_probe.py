"""R3: /health must report what the tier1 container actually runs.

The removed SECURITY_TIER1_WORKERS / SECURITY_TIER1_THREADS variables were only
ever read by the reporting layer, so an install could show 4x4 while the sidecar
really ran 1x1. These tests pin the replacement: effective values come from the
tier1 container's own settings, and live numbers come from its /health.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.runtime_profile import (
    effective_profile,
    reset_tier1_runtime_cache,
    resource_profile,
    runtime_snapshot,
    tier1_runtime,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "SECURITY_TIER1_ENABLED",
        "SECURITY_TIER1_URL",
        "SECURITY_TIER1_WORKERS",
        "SECURITY_TIER1_THREADS",
        "TIER1_WORKERS",
        "TIER1_THREADS",
        "TIER1_INFERENCE_WORKERS",
        "TIER1_INFERENCE_CAPACITY",
        "ENGINE_RESOURCE_EFFECTIVE_TIER1_WORKERS",
        "ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS",
        "ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS",
        "ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY",
        "ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS",
    ):
        monkeypatch.delenv(name, raising=False)
    reset_tier1_runtime_cache()
    yield
    reset_tier1_runtime_cache()


class _Sidecar:
    def __init__(self, payload):
        self.payload = payload
        self.hits = 0
        payload = self.payload
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib naming
                outer.hits += 1
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return "http://127.0.0.1:%d/classify" % self.server.server_port

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def test_disabled_tier1_is_not_probed():
    # Not probed: "reachable" is unknown (shown as "not obtained"), never False ("no").
    assert tier1_runtime() == {"probed": False, "reachable": None,
                               "capacity_matches_profile": None}


def test_enabled_tier1_reports_its_own_runtime(monkeypatch):
    sidecar = _Sidecar({
        "status": "healthy",
        "model_loaded": True,
        "runtime": {
            "configured_provider": "cpu",
            "execution_provider": "cuda",
            "onnx_provider": "CUDAExecutionProvider",
            "threads": 4,
            "batch_windows": 16,
        },
    })
    try:
        monkeypatch.setenv("SECURITY_TIER1_ENABLED", "true")
        monkeypatch.setenv("SECURITY_TIER1_URL", sidecar.url)
        live = tier1_runtime()
    finally:
        sidecar.close()
    assert live["probed"] is True and live["reachable"] is True
    assert live["model_loaded"] is True
    assert live["threads"] == 4
    assert live["batch_windows"] == 16
    assert live["execution_provider"] == "cuda"


def test_unreachable_tier1_does_not_break_health(monkeypatch):
    monkeypatch.setenv("SECURITY_TIER1_ENABLED", "true")
    monkeypatch.setenv("SECURITY_TIER1_URL", "http://127.0.0.1:9/classify")
    live = tier1_runtime()
    assert live == {"probed": True, "reachable": False, "capacity_matches_profile": None}
    # The engine's own health snapshot must still render.
    assert runtime_snapshot()["tier1_runtime"]["reachable"] is False


def test_live_runtime_is_cached(monkeypatch):
    sidecar = _Sidecar({"model_loaded": True, "runtime": {"threads": 2, "batch_windows": 8}})
    try:
        monkeypatch.setenv("SECURITY_TIER1_ENABLED", "true")
        monkeypatch.setenv("SECURITY_TIER1_URL", sidecar.url)
        tier1_runtime()
        tier1_runtime()
        tier1_runtime()
        assert sidecar.hits == 1, "/health must not probe the sidecar per request"
        reset_tier1_runtime_cache()
        tier1_runtime()
        assert sidecar.hits == 2, "reset must allow a fresh probe"
    finally:
        sidecar.close()


def test_effective_tier1_values_come_from_the_container_settings(monkeypatch):
    monkeypatch.setenv("TIER1_WORKERS", "4")
    monkeypatch.setenv("TIER1_THREADS", "4")
    monkeypatch.setenv("TIER1_INFERENCE_WORKERS", "8")
    monkeypatch.setenv("TIER1_INFERENCE_CAPACITY", "256")
    effective = effective_profile()
    assert effective["tier1_workers"] == "4"
    assert effective["tier1_threads"] == "4"
    assert effective["tier1_inference_workers"] == "8"
    assert effective["tier1_inference_capacity"] == "256"


def test_removed_display_only_vars_no_longer_steer_the_report(monkeypatch):
    # An old .env may still carry these; they must not fake the tier1 shape.
    monkeypatch.setenv("SECURITY_TIER1_WORKERS", "8")
    monkeypatch.setenv("SECURITY_TIER1_THREADS", "8")
    monkeypatch.setenv("TIER1_WORKERS", "1")
    monkeypatch.setenv("TIER1_THREADS", "2")
    effective = effective_profile()
    assert effective["tier1_workers"] == "1"
    assert effective["tier1_threads"] == "2"


def test_autotune_records_survive_into_the_profile(monkeypatch):
    monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_WORKERS", "4")
    monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY", "256")
    monkeypatch.setenv("ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS", "within_limit")
    profile = resource_profile()
    assert profile["tier1_concurrency_status"] == "within_limit"
    assert profile["effective"]["tier1_workers"] == "4"
    assert profile["effective"]["tier1_inference_capacity"] == "256"
