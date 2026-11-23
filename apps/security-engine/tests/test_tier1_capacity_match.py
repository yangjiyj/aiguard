"""S1: the engine must notice when the sidecar pool is not the autotuned pool.

An overlay pinned 2x16 while engine-resource-autotune.sh wrote 8x256 and the
supply check read the .env values only, so /health said within_limit while the
sidecar answered 503. ``tier1_runtime.capacity_matches_profile`` closes that gap
by comparing the container's own numbers with the autotuned profile.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.runtime_profile import reset_tier1_runtime_cache, tier1_runtime


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "SECURITY_TIER1_ENABLED",
        "SECURITY_TIER1_URL",
        "TIER1_INFERENCE_WORKERS",
        "TIER1_INFERENCE_CAPACITY",
        "ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS",
        "ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY",
    ):
        monkeypatch.delenv(name, raising=False)
    reset_tier1_runtime_cache()
    yield
    reset_tier1_runtime_cache()


class _Sidecar:
    def __init__(self, payload):
        self.payload = payload

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib naming
                body = json.dumps(self.server.payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.payload = payload
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


def _probe(monkeypatch, sidecar, expected_workers, expected_capacity):
    try:
        monkeypatch.setenv("SECURITY_TIER1_ENABLED", "true")
        monkeypatch.setenv("SECURITY_TIER1_URL", sidecar.url)
        if expected_workers is not None:
            monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS", expected_workers)
        if expected_capacity is not None:
            monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY", expected_capacity)
        return tier1_runtime()
    finally:
        sidecar.close()


def test_pool_smaller_than_the_profile_is_a_mismatch(monkeypatch):
    # 现场形状：autotune 说 8x256，overlay 把它按成 2x16。
    sidecar = _Sidecar({
        "model_loaded": True,
        "runtime": {"inference_workers": 2, "inference_capacity": 16, "uvicorn_workers": 1},
    })
    live = _probe(monkeypatch, sidecar, "8", "256")
    assert live["inference_workers"] == 2
    assert live["inference_capacity"] == 16
    assert live["capacity_matches_profile"] is False


def test_pool_equal_to_the_profile_matches(monkeypatch):
    sidecar = _Sidecar({
        "model_loaded": True,
        "runtime": {"inference_workers": 8, "inference_capacity": 256, "uvicorn_workers": 4},
    })
    live = _probe(monkeypatch, sidecar, "8", "256")
    assert live["capacity_matches_profile"] is True


def test_sidecar_without_pool_reporting_cannot_be_verified(monkeypatch):
    # 老镜像不报容量：不能当作"一致"，也不能说成"不一致"——tier1 镜像不是每个版本都重建，
    # 控制台把 False 显示成"否"，把 None 显示成"未获取"；这里只能是 None。
    sidecar = _Sidecar({"model_loaded": True, "runtime": {"execution_provider": "cpu"}})
    live = _probe(monkeypatch, sidecar, "8", "256")
    assert "inference_capacity" not in live
    assert live["capacity_matches_profile"] is None


def test_sidecar_reporting_only_half_of_the_pool_is_unverified_too(monkeypatch):
    sidecar = _Sidecar({"model_loaded": True, "runtime": {"inference_workers": 8}})
    live = _probe(monkeypatch, sidecar, "8", "256")
    assert live["capacity_matches_profile"] is None


def test_no_autotuned_profile_means_no_comparison(monkeypatch):
    sidecar = _Sidecar({"model_loaded": True, "runtime": {"inference_workers": 2,
                                                         "inference_capacity": 16}})
    live = _probe(monkeypatch, sidecar, None, None)
    assert live["capacity_matches_profile"] is None


def test_capacity_falls_back_to_the_container_keys(monkeypatch):
    # 没有 autotune 记录时按容器真实键比较，而不是恒为 None。
    monkeypatch.setenv("TIER1_INFERENCE_WORKERS", "8")
    monkeypatch.setenv("TIER1_INFERENCE_CAPACITY", "256")
    sidecar = _Sidecar({"model_loaded": True, "runtime": {"inference_workers": 8,
                                                         "inference_capacity": 256}})
    live = _probe(monkeypatch, sidecar, None, None)
    assert live["capacity_matches_profile"] is True


def test_disabled_tier1_reports_no_comparison():
    live = tier1_runtime()
    assert live["capacity_matches_profile"] is None
