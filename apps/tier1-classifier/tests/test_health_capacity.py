"""S1: /health must report the concurrency the sidecar really runs with.

The 2x16-vs-8x256 incident was invisible because /health only described the ONNX
runtime. These tests pin the capacity block so an overlay that pins a smaller pool
can no longer hide behind a healthy status.
"""
import importlib

from fastapi.testclient import TestClient


def _client(monkeypatch, workers, capacity, uvicorn_workers):
    monkeypatch.setenv("TIER1_INFERENCE_WORKERS", str(workers))
    monkeypatch.setenv("TIER1_INFERENCE_CAPACITY", str(capacity))
    monkeypatch.setenv("TIER1_WORKERS", str(uvicorn_workers))
    monkeypatch.delenv("JJD_TIER1_INTERNAL_TOKEN", raising=False)
    monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app), main


def test_health_reports_the_effective_inference_pool(monkeypatch):
    client, _ = _client(monkeypatch, workers=8, capacity=256, uvicorn_workers=4)
    runtime = client.get("/health").json()["runtime"]
    assert runtime["inference_workers"] == 8
    assert runtime["inference_capacity"] == 256
    assert runtime["uvicorn_workers"] == 4


def test_health_reports_pool_pressure(monkeypatch):
    client, _ = _client(monkeypatch, workers=2, capacity=4, uvicorn_workers=1)
    body = client.get("/health").json()
    assert body["pool"] == {"in_flight": 0, "rejected": 0, "expired": 0}


def test_health_capacity_survives_a_missing_model(monkeypatch):
    # 模型缺失时服务仍要报容量：否则引擎无法判断 sidecar 到底能吃多少在途。
    client, _ = _client(monkeypatch, workers=2, capacity=16, uvicorn_workers=1)
    body = client.get("/health").json()
    assert body["model_loaded"] is False
    assert body["runtime"]["inference_workers"] == 2
    assert body["runtime"]["inference_capacity"] == 16


def test_pool_snapshot_keeps_its_diagnostics_shape(monkeypatch):
    _, main = _client(monkeypatch, workers=1, capacity=8, uvicorn_workers=1)
    snapshot = main._INFERENCE_POOL.snapshot()
    # /health 只透出三个压力位，/diagnostics 仍要拿得到 submitted。
    assert {"in_flight", "submitted", "rejected", "expired"} <= set(snapshot)
    assert main._INFERENCE_POOL.workers == 1
    assert main._INFERENCE_POOL.capacity == 8
