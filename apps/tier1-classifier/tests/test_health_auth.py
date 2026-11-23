import os
import importlib

from fastapi.testclient import TestClient
import pytest

from app.header_compat import resolve_raw_headers


def _client(monkeypatch, secret: str | None, *, shared_secret: str | None = None):
    if secret is None:
        monkeypatch.delenv("JJD_TIER1_INTERNAL_TOKEN", raising=False)
    else:
        monkeypatch.setenv("JJD_TIER1_INTERNAL_TOKEN", secret)
    if shared_secret is None:
        monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)
    else:
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", shared_secret)
    monkeypatch.delenv("NEWAPI_INTERNAL_API_SECRET", raising=False)
    import app.main as m
    importlib.reload(m)
    return TestClient(m.app)


def test_health_no_auth_required(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "healthy"
    assert body["service"] == "tier1-classifier"
    # 模型未加载时仍健康（fail-open 设计），但 model_loaded 显式暴露
    assert body["model_loaded"] is False


def test_classify_rejects_missing_token(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.post("/classify", json={"text": "x"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid internal token"


def test_classify_rejects_wrong_token(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.post(
        "/classify",
        json={"text": "x"},
        headers={"X-JJDGuard-Internal-Token": "wrong"},
    )
    assert r.status_code == 401


def test_no_dedicated_secret_configured_fails_closed_without_shared_fallback(monkeypatch):
    c = _client(monkeypatch, None)
    r = c.post("/classify", json={"text": "hi"})
    assert r.status_code == 503


def test_shared_secret_is_not_accepted_as_tier1_secret(monkeypatch):
    c = _client(monkeypatch, None, shared_secret="shared-secret")
    r = c.post(
        "/classify",
        json={"text": "x"},
        headers={"X-JJDGuard-Internal-Token": "shared-secret"},
    )
    assert r.status_code == 503


def test_dedicated_secret_ignores_legacy_compatibility_values(monkeypatch):
    monkeypatch.setenv("JJD_TIER1_INTERNAL_TOKEN", "jjd-secret")
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "shared-secret-canary")
    monkeypatch.setenv("NEWAPI_INTERNAL_API_SECRET", "old-secret-canary")
    import app.main as m
    importlib.reload(m)
    client = TestClient(m.app)

    accepted = client.post(
        "/classify", json={"text": "x"},
        headers={"X-JJDGuard-Internal-Token": "jjd-secret"},
    )
    rejected = client.post(
        "/classify", json={"text": "x"},
        headers={"X-JJDGuard-Internal-Token": "old-secret-canary"},
    )
    assert accepted.status_code != 401
    assert rejected.status_code == 401


@pytest.mark.parametrize(
    ("raw", "want", "conflict"),
    [
        ([(b"x-jjdguard-internal-token", b"new")], "new", False),
        ([(b"x-newapi-internal-token", b"legacy")], "legacy", False),
        ([(b"X-JJDGuard-Internal-Token", b"same"), (b"x-newapi-internal-token", b"same")], "same", False),
        ([(b"x-jjdguard-internal-token", b"new-canary"), (b"x-newapi-internal-token", b"old-canary")], "", True),
        ([(b"x-jjdguard-internal-token", b"same"), (b"x-jjdguard-internal-token", b"same")], "same", False),
        ([(b"x-jjdguard-internal-token", b"one"), (b"x-jjdguard-internal-token", b"two")], "", True),
        ([(b"x-jjdguard-internal-token", b""), (b"x-newapi-internal-token", b" legacy\t")], "legacy", False),
        ([(b"x-jjdguard-internal-token", b"one,two")], "", True),
    ],
)
def test_raw_internal_header_contract(raw, want, conflict):
    assert resolve_raw_headers(raw, b"x-jjdguard-internal-token", b"x-newapi-internal-token") == (want, conflict)


def test_internal_token_conflict_rejected_before_comparison_without_value_leak(monkeypatch):
    c = _client(monkeypatch, "expected")
    response = c.post(
        "/classify",
        json={"text": "x"},
        headers=[
            ("X-JJDGuard-Internal-Token", "new-conflict-canary"),
            ("X-NewAPI-Internal-Token", "old-conflict-canary"),
        ],
    )
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "internal_token_header_conflict"}}
