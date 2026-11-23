"""
Scenario s01: 登录与跳转
- POST /admin/v1/login → 200 with token
- Unauthorized access → 401
- Login with wrong credentials → 401
"""
import pytest
import httpx

API_BASE = "http://127.0.0.1:8081"
ADMIN_USER = "admin"
ADMIN_PASS = "NapiE2E#2026!"


@pytest.mark.scenario
async def test_login_success():
    """Login with valid credentials returns token and user info."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as c:
        r = await c.post(
            "/admin/v1/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )
    assert r.status_code == 200, f"Login failed: {r.text[:300]}"
    data = r.json()
    assert "token" in data, f"No token in response: {data}"
    assert len(data["token"]) > 10, "Token too short"
    assert data.get("user", {}).get("username") == ADMIN_USER, f"Username mismatch: {data}"


@pytest.mark.scenario
async def test_login_wrong_password():
    """Login with wrong password returns 401."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as c:
        r = await c.post(
            "/admin/v1/login",
            json={"username": ADMIN_USER, "password": "wrong-password"},
        )
    assert r.status_code in (401, 403), f"Expected 401 for wrong password, got {r.status_code}"


@pytest.mark.scenario
async def test_unauthorized_access_returns_401():
    """Protected endpoint without auth token returns 401."""
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as c:
        r = await c.get("/admin/v1/tenants")
    assert r.status_code in (401, 403), (
        f"Expected 401 without auth, got {r.status_code}: {r.text[:200]}"
    )


@pytest.mark.scenario
async def test_token_in_subsequent_requests(admin_api):
    """Token from login works for subsequent requests."""
    r = await admin_api.get("/admin/v1/me")
    assert r.status_code == 200, f"GET /me failed with valid token: {r.text[:200]}"
    data = r.json()
    assert data.get("username") == ADMIN_USER, f"Unexpected user: {data}"
