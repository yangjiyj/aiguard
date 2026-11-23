"""
Smoke test: every admin endpoint returns expected status codes.
Endpoints are derived from apps/control-plane/cmd/server/main.go.
"""
import httpx
import pytest

API_BASE = "http://127.0.0.1:8081"

# (path, method, requires_auth, expected_status_or_list)
# For unauthenticated requests to protected endpoints: expect 401/403.
# For authenticated GET requests: expect < 500.
ENDPOINTS = [
    # Public
    ("/health", "GET", False, 200),
    # Auth
    ("/admin/v1/me", "GET", True, [200]),
    # Tenants
    ("/admin/v1/tenants", "GET", True, [200]),
    # Projects
    ("/admin/v1/projects", "GET", True, [200]),
    # Keys
    ("/admin/v1/keys", "GET", True, [200]),
    # Providers
    ("/admin/v1/providers", "GET", True, [200]),
    # Models
    ("/admin/v1/models", "GET", True, [200]),
    # Policies
    ("/admin/v1/policies/model", "GET", True, [200, 400, 404]),
    ("/admin/v1/policies/quota", "GET", True, [200, 400, 404]),
    # Rule sets
    ("/admin/v1/rule-sets", "GET", True, [200]),
    ("/admin/v1/rules", "GET", True, [200, 400]),  # requires rule_set_id param
    # Audit
    ("/admin/v1/audit/requests", "GET", True, [200]),
    ("/admin/v1/audit/events", "GET", True, [200]),
    ("/admin/v1/audit/dispositions", "GET", True, [200]),
    ("/admin/v1/audit/content", "GET", True, [200]),
    # Usage
    ("/admin/v1/usage/summary", "GET", True, [200, 400]),
    ("/admin/v1/usage/by-project", "GET", True, [200, 400]),
    ("/admin/v1/usage/by-model", "GET", True, [200, 400]),
    ("/admin/v1/usage/by-user", "GET", True, [200, 400]),
    ("/admin/v1/usage/by-key", "GET", True, [200, 400]),
    ("/admin/v1/usage/by-provider", "GET", True, [200, 400]),
    ("/admin/v1/usage/cost-coverage", "GET", True, [200, 400]),
    ("/admin/v1/usage/recommendations", "GET", True, [200, 400]),
    # Agent sessions (stats can take 20-25s on first query - DB has no index on session aggregation)
    ("/admin/v1/agent-sessions", "GET", True, [200]),
    ("/admin/v1/agent-sessions/stats", "GET", True, [200]),
    ("/admin/v1/agent-sessions/distribution", "GET", True, [200]),
    # Stats
    ("/admin/v1/stats/overview", "GET", True, [200]),
    ("/admin/v1/stats/users", "GET", True, [200, 400]),
    ("/admin/v1/stats/apps", "GET", True, [200, 400]),
    ("/admin/v1/stats/models", "GET", True, [200, 400]),
    # Tool audit
    ("/admin/v1/audit/tools/stats", "GET", True, [200, 400]),
    ("/admin/v1/audit/tools/high-risk", "GET", True, [200]),
    ("/admin/v1/audit/tools/trend", "GET", True, [200, 400]),
    # Tool config
    ("/admin/v1/tools/config", "GET", True, [200]),
    # Proxy
    ("/admin/v1/proxy/whitelist", "GET", True, [200]),
    ("/admin/v1/reverse-proxy/routes", "GET", True, [200]),
    # CA
    ("/admin/v1/ca/list", "GET", True, [200]),
    ("/admin/v1/ca/certificate", "GET", True, [200, 400, 404]),
    # Users
    ("/admin/v1/users", "GET", True, [200]),
    # System
    ("/admin/v1/system/settings", "GET", True, [200]),
    ("/admin/v1/system/audit-operations", "GET", True, [200]),
    ("/admin/v1/system/version", "GET", True, [200]),
    ("/admin/v1/system/upgrade/history", "GET", True, [200]),
    # Teams
    ("/admin/v1/teams", "GET", True, [200]),
    # Budget
    ("/admin/v1/budgets/snapshot", "GET", True, [200, 400]),
    ("/admin/v1/budgets/pause-log", "GET", True, [200]),
    # Prices
    ("/admin/v1/prices/sync-status", "GET", True, [200, 404]),
    # FX
    ("/admin/v1/fx/current", "GET", True, [200, 404]),
    ("/admin/v1/fx/history", "GET", True, [200]),
    # Savings
    ("/admin/v1/savings/summary", "GET", True, [200]),
    ("/admin/v1/savings/trend", "GET", True, [200]),
    ("/admin/v1/savings/config", "GET", True, [200, 404]),
    # Alerts
    ("/admin/v1/alerts/inbox", "GET", True, [200]),
    ("/admin/v1/notify-channels", "GET", True, [200]),
    # Audit chain
    ("/admin/v1/audit-chain/stats", "GET", True, [200]),
    # Anomalies
    ("/admin/v1/anomalies", "GET", True, [200, 503]),
    # Forecast
    ("/admin/v1/forecast/jobs", "GET", True, [200, 503]),
    # Routing policies
    ("/admin/v1/routing-policies", "GET", True, [200, 400]),  # requires scope_type + scope_ref
]


@pytest.mark.smoke
@pytest.mark.parametrize("path,method,auth,want", ENDPOINTS)
async def test_endpoint(admin_api, path, method, auth, want):
    if not auth:
        # Test public endpoint without auth
        async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as c:
            r = await c.request(method, path)
        expected = [want] if isinstance(want, int) else want
        assert r.status_code in expected, (
            f"{method} {path}: got {r.status_code}, body={r.text[:300]}"
        )
    else:
        # Test that unauthenticated access returns 401/403
        async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as c:
            r_unauth = await c.request(method, path)
        assert r_unauth.status_code in (401, 403), (
            f"Expected 401/403 without auth for {method} {path}, got {r_unauth.status_code}"
        )
        # Test that authenticated access returns expected status
        r = await getattr(admin_api, method.lower())(path, timeout=30.0)
        expected = [want] if isinstance(want, int) else want
        assert r.status_code in expected, (
            f"{method} {path}: got {r.status_code}, body={r.text[:300]}"
        )
