# JJDGuard E2E Test Suite

## Quick Start

```bash
cd tests/e2e

# 1. Install dependencies (one-time)
bash setup.sh

# 2. Run all tests
bash run_all.sh

# 3. Run with coverage
bash run_all.sh --with-coverage
```

## Prerequisites

- Python 3.11+
- All 7 Docker containers running and healthy
- PostgreSQL port 15432 exposed
- control-plane listening on 127.0.0.1:8081
- web-console on :3000

## Directory Structure

```
tests/e2e/
  lib/                  # Shared utilities
    api_client.py       # Async httpx admin API client
    browser.py          # Playwright browser session (KNOWN-LIMIT: ubuntu 26.04)
    db.py               # Direct PostgreSQL connection
    cleanup.py          # Test tenant cleanup
    fixtures.py         # Test data setup
  smoke/                # Fast smoke tests (< 5 min)
    test_api_health.py  # All 58 admin API endpoints
    test_pages_render.py# Frontend pages (skipped on ubuntu 26.04)
    test_db_schema.py   # Database schema validation
  scenarios/            # Business flow tests
    test_s01_login.py   # Auth flow
    test_s02_tenant_project.py  # Tenant + project CRUD
    test_s03_keys.py    # API key lifecycle
    test_s04_quota_policy.py    # Quota policy
    test_s05_savings_board.py   # Savings + is_test filter
    test_s06_anomaly.py         # Anomaly detection
    test_s07_routing_policy.py  # Routing policy CRUD
    test_s08_kill_switch.py     # Governor kill switch (read-only)
  coverage/             # Coverage collection scripts
    run_go_coverage.sh
    run_python_coverage.sh
    run_frontend_coverage.sh
  reports/              # Test output (gitignored)
    latest -> YYYYMMDD-HHMMSS/
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| E2E_API_BASE | http://127.0.0.1:8081 | control-plane URL |
| E2E_WEB_BASE | http://127.0.0.1:3000 | web-console URL |
| E2E_DB_DSN | postgresql://newapi:newapi@127.0.0.1:15432/newapi | DB connection |
| E2E_ADMIN_USER | admin | Admin username |
| E2E_ADMIN_PASS | NapiE2E#2026! | Admin password |
| E2E_REPORTS | tests/e2e/reports/latest | Report output dir |

## Known Limits

### Playwright Browser Tests (ubuntu 26.04)
Playwright does not support ubuntu >= 26.04 yet (as of 2026-05).
`test_pages_render.py` auto-skips with reason "Chromium binary not installed".

**Workarounds:**
1. Run browser tests from a docker container:
   ```bash
   docker run --rm --network host \
     -v $(pwd):/work -w /work/tests/e2e \
     mcr.microsoft.com/playwright/python:v1.40.0-jammy \
     python -m pytest smoke/test_pages_render.py -v
   ```
2. Or run from a macOS/ubuntu 24.04 machine.

### Admin Password Reset
If the admin password changes (e.g., password change required flow), update `E2E_ADMIN_PASS` env var.

To reset to the test-known password via DB:
```bash
python3 -c "
import bcrypt
h = bcrypt.hashpw(b'NapiE2E#2026!', bcrypt.gensalt(rounds=10))
print(h.decode())
"
# Then: docker exec docker-compose-postgres-1 psql -U newapi -d newapi \
#   -c "UPDATE users SET password_hash='<hash>', must_change_password=FALSE WHERE username='admin';"
```

### Anomaly & Forecast Modules
Some endpoints return 503 if the module dependency isn't wired in `Dependencies`.
`test_s06_anomaly.py` handles this gracefully (skips or passes with reduced assertions).

### s08 Kill Switch
ADR #5: Does not actually restart containers. Verifies governor initialization
via budget snapshot response structure and log keyword search.
If governor logs at DEBUG level, `test_governor_in_startup_logs` warns (but doesn't fail).

## Troubleshooting

**"Fixture setup failed" / "DB connection refused"**
- Check PostgreSQL: `docker ps | grep postgres`
- Port: `docker compose port postgres 5432` (should map to 15432)

**"401 Unauthorized" on API tests**
- Admin password changed; run password reset above

**"Package not found" import errors**
- Re-run `bash setup.sh` to reinstall the editable package
