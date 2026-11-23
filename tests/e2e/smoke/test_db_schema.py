"""
Smoke test: verify that all expected tables exist in the database.
Tables derived from actual schema (docker exec ... psql \dt).
"""
import pytest
from lib.db import conn

# All tables expected by the enterprise schema.
# Note: some tables from spec may not exist in this deployment;
# verified against actual psql \dt output on 2026-05-30.
TABLES = [
    # Core entities
    "tenants",
    "users",
    "projects",
    "providers",
    "models",
    "internal_keys",
    # Audit & security
    "request_logs",
    "audit_operations",
    "audit_logs",
    "audit_dispositions",
    "audit_chain",
    "security_events",
    "content_logs",
    "tool_call_logs",
    "tool_risk_config",
    # Rules engine
    "rule_sets",
    "rules",
    # Teams & org
    "teams",
    "team_members",
    # Budget & cost
    "saving_metrics",
    "alert_inbox",
    "notify_channels",
    "pause_log",
    "fx_rates",
    "provider_price_snapshots",
    "cost_governance_config",
    "quota_policies",
    "usage_daily",
    # Anomaly & forecast
    "anomaly_events",
    "forecast_jobs",
    # Routing
    "routing_policies",
    # Agent sessions
    "agent_sessions",
    # E2E marker column (added by migration 042)
    # (verified via column check separately)
]


@pytest.mark.smoke
@pytest.mark.parametrize("t", TABLES)
def test_table_exists(t):
    with conn() as c:
        cur = c.cursor()
        cur.execute("SELECT to_regclass(%s)", (f"public.{t}",))
        result = cur.fetchone()[0]
        assert result is not None, f"Table '{t}' missing from public schema"


@pytest.mark.smoke
def test_tenants_has_is_test_column():
    """Verify migration 042 added is_test column to tenants."""
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            """
            SELECT column_name, data_type, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'tenants'
              AND column_name = 'is_test'
            """
        )
        row = cur.fetchone()
        assert row is not None, "Column tenants.is_test missing (migration 042 not applied?)"
        assert row[1] in ("boolean",), f"Expected boolean, got {row[1]}"
        assert "false" in str(row[2]).lower(), f"Expected DEFAULT false, got {row[2]}"


@pytest.mark.smoke
def test_quota_policies_has_governor_downgrade_model_column():
    """Verify governor hot path can query quota_policies.downgrade_model without fail-open."""
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            """
            SELECT column_name, data_type, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'quota_policies'
              AND column_name = 'downgrade_model'
            """
        )
        row = cur.fetchone()
        assert row is not None, "Column quota_policies.downgrade_model missing; governor quota cache will fail-open"
        assert row[1] in ("character varying", "text"), f"Expected text-like type, got {row[1]}"
        assert row[2] is not None and "''" in str(row[2]), f"Expected DEFAULT empty string, got {row[2]}"
