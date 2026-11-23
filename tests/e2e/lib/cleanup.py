from .db import conn

TEST_TENANT_ID = "tenant_e2e_test"

# Tables in reverse FK order to avoid constraint violations.
# audit_chain is WORM — never deleted.
TABLES_REVERSE = [
    "anomaly_events",
    "forecast_jobs",
    "saving_metrics",
    "pause_log",
    "alert_inbox",
    "notify_channels",
    "routing_policies",
    "cost_governance_config",
    "request_logs",
    "quota_policies",
    "team_members",    # handled via teams join
    "teams",
    "internal_keys",
    "projects",
    "users",
    "tenants",
]


def cleanup_test_tenant():
    with conn() as c:
        cur = c.cursor()
        for t in TABLES_REVERSE:
            try:
                if t == "team_members":
                    cur.execute(
                        "DELETE FROM team_members WHERE team_id IN "
                        "(SELECT id FROM teams WHERE tenant_id=%s)",
                        (TEST_TENANT_ID,),
                    )
                elif t == "cost_governance_config":
                    cur.execute(
                        "DELETE FROM cost_governance_config WHERE tenant_id=%s",
                        (TEST_TENANT_ID,),
                    )
                elif t == "internal_keys":
                    cur.execute(
                        "DELETE FROM internal_keys WHERE tenant_id=%s OR "
                        "project_id IN (SELECT id FROM projects WHERE tenant_id=%s)",
                        (TEST_TENANT_ID, TEST_TENANT_ID),
                    )
                else:
                    cur.execute(
                        f"DELETE FROM {t} WHERE tenant_id=%s",
                        (TEST_TENANT_ID,),
                    )
            except Exception as e:
                # Non-fatal: table might not have tenant_id or may be empty
                pass
