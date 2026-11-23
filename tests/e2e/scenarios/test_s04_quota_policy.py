"""
Scenario s04: 配额策略 CRUD
- Set/update quota policy for a project
- Verify policy stored in DB
"""
import pytest
import uuid
from lib.db import conn


@pytest.mark.scenario
async def test_quota_policy_crud(admin_api):
    """Create project, set quota policy, verify in DB."""
    unique = uuid.uuid4().hex[:8]

    # Create project
    r_proj = await admin_api.post("/admin/v1/projects", json={"name": f"e2e-s04-{unique}"})
    assert r_proj.status_code == 200, f"Create project failed: {r_proj.text}"
    project_id = r_proj.json()["id"]

    try:
        # Set quota policy (uses project_id in body, not scope_type/scope_ref)
        r2 = await admin_api.put(
            "/admin/v1/policies/quota",
            json={
                "project_id": project_id,
                "monthly_budget_limit": 100.0,
                "daily_budget_limit": 10.0,
                "overage_action": "notify",  # valid: notify | rate_limit | pause_key | downgrade_model
            },
        )
        assert r2.status_code in (200, 201, 204), f"PUT quota policy failed: {r2.text[:300]}"

        # Verify in DB
        with conn() as c:
            cur = c.cursor()
            cur.execute(
                "SELECT scope_type, project_id, monthly_budget_limit, overage_action "
                "FROM quota_policies WHERE project_id=%s",
                (project_id,),
            )
            row = cur.fetchone()
            assert row is not None, f"Quota policy not found in DB for project {project_id}"
            assert row[0] == "project"
            assert float(row[2]) == 100.0
            assert row[3] == "notify"

    finally:
        from lib.db import conn as dbconn
        with dbconn() as c:
            c.cursor().execute("DELETE FROM quota_policies WHERE project_id=%s", (project_id,))
        await admin_api.delete(f"/admin/v1/projects/{project_id}")
