"""
Scenario s07: 路由策略 CRUD
- Upsert a routing policy
- Verify it's stored in DB
- Delete it
"""
import pytest
import uuid
from lib.db import conn


@pytest.mark.scenario
async def test_routing_policy_upsert_and_delete(admin_api):
    """Upsert a routing policy and verify DB state, then delete."""
    unique = uuid.uuid4().hex[:8]
    scope_ref = f"e2e-s07-{unique}"

    # Upsert routing policy
    r = await admin_api.put(
        "/admin/v1/routing-policies",
        json={
            "scope_type": "project",
            "scope_ref": scope_ref,
            "layer": "load_balance",
            "strategy": "round_robin",
            "config_json": {},
            "enabled": True,
        },
    )
    assert r.status_code in (200, 201, 204), (
        f"Upsert routing policy failed: {r.status_code} {r.text[:300]}"
    )

    # Verify in DB
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            "SELECT id, scope_type, strategy, enabled FROM routing_policies WHERE scope_ref=%s",
            (scope_ref,),
        )
        row = cur.fetchone()
        assert row is not None, f"Routing policy not found in DB for scope_ref={scope_ref}"
        policy_id = row[0]
        assert row[1] == "project"
        assert row[2] == "round_robin"
        assert row[3] is True

    # Delete it
    r2 = await admin_api.delete(f"/admin/v1/routing-policies/{policy_id}")
    assert r2.status_code in (200, 204), f"Delete routing policy failed: {r2.text[:200]}"

    # Verify deleted
    with conn() as c:
        cur = c.cursor()
        cur.execute("SELECT id FROM routing_policies WHERE id=%s", (policy_id,))
        assert cur.fetchone() is None, "Routing policy still in DB after delete"
