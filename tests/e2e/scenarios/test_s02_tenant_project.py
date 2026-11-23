"""
Scenario s02: 租户 + 项目 CRUD
- Create tenant
- List tenants → new tenant visible
- Create project under admin tenant
- List projects → new project visible
- Delete project
- Cleanup: delete tenant
"""
import pytest
import uuid
from lib.cleanup import TEST_TENANT_ID


@pytest.mark.scenario
async def test_tenant_crud(admin_api):
    """Create and delete a tenant."""
    unique = uuid.uuid4().hex[:8]
    tenant_name = f"e2e-s02-{unique}"

    # Create
    r = await admin_api.post(
        "/admin/v1/tenants",
        json={"name": tenant_name, "edition": "cloud"},
    )
    assert r.status_code == 200, f"Create tenant failed: {r.text[:300]}"
    tenant = r.json()
    tenant_id = tenant["id"]
    assert tenant["name"] == tenant_name

    try:
        # List - new tenant should appear
        r2 = await admin_api.get("/admin/v1/tenants")
        assert r2.status_code == 200
        data = r2.json()
        ids = [t["id"] for t in data.get("data", [])]
        assert tenant_id in ids, f"New tenant {tenant_id} not in list: {ids[:5]}"

        # Get single tenant
        r3 = await admin_api.get(f"/admin/v1/tenants/{tenant_id}")
        assert r3.status_code == 200
        assert r3.json()["id"] == tenant_id

    finally:
        # No delete-tenant endpoint; clean via DB
        from lib.db import conn
        with conn() as c:
            c.cursor().execute("DELETE FROM tenants WHERE id=%s", (tenant_id,))


@pytest.mark.scenario
async def test_project_crud(admin_api):
    """Create and delete a project under admin tenant."""
    unique = uuid.uuid4().hex[:8]
    project_name = f"e2e-s02-proj-{unique}"

    # Create
    r = await admin_api.post(
        "/admin/v1/projects",
        json={"name": project_name},
    )
    assert r.status_code == 200, f"Create project failed: {r.text[:300]}"
    project = r.json()
    project_id = project["id"]
    assert project["name"] == project_name

    # List
    r2 = await admin_api.get("/admin/v1/projects")
    assert r2.status_code == 200
    data = r2.json()
    ids = [p["id"] for p in data.get("data", [])]
    assert project_id in ids, f"New project {project_id} not in list: {ids[:5]}"

    # Delete
    r3 = await admin_api.delete(f"/admin/v1/projects/{project_id}")
    assert r3.status_code in (200, 204), f"Delete project failed: {r3.text[:200]}"

    # Verify deleted (list again)
    r4 = await admin_api.get("/admin/v1/projects")
    assert r4.status_code == 200
    ids_after = [p["id"] for p in r4.json().get("data", [])]
    assert project_id not in ids_after, f"Project {project_id} still in list after delete"
