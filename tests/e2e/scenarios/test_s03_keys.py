"""
Scenario s03: API Keys 生命周期
- Create a key for a project
- List keys → new key visible
- Revoke key
- Delete key
"""
import pytest
import uuid


@pytest.mark.scenario
async def test_key_lifecycle(admin_api):
    """Create, list, revoke, and delete an API key."""
    unique = uuid.uuid4().hex[:8]

    # First need a project
    r_proj = await admin_api.post("/admin/v1/projects", json={"name": f"e2e-s03-proj-{unique}"})
    assert r_proj.status_code == 200, f"Create project failed: {r_proj.text}"
    project_id = r_proj.json()["id"]

    try:
        # Create key
        r = await admin_api.post(
            "/admin/v1/keys",
            json={"name": f"e2e-key-{unique}", "project_id": project_id},
        )
        assert r.status_code == 200, f"Create key failed: {r.text[:300]}"
        key_data = r.json()
        key_id = key_data.get("id") or key_data.get("key_id")
        assert key_id, f"No id in key response: {key_data}"

        # List keys
        r2 = await admin_api.get("/admin/v1/keys")
        assert r2.status_code == 200
        key_ids = [k.get("id") or k.get("key_id") for k in r2.json().get("data", [])]
        assert key_id in key_ids, f"Key {key_id} not in list: {key_ids[:5]}"

        # Revoke key  
        key_prefix = key_data.get("key_prefix", "")
        if key_prefix:
            r3 = await admin_api.post(f"/admin/v1/keys/{key_id}/revoke")
            assert r3.status_code in (200, 204), f"Revoke failed: {r3.text[:200]}"

    finally:
        # Cleanup: delete key then project
        try:
            await admin_api.delete(f"/admin/v1/keys/{key_id}")
        except Exception:
            pass
        await admin_api.delete(f"/admin/v1/projects/{project_id}")
