"""
Scenario s05: 节省看板 + is_test 过滤验证
- Write test data for test tenant
- GET /savings/summary without include_test=true → test tenant excluded
- GET /savings/summary?include_test=true → test tenant included
"""
import pytest
from lib.db import conn
from lib.cleanup import TEST_TENANT_ID


def _insert_test_saving(tenant_id: str, saving_usd: float):
    """Insert a saving_metrics row for the given tenant.
    Note: saving_metrics.id is bigint (auto-increment), not UUID.
    """
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            """
            INSERT INTO saving_metrics
                (tenant_id, date, source, saving_usd, saving_cny, request_count)
            VALUES
                (%s, CURRENT_DATE, 'model_downgrade', %s, %s, 1)
            RETURNING id
            """,
            (tenant_id, saving_usd, saving_usd * 7.2),
        )
        return cur.fetchone()[0]


def _delete_saving_by_id(row_id):
    with conn() as c:
        c.cursor().execute("DELETE FROM saving_metrics WHERE id=%s", (row_id,))


def _sum_savings_usd(summary_json: dict) -> float:
    return float(summary_json.get("total_usd", 0))


@pytest.mark.scenario
async def test_savings_board_filters_test_tenant(admin_api, test_tenant):
    """Savings board excludes test tenant data by default."""
    # Insert test data for test tenant
    row_id = _insert_test_saving(TEST_TENANT_ID, 999.99)

    try:
        # Without include_test: total_usd should NOT include 999.99 from test tenant
        r = await admin_api.get("/admin/v1/savings/summary?range=7d")
        assert r.status_code == 200, f"GET savings/summary failed: {r.text[:200]}"
        total_default = _sum_savings_usd(r.json())

        # With include_test: total_usd SHOULD include test tenant
        r2 = await admin_api.get("/admin/v1/savings/summary?range=7d&include_test=true")
        assert r2.status_code == 200, f"GET savings/summary?include_test failed: {r2.text[:200]}"
        total_with_test = _sum_savings_usd(r2.json())

        # With test data included should be >= without
        assert total_with_test >= total_default, (
            f"include_test=true ({total_with_test}) < default ({total_default})"
        )
        # The test tenant's 999.99 should appear when include_test=true
        diff = total_with_test - total_default
        assert diff >= 999.0, (
            f"Expected ~999 extra with include_test, got diff={diff:.2f} "
            f"(default={total_default:.2f}, with_test={total_with_test:.2f})"
        )

    finally:
        _delete_saving_by_id(row_id)
