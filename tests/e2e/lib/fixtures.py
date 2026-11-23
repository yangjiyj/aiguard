from .db import conn
from .cleanup import TEST_TENANT_ID, cleanup_test_tenant


def ensure_test_tenant():
    """Create a clean test tenant (idempotent)."""
    cleanup_test_tenant()
    with conn() as c:
        cur = c.cursor()
        cur.execute(
            """
            INSERT INTO tenants (id, name, edition, status, is_test)
            VALUES (%s, %s, 'enterprise', 'active', TRUE)
            ON CONFLICT (id) DO UPDATE SET is_test = TRUE, status = 'active'
            """,
            (TEST_TENANT_ID, "E2E Test Tenant"),
        )
