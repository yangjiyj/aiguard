-- 075_org_test_tenant_visibility_fix.sql
-- 补齐组织管理中测试/回归租户的 is_test 标记；只隐藏，不删除数据。
BEGIN;

UPDATE tenants
SET is_test = TRUE
WHERE COALESCE(is_test, FALSE) = FALSE
  AND (
    id LIKE 'tenant\_audit\_stats\_%' ESCAPE '\'
    OR id LIKE 'tenant\_weak\_signal\_%' ESCAPE '\'
    OR id LIKE 'tenant\_resolve\_a\_%' ESCAPE '\'
    OR id LIKE 'tenant\_resolve\_b\_%' ESCAPE '\'
    OR id LIKE 'tenant\_auditdetail\_%' ESCAPE '\'
    OR id LIKE 'tenant\_content\_%' ESCAPE '\'
    OR id LIKE 'tenant\_rp\_test\_%' ESCAPE '\'
    OR id LIKE 'tfx\_%' ESCAPE '\'
  );

COMMIT;
