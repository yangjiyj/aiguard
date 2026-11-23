-- 051_audit_operations_user_nullable.sql
-- 操作审计是历史流水，不应阻断账号删除；删除用户时保留审计记录并解绑 user_id。
BEGIN;

ALTER TABLE audit_operations
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE audit_operations
    DROP CONSTRAINT IF EXISTS audit_operations_user_id_fkey;

UPDATE audit_operations ao
SET user_id = NULL
WHERE user_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = ao.user_id);

ALTER TABLE audit_operations
    ADD CONSTRAINT audit_operations_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

COMMIT;
