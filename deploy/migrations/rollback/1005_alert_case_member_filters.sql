-- deploy/migrations/rollback/1005_alert_case_member_filters.sql
-- 删除按用户、会话筛选用的物化列与索引；先于 1002 的回滚执行。回退后的控制面不读这些列。
BEGIN;
DROP INDEX IF EXISTS idx_alert_case_members_actor;
DROP INDEX IF EXISTS idx_alert_case_members_session;
DROP INDEX IF EXISTS idx_alert_case_members_endpoint_session;
DROP INDEX IF EXISTS idx_alert_case_members_conversation_key;
ALTER TABLE alert_case_members
    DROP COLUMN IF EXISTS actor_user_id,
    DROP COLUMN IF EXISTS filter_session_id,
    DROP COLUMN IF EXISTS endpoint_session_id;
COMMIT;
