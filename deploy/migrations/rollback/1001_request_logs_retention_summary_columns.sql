-- deploy/migrations/rollback/1001_request_logs_retention_summary_columns.sql
-- 删除留存完整汇总的三个预算列。回退到不读这些列的版本后执行；只删预算结果，原始数据不受影响。
-- 必须先执行 deploy/migrations/rollback/1006_alert_retention_dirty_triggers.sql：1006 的触发器函数引用这三列，
-- 列删了而触发器还在，安全事件、正文、留存会话都会写不进库。下面的检查发现 1006 的触发器还在就拒绝执行。
-- 整个脚本包在一个事务里：不带 ON_ERROR_STOP 的 psql -f 时，检查报错后事务已中止，后面的 DROP COLUMN 不会执行，
-- 最后的 COMMIT 变成回滚。
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname LIKE 'trg\_retention\_summary\_stale\_%' AND NOT tgisinternal) OR EXISTS (SELECT 1 FROM pg_proc WHERE proname LIKE 'jjd\_retention\_summary\_stale\_%') THEN
        RAISE EXCEPTION '1006 的留存预算列触发器还在：先执行 deploy/migrations/rollback/1006_alert_retention_dirty_triggers.sql，再回滚 1001';
    END IF;
END
$$;
ALTER TABLE request_logs
    DROP COLUMN IF EXISTS risk_reasons,
    DROP COLUMN IF EXISTS request_body_exists,
    DROP COLUMN IF EXISTS response_body_exists;
COMMIT;
