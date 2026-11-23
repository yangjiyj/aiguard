-- deploy/migrations/rollback/1009_alert_case_dirty_quarantine.sql
-- 删除坏条目隔离表，恢复队列表的默认清理参数。隔离表里的条目会丢失（物化结果可从原始表重建：回滚后再升级时
-- 控制面会按口径指纹重建）。
-- 本文件不删除 schema_migrations 里 1009 的记录：回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '1009_alert_case_dirty_quarantine.sql';
-- 再运行升级。
BEGIN;
DROP TABLE IF EXISTS alert_case_dirty_quarantine;
DO $$
BEGIN
    IF to_regclass('alert_case_dirty') IS NOT NULL THEN
        ALTER TABLE alert_case_dirty RESET (
            autovacuum_vacuum_scale_factor, autovacuum_vacuum_threshold,
            autovacuum_vacuum_insert_scale_factor, autovacuum_vacuum_insert_threshold,
            autovacuum_analyze_scale_factor, autovacuum_analyze_threshold);
    END IF;
END
$$;
COMMIT;
