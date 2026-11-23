-- deploy/migrations/rollback/1004_alert_case_store_version.sql
-- 删除物化口径版本表；先于 1002 的回滚执行。
DROP TABLE IF EXISTS alert_case_store_version;
