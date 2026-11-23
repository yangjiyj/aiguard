-- deploy/migrations/rollback/1008_alert_case_trigger_digest.sql
-- 删除告警案件物化登记触发器的定义摘要表。删掉后控制面认为物化表未迁移完整，告警读接口实时查询。
-- 本文件不删除 schema_migrations 里 1008 的记录：回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '1008_alert_case_trigger_digest.sql';
-- 再运行升级。
BEGIN;
DROP TABLE IF EXISTS alert_case_trigger_expected;
DROP FUNCTION IF EXISTS jjd_alert_case_trigger_digest();
COMMIT;
