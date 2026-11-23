-- deploy/migrations/rollback/1002_alert_case_store.sql
-- 删除告警案件物化表。先回退到不读这些表的控制面版本，并先执行 1003 的回滚（触发器会写 alert_case_dirty）。
-- 物化结果都能从 security_events 等原始表重新算出，删除不丢原始数据；重新升级时 1002 会重新登记回填。
-- 必须先回滚 1006、1003（顺序见 rollback/1003）：1003 的触发器往 alert_case_dirty 写，表删了而触发器还在，
-- 安全事件、请求、留存会话、处置、告警组、凭据都会写不进库。下面的检查发现 1003 的触发器还在就拒绝执行。
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname LIKE 'trg\_alert\_case\_dirty\_%' AND NOT tgisinternal) OR EXISTS (SELECT 1 FROM pg_proc WHERE proname LIKE 'jjd\_alert\_case\_dirty\_%') THEN
        RAISE EXCEPTION '1003 的登记触发器还在：先执行 rollback/1006、rollback/1003（顺序见 rollback/1003），再回滚 1002';
    END IF;
END
$$;
DROP TABLE IF EXISTS alert_case_backfill;
DROP TABLE IF EXISTS alert_case_dirty;
DROP TABLE IF EXISTS alert_case_groups;
DROP TABLE IF EXISTS alert_cases;
DROP TABLE IF EXISTS alert_case_members;
COMMIT;
