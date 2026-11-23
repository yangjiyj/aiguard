-- deploy/migrations/rollback/1003_alert_case_dirty_triggers.sql
-- 删除告警案件物化的变更登记触发器与函数。回退到旧版控制面后若不删，alert_case_dirty 会持续增长（无人消化）。
-- 触发器删掉后物化结果不再跟随数据变化，所以同时把回填置为未完成、清掉口径指纹：再升级时控制面会重建，
-- 重建完成前告警读接口实时查询（控制面另会检查触发器是否齐全，缺任何一个都不用物化表）。
-- 下面的检查发现 1006 的触发器还在就拒绝执行。
-- 顺序：1006 重定义了本文件删掉的同名触发器和 jjd_alert_case_dirty_access_rows，所以
--   1. 先执行 deploy/migrations/rollback/1006_alert_retention_dirty_triggers.sql，再执行本文件；
--   2. 回滚后如需再升级，先手工删除 1003、1006 两条迁移记录（1008 的记录保留：重跑 1006 后触发器定义与
--      1008 记下的摘要一致）：
--        DELETE FROM schema_migrations WHERE version IN ('1003_alert_case_dirty_triggers.sql', '1006_alert_retention_dirty_triggers.sql');
--   3. 运行升级：迁移运行器按编号先重建 1003、再执行 1006，触发器回到最新定义。
-- 本文件不删除迁移记录。只删 1003 的记录再升级，触发器会停在 1003 的旧定义：控制面比对触发器定义摘要
-- （迁移 1008）发现不一致，告警读接口会一直实时查询、物化结果不再使用，直到按上面的顺序补跑 1006。
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgname LIKE 'trg\_retention\_summary\_stale\_%' AND NOT tgisinternal) OR EXISTS (SELECT 1 FROM pg_proc WHERE proname LIKE 'jjd\_retention\_summary\_stale\_%') THEN
        RAISE EXCEPTION '1006 还在（它重定义了本文件删除的同名触发器）：先执行 deploy/migrations/rollback/1006_alert_retention_dirty_triggers.sql，再回滚 1003';
    END IF;
END
$$;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_insert ON security_events;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_delete ON security_events;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_update ON security_events;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_request_update ON request_logs;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_access_insert ON access_content_logs;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_access_delete ON access_content_logs;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_access_update ON access_content_logs;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_disposition ON audit_dispositions;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_group_insert_delete ON alert_groups;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_group_update ON alert_groups;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_key_insert_delete ON internal_keys;
DROP TRIGGER IF EXISTS trg_alert_case_dirty_key_update ON internal_keys;
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_event_rows();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_event_update();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_request_update();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_access_rows();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_access_update();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_disposition();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_group();
DROP FUNCTION IF EXISTS jjd_alert_case_dirty_key();
DO $$
BEGIN
    IF to_regclass('alert_case_backfill') IS NOT NULL THEN
        UPDATE alert_case_backfill SET done = FALSE, cursor_event_id = '', updated_at = now() WHERE done OR cursor_event_id <> '';
    END IF;
    IF to_regclass('alert_case_store_version') IS NOT NULL THEN
        UPDATE alert_case_store_version SET logic_version = '', updated_at = now() WHERE logic_version <> '';
    END IF;
END
$$;
COMMIT;
