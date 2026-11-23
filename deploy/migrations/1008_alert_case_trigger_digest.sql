BEGIN;

-- 1008_alert_case_trigger_digest: 记下告警案件物化登记触发器的定义摘要（2.9.22 批次 7）。
--
-- 1003 建、1006 改的 12 个登记触发器（定义、启用状态、触发器函数体）算一个摘要存进 alert_case_trigger_expected。
-- 控制面每次用物化表前用同一个表达式现算一遍：与这里记下的不一致（例如按 1003 的回滚说明回滚后只重跑了 1003，
-- 触发器被降回旧定义；或有人改了、删了、停用了触发器），就改走实时查询并作废物化结果，定义恢复后再重建。
-- 以后改这些触发器的迁移，最后要用同一个表达式重新记一次摘要（本表只有一行）。
-- 回滚：deploy/migrations/rollback/1008_alert_case_trigger_digest.sql。

CREATE TABLE IF NOT EXISTS alert_case_trigger_expected (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    digest     TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 摘要函数：控制面完整性检查用的是同一个表达式（alertCaseTriggerDigestSQL），测试核对两边一字不差。
CREATE OR REPLACE FUNCTION jjd_alert_case_trigger_digest() RETURNS text LANGUAGE sql STABLE AS $$
SELECT (SELECT md5(string_agg(wanted.tbl||'.'||wanted.name||'='||COALESCE(pg_get_triggerdef(t.oid)||' enabled='||t.tgenabled::text||' function='||p.prosrc,'missing'), E'\n' ORDER BY wanted.tbl, wanted.name)) FROM unnest(ARRAY['security_events','security_events','security_events','request_logs','access_content_logs','access_content_logs','access_content_logs','audit_dispositions','alert_groups','alert_groups','internal_keys','internal_keys']::text[], ARRAY['trg_alert_case_dirty_event_insert','trg_alert_case_dirty_event_delete','trg_alert_case_dirty_event_update','trg_alert_case_dirty_request_update','trg_alert_case_dirty_access_insert','trg_alert_case_dirty_access_delete','trg_alert_case_dirty_access_update','trg_alert_case_dirty_disposition','trg_alert_case_dirty_group_insert_delete','trg_alert_case_dirty_group_update','trg_alert_case_dirty_key_insert_delete','trg_alert_case_dirty_key_update']::text[]) AS wanted(tbl, name) LEFT JOIN pg_trigger t ON t.tgrelid = to_regclass(wanted.tbl) AND t.tgname = wanted.name AND NOT t.tgisinternal LEFT JOIN pg_proc p ON p.oid = t.tgfoid)
$$;

INSERT INTO alert_case_trigger_expected (singleton, digest, recorded_by)
VALUES (TRUE, jjd_alert_case_trigger_digest(), '1008_alert_case_trigger_digest.sql')
ON CONFLICT (singleton) DO UPDATE SET digest = EXCLUDED.digest, recorded_by = EXCLUDED.recorded_by, updated_at = now()
WHERE alert_case_trigger_expected.digest IS DISTINCT FROM EXCLUDED.digest;

COMMIT;
