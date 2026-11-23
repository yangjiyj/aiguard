BEGIN;

-- 1006_alert_retention_dirty_triggers: 物化与预算列跟上数据变化的触发器补充（2.9.22 批次 7）。
--
-- 告警案件物化（1003 的补充）：
--   * 留存会话新增、删除时，只要有会话编号就登记该请求（1003 只在请求已有告警时登记：告警与留存并发写入
--     时，留存先提交、告警后提交，两次检查都落空，案件会一直用旧的会话归并）。
--   * 安全事件的读取元数据（生成列 alert_read_metadata_v1）变化也登记事件。
--   * 请求记录的项目、代理方式变化也登记请求（按用户、会话筛选时关联请求记录要用到）。
-- 留存完整汇总的预算列（1001 的 risk_reasons、request_body_exists、response_body_exists）：
--   * 正文条目、旧正文表、留存会话增删改（含保留期清理、标题请求清理）时，把相关请求的“有无正文”置空；
--   * 安全事件增删、命中摘要变化时（含超过 15 分钟刷新窗口才到的事件），把相关请求的风险原因置空；
--   * 请求记录的审计结果、目标、代理方式、环境作用域变化时，把三列置空。
--   置空后读路径用 COALESCE 回退原表达式，结果始终与实时一致；控制面周期任务按部分索引把空值重新算出。
-- 触发器只追加队列或置空本行，不做重算。回滚：deploy/migrations/rollback/1006_alert_retention_dirty_triggers.sql。

-- 建删触发器要在这些表上取 SHARE ROW EXCLUSIVE（挡住写入），按写入方的先后顺序一次拿齐，避免与正在写入的请求
-- 交叉等锁；需要在停写入的维护窗口执行。
LOCK TABLE request_logs, security_events, access_content_logs, content_log_entries, content_logs_legacy
    IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_access_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT n.tenant_id, 'request', n.request_id FROM alert_case_new_rows n
        WHERE COALESCE(n.conversation_id, '') <> '';
    ELSE
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT o.tenant_id, 'request', o.request_id FROM alert_case_old_rows o
        WHERE COALESCE(o.conversation_id, '') <> '';
    END IF;
    RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_update ON security_events;
CREATE TRIGGER trg_alert_case_dirty_event_update AFTER UPDATE ON security_events
    FOR EACH ROW WHEN (
        OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.request_id IS DISTINCT FROM NEW.request_id OR OLD.project_id IS DISTINCT FROM NEW.project_id
        OR OLD.created_at IS DISTINCT FROM NEW.created_at OR OLD.event_type IS DISTINCT FROM NEW.event_type
        OR OLD.severity IS DISTINCT FROM NEW.severity OR OLD.rule_id IS DISTINCT FROM NEW.rule_id
        OR OLD.action_taken IS DISTINCT FROM NEW.action_taken OR OLD.matched_summary IS DISTINCT FROM NEW.matched_summary
        OR OLD.alert_read_metadata_v1 IS DISTINCT FROM NEW.alert_read_metadata_v1
        OR OLD.principal_key IS DISTINCT FROM NEW.principal_key OR OLD.alert_group_id IS DISTINCT FROM NEW.alert_group_id
        OR OLD.conversation_key IS DISTINCT FROM NEW.conversation_key OR OLD.user_id IS DISTINCT FROM NEW.user_id)
    EXECUTE FUNCTION jjd_alert_case_dirty_event_update();

DROP TRIGGER IF EXISTS trg_alert_case_dirty_request_update ON request_logs;
CREATE TRIGGER trg_alert_case_dirty_request_update AFTER UPDATE ON request_logs
    FOR EACH ROW WHEN (
        OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.created_at IS DISTINCT FROM NEW.created_at OR OLD.session_id IS DISTINCT FROM NEW.session_id
        OR OLD.client_id IS DISTINCT FROM NEW.client_id OR OLD.user_id IS DISTINCT FROM NEW.user_id
        OR OLD.source_ip IS DISTINCT FROM NEW.source_ip OR OLD.proxy_target_host IS DISTINCT FROM NEW.proxy_target_host
        OR OLD.model_id IS DISTINCT FROM NEW.model_id OR OLD.principal_context_json IS DISTINCT FROM NEW.principal_context_json
        OR OLD.environment_scope IS DISTINCT FROM NEW.environment_scope OR OLD.project_id IS DISTINCT FROM NEW.project_id
        OR OLD.proxy_mode IS DISTINCT FROM NEW.proxy_mode)
    EXECUTE FUNCTION jjd_alert_case_dirty_request_update();

-- 正文条目与旧正文表：request_id 是 request_logs.id。
CREATE OR REPLACE FUNCTION jjd_retention_summary_stale_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        UPDATE request_logs rl SET request_body_exists = NULL, response_body_exists = NULL
        FROM (SELECT DISTINCT tenant_id, request_id FROM retention_new_rows) changed
        WHERE rl.tenant_id = changed.tenant_id AND rl.id = changed.request_id
          AND (rl.request_body_exists IS NOT NULL OR rl.response_body_exists IS NOT NULL);
    END IF;
    IF TG_OP IN ('DELETE', 'UPDATE') THEN
        UPDATE request_logs rl SET request_body_exists = NULL, response_body_exists = NULL
        FROM (SELECT DISTINCT tenant_id, request_id FROM retention_old_rows) changed
        WHERE rl.tenant_id = changed.tenant_id AND rl.id = changed.request_id
          AND (rl.request_body_exists IS NOT NULL OR rl.response_body_exists IS NOT NULL);
    END IF;
    RETURN NULL;
END
$$;

-- 留存会话：request_id 是 request_logs.request_id。
CREATE OR REPLACE FUNCTION jjd_retention_summary_stale_access() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        UPDATE request_logs rl SET request_body_exists = NULL, response_body_exists = NULL
        FROM (SELECT DISTINCT tenant_id, request_id FROM retention_new_rows) changed
        WHERE rl.tenant_id = changed.tenant_id AND rl.request_id = changed.request_id
          AND (rl.request_body_exists IS NOT NULL OR rl.response_body_exists IS NOT NULL);
    END IF;
    IF TG_OP IN ('DELETE', 'UPDATE') THEN
        UPDATE request_logs rl SET request_body_exists = NULL, response_body_exists = NULL
        FROM (SELECT DISTINCT tenant_id, request_id FROM retention_old_rows) changed
        WHERE rl.tenant_id = changed.tenant_id AND rl.request_id = changed.request_id
          AND (rl.request_body_exists IS NOT NULL OR rl.response_body_exists IS NOT NULL);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_retention_summary_stale_event_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE request_logs rl SET risk_reasons = NULL
        FROM (SELECT DISTINCT tenant_id, request_id FROM retention_new_rows WHERE request_id IS NOT NULL) changed
        WHERE rl.tenant_id = changed.tenant_id AND rl.request_id = changed.request_id AND rl.risk_reasons IS NOT NULL;
    ELSE
        UPDATE request_logs rl SET risk_reasons = NULL
        FROM (SELECT DISTINCT tenant_id, request_id FROM retention_old_rows WHERE request_id IS NOT NULL) changed
        WHERE rl.tenant_id = changed.tenant_id AND rl.request_id = changed.request_id AND rl.risk_reasons IS NOT NULL;
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_retention_summary_stale_event_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE request_logs SET risk_reasons = NULL
    WHERE risk_reasons IS NOT NULL AND (
        (tenant_id = NEW.tenant_id AND request_id = NEW.request_id)
        OR (tenant_id = OLD.tenant_id AND request_id = OLD.request_id));
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_retention_summary_stale_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.risk_reasons := NULL;
    NEW.request_body_exists := NULL;
    NEW.response_body_exists := NULL;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_retention_summary_stale_entries_insert ON content_log_entries;
CREATE TRIGGER trg_retention_summary_stale_entries_insert AFTER INSERT ON content_log_entries
    REFERENCING NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_content();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_entries_update ON content_log_entries;
CREATE TRIGGER trg_retention_summary_stale_entries_update AFTER UPDATE ON content_log_entries
    REFERENCING OLD TABLE AS retention_old_rows NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_content();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_entries_delete ON content_log_entries;
CREATE TRIGGER trg_retention_summary_stale_entries_delete AFTER DELETE ON content_log_entries
    REFERENCING OLD TABLE AS retention_old_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_content();

DROP TRIGGER IF EXISTS trg_retention_summary_stale_legacy_insert ON content_logs_legacy;
CREATE TRIGGER trg_retention_summary_stale_legacy_insert AFTER INSERT ON content_logs_legacy
    REFERENCING NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_content();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_legacy_update ON content_logs_legacy;
CREATE TRIGGER trg_retention_summary_stale_legacy_update AFTER UPDATE ON content_logs_legacy
    REFERENCING OLD TABLE AS retention_old_rows NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_content();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_legacy_delete ON content_logs_legacy;
CREATE TRIGGER trg_retention_summary_stale_legacy_delete AFTER DELETE ON content_logs_legacy
    REFERENCING OLD TABLE AS retention_old_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_content();

DROP TRIGGER IF EXISTS trg_retention_summary_stale_access_insert ON access_content_logs;
CREATE TRIGGER trg_retention_summary_stale_access_insert AFTER INSERT ON access_content_logs
    REFERENCING NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_access();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_access_update ON access_content_logs;
CREATE TRIGGER trg_retention_summary_stale_access_update AFTER UPDATE ON access_content_logs
    REFERENCING OLD TABLE AS retention_old_rows NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_access();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_access_delete ON access_content_logs;
CREATE TRIGGER trg_retention_summary_stale_access_delete AFTER DELETE ON access_content_logs
    REFERENCING OLD TABLE AS retention_old_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_access();

DROP TRIGGER IF EXISTS trg_retention_summary_stale_event_insert ON security_events;
CREATE TRIGGER trg_retention_summary_stale_event_insert AFTER INSERT ON security_events
    REFERENCING NEW TABLE AS retention_new_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_event_rows();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_event_delete ON security_events;
CREATE TRIGGER trg_retention_summary_stale_event_delete AFTER DELETE ON security_events
    REFERENCING OLD TABLE AS retention_old_rows FOR EACH STATEMENT EXECUTE FUNCTION jjd_retention_summary_stale_event_rows();
DROP TRIGGER IF EXISTS trg_retention_summary_stale_event_update ON security_events;
CREATE TRIGGER trg_retention_summary_stale_event_update AFTER UPDATE ON security_events
    FOR EACH ROW WHEN (
        OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.event_type IS DISTINCT FROM NEW.event_type OR OLD.matched_summary IS DISTINCT FROM NEW.matched_summary)
    EXECUTE FUNCTION jjd_retention_summary_stale_event_update();

DROP TRIGGER IF EXISTS trg_retention_summary_stale_request ON request_logs;
CREATE TRIGGER trg_retention_summary_stale_request BEFORE UPDATE ON request_logs
    FOR EACH ROW WHEN (
        OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.id IS DISTINCT FROM NEW.id
        OR OLD.input_audit_result IS DISTINCT FROM NEW.input_audit_result
        OR OLD.output_audit_result IS DISTINCT FROM NEW.output_audit_result
        OR OLD.proxy_target_host IS DISTINCT FROM NEW.proxy_target_host
        OR OLD.proxy_mode IS DISTINCT FROM NEW.proxy_mode
        OR OLD.environment_scope IS DISTINCT FROM NEW.environment_scope)
    EXECUTE FUNCTION jjd_retention_summary_stale_request();

COMMIT;
