BEGIN;

-- 1003_alert_case_dirty_triggers: 告警案件物化的变更登记（2.9.22 批次 7）。
--
-- 案件归并要用到的输入一变，就往 alert_case_dirty 记一笔，由控制面重算受影响的命中和案件：
--   * security_events 新增、删除，或归并用到的列（请求、项目、类型、级别、动作、命中摘要、主体、告警组、
--     会话键、时间）有变化：记事件；换了告警组时把旧组也记上（开发作用域折叠看整组）。
--   * request_logs 归并用到的列（时间、会话、凭据、用户、来源地址、目标、模型、主体、环境作用域）变化：记请求。
--     新增请求不用记：security_events 外键要求请求先落库。
--   * access_content_logs 新增、删除或会话编号变化，且该请求已有告警：记请求（无会话键时按留存会话归并）。
--   * audit_dispositions：事件、请求处置记对应事件/请求；案件处置记案件。
--   * alert_groups 新增、删除，或状态、测评标记、类别、类型、代表请求变化：记告警组。
--   * internal_keys 新增、删除或流量标记（traffic_class）变化：记凭据（车道看凭据标记）。
-- 触发器只追加一行队列，不做重算；告警组、请求记录上的其他高频更新不触发。
-- 回滚：deploy/migrations/rollback/1003_alert_case_dirty_triggers.sql。

-- 建删触发器要在这些表上取 SHARE ROW EXCLUSIVE（挡住写入），按写入方的先后顺序一次拿齐，避免与正在写入的请求
-- 交叉等锁；需要在停写入的维护窗口执行。
LOCK TABLE request_logs, security_events, access_content_logs, alert_groups, audit_dispositions, internal_keys
    IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_event_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT n.tenant_id, 'event', n.id FROM alert_case_new_rows n;
    ELSE
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT o.tenant_id, 'event', o.id FROM alert_case_old_rows o;
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT o.tenant_id, 'group', o.alert_group_id FROM alert_case_old_rows o WHERE o.alert_group_id IS NOT NULL;
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_event_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (NEW.tenant_id, 'event', NEW.id);
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.id IS DISTINCT FROM NEW.id THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, 'event', OLD.id);
    END IF;
    IF OLD.alert_group_id IS NOT NULL AND OLD.alert_group_id IS DISTINCT FROM NEW.alert_group_id THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, 'group', OLD.alert_group_id);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_request_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (NEW.tenant_id, 'request', NEW.request_id);
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, 'request', OLD.request_id);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_access_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT n.tenant_id, 'request', n.request_id FROM alert_case_new_rows n
        WHERE COALESCE(n.conversation_id, '') <> ''
          AND EXISTS (SELECT 1 FROM security_events se WHERE se.tenant_id = n.tenant_id AND se.request_id = n.request_id);
    ELSE
        INSERT INTO alert_case_dirty (tenant_id, kind, ref)
        SELECT DISTINCT o.tenant_id, 'request', o.request_id FROM alert_case_old_rows o
        WHERE COALESCE(o.conversation_id, '') <> ''
          AND EXISTS (SELECT 1 FROM security_events se WHERE se.tenant_id = o.tenant_id AND se.request_id = o.request_id);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_access_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (NEW.tenant_id, 'request', NEW.request_id);
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, 'request', OLD.request_id);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    kinds CONSTANT jsonb := '{"security_event":"event","request":"request","alert_case":"case"}';
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') AND kinds ? NEW.subject_type THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (NEW.tenant_id, kinds->>NEW.subject_type, NEW.subject_id);
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE') AND kinds ? OLD.subject_type THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, kinds->>OLD.subject_type, OLD.subject_id);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_group() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (NEW.tenant_id, 'group', NEW.id);
    END IF;
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.id IS DISTINCT FROM NEW.id)) THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, 'group', OLD.id);
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION jjd_alert_case_dirty_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (NEW.tenant_id, 'key', NEW.id);
    END IF;
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.id IS DISTINCT FROM NEW.id)) THEN
        INSERT INTO alert_case_dirty (tenant_id, kind, ref) VALUES (OLD.tenant_id, 'key', OLD.id);
    END IF;
    RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_insert ON security_events;
CREATE TRIGGER trg_alert_case_dirty_event_insert AFTER INSERT ON security_events
    REFERENCING NEW TABLE AS alert_case_new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION jjd_alert_case_dirty_event_rows();
DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_delete ON security_events;
CREATE TRIGGER trg_alert_case_dirty_event_delete AFTER DELETE ON security_events
    REFERENCING OLD TABLE AS alert_case_old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION jjd_alert_case_dirty_event_rows();
DROP TRIGGER IF EXISTS trg_alert_case_dirty_event_update ON security_events;
CREATE TRIGGER trg_alert_case_dirty_event_update AFTER UPDATE ON security_events
    FOR EACH ROW WHEN (
        OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.request_id IS DISTINCT FROM NEW.request_id OR OLD.project_id IS DISTINCT FROM NEW.project_id
        OR OLD.created_at IS DISTINCT FROM NEW.created_at OR OLD.event_type IS DISTINCT FROM NEW.event_type
        OR OLD.severity IS DISTINCT FROM NEW.severity OR OLD.rule_id IS DISTINCT FROM NEW.rule_id
        OR OLD.action_taken IS DISTINCT FROM NEW.action_taken OR OLD.matched_summary IS DISTINCT FROM NEW.matched_summary
        OR OLD.principal_key IS DISTINCT FROM NEW.principal_key OR OLD.alert_group_id IS DISTINCT FROM NEW.alert_group_id
        OR OLD.conversation_key IS DISTINCT FROM NEW.conversation_key)
    EXECUTE FUNCTION jjd_alert_case_dirty_event_update();

DROP TRIGGER IF EXISTS trg_alert_case_dirty_request_update ON request_logs;
CREATE TRIGGER trg_alert_case_dirty_request_update AFTER UPDATE ON request_logs
    FOR EACH ROW WHEN (
        OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.created_at IS DISTINCT FROM NEW.created_at OR OLD.session_id IS DISTINCT FROM NEW.session_id
        OR OLD.client_id IS DISTINCT FROM NEW.client_id OR OLD.user_id IS DISTINCT FROM NEW.user_id
        OR OLD.source_ip IS DISTINCT FROM NEW.source_ip OR OLD.proxy_target_host IS DISTINCT FROM NEW.proxy_target_host
        OR OLD.model_id IS DISTINCT FROM NEW.model_id OR OLD.principal_context_json IS DISTINCT FROM NEW.principal_context_json
        OR OLD.environment_scope IS DISTINCT FROM NEW.environment_scope)
    EXECUTE FUNCTION jjd_alert_case_dirty_request_update();

DROP TRIGGER IF EXISTS trg_alert_case_dirty_access_insert ON access_content_logs;
CREATE TRIGGER trg_alert_case_dirty_access_insert AFTER INSERT ON access_content_logs
    REFERENCING NEW TABLE AS alert_case_new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION jjd_alert_case_dirty_access_rows();
DROP TRIGGER IF EXISTS trg_alert_case_dirty_access_delete ON access_content_logs;
CREATE TRIGGER trg_alert_case_dirty_access_delete AFTER DELETE ON access_content_logs
    REFERENCING OLD TABLE AS alert_case_old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION jjd_alert_case_dirty_access_rows();
DROP TRIGGER IF EXISTS trg_alert_case_dirty_access_update ON access_content_logs;
CREATE TRIGGER trg_alert_case_dirty_access_update AFTER UPDATE ON access_content_logs
    FOR EACH ROW WHEN (
        OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.conversation_id IS DISTINCT FROM NEW.conversation_id OR OLD.created_at IS DISTINCT FROM NEW.created_at)
    EXECUTE FUNCTION jjd_alert_case_dirty_access_update();

DROP TRIGGER IF EXISTS trg_alert_case_dirty_disposition ON audit_dispositions;
CREATE TRIGGER trg_alert_case_dirty_disposition AFTER INSERT OR UPDATE OR DELETE ON audit_dispositions
    FOR EACH ROW EXECUTE FUNCTION jjd_alert_case_dirty_disposition();

DROP TRIGGER IF EXISTS trg_alert_case_dirty_group_insert_delete ON alert_groups;
CREATE TRIGGER trg_alert_case_dirty_group_insert_delete AFTER INSERT OR DELETE ON alert_groups
    FOR EACH ROW EXECUTE FUNCTION jjd_alert_case_dirty_group();
DROP TRIGGER IF EXISTS trg_alert_case_dirty_group_update ON alert_groups;
CREATE TRIGGER trg_alert_case_dirty_group_update AFTER UPDATE ON alert_groups
    FOR EACH ROW WHEN (
        OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.status IS DISTINCT FROM NEW.status OR OLD.is_canary IS DISTINCT FROM NEW.is_canary
        OR OLD.class_key IS DISTINCT FROM NEW.class_key OR OLD.alert_type IS DISTINCT FROM NEW.alert_type
        OR OLD.request_id IS DISTINCT FROM NEW.request_id)
    EXECUTE FUNCTION jjd_alert_case_dirty_group();

DROP TRIGGER IF EXISTS trg_alert_case_dirty_key_insert_delete ON internal_keys;
CREATE TRIGGER trg_alert_case_dirty_key_insert_delete AFTER INSERT OR DELETE ON internal_keys
    FOR EACH ROW EXECUTE FUNCTION jjd_alert_case_dirty_key();
DROP TRIGGER IF EXISTS trg_alert_case_dirty_key_update ON internal_keys;
CREATE TRIGGER trg_alert_case_dirty_key_update AFTER UPDATE ON internal_keys
    FOR EACH ROW WHEN (
        OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.traffic_class IS DISTINCT FROM NEW.traffic_class)
    EXECUTE FUNCTION jjd_alert_case_dirty_key();

COMMIT;
