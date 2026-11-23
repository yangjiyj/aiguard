BEGIN;

-- 1009_alert_case_dirty_quarantine: 告警案件物化待重算队列的坏条目隔离与清理参数（2.9.22 批次 7）。
--
-- * alert_case_dirty_quarantine：后台消化时一批失败会逐条重试，仍失败的条目移到这里（记下错误、次数、时间），
--   不再卡住同租户的其他条目；该租户的告警读接口改走实时查询，后台每隔一段时间重试，成功后移除。
-- * alert_case_dirty 是高频插入、删除的队列表：按固定行数而不是比例触发清理和统计，避免表膨胀、计划失准。
-- 回滚：deploy/migrations/rollback/1009_alert_case_dirty_quarantine.sql。

CREATE TABLE IF NOT EXISTS alert_case_dirty_quarantine (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL,
    kind            VARCHAR(16) NOT NULL,
    ref             TEXT        NOT NULL,
    last_error      TEXT        NOT NULL DEFAULT '',
    attempts        INTEGER     NOT NULL DEFAULT 1,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT alert_case_dirty_quarantine_kind_check CHECK (kind IN ('event', 'request', 'group', 'key', 'case'))
);
CREATE INDEX IF NOT EXISTS idx_alert_case_dirty_quarantine_tenant
    ON alert_case_dirty_quarantine (tenant_id, last_failed_at);

ALTER TABLE alert_case_dirty SET (
    autovacuum_vacuum_scale_factor = 0,
    autovacuum_vacuum_threshold = 5000,
    autovacuum_vacuum_insert_scale_factor = 0,
    autovacuum_vacuum_insert_threshold = 5000,
    autovacuum_analyze_scale_factor = 0,
    autovacuum_analyze_threshold = 5000
);

COMMIT;
