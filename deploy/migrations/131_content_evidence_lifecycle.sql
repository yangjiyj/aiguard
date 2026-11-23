BEGIN;

-- 仅持久化内容留证的生命周期元数据。正文仍由 access_content_logs 按期清理，
-- request_logs 不复制请求、响应或文件内容。
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS content_evidence_retention_until TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION sync_request_content_evidence_retention_until()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE request_logs
    SET content_evidence_retention_until = NEW.retention_until
    WHERE tenant_id = NEW.tenant_id
      AND request_id = NEW.request_id
      AND content_evidence_retention_until IS DISTINCT FROM NEW.retention_until;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_access_content_evidence_lifecycle ON access_content_logs;
CREATE TRIGGER trg_access_content_evidence_lifecycle
AFTER INSERT OR UPDATE OF retention_until ON access_content_logs
FOR EACH ROW
EXECUTE FUNCTION sync_request_content_evidence_retention_until();

-- Historical rows are handled by request_log_compatibility_v1 after migration
-- 835. The trigger protects concurrent and future writes immediately.

COMMIT;
