-- 143_alert_list_indexes.sql
-- Bounded alert inbox pages avoid repeated scans of request_logs/body_json.

CREATE INDEX IF NOT EXISTS idx_alert_groups_tenant_disposition_last_seen
  ON alert_groups (tenant_id, disposition_class, last_seen_at DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_request_created
  ON request_logs (tenant_id, request_id, created_at DESC);
