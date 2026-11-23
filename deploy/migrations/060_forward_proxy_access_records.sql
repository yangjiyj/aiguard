-- 060_forward_proxy_access_records.sql
-- 正向代理访问记录：在请求审计底座上补充出口代理可见性字段。

ALTER TABLE request_logs
    ALTER COLUMN project_id DROP NOT NULL;

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS proxy_mode VARCHAR(16) DEFAULT 'reverse',
    ADD COLUMN IF NOT EXISTS proxy_target_host VARCHAR(255),
    ADD COLUMN IF NOT EXISTS proxy_target_path TEXT,
    ADD COLUMN IF NOT EXISTS proxy_method VARCHAR(16),
    ADD COLUMN IF NOT EXISTS proxy_source_ip VARCHAR(64),
    ADD COLUMN IF NOT EXISTS proxy_user_agent TEXT,
    ADD COLUMN IF NOT EXISTS proxy_request_bytes BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS proxy_response_bytes BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS proxy_tls_inspected BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS proxy_provider VARCHAR(64),
    ADD COLUMN IF NOT EXISTS proxy_endpoint_kind VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_request_logs_forward_proxy_created
    ON request_logs (tenant_id, created_at DESC)
    WHERE proxy_mode = 'forward';

CREATE INDEX IF NOT EXISTS idx_request_logs_forward_proxy_target
    ON request_logs (tenant_id, proxy_target_host, created_at DESC)
    WHERE proxy_mode = 'forward';

CREATE INDEX IF NOT EXISTS idx_request_logs_forward_proxy_provider
    ON request_logs (tenant_id, proxy_provider, created_at DESC)
    WHERE proxy_mode = 'forward';

COMMENT ON COLUMN request_logs.proxy_target_host IS '正向代理访问目标域名，不复用 model_id 存储外部网站。';
COMMENT ON COLUMN request_logs.proxy_tls_inspected IS '正向代理是否完成 HTTPS 解密审计。false 时只保证域名级可见。';
