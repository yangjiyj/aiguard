-- 061_access_retention.sql
-- 访问留存：把正向代理访问记录升级为审计合规的统一访问留存底座。

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS proxy_product VARCHAR(96),
    ADD COLUMN IF NOT EXISTS proxy_access_type VARCHAR(32) DEFAULT 'normal_public',
    ADD COLUMN IF NOT EXISTS proxy_path_template TEXT,
    ADD COLUMN IF NOT EXISTS proxy_url_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS proxy_retention_level VARCHAR(32) DEFAULT 'summary',
    ADD COLUMN IF NOT EXISTS proxy_content_retained BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_request_logs_access_retention_type
    ON request_logs (tenant_id, proxy_access_type, created_at DESC)
    WHERE proxy_mode = 'forward';

CREATE INDEX IF NOT EXISTS idx_request_logs_access_retention_hash
    ON request_logs (tenant_id, proxy_url_hash)
    WHERE proxy_mode = 'forward' AND proxy_url_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS access_content_logs (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'acl_' || substr(gen_random_uuid()::text, 1, 12),
    request_id VARCHAR(64) NOT NULL REFERENCES request_logs(request_id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    provider VARCHAR(64),
    product VARCHAR(96),
    model VARCHAR(128),
    conversation_id VARCHAR(128),
    request_content_encrypted TEXT,
    response_content_encrypted TEXT,
    request_content_redacted TEXT,
    response_content_redacted TEXT,
    file_metadata_json JSONB DEFAULT '[]',
    tool_call_metadata_json JSONB DEFAULT '[]',
    decoder_name VARCHAR(64),
    decoder_version VARCHAR(32),
    retention_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_content_logs_tenant_created
    ON access_content_logs (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_access_content_logs_request
    ON access_content_logs (request_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_content_logs_request_unique
    ON access_content_logs (request_id);

COMMENT ON COLUMN request_logs.proxy_access_type IS '访问留存分类：llm / ai_ide / normal_public / risk / unknown_ai_candidate。';
COMMENT ON COLUMN request_logs.proxy_path_template IS '普通公网访问路径摘要，不包含 query/body。';
COMMENT ON COLUMN request_logs.proxy_url_hash IS '完整 URL 哈希，用于审计复核，不保存普通公网 query 明文。';
COMMENT ON TABLE access_content_logs IS '大模型访问内容留存，仅用于按策略保留请求/响应内容与文件、工具元信息。';
