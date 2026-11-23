-- 077_request_logs_proxy_access_type_resolved.sql
-- 内容留证 access_type 查询提速：把查询期 CASE 物化为可索引列。
--
-- Manual execution only: CREATE INDEX CONCURRENTLY cannot run inside an
-- explicit transaction block. Apply this DDL/backfill before deploying code
-- that reads request_logs.proxy_access_type_resolved.

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS proxy_access_type_resolved VARCHAR(32) DEFAULT 'normal_public';

COMMENT ON COLUMN request_logs.proxy_access_type_resolved IS
    '访问留存查询用物化分类，按旧 CASE 规则解析：llm / ai_ide / normal_public / unknown_ai_candidate。';

UPDATE request_logs rl
SET proxy_access_type_resolved = CASE
    WHEN COALESCE(rl.proxy_mode, '') <> 'forward' AND COALESCE(rl.model_id, '') <> '' THEN 'llm'
    WHEN COALESCE(rl.proxy_access_type, '') <> '' THEN rl.proxy_access_type
    WHEN COALESCE(rl.proxy_provider, '') <> '' THEN 'llm'
    ELSE 'normal_public'
END
WHERE rl.proxy_access_type_resolved IS DISTINCT FROM CASE
    WHEN COALESCE(rl.proxy_mode, '') <> 'forward' AND COALESCE(rl.model_id, '') <> '' THEN 'llm'
    WHEN COALESCE(rl.proxy_access_type, '') <> '' THEN rl.proxy_access_type
    WHEN COALESCE(rl.proxy_provider, '') <> '' THEN 'llm'
    ELSE 'normal_public'
END;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_forward_acctype_created
    ON request_logs (tenant_id, proxy_access_type_resolved, created_at DESC)
    WHERE proxy_mode = 'forward';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_acctype_created
    ON request_logs (tenant_id, proxy_access_type_resolved, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_content_logs_tenant_request
    ON access_content_logs (tenant_id, request_id);
