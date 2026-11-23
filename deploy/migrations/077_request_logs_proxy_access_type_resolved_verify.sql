-- 077_request_logs_proxy_access_type_resolved_verify.sql
-- Run manually after applying 077 to confirm semantic parity and plan shape.

-- 1. Semantic parity: must return zero rows.
SELECT COUNT(*) AS mismatched_access_type_rows
FROM request_logs rl
WHERE COALESCE(rl.proxy_access_type_resolved, '') IS DISTINCT FROM CASE
    WHEN COALESCE(rl.proxy_mode, '') <> 'forward' AND COALESCE(rl.model_id, '') <> '' THEN 'llm'
    WHEN COALESCE(rl.proxy_access_type, '') <> '' THEN rl.proxy_access_type
    WHEN COALESCE(rl.proxy_provider, '') <> '' THEN 'llm'
    ELSE 'normal_public'
END;

-- 2. Hot tab plan as issued by AccessRetention when no direction filter is selected.
-- Replace :tenant_id with the production tenant.
-- Expected: Index Scan/Bitmap Index Scan using idx_request_logs_acctype_created,
-- no Seq Scan/Parallel Seq Scan on request_logs, and sub-second execution for 24h.
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    rl.request_id,
    rl.created_at,
    rl.proxy_access_type_resolved
FROM request_logs rl
WHERE rl.tenant_id = :'tenant_id'
    AND rl.proxy_access_type_resolved = 'llm'
    AND rl.created_at >= NOW() - INTERVAL '24 hours'
    AND rl.created_at <= NOW()
    AND EXISTS (
        SELECT 1
        FROM access_content_logs acl_content
        WHERE acl_content.tenant_id = rl.tenant_id
            AND acl_content.request_id = rl.request_id
            AND (
                NULLIF(BTRIM(COALESCE(acl_content.request_content_redacted, '')), '') IS NOT NULL
                OR NULLIF(BTRIM(COALESCE(acl_content.response_content_redacted, '')), '') IS NOT NULL
                OR COALESCE(acl_content.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
            )
    )
    AND COALESCE(rl.proxy_endpoint_kind, '') <> 'file'
    AND UPPER(COALESCE(rl.proxy_method, '')) NOT IN ('GET', 'HEAD', 'OPTIONS')
ORDER BY rl.created_at DESC
LIMIT 50;

-- 3. Forward-only plan should use the smaller partial index requested for the hot tab.
-- Expected: idx_request_logs_forward_acctype_created.
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    rl.request_id,
    rl.created_at,
    rl.proxy_access_type_resolved
FROM request_logs rl
WHERE rl.tenant_id = :'tenant_id'
    AND rl.proxy_mode = 'forward'
    AND rl.proxy_access_type_resolved = 'llm'
    AND rl.created_at >= NOW() - INTERVAL '7 days'
    AND rl.created_at <= NOW()
    AND EXISTS (
        SELECT 1
        FROM access_content_logs acl_content
        WHERE acl_content.tenant_id = rl.tenant_id
            AND acl_content.request_id = rl.request_id
            AND (
                NULLIF(BTRIM(COALESCE(acl_content.request_content_redacted, '')), '') IS NOT NULL
                OR NULLIF(BTRIM(COALESCE(acl_content.response_content_redacted, '')), '') IS NOT NULL
                OR COALESCE(acl_content.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
            )
    )
    AND COALESCE(rl.proxy_endpoint_kind, '') <> 'file'
    AND UPPER(COALESCE(rl.proxy_method, '')) NOT IN ('GET', 'HEAD', 'OPTIONS')
ORDER BY rl.created_at DESC
LIMIT 50;

-- 4. Seven-day comparison query for before/after evidence.
EXPLAIN (ANALYZE, BUFFERS)
SELECT
    rl.request_id,
    rl.created_at,
    rl.proxy_access_type_resolved
FROM request_logs rl
WHERE rl.tenant_id = :'tenant_id'
    AND rl.proxy_access_type_resolved = 'llm'
    AND rl.created_at >= NOW() - INTERVAL '7 days'
    AND rl.created_at <= NOW()
    AND EXISTS (
        SELECT 1
        FROM access_content_logs acl_content
        WHERE acl_content.tenant_id = rl.tenant_id
            AND acl_content.request_id = rl.request_id
            AND (
                NULLIF(BTRIM(COALESCE(acl_content.request_content_redacted, '')), '') IS NOT NULL
                OR NULLIF(BTRIM(COALESCE(acl_content.response_content_redacted, '')), '') IS NOT NULL
                OR COALESCE(acl_content.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
            )
    )
    AND COALESCE(rl.proxy_endpoint_kind, '') <> 'file'
    AND UPPER(COALESCE(rl.proxy_method, '')) NOT IN ('GET', 'HEAD', 'OPTIONS')
ORDER BY rl.created_at DESC
LIMIT 50;
