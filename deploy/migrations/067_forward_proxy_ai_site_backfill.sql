-- 067_forward_proxy_ai_site_backfill.sql
-- Backfill forward-proxy rows for newly recognized Web LLM / AI IDE traffic.
-- This is intentionally metadata-only: it does not change retained request/response bodies.

UPDATE request_logs
SET
    proxy_provider = 'google',
    proxy_product = 'gemini',
    proxy_access_type = 'llm',
    proxy_endpoint_kind = 'gemini_web',
    proxy_retention_level = 'content'
WHERE COALESCE(proxy_mode, '') = 'forward'
    AND LOWER(COALESCE(proxy_target_host, '')) IN ('gemini.google.com', 'www.gemini.google.com', 'aistudio.google.com', 'notebooklm.google.com')
    AND (
        COALESCE(proxy_target_path, '') = '/'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/app%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/_/bardchatui/data/%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '%batchexecute%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '%bardfrontendservice%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '%streamgenerate%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '%/chat%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '%/prompt%'
    );

UPDATE request_logs
SET
    proxy_provider = 'tencent',
    proxy_product = 'codebuddy',
    proxy_access_type = 'ai_ide',
    proxy_endpoint_kind = 'openai_compatible',
    proxy_retention_level = 'content'
WHERE COALESCE(proxy_mode, '') = 'forward'
    AND LOWER(COALESCE(proxy_target_host, '')) = 'copilot.tencent.com'
    AND (
        LOWER(COALESCE(proxy_target_path, '')) LIKE '/v2/chat/completions%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/v1/chat/completions%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '%/chat/completions%'
    );

UPDATE request_logs
SET
    proxy_provider = 'tencent',
    proxy_product = 'codebuddy',
    proxy_access_type = 'ai_ide',
    proxy_endpoint_kind = 'coding_ai',
    proxy_retention_level = 'summary'
WHERE COALESCE(proxy_mode, '') = 'forward'
    AND LOWER(COALESCE(proxy_target_host, '')) = 'copilot.tencent.com'
    AND (
        LOWER(COALESCE(proxy_target_path, '')) LIKE '/v2/update%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/v3/config%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/v2/activity/%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/v2/report%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/v2/plugin/%'
    );

UPDATE request_logs
SET
    proxy_provider = 'microsoft',
    proxy_product = 'vscode_marketplace',
    proxy_access_type = 'ai_ide',
    proxy_endpoint_kind = 'software_update',
    proxy_retention_level = 'summary'
WHERE COALESCE(proxy_mode, '') = 'forward'
    AND (
        LOWER(COALESCE(proxy_target_host, '')) = 'main.vscode-cdn.net'
        OR LOWER(COALESCE(proxy_target_host, '')) LIKE '%.vscode-cdn.net'
        OR LOWER(COALESCE(proxy_target_host, '')) = 'marketplace.visualstudio.com'
    )
    AND (
        LOWER(COALESCE(proxy_target_path, '')) LIKE '/extensions%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/core%'
        OR LOWER(COALESCE(proxy_target_path, '')) LIKE '/items%'
    );

UPDATE access_content_logs acl
SET
    provider = NULLIF(rl.proxy_provider, ''),
    product = NULLIF(rl.proxy_product, '')
FROM request_logs rl
WHERE acl.request_id = rl.request_id
    AND acl.tenant_id = rl.tenant_id
    AND COALESCE(rl.proxy_mode, '') = 'forward'
    AND COALESCE(rl.proxy_access_type, '') IN ('llm', 'ai_ide')
    AND (NULLIF(acl.provider, '') IS NULL OR NULLIF(acl.product, '') IS NULL);
