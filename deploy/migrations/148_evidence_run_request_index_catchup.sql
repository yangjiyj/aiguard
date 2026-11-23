BEGIN;

-- 146 backfills a snapshot and 147 installs the live triggers. Requests
-- committed between those two points may be absent from the read model.
-- Reconcile only missing request rows; never copy retained customer bodies.
WITH missing_requests AS MATERIALIZED (
    SELECT
        rl.id AS request_log_id,
        rl.request_id,
        rl.tenant_id,
        rl.created_at,
        COALESCE(rl.session_id, '') AS session_id,
        COALESCE(rl.evidence_run_id, '') AS raw_evidence_run_id,
        COALESCE(rl.evidence_run_source, '') AS raw_evidence_run_source,
        COALESCE(rl.agent_type, '') AS raw_agent_type,
        COALESCE(rl.agent_runtime, '') AS raw_agent_runtime,
        COALESCE(rl.agent_detection_source, '') AS raw_detection_source,
        COALESCE(rl.agent_detection_confidence, 0) AS raw_detection_confidence,
        COALESCE(rl.user_id, '') AS user_id,
        COALESCE(rl.client_id, '') AS client_id,
        COALESCE(rl.proxy_source_ip, '') AS proxy_source_ip,
        COALESCE(rl.source_ip, '') AS source_ip
    FROM request_logs rl
    WHERE NOT EXISTS (
        SELECT 1
        FROM evidence_run_request_index eri
        WHERE eri.tenant_id = rl.tenant_id
          AND eri.request_log_id = rl.id
    )
),
vscode_matches AS MATERIALIZED (
    SELECT mr.tenant_id, mr.request_log_id, TRUE AS matched
    FROM missing_requests mr
    JOIN content_logs cl
      ON cl.tenant_id = mr.tenant_id AND cl.request_id = mr.request_log_id
    WHERE mr.raw_agent_type = 'vscode'
      AND (cl.content ILIKE '%OpenAI Codex%' OR cl.content ILIKE '%Codex Desktop%')
    GROUP BY mr.tenant_id, mr.request_log_id
),
request_identity AS MATERIALIZED (
    SELECT
        mr.*,
        CASE
            WHEN mr.raw_evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN ''
            ELSE mr.raw_evidence_run_id
        END AS evidence_run_id,
        mr.raw_evidence_run_source AS evidence_run_source,
        COALESCE(acl.conversation_id, '') AS conversation_id,
        COALESCE(acl.section_id, '') AS section_id,
        CASE WHEN mr.raw_agent_type = 'vscode' AND COALESCE(vm.matched, FALSE)
            THEN 'openai-codex' ELSE mr.raw_agent_type END AS effective_agent_type,
        COALESCE(NULLIF(mr.raw_agent_runtime, ''), CASE WHEN mr.raw_agent_type = 'vscode' THEN 'vscode' ELSE '' END) AS effective_agent_runtime,
        CASE WHEN mr.raw_agent_type = 'vscode' AND COALESCE(vm.matched, FALSE)
            THEN 'content' ELSE mr.raw_detection_source END AS effective_detection_source,
        CASE WHEN mr.raw_agent_type = 'vscode' AND COALESCE(vm.matched, FALSE)
            THEN 0.98 ELSE mr.raw_detection_confidence END AS effective_detection_confidence
    FROM missing_requests mr
    LEFT JOIN vscode_matches vm
      ON vm.tenant_id = mr.tenant_id AND vm.request_log_id = mr.request_log_id
    LEFT JOIN LATERAL (
        SELECT conversation_id, section_id, request_content_redacted
        FROM access_content_logs acl_inner
        WHERE acl_inner.tenant_id = mr.tenant_id AND acl_inner.request_id = mr.request_id
        ORDER BY acl_inner.created_at DESC, acl_inner.id DESC
        LIMIT 1
    ) acl ON TRUE
),
with_titles AS MATERIALIZED (
    SELECT
        ri.*,
        md5(COALESCE(NULLIF(BTRIM(title_cl.content, '"'), ''), NULLIF(acl.request_content_redacted, ''), '')) AS title_hash,
        COALESCE((
            SELECT string_agg(
                CASE WHEN cl.role IN ('user', 'assistant')
                    THEN LEFT(cl.role, 1) || ':' || md5(COALESCE(cl.content, ''))
                    ELSE LEFT(COALESCE(cl.role, 'other'), 1) || ':' || octet_length(COALESCE(cl.content, ''))::text
                END,
                ':' ORDER BY cl.created_at, cl.id
            )
            FROM content_logs cl
            WHERE cl.tenant_id = ri.tenant_id AND cl.request_id = ri.request_log_id
        ), '') AS transcript_signature,
        COALESCE(NULLIF(ri.client_id, ''), NULLIF(ri.user_id, ''), NULLIF(ri.proxy_source_ip, ''), NULLIF(ri.source_ip, ''), ri.request_id) AS chain_principal
    FROM request_identity ri
    LEFT JOIN LATERAL (
        SELECT content
        FROM content_logs cl
        WHERE cl.tenant_id = ri.tenant_id
          AND cl.request_id = ri.request_log_id
          AND cl.role = 'user'
          AND BTRIM(cl.content) <> ''
          AND cl.content NOT LIKE '<environment_context>%'
          AND cl.content NOT LIKE '<system-reminder>%'
          AND cl.content NOT ILIKE 'the user stepped away and is coming back%'
          AND cl.content NOT ILIKE 'recap in under % words%'
          AND cl.content NOT ILIKE 'you are claude code%'
        ORDER BY cl.created_at ASC, cl.id ASC
        LIMIT 1
    ) title_cl ON TRUE
    LEFT JOIN LATERAL (
        SELECT request_content_redacted
        FROM access_content_logs acl_inner
        WHERE acl_inner.tenant_id = ri.tenant_id AND acl_inner.request_id = ri.request_id
        ORDER BY acl_inner.created_at DESC, acl_inner.id DESC
        LIMIT 1
    ) acl ON TRUE
)
INSERT INTO evidence_run_request_index (
    tenant_id, request_log_id, request_id, created_at,
    effective_agent_type, effective_agent_runtime, effective_detection_source, effective_detection_confidence,
    session_id, evidence_run_id, evidence_run_source, conversation_id, section_id,
    chain_principal, title_hash, transcript_signature, derived_chain_root, derived_chain_size,
    chain_dirty, updated_at
)
SELECT
    tenant_id,
    request_log_id,
    request_id,
    created_at,
    effective_agent_type,
    effective_agent_runtime,
    effective_detection_source,
    effective_detection_confidence,
    session_id,
    evidence_run_id,
    evidence_run_source,
    conversation_id,
    section_id,
    CASE WHEN evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
        THEN chain_principal ELSE '' END,
    CASE WHEN evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
        THEN title_hash ELSE '' END,
    CASE WHEN evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
        THEN transcript_signature ELSE '' END,
    CASE WHEN evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
        THEN request_id ELSE '' END,
    CASE WHEN evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
        THEN 1 ELSE 0 END,
    evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate'),
    NOW()
FROM with_titles
ON CONFLICT (tenant_id, request_log_id) DO NOTHING;

COMMIT;
