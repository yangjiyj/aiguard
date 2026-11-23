BEGIN;

-- 147 already installed the hot-table triggers. Replace only their function:
-- late content rows must use the same Codex classification as the historical
-- backfill, without taking DDL locks on the three ingest tables.
CREATE OR REPLACE FUNCTION sync_evidence_run_request_index()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_tenant_id VARCHAR(64);
    v_request_log_id VARCHAR(64);
    v_request_id VARCHAR(64);
    old_chain_principal VARCHAR(256);
    old_agent_type VARCHAR(64);
    old_title_hash CHAR(32);
    old_candidate BOOLEAN := FALSE;
    v_codex_match BOOLEAN := FALSE;
BEGIN
    IF TG_TABLE_NAME = 'request_logs' THEN
        v_tenant_id := NEW.tenant_id;
        v_request_log_id := NEW.id;
        v_request_id := NEW.request_id;
    ELSIF TG_TABLE_NAME = 'content_logs' THEN
        SELECT rl.tenant_id, rl.id, rl.request_id
        INTO v_tenant_id, v_request_log_id, v_request_id
        FROM request_logs rl
        WHERE rl.tenant_id = NEW.tenant_id AND rl.id = NEW.request_id
        LIMIT 1;
        v_codex_match := NEW.content ILIKE '%OpenAI Codex%'
            OR NEW.content ILIKE '%Codex Desktop%';
    ELSIF TG_TABLE_NAME = 'access_content_logs' THEN
        SELECT rl.tenant_id, rl.id, rl.request_id
        INTO v_tenant_id, v_request_log_id, v_request_id
        FROM request_logs rl
        WHERE rl.tenant_id = NEW.tenant_id AND rl.request_id = NEW.request_id
        LIMIT 1;
    END IF;

    IF v_request_log_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT
        eri.chain_principal,
        eri.effective_agent_type,
        eri.title_hash,
        eri.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
    INTO old_chain_principal, old_agent_type, old_title_hash, old_candidate
    FROM evidence_run_request_index eri
    WHERE eri.tenant_id = v_tenant_id AND eri.request_log_id = v_request_log_id;

    IF old_candidate THEN
        UPDATE evidence_run_request_index eri
        SET chain_dirty = TRUE, updated_at = NOW()
        WHERE eri.tenant_id = v_tenant_id
          AND eri.chain_principal = old_chain_principal
          AND eri.effective_agent_type = old_agent_type
          AND eri.title_hash = old_title_hash
          AND eri.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate');
    END IF;

    INSERT INTO evidence_run_request_index (
        tenant_id, request_log_id, request_id, created_at,
        effective_agent_type, effective_agent_runtime, effective_detection_source, effective_detection_confidence,
        session_id, evidence_run_id, evidence_run_source, conversation_id, section_id,
        chain_principal, title_hash, transcript_signature, derived_chain_root, derived_chain_size,
        chain_dirty, updated_at
    )
    SELECT
        rl.tenant_id,
        rl.id,
        rl.request_id,
        rl.created_at,
        CASE WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
            THEN 'openai-codex' ELSE COALESCE(rl.agent_type, '') END,
        COALESCE(NULLIF(rl.agent_runtime, ''), CASE WHEN rl.agent_type = 'vscode' THEN 'vscode' ELSE '' END),
        CASE WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
            THEN 'content' ELSE COALESCE(rl.agent_detection_source, '') END,
        CASE WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
            THEN 0.98 ELSE COALESCE(rl.agent_detection_confidence, 0) END,
        COALESCE(rl.session_id, ''),
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN '' ELSE COALESCE(rl.evidence_run_id, '') END,
        COALESCE(rl.evidence_run_source, ''),
        COALESCE(acl.conversation_id, ''),
        COALESCE(acl.section_id, ''),
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN COALESCE(NULLIF(rl.client_id, ''), NULLIF(rl.user_id, ''), NULLIF(rl.proxy_source_ip, ''), NULLIF(rl.source_ip, ''), rl.request_id)
            ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN md5(COALESCE(NULLIF(BTRIM(title_cl.content, '"'), ''), NULLIF(title_acl.request_content_redacted, ''), ''))
            ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN COALESCE((
                SELECT string_agg(
                    CASE WHEN cl.role IN ('user', 'assistant')
                        THEN LEFT(cl.role, 1) || ':' || md5(COALESCE(cl.content, ''))
                        ELSE LEFT(COALESCE(cl.role, 'other'), 1) || ':' || octet_length(COALESCE(cl.content, ''))::text
                    END,
                    ':' ORDER BY cl.created_at, cl.id
                )
                FROM content_logs cl
                WHERE cl.tenant_id = rl.tenant_id AND cl.request_id = rl.id
            ), '')
            ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN rl.request_id ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN 1 ELSE 0 END,
        COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate'),
        NOW()
    FROM request_logs rl
    LEFT JOIN LATERAL (
        SELECT conversation_id, section_id, request_content_redacted
        FROM access_content_logs acl_inner
        WHERE acl_inner.tenant_id = rl.tenant_id AND acl_inner.request_id = rl.request_id
        ORDER BY acl_inner.created_at DESC, acl_inner.id DESC
        LIMIT 1
    ) acl ON TRUE
    LEFT JOIN LATERAL (
        SELECT request_content_redacted
        FROM access_content_logs acl_title
        WHERE acl_title.tenant_id = rl.tenant_id
          AND acl_title.request_id = rl.request_id
          AND BTRIM(acl_title.request_content_redacted) <> ''
          AND acl_title.request_content_redacted NOT ILIKE '<environment_context>%'
          AND acl_title.request_content_redacted NOT ILIKE '<system-reminder>%'
          AND acl_title.request_content_redacted NOT ILIKE '<skills_instructions>%'
          AND acl_title.request_content_redacted NOT ILIKE '<available_skills>%'
          AND acl_title.request_content_redacted NOT ILIKE 'available tools:%'
          AND acl_title.request_content_redacted NOT ILIKE 'system prompt:%'
          AND acl_title.request_content_redacted NOT ILIKE '<codex_delegation>%'
          AND acl_title.request_content_redacted NOT ILIKE '<app-context>%'
          AND acl_title.request_content_redacted NOT ILIKE '<plugins_instructions>%'
          AND acl_title.request_content_redacted NOT ILIKE '<permissions instructions>%'
          AND acl_title.request_content_redacted NOT ILIKE '<system>%'
          AND acl_title.request_content_redacted NOT ILIKE '<tool%'
          AND acl_title.request_content_redacted NOT ILIKE 'the user stepped away and is coming back%'
          AND acl_title.request_content_redacted NOT ILIKE 'internal recap%'
          AND acl_title.request_content_redacted NOT ILIKE 'recap in under % words%'
          AND acl_title.request_content_redacted NOT ILIKE 'you are claude code%'
          AND acl_title.request_content_redacted NOT ILIKE 'you are codex%'
          AND acl_title.request_content_redacted NOT ILIKE '## skills%'
          AND acl_title.request_content_redacted NOT ILIKE '## tools%'
          AND acl_title.request_content_redacted NOT ILIKE '# skills%'
          AND acl_title.request_content_redacted NOT ILIKE '# tools%'
          AND acl_title.request_content_redacted NOT ILIKE '# recap%'
          AND acl_title.request_content_redacted NOT ILIKE '# summary%'
        ORDER BY acl_title.created_at ASC, acl_title.id ASC
        LIMIT 1
    ) title_acl ON TRUE
    LEFT JOIN LATERAL (
        SELECT content
        FROM content_logs cl
        WHERE cl.tenant_id = rl.tenant_id
          AND cl.request_id = rl.id
          AND cl.role = 'user'
          AND BTRIM(cl.content) <> ''
          AND cl.content NOT ILIKE '<environment_context>%'
          AND cl.content NOT ILIKE '<system-reminder>%'
          AND cl.content NOT ILIKE '<skills_instructions>%'
          AND cl.content NOT ILIKE '<available_skills>%'
          AND cl.content NOT ILIKE 'available tools:%'
          AND cl.content NOT ILIKE 'system prompt:%'
          AND cl.content NOT ILIKE '<codex_delegation>%'
          AND cl.content NOT ILIKE '<app-context>%'
          AND cl.content NOT ILIKE '<plugins_instructions>%'
          AND cl.content NOT ILIKE '<permissions instructions>%'
          AND cl.content NOT ILIKE '<system>%'
          AND cl.content NOT ILIKE '<tool%'
          AND cl.content NOT ILIKE 'the user stepped away and is coming back%'
          AND cl.content NOT ILIKE 'internal recap%'
          AND cl.content NOT ILIKE 'recap in under % words%'
          AND cl.content NOT ILIKE 'you are claude code%'
          AND cl.content NOT ILIKE 'you are codex%'
          AND cl.content NOT ILIKE '## skills%'
          AND cl.content NOT ILIKE '## tools%'
          AND cl.content NOT ILIKE '# skills%'
          AND cl.content NOT ILIKE '# tools%'
          AND cl.content NOT ILIKE '# recap%'
          AND cl.content NOT ILIKE '# summary%'
        ORDER BY cl.created_at ASC, cl.id ASC
        LIMIT 1
    ) title_cl ON TRUE
    WHERE rl.tenant_id = v_tenant_id AND rl.id = v_request_log_id
    ON CONFLICT (tenant_id, request_log_id) DO UPDATE SET
        request_id = EXCLUDED.request_id,
        created_at = EXCLUDED.created_at,
        effective_agent_type = CASE
            WHEN v_codex_match THEN 'openai-codex'
            WHEN evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_agent_type
            ELSE EXCLUDED.effective_agent_type
        END,
        effective_agent_runtime = EXCLUDED.effective_agent_runtime,
        effective_detection_source = CASE
            WHEN v_codex_match THEN 'content'
            WHEN evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_source
            ELSE EXCLUDED.effective_detection_source
        END,
        effective_detection_confidence = CASE
            WHEN v_codex_match THEN 0.98
            WHEN evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_confidence
            ELSE EXCLUDED.effective_detection_confidence
        END,
        session_id = EXCLUDED.session_id,
        evidence_run_id = EXCLUDED.evidence_run_id,
        evidence_run_source = EXCLUDED.evidence_run_source,
        conversation_id = EXCLUDED.conversation_id,
        section_id = EXCLUDED.section_id,
        chain_principal = EXCLUDED.chain_principal,
        title_hash = EXCLUDED.title_hash,
        transcript_signature = EXCLUDED.transcript_signature,
        chain_dirty = CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN evidence_run_request_index.chain_dirty
                     OR evidence_run_request_index.transcript_signature IS DISTINCT FROM EXCLUDED.transcript_signature
                     OR evidence_run_request_index.title_hash IS DISTINCT FROM EXCLUDED.title_hash
                     OR evidence_run_request_index.effective_agent_type IS DISTINCT FROM EXCLUDED.effective_agent_type
                     OR evidence_run_request_index.chain_principal IS DISTINCT FROM EXCLUDED.chain_principal
            ELSE FALSE
        END,
        derived_chain_root = CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN COALESCE(NULLIF(evidence_run_request_index.derived_chain_root, ''), EXCLUDED.request_id)
            ELSE ''
        END,
        derived_chain_size = CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN GREATEST(evidence_run_request_index.derived_chain_size, 1)
            ELSE 0
        END,
        updated_at = NOW();

    RETURN NEW;
END;
$$;

COMMIT;
