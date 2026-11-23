BEGIN;

-- Trigger installation requires write-compatible locks on all hot log tables.
-- NOWAIT makes an online writer a fast, retryable deployment failure instead
-- of allowing DDL and request ingestion to deadlock.
SET LOCAL lock_timeout = '5s';
LOCK TABLE request_logs, content_logs, access_content_logs
    IN SHARE ROW EXCLUSIVE MODE NOWAIT;

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
        COALESCE(rl.agent_type, ''),
        COALESCE(NULLIF(rl.agent_runtime, ''), CASE WHEN rl.agent_type = 'vscode' THEN 'vscode' ELSE '' END),
        COALESCE(rl.agent_detection_source, ''),
        COALESCE(rl.agent_detection_confidence, 0),
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
            THEN md5(COALESCE(NULLIF(BTRIM(title_cl.content, '"'), ''), NULLIF(acl.request_content_redacted, ''), ''))
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
        SELECT content
        FROM content_logs cl
        WHERE cl.tenant_id = rl.tenant_id
          AND cl.request_id = rl.id
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
    WHERE rl.tenant_id = v_tenant_id AND rl.id = v_request_log_id
    ON CONFLICT (tenant_id, request_log_id) DO UPDATE SET
        request_id = EXCLUDED.request_id,
        created_at = EXCLUDED.created_at,
        effective_agent_type = EXCLUDED.effective_agent_type,
        effective_agent_runtime = EXCLUDED.effective_agent_runtime,
        effective_detection_source = EXCLUDED.effective_detection_source,
        effective_detection_confidence = EXCLUDED.effective_detection_confidence,
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

DROP TRIGGER IF EXISTS trg_request_logs_evidence_run_request_index ON request_logs;
CREATE TRIGGER trg_request_logs_evidence_run_request_index
AFTER INSERT OR UPDATE OF
    request_id, tenant_id, created_at, session_id, agent_type, agent_runtime,
    agent_detection_source, agent_detection_confidence, evidence_run_id, evidence_run_source,
    user_id, client_id, proxy_source_ip, source_ip
ON request_logs
FOR EACH ROW
EXECUTE FUNCTION sync_evidence_run_request_index();

DROP TRIGGER IF EXISTS trg_content_logs_evidence_run_request_index ON content_logs;
CREATE TRIGGER trg_content_logs_evidence_run_request_index
AFTER INSERT OR UPDATE OF content, role, session_id
ON content_logs
FOR EACH ROW
EXECUTE FUNCTION sync_evidence_run_request_index();

DROP TRIGGER IF EXISTS trg_access_content_logs_evidence_run_request_index ON access_content_logs;
CREATE TRIGGER trg_access_content_logs_evidence_run_request_index
AFTER INSERT OR UPDATE OF request_id, conversation_id, section_id, request_content_redacted, response_content_redacted
ON access_content_logs
FOR EACH ROW
EXECUTE FUNCTION sync_evidence_run_request_index();

COMMIT;
