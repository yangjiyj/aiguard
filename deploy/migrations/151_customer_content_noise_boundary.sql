BEGIN;

-- Version the customer-visible projection so a rule change can be applied to
-- old rows without touching the broader internal audit-retention flag.
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS customer_content_rule_version SMALLINT NOT NULL DEFAULT 0;

-- This predicate is deliberately narrower than the audit-retention superset:
-- system prompts, runtime envelopes, tool/skill material and recaps remain in
-- the audit tables but cannot make a request appear as customer正文.
CREATE OR REPLACE FUNCTION jjdguard_customer_content_text(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(BTRIM(value), '') <> ''
       AND (
           value ~* '(?is)<user_query[^>]*>[[:space:]]*.+</user_query>'
           OR NOT (
               value ~* '^[[:space:]]*<environment_context>'
               OR value ~* '^[[:space:]]*<system-reminder>'
               OR value ~* '^[[:space:]]*<skills_instructions>'
               OR value ~* '^[[:space:]]*<codex_delegation>'
               OR value ~* '^[[:space:]]*<app-context>'
               OR value ~* '^[[:space:]]*<plugins_instructions>'
               OR value ~* '^[[:space:]]*<permissions[[:space:]]+instructions>'
               OR value ~* '^[[:space:]]*<system>'
               OR value ~* '^[[:space:]]*<tool'
               OR value ~* '^[[:space:]]*<available_skills>'
               OR value ~* '^[[:space:]]*available[[:space:]]+tools:'
               OR value ~* '^[[:space:]]*system[[:space:]]+prompt:'
               OR value ~* '^[[:space:]]*available[[:space:]]+agent[[:space:]]+types'
               OR value ~* '^[[:space:]]*the user stepped away and is coming back'
               OR value ~* '^[[:space:]]*internal[[:space:]]+recap'
               OR value ~* '^[[:space:]]*recap in under [0-9]+ words'
               OR value ~* '^[[:space:]]*you are claude code'
               OR value ~* '^[[:space:]]*you are codex'
               OR value ~* '^[[:space:]]*## skills'
               OR value ~* '^[[:space:]]*## tools'
               OR value ~* '^[[:space:]]*# skills'
               OR value ~* '^[[:space:]]*# tools'
               OR value ~* '^[[:space:]]*#( recap| summary)'
           )
       );
$$;

-- Historical customer projection is owned by
-- customer_content_projection_v1.

/*
-- Superseded historical implementation retained as checksum documentation.
-- Repair prompt-cache grouping hashes without persisting plaintext. The
-- online refresh cron will rebuild derived chain roots for the dirty groups.
WITH repaired_titles AS MATERIALIZED (
    SELECT
        eri.tenant_id,
        eri.request_log_id,
        md5(COALESCE(
            NULLIF(BTRIM(title_cl.content, '"'), ''),
            NULLIF(acl.request_content_redacted, ''),
            ''
        )) AS title_hash
    FROM evidence_run_request_index eri
    JOIN request_logs rl
      ON rl.tenant_id = eri.tenant_id AND rl.id = eri.request_log_id
    LEFT JOIN LATERAL (
        SELECT content
        FROM content_logs cl
        WHERE cl.tenant_id = rl.tenant_id
          AND cl.request_id = rl.id
          AND cl.role = 'user'
          AND jjdguard_customer_content_text(cl.content)
        ORDER BY cl.created_at ASC, cl.id ASC
        LIMIT 1
    ) title_cl ON TRUE
    LEFT JOIN LATERAL (
        SELECT request_content_redacted
        FROM access_content_logs acl_inner
        WHERE acl_inner.tenant_id = rl.tenant_id
          AND acl_inner.request_id = rl.request_id
          AND jjdguard_customer_content_text(acl_inner.request_content_redacted)
        ORDER BY acl_inner.created_at ASC, acl_inner.id ASC
        LIMIT 1
    ) acl ON TRUE
    WHERE eri.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
)
UPDATE evidence_run_request_index eri
SET title_hash = repaired_titles.title_hash,
    chain_dirty = eri.chain_dirty OR eri.title_hash IS DISTINCT FROM repaired_titles.title_hash,
    updated_at = NOW()
FROM repaired_titles
WHERE eri.tenant_id = repaired_titles.tenant_id
  AND eri.request_log_id = repaired_titles.request_log_id;
*/

-- Prompt-cache title hashes are repaired by evidence_title_noise_v1 after its
-- concurrent cursor index. This expand migration never scans historical
-- request or evidence rows.

-- 149 already installed the hot-table triggers. Replace only their function:
-- new content rows must use the same title boundary as the historical repair,
-- without reinstalling triggers or taking another DDL lock on ingest tables.
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
            THEN md5(COALESCE(
                NULLIF(BTRIM(title_cl.content, '"'), ''),
                NULLIF(CASE WHEN jjdguard_customer_content_text(acl.request_content_redacted) THEN acl.request_content_redacted ELSE '' END, ''),
                ''
            ))
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
          AND jjdguard_customer_content_text(cl.content)
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
