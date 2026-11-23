BEGIN;

-- 回滚 987：把消息行（含去重正文）还原进单表 content_logs，派生触发器与两个函数恢复到 986 版本。
-- 执行前请确认服务已停写（迁移器在维护窗口内执行），并已同时回退到 987 之前的程序版本
-- （987 之后的控制面保留期清理、worker 回填直接访问 content_log_entries / content_logs_legacy）。

DROP TRIGGER IF EXISTS content_logs_view_insert ON content_logs;
DROP TRIGGER IF EXISTS content_logs_view_update ON content_logs;
DROP TRIGGER IF EXISTS content_logs_view_delete ON content_logs;
DROP TRIGGER IF EXISTS trg_content_log_entries_customer_content_projection ON content_log_entries;
DROP TRIGGER IF EXISTS trg_content_log_entries_evidence_run_request_index ON content_log_entries;
DROP TRIGGER IF EXISTS trg_content_logs_legacy_customer_content_projection ON content_logs_legacy;
DROP TRIGGER IF EXISTS trg_content_logs_evidence_run_request_index ON content_logs_legacy;
DROP VIEW IF EXISTS content_logs;

ALTER TABLE content_logs_legacy RENAME TO content_logs;

-- 新行写回原表（正文从正文表取回）。原表上的派生触发器在最后才恢复，避免回灌时逐行重算。
INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at, environment_scope, message_index)
SELECT e.id, e.request_id, e.tenant_id, e.user_id, e.session_id, e.role, b.content, e.tokens, e.created_at, e.environment_scope, e.message_index
FROM content_log_entries e
JOIN content_log_bodies b ON b.tenant_id = e.tenant_id AND b.content_sha256 = e.content_sha256
ON CONFLICT (id) DO NOTHING;

DROP FUNCTION IF EXISTS content_logs_view_insert();
DROP FUNCTION IF EXISTS content_logs_view_update();
DROP FUNCTION IF EXISTS content_logs_view_delete();
DROP FUNCTION IF EXISTS content_log_row_customer_projection();
DROP FUNCTION IF EXISTS content_log_body_ensure(VARCHAR, TEXT);
DROP FUNCTION IF EXISTS prune_content_log_bodies(INTEGER, TIMESTAMPTZ);
DROP TABLE IF EXISTS content_log_entries;
DROP TABLE IF EXISTS content_log_bodies;

-- 两个派生函数恢复为 986 版本（987 版本引用了已删除的表）。
CREATE OR REPLACE FUNCTION public.jjdguard_refresh_request_customer_content_projection(p_tenant_id character varying, p_request_id character varying)
 RETURNS void
 LANGUAGE plpgsql
AS $$
BEGIN
    -- Serialize sibling evidence writes before acquiring the snapshot used by
    -- the UPDATE below. One UPDATE alone can wait on the row and still evaluate
    -- its child-table EXISTS clauses against its pre-wait READ COMMITTED snapshot.
    -- NO KEY UPDATE remains compatible with the KEY SHARE locks taken by child
    -- foreign keys; FOR UPDATE here can deadlock two concurrent child inserts.
    PERFORM 1
    FROM request_logs rl
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id
    FOR NO KEY UPDATE;

    UPDATE request_logs rl
    SET has_customer_content = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND (
                      jjdguard_customer_content_text(acl.request_content_redacted)
                      OR jjdguard_customer_content_text(acl.response_content_redacted)
                      OR COALESCE(acl.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
                  )
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role IN ('user', 'assistant')
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        has_customer_request_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.request_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'user'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        has_customer_response_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.response_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'assistant'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        customer_content_rule_version = 1
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id
      -- 986：派生值不变就不写。长对话一个请求逐条插入上千条消息，
      -- 原来每插一条都把同一行 request_logs 整行重写一次。
      AND (rl.customer_content_rule_version IS DISTINCT FROM 1
        OR rl.has_customer_content IS DISTINCT FROM (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND (
                      jjdguard_customer_content_text(acl.request_content_redacted)
                      OR jjdguard_customer_content_text(acl.response_content_redacted)
                      OR COALESCE(acl.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
                  )
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role IN ('user', 'assistant')
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        )
        OR rl.has_customer_request_body IS DISTINCT FROM (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.request_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'user'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        )
        OR rl.has_customer_response_body IS DISTINCT FROM (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.response_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'assistant'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ));
END;
$$;

CREATE OR REPLACE FUNCTION public.sync_evidence_run_request_index()
 RETURNS trigger
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
          AND eri.chain_dirty IS DISTINCT FROM TRUE
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
        CASE
            WHEN LOWER(BTRIM(COALESCE(rl.agent_type, ''))) IN (
                'openai-codex', 'codex', 'codex-cli', 'openai codex'
            ) THEN 'openai-codex'
            WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
                THEN 'openai-codex'
            ELSE COALESCE(rl.agent_type, '')
        END,
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
    -- 986：所有派生列都没变时不写（原来每插一条消息都重写一次索引行）。
    ON CONFLICT (tenant_id, request_log_id) DO UPDATE SET
        request_id = EXCLUDED.request_id,
        created_at = EXCLUDED.created_at,
        effective_agent_type = CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_agent_type
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_agent_type
            ELSE EXCLUDED.effective_agent_type
        END,
        effective_agent_runtime = EXCLUDED.effective_agent_runtime,
        effective_detection_source = CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_source
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_source
            ELSE EXCLUDED.effective_detection_source
        END,
        effective_detection_confidence = CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_confidence
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
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
        updated_at = NOW()
    WHERE evidence_run_request_index.request_id IS DISTINCT FROM (EXCLUDED.request_id)
       OR evidence_run_request_index.created_at IS DISTINCT FROM (EXCLUDED.created_at)
       OR evidence_run_request_index.effective_agent_type IS DISTINCT FROM (CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_agent_type
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_agent_type
            ELSE EXCLUDED.effective_agent_type
        END)
       OR evidence_run_request_index.effective_agent_runtime IS DISTINCT FROM (EXCLUDED.effective_agent_runtime)
       OR evidence_run_request_index.effective_detection_source IS DISTINCT FROM (CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_source
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_source
            ELSE EXCLUDED.effective_detection_source
        END)
       OR evidence_run_request_index.effective_detection_confidence IS DISTINCT FROM (CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_confidence
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_confidence
            ELSE EXCLUDED.effective_detection_confidence
        END)
       OR evidence_run_request_index.session_id IS DISTINCT FROM (EXCLUDED.session_id)
       OR evidence_run_request_index.evidence_run_id IS DISTINCT FROM (EXCLUDED.evidence_run_id)
       OR evidence_run_request_index.evidence_run_source IS DISTINCT FROM (EXCLUDED.evidence_run_source)
       OR evidence_run_request_index.conversation_id IS DISTINCT FROM (EXCLUDED.conversation_id)
       OR evidence_run_request_index.section_id IS DISTINCT FROM (EXCLUDED.section_id)
       OR evidence_run_request_index.chain_principal IS DISTINCT FROM (EXCLUDED.chain_principal)
       OR evidence_run_request_index.title_hash IS DISTINCT FROM (EXCLUDED.title_hash)
       OR evidence_run_request_index.transcript_signature IS DISTINCT FROM (EXCLUDED.transcript_signature)
       OR evidence_run_request_index.chain_dirty IS DISTINCT FROM (CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN evidence_run_request_index.chain_dirty
                     OR evidence_run_request_index.transcript_signature IS DISTINCT FROM EXCLUDED.transcript_signature
                     OR evidence_run_request_index.title_hash IS DISTINCT FROM EXCLUDED.title_hash
                     OR evidence_run_request_index.effective_agent_type IS DISTINCT FROM EXCLUDED.effective_agent_type
                     OR evidence_run_request_index.chain_principal IS DISTINCT FROM EXCLUDED.chain_principal
            ELSE FALSE
        END)
       OR evidence_run_request_index.derived_chain_root IS DISTINCT FROM (CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN COALESCE(NULLIF(evidence_run_request_index.derived_chain_root, ''), EXCLUDED.request_id)
            ELSE ''
        END)
       OR evidence_run_request_index.derived_chain_size IS DISTINCT FROM (CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN GREATEST(evidence_run_request_index.derived_chain_size, 1)
            ELSE 0
        END);

    RETURN NEW;
END;
$$;

-- 987 生效期间投影与证据索引已由消息行表上的触发器维护，回灌的是同样的内容，无需重算。
CREATE TRIGGER trg_content_logs_customer_content_projection
    AFTER INSERT OR DELETE OR UPDATE OF tenant_id, request_id, role, content ON content_logs
    FOR EACH ROW EXECUTE FUNCTION refresh_request_customer_content_projection();
CREATE TRIGGER trg_content_logs_evidence_run_request_index
    AFTER INSERT OR UPDATE OF content, role, session_id ON content_logs
    FOR EACH ROW EXECUTE FUNCTION sync_evidence_run_request_index();

COMMIT;
