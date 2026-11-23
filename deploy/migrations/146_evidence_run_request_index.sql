BEGIN;

-- Read model for customer-safe evidence grouping. It deliberately stores only
-- attribution metadata, correlation keys, and one-way transcript facts.
CREATE TABLE IF NOT EXISTS evidence_run_request_index (
    tenant_id VARCHAR(64) NOT NULL,
    request_log_id VARCHAR(64) NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
    request_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    effective_agent_type VARCHAR(64) NOT NULL DEFAULT '',
    effective_agent_runtime VARCHAR(64) NOT NULL DEFAULT '',
    effective_detection_source VARCHAR(32) NOT NULL DEFAULT '',
    effective_detection_confidence REAL NOT NULL DEFAULT 0,
    session_id VARCHAR(256) NOT NULL DEFAULT '',
    evidence_run_id VARCHAR(64) NOT NULL DEFAULT '',
    evidence_run_source VARCHAR(64) NOT NULL DEFAULT '',
    conversation_id VARCHAR(256) NOT NULL DEFAULT '',
    section_id VARCHAR(256) NOT NULL DEFAULT '',
    chain_principal VARCHAR(256) NOT NULL DEFAULT '',
    title_hash CHAR(32) NOT NULL DEFAULT '',
    transcript_signature TEXT NOT NULL DEFAULT '',
    derived_chain_root VARCHAR(64) NOT NULL DEFAULT '',
    derived_chain_size INTEGER NOT NULL DEFAULT 0 CHECK (derived_chain_size >= 0),
    chain_dirty BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_log_id)
);

WITH request_scope AS MATERIALIZED (
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
),
vscode_matches AS MATERIALIZED (
    SELECT rs.tenant_id, rs.request_log_id, TRUE AS matched
    FROM request_scope rs
    JOIN content_logs cl
      ON cl.tenant_id = rs.tenant_id AND cl.request_id = rs.request_log_id
    WHERE rs.raw_agent_type = 'vscode'
      AND (cl.content ILIKE '%OpenAI Codex%' OR cl.content ILIKE '%Codex Desktop%')
    GROUP BY rs.tenant_id, rs.request_log_id
),
request_identity AS MATERIALIZED (
    SELECT
        rs.*,
        CASE
            WHEN rs.raw_evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN ''
            ELSE rs.raw_evidence_run_id
        END AS evidence_run_id,
        rs.raw_evidence_run_source AS evidence_run_source,
        COALESCE(acl.conversation_id, '') AS conversation_id,
        COALESCE(acl.section_id, '') AS section_id,
        CASE WHEN rs.raw_agent_type = 'vscode' AND COALESCE(vm.matched, FALSE)
            THEN 'openai-codex' ELSE rs.raw_agent_type END AS effective_agent_type,
        COALESCE(NULLIF(rs.raw_agent_runtime, ''), CASE WHEN rs.raw_agent_type = 'vscode' THEN 'vscode' ELSE '' END) AS effective_agent_runtime,
        CASE WHEN rs.raw_agent_type = 'vscode' AND COALESCE(vm.matched, FALSE)
            THEN 'content' ELSE rs.raw_detection_source END AS effective_detection_source,
        CASE WHEN rs.raw_agent_type = 'vscode' AND COALESCE(vm.matched, FALSE)
            THEN 0.98 ELSE rs.raw_detection_confidence END AS effective_detection_confidence
    FROM request_scope rs
    LEFT JOIN vscode_matches vm
      ON vm.tenant_id = rs.tenant_id AND vm.request_log_id = rs.request_log_id
    LEFT JOIN LATERAL (
        SELECT conversation_id, section_id
        FROM access_content_logs acl_inner
        WHERE acl_inner.tenant_id = rs.tenant_id AND acl_inner.request_id = rs.request_id
        ORDER BY acl_inner.created_at DESC, acl_inner.id DESC
        LIMIT 1
    ) acl ON TRUE
),
candidate_scope AS MATERIALIZED (
    SELECT *
    FROM request_identity ri
    WHERE ri.raw_evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
      AND ri.session_id = ''
      AND ri.conversation_id = ''
      AND ri.effective_agent_type <> ''
),
candidate_chain_content AS MATERIALIZED (
    SELECT
        cs.tenant_id,
        cs.request_log_id,
        string_agg(
            CASE WHEN cl.role IN ('user', 'assistant')
                THEN LEFT(cl.role, 1) || ':' || md5(COALESCE(cl.content, ''))
                ELSE LEFT(COALESCE(cl.role, 'other'), 1) || ':' || octet_length(COALESCE(cl.content, ''))::text
            END,
            ':' ORDER BY cl.created_at, cl.id
        ) AS transcript_signature
    FROM candidate_scope cs
    JOIN content_logs cl
      ON cl.tenant_id = cs.tenant_id AND cl.request_id = cs.request_log_id
    GROUP BY cs.tenant_id, cs.request_log_id
),
candidate_titles AS MATERIALIZED (
    SELECT
        cs.tenant_id,
        cs.request_log_id,
        md5(COALESCE(NULLIF(BTRIM(title_cl.content, '"'), ''), NULLIF(acl.request_content_redacted, ''), '')) AS title_hash
    FROM candidate_scope cs
    LEFT JOIN LATERAL (
        SELECT content
        FROM content_logs cl
        WHERE cl.tenant_id = cs.tenant_id
          AND cl.request_id = cs.request_log_id
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
        WHERE acl_inner.tenant_id = cs.tenant_id AND acl_inner.request_id = cs.request_id
        ORDER BY acl_inner.created_at DESC, acl_inner.id DESC
        LIMIT 1
    ) acl ON TRUE
),
candidate_chain_base AS MATERIALIZED (
    SELECT
        cs.tenant_id,
        cs.request_log_id,
        cs.request_id,
        cs.created_at,
        cs.effective_agent_type,
        COALESCE(ct.title_hash, md5('')) AS title_hash,
        COALESCE(NULLIF(cs.client_id, ''), NULLIF(cs.user_id, ''), NULLIF(cs.proxy_source_ip, ''), NULLIF(cs.source_ip, ''), cs.request_id) AS chain_principal,
        COALESCE(cc.transcript_signature, '') AS transcript_signature
    FROM candidate_scope cs
    LEFT JOIN candidate_chain_content cc
      ON cc.tenant_id = cs.tenant_id AND cc.request_log_id = cs.request_log_id
    LEFT JOIN candidate_titles ct
      ON ct.tenant_id = cs.tenant_id AND ct.request_log_id = cs.request_log_id
),
unlinked_ordered AS (
    SELECT
        ccb.*,
        LAG(ccb.transcript_signature) OVER (
            PARTITION BY ccb.tenant_id, ccb.chain_principal, ccb.effective_agent_type, ccb.title_hash
            ORDER BY ccb.created_at, ccb.request_id
        ) AS previous_signature
    FROM candidate_chain_base ccb
),
unlinked_marked AS (
    SELECT
        uo.*,
        SUM(CASE
            WHEN COALESCE(uo.previous_signature, '') <> ''
             AND uo.transcript_signature LIKE uo.previous_signature || ':%'
            THEN 0 ELSE 1 END
        ) OVER (
            PARTITION BY uo.tenant_id, uo.chain_principal, uo.effective_agent_type, uo.title_hash
            ORDER BY uo.created_at, uo.request_id
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS chain_number
    FROM unlinked_ordered uo
),
unlinked_derived AS (
    SELECT
        um.tenant_id,
        um.request_log_id,
        FIRST_VALUE(um.request_id) OVER (
            PARTITION BY um.tenant_id, um.chain_principal, um.effective_agent_type, um.title_hash, um.chain_number
            ORDER BY um.created_at, um.request_id
        ) AS derived_chain_root,
        COUNT(*) OVER (
            PARTITION BY um.tenant_id, um.chain_principal, um.effective_agent_type, um.title_hash, um.chain_number
        ) AS derived_chain_size
    FROM unlinked_marked um
),
fingerprints AS (
    SELECT
        ri.*,
        COALESCE(ccb.chain_principal, '') AS chain_principal,
        COALESCE(ccb.title_hash, '') AS title_hash,
        COALESCE(ccb.transcript_signature, '') AS transcript_signature,
        COALESCE(ud.derived_chain_root, '') AS derived_chain_root,
        COALESCE(ud.derived_chain_size, 0) AS derived_chain_size
    FROM request_identity ri
    LEFT JOIN candidate_chain_base ccb
      ON ccb.tenant_id = ri.tenant_id AND ccb.request_log_id = ri.request_log_id
    LEFT JOIN unlinked_derived ud
      ON ud.tenant_id = ri.tenant_id AND ud.request_log_id = ri.request_log_id
)
INSERT INTO evidence_run_request_index (
    tenant_id, request_log_id, request_id, created_at,
    effective_agent_type, effective_agent_runtime, effective_detection_source, effective_detection_confidence,
    session_id, evidence_run_id, evidence_run_source, conversation_id, section_id,
    chain_principal, title_hash, transcript_signature, derived_chain_root, derived_chain_size,
    chain_dirty, updated_at
)
SELECT
    tenant_id, request_log_id, request_id, created_at,
    effective_agent_type, effective_agent_runtime, effective_detection_source, effective_detection_confidence,
    session_id, evidence_run_id, evidence_run_source, conversation_id, section_id,
    chain_principal, title_hash, transcript_signature, derived_chain_root, derived_chain_size,
    FALSE, NOW()
FROM fingerprints
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
    derived_chain_root = EXCLUDED.derived_chain_root,
    derived_chain_size = EXCLUDED.derived_chain_size,
    chain_dirty = FALSE,
    updated_at = NOW();

CREATE INDEX IF NOT EXISTS idx_evidence_run_request_index_tenant_created
    ON evidence_run_request_index (tenant_id, created_at DESC, request_log_id);
CREATE INDEX IF NOT EXISTS idx_evidence_run_request_index_tenant_agent_created
    ON evidence_run_request_index (tenant_id, effective_agent_type, created_at DESC, request_log_id);
CREATE INDEX IF NOT EXISTS idx_evidence_run_request_index_tenant_conversation
    ON evidence_run_request_index (tenant_id, conversation_id, section_id, created_at DESC)
    WHERE conversation_id <> '';
CREATE INDEX IF NOT EXISTS idx_evidence_run_request_index_dirty
    ON evidence_run_request_index (tenant_id, chain_principal, effective_agent_type, title_hash, created_at, request_id)
    WHERE chain_dirty;

COMMIT;
