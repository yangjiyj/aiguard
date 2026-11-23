-- MCP confirmations are executable once, unlike local AgentGuard confirmations.
-- Request and result material are AES-GCM ciphertext only. Invocation tombstones
-- remain after result expiry so an expired result can never become executable again.

CREATE UNIQUE INDEX IF NOT EXISTS idx_agentguard_confirmations_id_tenant
  ON agentguard_confirmations(id, tenant_id);

CREATE TABLE IF NOT EXISTS mcp_confirmation_executions (
  confirmation_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  invocation_id VARCHAR(64),
  scope_key CHAR(64),
  canonical_request_hash CHAR(64),
  principal_hash CHAR(64),
  replay_context_ciphertext TEXT NOT NULL,
  replay_context_hash CHAR(64) NOT NULL,
  tool_id VARCHAR(128) NOT NULL DEFAULT '',
  supply_chain_revision VARCHAR(128) NOT NULL DEFAULT '',
  approved_schema_hash VARCHAR(128) NOT NULL DEFAULT '',
  server_route_hash VARCHAR(128) NOT NULL DEFAULT '',
  execution_status VARCHAR(16) NOT NULL DEFAULT 'pending',
  evidence_status VARCHAR(16) NOT NULL DEFAULT 'pending',
  attempt_id VARCHAR(64),
  started_at TIMESTAMPTZ,
  gateway_claimed_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  audit_request_id VARCHAR(128),
  audit_error_code VARCHAR(64),
  tool_log_id VARCHAR(64),
  response_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_code VARCHAR(64),
  result_ciphertext TEXT,
  result_hash CHAR(64),
  result_plaintext_bytes BIGINT,
  result_http_status INTEGER,
  result_media_type VARCHAR(128),
  result_rpc_id VARCHAR(512),
  result_protocol VARCHAR(64),
  result_session_id VARCHAR(512),
  result_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (confirmation_id),
  CONSTRAINT fk_mcp_confirmation_execution_tenant
    FOREIGN KEY (confirmation_id, tenant_id)
    REFERENCES agentguard_confirmations(id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT mcp_confirmation_ciphertext_only
    CHECK (replay_context_ciphertext LIKE 'enc:v1:%'),
  CONSTRAINT mcp_confirmation_context_hash
    CHECK (replay_context_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT mcp_confirmation_scope_hashes
    CHECK ((scope_key IS NULL OR scope_key ~ '^[0-9a-f]{64}$')
       AND (canonical_request_hash IS NULL OR canonical_request_hash ~ '^[0-9a-f]{64}$')
       AND (principal_hash IS NULL OR principal_hash ~ '^[0-9a-f]{64}$')),
  CONSTRAINT mcp_confirmation_execution_status
    CHECK (execution_status IN ('pending','executing','executed','failed','unknown')),
  CONSTRAINT mcp_confirmation_evidence_status
    CHECK (evidence_status IN ('pending','complete','failed')),
  CONSTRAINT mcp_confirmation_result_ciphertext_only
    CHECK (result_ciphertext IS NULL OR result_ciphertext LIKE 'enc:v2:%'),
  CONSTRAINT mcp_confirmation_result_size
    CHECK (result_plaintext_bytes IS NULL OR (result_plaintext_bytes >= 0 AND result_plaintext_bytes <= 8388608))
);

-- ADD COLUMN keeps development databases that ran an earlier draft of 116
-- upgradeable. New production installs receive the same columns in CREATE TABLE.
ALTER TABLE mcp_confirmation_executions
  ADD COLUMN IF NOT EXISTS invocation_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS scope_key CHAR(64),
  ADD COLUMN IF NOT EXISTS canonical_request_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS principal_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS tool_id VARCHAR(128) NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS supply_chain_revision VARCHAR(128) NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS execution_status VARCHAR(16) NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS approved_schema_hash VARCHAR(128) NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS server_route_hash VARCHAR(128) NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS evidence_status VARCHAR(16) NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS audit_request_id VARCHAR(128),
  ADD COLUMN IF NOT EXISTS audit_error_code VARCHAR(64),
  ADD COLUMN IF NOT EXISTS tool_log_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS result_ciphertext TEXT,
	ADD COLUMN IF NOT EXISTS attempt_id VARCHAR(64),
	ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ,
	ADD COLUMN IF NOT EXISTS gateway_claimed_at TIMESTAMPTZ,
	ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ,
	ADD COLUMN IF NOT EXISTS response_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
	ADD COLUMN IF NOT EXISTS error_code VARCHAR(64),
	ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS result_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS result_plaintext_bytes BIGINT,
  ADD COLUMN IF NOT EXISTS result_http_status INTEGER,
  ADD COLUMN IF NOT EXISTS result_media_type VARCHAR(128),
  ADD COLUMN IF NOT EXISTS result_rpc_id VARCHAR(512),
  ADD COLUMN IF NOT EXISTS result_protocol VARCHAR(64),
  ADD COLUMN IF NOT EXISTS result_session_id VARCHAR(512),
  ADD COLUMN IF NOT EXISTS result_expires_at TIMESTAMPTZ;

-- Earlier development drafts allowed nullable identity columns. Convert them
-- into non-replayable deterministic tombstones before enforcing the v2
-- identity contract; no plaintext request material is needed for this repair.
UPDATE mcp_confirmation_executions
SET invocation_id = COALESCE(invocation_id, 'mcpinv_' || substr(md5(tenant_id || ':' || confirmation_id) || md5(confirmation_id || ':' || tenant_id), 1, 57)),
    scope_key = COALESCE(scope_key, md5('scope:' || tenant_id || ':' || confirmation_id) || md5('scope2:' || confirmation_id || ':' || tenant_id)),
    canonical_request_hash = COALESCE(canonical_request_hash, md5('request:' || tenant_id || ':' || confirmation_id) || md5('request2:' || confirmation_id || ':' || tenant_id)),
    principal_hash = COALESCE(principal_hash, md5('principal:' || tenant_id || ':' || confirmation_id) || md5('principal2:' || confirmation_id || ':' || tenant_id)),
    approved_schema_hash = CASE WHEN approved_schema_hash ~ '^[0-9a-f]{64}$' THEN approved_schema_hash ELSE md5('schema:' || tenant_id || ':' || confirmation_id) || md5('schema2:' || confirmation_id || ':' || tenant_id) END,
    server_route_hash = CASE WHEN server_route_hash ~ '^[0-9a-f]{64}$' THEN server_route_hash ELSE md5('route:' || tenant_id || ':' || confirmation_id) || md5('route2:' || confirmation_id || ':' || tenant_id) END;

UPDATE mcp_confirmation_executions
SET evidence_status='failed',
    audit_error_code=COALESCE(audit_error_code, 'legacy_evidence_unlinked')
WHERE evidence_status='complete'
  AND (audit_request_id IS NULL OR tool_log_id IS NULL);

ALTER TABLE mcp_confirmation_executions
  ALTER COLUMN invocation_id SET NOT NULL,
  ALTER COLUMN scope_key SET NOT NULL,
  ALTER COLUMN canonical_request_hash SET NOT NULL,
  ALTER COLUMN principal_hash SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='mcp_confirmation_scope_hashes'
      AND conrelid='mcp_confirmation_executions'::regclass
  ) THEN
    ALTER TABLE mcp_confirmation_executions ADD CONSTRAINT mcp_confirmation_scope_hashes
      CHECK (scope_key ~ '^[0-9a-f]{64}$'
         AND canonical_request_hash ~ '^[0-9a-f]{64}$'
         AND principal_hash ~ '^[0-9a-f]{64}$');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='mcp_confirmation_approved_hashes'
      AND conrelid='mcp_confirmation_executions'::regclass
  ) THEN
    ALTER TABLE mcp_confirmation_executions ADD CONSTRAINT mcp_confirmation_approved_hashes
      CHECK (approved_schema_hash ~ '^[0-9a-f]{64}$'
         AND server_route_hash ~ '^[0-9a-f]{64}$');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='mcp_confirmation_evidence_status'
      AND conrelid='mcp_confirmation_executions'::regclass
  ) THEN
    ALTER TABLE mcp_confirmation_executions ADD CONSTRAINT mcp_confirmation_evidence_status
      CHECK (evidence_status IN ('pending','complete','failed'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='mcp_confirmation_evidence_link'
      AND conrelid='mcp_confirmation_executions'::regclass
  ) THEN
    ALTER TABLE mcp_confirmation_executions ADD CONSTRAINT mcp_confirmation_evidence_link
      CHECK (evidence_status <> 'complete'
         OR (audit_request_id IS NOT NULL AND tool_log_id IS NOT NULL));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='mcp_confirmation_result_ciphertext_only'
      AND conrelid='mcp_confirmation_executions'::regclass
  ) THEN
    ALTER TABLE mcp_confirmation_executions ADD CONSTRAINT mcp_confirmation_result_ciphertext_only
      CHECK (result_ciphertext IS NULL OR result_ciphertext LIKE 'enc:v2:%');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='mcp_confirmation_result_size'
      AND conrelid='mcp_confirmation_executions'::regclass
  ) THEN
    ALTER TABLE mcp_confirmation_executions ADD CONSTRAINT mcp_confirmation_result_size
      CHECK (result_plaintext_bytes IS NULL OR (result_plaintext_bytes >= 0 AND result_plaintext_bytes <= 8388608));
  END IF;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_confirmation_execution_attempt
  ON mcp_confirmation_executions(attempt_id)
  WHERE attempt_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_confirmation_tenant_scope
  ON mcp_confirmation_executions(tenant_id, scope_key);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_confirmation_invocation
  ON mcp_confirmation_executions(invocation_id)
  WHERE invocation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_confirmation_execution_tenant_status
  ON mcp_confirmation_executions(tenant_id, execution_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_confirmation_evidence_status
  ON mcp_confirmation_executions(tenant_id, evidence_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_confirmation_tool_log
  ON mcp_confirmation_executions(tenant_id, tool_log_id)
  WHERE tool_log_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_confirmation_audit_request
  ON mcp_confirmation_executions(tenant_id, audit_request_id)
  WHERE audit_request_id IS NOT NULL;

COMMENT ON TABLE mcp_confirmation_executions IS
  'MCP 人工确认单单次执行及结果墓碑；unknown 和 result_expired 均不得自动重试';
