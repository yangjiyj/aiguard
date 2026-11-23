ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS agent_runtime varchar(64),
    ADD COLUMN IF NOT EXISTS agent_detection_source varchar(32),
    ADD COLUMN IF NOT EXISTS agent_detection_confidence real,
    ADD COLUMN IF NOT EXISTS evidence_run_id varchar(64),
    ADD COLUMN IF NOT EXISTS evidence_run_source varchar(64);

CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_evidence_run_created
    ON request_logs (tenant_id, evidence_run_id, created_at DESC)
    WHERE evidence_run_id IS NOT NULL;

COMMENT ON COLUMN request_logs.agent_runtime IS
    'Client runtime evidence (for example vscode/electron), separate from the AI product identity';
COMMENT ON COLUMN request_logs.agent_detection_source IS
    'Attribution source: explicit_header, client_header, user_agent, user_agent_runtime, or content';
COMMENT ON COLUMN request_logs.agent_detection_confidence IS
    'Attribution confidence in the inclusive range 0..1';
COMMENT ON COLUMN request_logs.evidence_run_id IS
    'Tenant-scoped one-way digest of an exact session/task correlation key';
COMMENT ON COLUMN request_logs.evidence_run_source IS
    'Protocol field used to derive evidence_run_id; raw correlation values are not retained';
