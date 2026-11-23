CREATE TABLE IF NOT EXISTS audit_dispositions (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'ad_' || substr(gen_random_uuid()::text, 1, 12),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_type VARCHAR(32) NOT NULL,
    subject_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    note TEXT,
    operator_id VARCHAR(64),
    operator_name VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_dispositions_subject_unique UNIQUE (tenant_id, subject_type, subject_id),
    CONSTRAINT audit_dispositions_subject_type_check CHECK (subject_type IN ('request', 'session', 'security_event', 'tool_call')),
    CONSTRAINT audit_dispositions_status_check CHECK (status IN ('open', 'resolved', 'false_positive', 'accepted', 'escalated'))
);

CREATE INDEX IF NOT EXISTS idx_audit_dispositions_tenant_status ON audit_dispositions(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_dispositions_subject ON audit_dispositions(tenant_id, subject_type, subject_id);
