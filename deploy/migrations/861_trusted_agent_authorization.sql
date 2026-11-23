-- T13.dev: server-issued Agent principal credentials and unified action authorization.
-- Runtime-safe only after the deployment applies this migration in sequence.
CREATE TABLE IF NOT EXISTS agent_authorization_principals (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    credential_hash CHAR(64) NOT NULL UNIQUE,
    credential_prefix VARCHAR(8) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    credential_rotated_at TIMESTAMPTZ,
    UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_authorization_principals_tenant_created
    ON agent_authorization_principals (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_authorization_principals_active_expiry
    ON agent_authorization_principals (tenant_id, expires_at)
    WHERE status = 'active' AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS agent_authorization_grants (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    principal_id UUID NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(256) NOT NULL,
    conditions_json JSONB NOT NULL DEFAULT '{}'::JSONB
        CHECK (jsonb_typeof(conditions_json) = 'object'),
    expires_at TIMESTAMPTZ NOT NULL,
    quota_max BIGINT NOT NULL CHECK (quota_max BETWEEN 1 AND 1000000),
    quota_window_seconds INTEGER NOT NULL CHECK (quota_window_seconds BETWEEN 1 AND 86400),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, principal_id, id),
    UNIQUE (tenant_id, principal_id, action, resource_type, resource_id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_authorization_grants_lookup
    ON agent_authorization_grants (tenant_id, principal_id, action, resource_type, resource_id, expires_at);

CREATE TABLE IF NOT EXISTS agent_authorization_usage (
    tenant_id VARCHAR(64) NOT NULL,
    principal_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    used BIGINT NOT NULL CHECK (used > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, principal_id, grant_id, window_start),
    FOREIGN KEY (tenant_id, principal_id, grant_id)
        REFERENCES agent_authorization_grants (tenant_id, principal_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_authorization_requests (
    tenant_id VARCHAR(64) NOT NULL,
    principal_id UUID NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL CHECK (state IN ('pending', 'complete')),
    decision_json JSONB,
    grant_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, principal_id, idempotency_key),
    CHECK ((state = 'pending' AND decision_json IS NULL) OR (state = 'complete' AND decision_json IS NOT NULL)),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, principal_id, grant_id)
        REFERENCES agent_authorization_grants (tenant_id, principal_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_authorization_requests_expiry
    ON agent_authorization_requests (expires_at);
