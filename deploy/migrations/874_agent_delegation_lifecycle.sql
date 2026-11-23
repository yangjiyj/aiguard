-- T22.dev: tenant-scoped delegated principals, grant ceilings, and correlated child-call investigation.
-- Apply only after migrations 861-873; this is source-only until deployment applies it.
CREATE TABLE IF NOT EXISTS agent_delegations (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parent_principal_id UUID NOT NULL,
    child_principal_id UUID NOT NULL,
    project_id VARCHAR(256) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    authorization_idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > created_at),
    CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    CHECK (parent_principal_id <> child_principal_id),
    CHECK (length(project_id) BETWEEN 1 AND 256),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, child_principal_id),
    UNIQUE (tenant_id, parent_principal_id, idempotency_key),
    UNIQUE (tenant_id, parent_principal_id, authorization_idempotency_key),
    UNIQUE (tenant_id, id, parent_principal_id, child_principal_id),
    FOREIGN KEY (tenant_id, parent_principal_id)
        REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, child_principal_id)
        REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_delegations_parent_active
    ON agent_delegations (tenant_id, parent_principal_id, created_at DESC)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_agent_delegations_expiry
    ON agent_delegations (tenant_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS agent_delegation_grants (
    tenant_id VARCHAR(64) NOT NULL,
    delegation_id UUID NOT NULL,
    parent_principal_id UUID NOT NULL,
    child_principal_id UUID NOT NULL,
    child_grant_id UUID NOT NULL,
    parent_grant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, delegation_id, child_grant_id),
    FOREIGN KEY (tenant_id, delegation_id, parent_principal_id, child_principal_id)
        REFERENCES agent_delegations (tenant_id, id, parent_principal_id, child_principal_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, child_principal_id, child_grant_id)
        REFERENCES agent_authorization_grants (tenant_id, principal_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, parent_principal_id, parent_grant_id)
        REFERENCES agent_authorization_grants (tenant_id, principal_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_delegation_grants_parent
    ON agent_delegation_grants (tenant_id, parent_principal_id, parent_grant_id);

CREATE TABLE IF NOT EXISTS agent_delegation_calls (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    delegation_id UUID NOT NULL,
    parent_principal_id UUID NOT NULL,
    child_principal_id UUID NOT NULL,
    calling_principal_id UUID NOT NULL,
    project_id VARCHAR(256) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(256) NOT NULL,
    authorization_idempotency_key VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    run_id VARCHAR(256),
    instance_id VARCHAR(256),
    tool_call_id VARCHAR(256),
    allowed BOOLEAN NOT NULL,
    reason VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (tenant_id, delegation_id, parent_principal_id, child_principal_id)
        REFERENCES agent_delegations (tenant_id, id, parent_principal_id, child_principal_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, calling_principal_id)
        REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, delegation_id, calling_principal_id,
            authorization_idempotency_key, request_hash, allowed, reason)
);
CREATE INDEX IF NOT EXISTS idx_agent_delegation_calls_investigation
    ON agent_delegation_calls (tenant_id, delegation_id, created_at DESC, id);
