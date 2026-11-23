-- T15: exact-scope agent authorization approvals and short-lived exceptions.
-- Source-only migration; apply only through the normal reviewed deployment sequence.
ALTER TABLE agentguard_confirmations
    DROP CONSTRAINT IF EXISTS agentguard_confirmations_status_check;
ALTER TABLE agentguard_confirmations
    ADD CONSTRAINT agentguard_confirmations_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'revoked'));

ALTER TABLE agentguard_confirmations
    ADD COLUMN IF NOT EXISTS agent_authorization_principal_id UUID,
    ADD COLUMN IF NOT EXISTS agent_authorization_grant_id UUID,
    ADD COLUMN IF NOT EXISTS agent_authorization_action VARCHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_resource_type VARCHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_resource_id VARCHAR(256),
    ADD COLUMN IF NOT EXISTS agent_authorization_arguments_sha256 CHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_key_sha256 CHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_approval_key_sha256 CHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_request_sha256 CHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_exception_id UUID,
    ADD COLUMN IF NOT EXISTS agent_authorization_claim_key_sha256 CHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_claim_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS agent_authorization_claimed_at TIMESTAMPTZ;

ALTER TABLE agentguard_confirmations
    DROP CONSTRAINT IF EXISTS agentguard_confirmation_agent_authorization_binding_check;
ALTER TABLE agentguard_confirmations
    ADD CONSTRAINT agentguard_confirmation_agent_authorization_binding_check CHECK (
        (
            source = 'agent_authorization'
            AND agent_authorization_principal_id IS NOT NULL
            AND agent_authorization_grant_id IS NOT NULL
            AND agent_authorization_action IS NOT NULL
            AND agent_authorization_resource_type IS NOT NULL
            AND agent_authorization_resource_id IS NOT NULL
            AND agent_authorization_arguments_sha256 IS NOT NULL
            AND agent_authorization_arguments_sha256 ~ '^[0-9a-f]{64}$'
            AND agent_authorization_key_sha256 IS NOT NULL
            AND agent_authorization_key_sha256 ~ '^[0-9a-f]{64}$'
            AND agent_authorization_approval_key_sha256 IS NOT NULL
            AND agent_authorization_approval_key_sha256 ~ '^[0-9a-f]{64}$'
            AND agent_authorization_request_sha256 IS NOT NULL
            AND agent_authorization_request_sha256 ~ '^[0-9a-f]{64}$'
            AND position('*' in agent_authorization_resource_id) = 0
            AND (
                (agent_authorization_claim_key_sha256 IS NULL AND agent_authorization_claim_id IS NULL AND agent_authorization_claimed_at IS NULL)
                OR
                (agent_authorization_claim_key_sha256 IS NOT NULL AND agent_authorization_claim_key_sha256 ~ '^[0-9a-f]{64}$' AND agent_authorization_claim_id IS NOT NULL AND agent_authorization_claimed_at IS NOT NULL)
            )
        )
        OR
        (
            source IS DISTINCT FROM 'agent_authorization'
            AND agent_authorization_principal_id IS NULL
            AND agent_authorization_grant_id IS NULL
            AND agent_authorization_action IS NULL
            AND agent_authorization_resource_type IS NULL
            AND agent_authorization_resource_id IS NULL
            AND agent_authorization_arguments_sha256 IS NULL
            AND agent_authorization_key_sha256 IS NULL
            AND agent_authorization_approval_key_sha256 IS NULL
            AND agent_authorization_request_sha256 IS NULL
            AND agent_authorization_exception_id IS NULL
            AND agent_authorization_claim_key_sha256 IS NULL
            AND agent_authorization_claim_id IS NULL
            AND agent_authorization_claimed_at IS NULL
        )
    );

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agentguard_confirmation_agent_authorization_principal_fk'
    ) THEN
        ALTER TABLE agentguard_confirmations
            ADD CONSTRAINT agentguard_confirmation_agent_authorization_principal_fk
            FOREIGN KEY (tenant_id, agent_authorization_principal_id)
            REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agentguard_confirmation_agent_authorization_grant_fk'
    ) THEN
        ALTER TABLE agentguard_confirmations
            ADD CONSTRAINT agentguard_confirmation_agent_authorization_grant_fk
            FOREIGN KEY (tenant_id, agent_authorization_principal_id, agent_authorization_grant_id)
            REFERENCES agent_authorization_grants (tenant_id, principal_id, id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_authorization_approval_idempotency
    ON agentguard_confirmations (tenant_id, agent_authorization_principal_id, agent_authorization_approval_key_sha256)
    WHERE source = 'agent_authorization';
CREATE INDEX IF NOT EXISTS idx_agent_authorization_approval_queue
    ON agentguard_confirmations (tenant_id, status, created_at DESC)
    WHERE source = 'agent_authorization';
CREATE INDEX IF NOT EXISTS idx_agent_authorization_approval_expiry
    ON agentguard_confirmations (tenant_id, expires_at, created_at)
    WHERE source = 'agent_authorization' AND status IN ('pending', 'approved');
CREATE INDEX IF NOT EXISTS idx_agent_authorization_claimed
    ON agentguard_confirmations (tenant_id, agent_authorization_principal_id, agent_authorization_claimed_at)
    WHERE source = 'agent_authorization';

CREATE TABLE IF NOT EXISTS agent_authorization_approval_exceptions (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    principal_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(256) NOT NULL,
    arguments_sha256 CHAR(64) NOT NULL CHECK (arguments_sha256 ~ '^[0-9a-f]{64}$'),
    created_by VARCHAR(64) NOT NULL,
    reason VARCHAR(512) NOT NULL CHECK (length(btrim(reason)) > 0),
    idempotency_key_sha256 CHAR(64) NOT NULL CHECK (idempotency_key_sha256 ~ '^[0-9a-f]{64}$'),
    request_sha256 CHAR(64) NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_by VARCHAR(64),
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (position('*' in resource_id) = 0),
    UNIQUE (tenant_id, principal_id, id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES agent_authorization_principals (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, principal_id, grant_id)
        REFERENCES agent_authorization_grants (tenant_id, principal_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_authorization_exception_idempotency
    ON agent_authorization_approval_exceptions (tenant_id, created_by, idempotency_key_sha256);
CREATE INDEX IF NOT EXISTS idx_agent_authorization_exception_exact_active
    ON agent_authorization_approval_exceptions
       (tenant_id, principal_id, grant_id, action, resource_type, resource_id, arguments_sha256, expires_at)
    WHERE revoked_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agentguard_confirmation_agent_authorization_exception_fk'
    ) THEN
        ALTER TABLE agentguard_confirmations
            ADD CONSTRAINT agentguard_confirmation_agent_authorization_exception_fk
            FOREIGN KEY (tenant_id, agent_authorization_principal_id, agent_authorization_exception_id)
            REFERENCES agent_authorization_approval_exceptions (tenant_id, principal_id, id);
    END IF;
END $$;
