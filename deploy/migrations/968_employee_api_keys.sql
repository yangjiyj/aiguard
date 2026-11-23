-- One managed employee credential per tenant/user. Plaintext is never persisted here.
CREATE TABLE IF NOT EXISTS employee_api_keys (
 tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 key_id VARCHAR(64) NOT NULL UNIQUE REFERENCES internal_keys(id) ON DELETE CASCADE,
 department_id VARCHAR(64) NOT NULL REFERENCES teams(id),
 department_version BIGINT NOT NULL CHECK (department_version > 0),
 generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
 first_claim_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY (tenant_id,user_id)
);
