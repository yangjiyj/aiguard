BEGIN;

CREATE TABLE IF NOT EXISTS policy_suggestions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id text NOT NULL,
    source text NOT NULL CHECK (source = 'lse'),
    type text NOT NULL,
    action text NOT NULL CHECK (action IN ('block', 'alert', 'mask')),
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval', 'published', 'rejected')),
    rule_set_id text,
    rule_set_version text,
    reviewer text,
    review_note text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_suggestions_tenant_status_created
    ON policy_suggestions (tenant_id, status, created_at DESC);

COMMIT;
