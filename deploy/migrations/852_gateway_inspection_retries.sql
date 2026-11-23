BEGIN;
CREATE TABLE IF NOT EXISTS gateway_inspection_retries (
 id text PRIMARY KEY, tenant_id text NOT NULL, request_id text NOT NULL, stage text NOT NULL CHECK(stage IN ('input','output')),
 environment_scope text NOT NULL, payload_encrypted text NOT NULL, payload_bytes bigint NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','expired')),
 attempts integer NOT NULL DEFAULT 0, lease_token text, lease_until timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT now(), last_reason text NOT NULL DEFAULT '',
 engine_build text NOT NULL DEFAULT '', semantic_revision text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours'
);
CREATE INDEX IF NOT EXISTS gateway_inspection_retries_pending ON gateway_inspection_retries(environment_scope,tenant_id,next_attempt_at) WHERE status IN ('pending','running');
CREATE INDEX IF NOT EXISTS gateway_inspection_retries_request ON gateway_inspection_retries(tenant_id,request_id,stage);
CREATE INDEX IF NOT EXISTS gateway_inspection_retries_updated ON gateway_inspection_retries(tenant_id,updated_at);
COMMIT;
