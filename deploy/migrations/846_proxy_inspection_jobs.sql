BEGIN;
CREATE TABLE IF NOT EXISTS proxy_inspection_jobs (
 tenant_id text NOT NULL, request_id text NOT NULL,
 environment_scope text NOT NULL DEFAULT 'customer',
 target_host text NOT NULL, mode text NOT NULL CHECK(mode IN ('audit','enforce')),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed')),
 admission text NOT NULL DEFAULT 'waiting', inspection_version text NOT NULL DEFAULT '', total_parts integer NOT NULL CHECK(total_parts>0),
 completed_parts integer NOT NULL DEFAULT 0, payload_bytes bigint NOT NULL,
 last_claimed_at timestamptz NOT NULL DEFAULT 'epoch', last_error text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours',
 PRIMARY KEY(tenant_id,request_id)
);
CREATE TABLE IF NOT EXISTS proxy_inspection_parts (
 tenant_id text NOT NULL, request_id text NOT NULL, part_index integer NOT NULL,
 payload_encrypted text NOT NULL, result_encrypted text NOT NULL DEFAULT '',
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed')),
 attempts integer NOT NULL DEFAULT 0, lease_token text, lease_until timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT now(), last_error text NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,request_id,part_index),
 FOREIGN KEY(tenant_id,request_id) REFERENCES proxy_inspection_jobs(tenant_id,request_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_proxy_inspection_ready ON proxy_inspection_parts(next_attempt_at) WHERE status IN ('pending','running');
CREATE INDEX IF NOT EXISTS idx_proxy_inspection_expiry ON proxy_inspection_jobs(expires_at);
COMMENT ON TABLE proxy_inspection_jobs IS 'Durable bounded proxy inspection; no plaintext content, clean verdict only after every part completes';
COMMIT;
