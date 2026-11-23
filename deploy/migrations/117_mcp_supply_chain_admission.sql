-- MCP supply-chain admission: observed and approved snapshots never share mutable state.
ALTER TABLE mcp_servers
  ADD COLUMN IF NOT EXISTS admission_status TEXT NOT NULL DEFAULT 'unverified',
  ADD COLUMN IF NOT EXISTS observed_manifest_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS approved_manifest_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approved_manifest_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS quarantine_reason TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admission_reviewed_by TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS observed_route_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approved_route_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mcp_tools
  ADD COLUMN IF NOT EXISTS admission_status TEXT NOT NULL DEFAULT 'unverified',
  ADD COLUMN IF NOT EXISTS approved_schema_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approved_schema_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS quarantine_reason TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admission_reviewed_by TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admission_reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admission_revision BIGINT NOT NULL DEFAULT 0;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='mcp_servers'::regclass AND conname='mcp_servers_admission_status_check') THEN
    ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_admission_status_check CHECK (admission_status IN ('unverified','approved','quarantined','revoked'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='mcp_tools'::regclass AND conname='mcp_tools_admission_status_check') THEN
    ALTER TABLE mcp_tools ADD CONSTRAINT mcp_tools_admission_status_check CHECK (admission_status IN ('unverified','approved','quarantined','revoked'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='mcp_servers'::regclass AND conname='mcp_servers_admission_revision_check') THEN
    ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_admission_revision_check CHECK (admission_revision >= 0);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='mcp_tools'::regclass AND conname='mcp_tools_admission_revision_check') THEN
    ALTER TABLE mcp_tools ADD CONSTRAINT mcp_tools_admission_revision_check CHECK (admission_revision >= 0);
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_servers_tenant_id_id ON mcp_servers (tenant_id,id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_tools_tenant_id_id ON mcp_tools (tenant_id,id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='mcp_tools'::regclass AND conname='mcp_tools_tenant_server_fk') THEN
    ALTER TABLE mcp_tools ADD CONSTRAINT mcp_tools_tenant_server_fk
      FOREIGN KEY (tenant_id,server_id) REFERENCES mcp_servers (tenant_id,id) ON DELETE CASCADE NOT VALID;
  END IF;
END $$;
CREATE OR REPLACE FUNCTION compute_mcp_route_hash(
  p_server_url TEXT, p_transport TEXT, p_allow_private BOOLEAN,
  p_auth_key_ref TEXT, p_auth_ciphertext TEXT
) RETURNS TEXT AS $$
  SELECT encode(sha256(convert_to(
    COALESCE(p_server_url,'') || chr(31) ||
    COALESCE(p_transport,'streamable_http') || chr(31) ||
    COALESCE(p_allow_private,FALSE)::text || chr(31) ||
    COALESCE(p_auth_key_ref,'') || chr(31) ||
    encode(sha256(convert_to(COALESCE(p_auth_ciphertext,''),'UTF8')),'hex'),
    'UTF8'
  )),'hex')
$$ LANGUAGE SQL IMMUTABLE;
CREATE OR REPLACE FUNCTION set_mcp_server_route_hash() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext);
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_mcp_server_route_hash_insert ON mcp_servers;
CREATE TRIGGER trg_mcp_server_route_hash_insert BEFORE INSERT ON mcp_servers
FOR EACH ROW EXECUTE FUNCTION set_mcp_server_route_hash();
CREATE OR REPLACE FUNCTION enforce_mcp_server_admission_transition() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext);
  IF OLD.admission_status='approved' AND ROW(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext)
     IS DISTINCT FROM ROW(OLD.server_url,OLD.transport,OLD.allow_private_egress,OLD.auth_key_ref,OLD.auth_ciphertext) THEN
    NEW.admission_status:='quarantined'; NEW.quarantine_reason:='route_binding_changed';
    NEW.quarantined_at:=now(); NEW.admission_reviewed_by:='system'; NEW.admission_reviewed_at:=now();
  ELSIF OLD.admission_status='approved' AND OLD.manifest_hash<>'' AND NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash THEN
    NEW.admission_status:='quarantined'; NEW.quarantine_reason:='rug_pull_manifest_changed';
    NEW.quarantined_at:=now(); NEW.admission_reviewed_by:='system'; NEW.admission_reviewed_at:=now();
  END IF;
  IF ROW(NEW.admission_status,NEW.approved_manifest_hash,NEW.approved_manifest_snapshot,NEW.approved_route_hash,NEW.quarantine_reason,NEW.quarantined_at,NEW.admission_reviewed_by,NEW.admission_reviewed_at)
     IS DISTINCT FROM ROW(OLD.admission_status,OLD.approved_manifest_hash,OLD.approved_manifest_snapshot,OLD.approved_route_hash,OLD.quarantine_reason,OLD.quarantined_at,OLD.admission_reviewed_by,OLD.admission_reviewed_at)
  THEN NEW.admission_revision:=OLD.admission_revision+1; ELSE NEW.admission_revision:=OLD.admission_revision; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_mcp_server_admission_transition ON mcp_servers;
CREATE TRIGGER trg_mcp_server_admission_transition BEFORE UPDATE ON mcp_servers
FOR EACH ROW EXECUTE FUNCTION enforce_mcp_server_admission_transition();
UPDATE mcp_servers SET observed_route_hash=compute_mcp_route_hash(
  server_url,transport,allow_private_egress,auth_key_ref,auth_ciphertext
);
CREATE OR REPLACE FUNCTION enforce_mcp_tool_admission_transition() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.admission_status='approved' AND OLD.schema_hash<>'' AND NEW.schema_hash IS DISTINCT FROM OLD.schema_hash THEN
    NEW.admission_status:='quarantined'; NEW.quarantine_reason:='rug_pull_schema_changed';
    NEW.quarantined_at:=now(); NEW.admission_reviewed_by:='system'; NEW.admission_reviewed_at:=now();
  END IF;
  IF ROW(NEW.admission_status,NEW.approved_schema_hash,NEW.approved_schema_snapshot,NEW.quarantine_reason,NEW.quarantined_at,NEW.admission_reviewed_by,NEW.admission_reviewed_at)
     IS DISTINCT FROM ROW(OLD.admission_status,OLD.approved_schema_hash,OLD.approved_schema_snapshot,OLD.quarantine_reason,OLD.quarantined_at,OLD.admission_reviewed_by,OLD.admission_reviewed_at)
  THEN NEW.admission_revision:=OLD.admission_revision+1; ELSE NEW.admission_revision:=OLD.admission_revision; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_mcp_tool_admission_transition ON mcp_tools;
CREATE TRIGGER trg_mcp_tool_admission_transition BEFORE UPDATE ON mcp_tools
FOR EACH ROW EXECUTE FUNCTION enforce_mcp_tool_admission_transition();
CREATE INDEX IF NOT EXISTS idx_mcp_servers_admission ON mcp_servers (tenant_id,admission_status,admission_revision);
CREATE INDEX IF NOT EXISTS idx_mcp_tools_admission ON mcp_tools (tenant_id,server_id,admission_status,removed,admission_revision);
COMMENT ON COLUMN mcp_servers.approved_manifest_snapshot IS 'Exact administrator-approved manifest; sync only changes observed_manifest_snapshot';
COMMENT ON COLUMN mcp_tools.approved_schema_snapshot IS 'Exact administrator-approved tool description and input schema';
COMMENT ON COLUMN mcp_servers.admission_revision IS 'Monotonic supply-chain admission revision';
COMMENT ON COLUMN mcp_tools.admission_revision IS 'Monotonic supply-chain admission revision';
COMMENT ON COLUMN mcp_servers.observed_route_hash IS
  'SHA-256 binding of URL, transport, private-egress flag, auth key ref, and an inner SHA-256 of ciphertext; never exposes credentials';
COMMENT ON COLUMN mcp_servers.approved_route_hash IS
  'Exact route binding approved together with the server manifest';
COMMENT ON COLUMN mcp_tools.poison_flags IS
  'Description-poison findings used by supply-chain admission; non-empty findings quarantine the exact tool snapshot';
