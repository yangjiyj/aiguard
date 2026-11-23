-- Gateway-visible Skill assets, immutable scanned versions and invocation facts.
-- This does not claim endpoint installation discovery or local execution control.

CREATE TABLE IF NOT EXISTS skill_assets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  canonical_name VARCHAR(255) NOT NULL,
  display_name VARCHAR(255) NOT NULL DEFAULT '',
  source_type VARCHAR(16) NOT NULL
    CHECK (source_type IN ('observed', 'uploaded')),
  source_uri TEXT NOT NULL DEFAULT '',
  publisher VARCHAR(255) NOT NULL DEFAULT '',
  admission_status VARCHAR(16) NOT NULL DEFAULT 'unverified'
    CHECK (admission_status IN ('unverified', 'approved', 'quarantined', 'revoked')),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, canonical_name, source_type)
);

CREATE TABLE IF NOT EXISTS skill_asset_versions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  declared_version VARCHAR(255) NOT NULL DEFAULT '',
  source_commit VARCHAR(255) NOT NULL DEFAULT '',
  bundle_hash VARCHAR(64) NOT NULL
    CHECK (bundle_hash ~ '^[0-9a-f]{64}$'),
  tree_hash VARCHAR(64) NOT NULL
    CHECK (tree_hash ~ '^[0-9a-f]{64}$'),
  signature_status VARCHAR(16) NOT NULL DEFAULT 'unknown'
    CHECK (signature_status IN ('unknown', 'unsigned', 'verified', 'invalid')),
  signer_identity VARCHAR(512) NOT NULL DEFAULT '',
  manifest_json JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(manifest_json) = 'object'),
  findings_json JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(findings_json) = 'array'),
  risk_level VARCHAR(16) NOT NULL DEFAULT 'low'
    CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  decision VARCHAR(16) NOT NULL DEFAULT 'confirm'
    CHECK (decision IN ('allow', 'confirm', 'block')),
  scan_status VARCHAR(16) NOT NULL DEFAULT 'completed'
    CHECK (scan_status IN ('pending', 'completed', 'failed')),
  scan_error_code VARCHAR(64) NOT NULL DEFAULT '',
  admission_status VARCHAR(16) NOT NULL DEFAULT 'unverified'
    CHECK (admission_status IN ('unverified', 'approved', 'quarantined', 'revoked')),
  approved_at TIMESTAMPTZ,
  approved_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, asset_id, id),
  UNIQUE (tenant_id, asset_id, bundle_hash),
  CONSTRAINT skill_asset_versions_tenant_asset_fk
    FOREIGN KEY (tenant_id, asset_id)
    REFERENCES skill_assets (tenant_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS skill_invocations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  asset_id TEXT,
  asset_version_id TEXT,
  request_id TEXT NOT NULL,
  session_id TEXT NOT NULL DEFAULT '',
  tool_call_id TEXT NOT NULL DEFAULT '',
  canonical_name VARCHAR(255) NOT NULL,
  declared_version VARCHAR(255) NOT NULL DEFAULT '',
  source_uri TEXT NOT NULL DEFAULT '',
  status VARCHAR(24) NOT NULL
    CHECK (status IN (
      'proposed', 'confirmed', 'blocked', 'forwarded',
      'result_observed', 'completed', 'failed'
    )),
  raw_decision VARCHAR(16) NOT NULL
    CHECK (raw_decision IN ('allow', 'audit', 'confirm', 'block')),
  effective_decision VARCHAR(16) NOT NULL
    CHECK (effective_decision IN ('allow', 'audit', 'confirm', 'block')),
  parameters_digest VARCHAR(64) NOT NULL DEFAULT ''
    CHECK (parameters_digest = '' OR parameters_digest ~ '^[0-9a-f]{64}$'),
  redacted_preview_json JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(redacted_preview_json) = 'object'),
  result_status VARCHAR(24) NOT NULL DEFAULT '',
  result_findings_json JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(result_findings_json) = 'array'),
  attribution_mode VARCHAR(16) NOT NULL DEFAULT 'explicit'
    CHECK (attribution_mode IN ('explicit', 'linked', 'inferred', 'none')),
  attribution_confidence DOUBLE PRECISION NOT NULL DEFAULT 1
    CHECK (attribution_confidence >= 0 AND attribution_confidence <= 1),
  proposed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  forwarded_at TIMESTAMPTZ,
  result_observed_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, id),
  CONSTRAINT skill_invocations_tenant_asset_fk
    FOREIGN KEY (tenant_id, asset_id)
    REFERENCES skill_assets (tenant_id, id)
    ON DELETE SET NULL,
  CONSTRAINT skill_invocations_tenant_version_fk
    FOREIGN KEY (tenant_id, asset_version_id)
    REFERENCES skill_asset_versions (tenant_id, id)
    ON DELETE SET NULL,
  CONSTRAINT skill_invocations_tenant_asset_version_fk
    FOREIGN KEY (tenant_id, asset_id, asset_version_id)
    REFERENCES skill_asset_versions (tenant_id, asset_id, id)
);

DROP INDEX IF EXISTS idx_skill_invocations_tool_call;
CREATE UNIQUE INDEX IF NOT EXISTS idx_skill_invocations_tool_call
  ON skill_invocations (tenant_id, session_id, tool_call_id)
  WHERE session_id <> '' AND tool_call_id <> '';

CREATE INDEX IF NOT EXISTS idx_skill_assets_tenant_seen
  ON skill_assets (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_skill_versions_tenant_asset
  ON skill_asset_versions (tenant_id, asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_tenant_created
  ON skill_invocations (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_tenant_session
  ON skill_invocations (tenant_id, session_id, created_at DESC)
  WHERE session_id <> '';

CREATE OR REPLACE FUNCTION reject_approved_skill_version_mutation()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.admission_status IN ('approved', 'quarantined', 'revoked') AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.asset_id IS DISTINCT FROM OLD.asset_id OR
    NEW.declared_version IS DISTINCT FROM OLD.declared_version OR
    NEW.source_commit IS DISTINCT FROM OLD.source_commit OR
    NEW.bundle_hash IS DISTINCT FROM OLD.bundle_hash OR
    NEW.tree_hash IS DISTINCT FROM OLD.tree_hash OR
    NEW.signature_status IS DISTINCT FROM OLD.signature_status OR
    NEW.signer_identity IS DISTINCT FROM OLD.signer_identity OR
    NEW.manifest_json IS DISTINCT FROM OLD.manifest_json OR
    NEW.findings_json IS DISTINCT FROM OLD.findings_json OR
    NEW.risk_level IS DISTINCT FROM OLD.risk_level OR
    NEW.decision IS DISTINCT FROM OLD.decision OR
    NEW.scan_status IS DISTINCT FROM OLD.scan_status OR
    NEW.scan_error_code IS DISTINCT FROM OLD.scan_error_code
  ) THEN
    RAISE EXCEPTION 'approved skill version content is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS skill_asset_versions_immutable ON skill_asset_versions;
CREATE TRIGGER skill_asset_versions_immutable
BEFORE UPDATE ON skill_asset_versions
FOR EACH ROW EXECUTE FUNCTION reject_approved_skill_version_mutation();

COMMENT ON TABLE skill_assets IS
  'Skill assets observed through the model gateway or submitted for scanning; not endpoint installation inventory.';
COMMENT ON TABLE skill_asset_versions IS
  'Immutable Skill definition or uploaded bundle versions with static-scan and admission facts.';
COMMENT ON TABLE skill_invocations IS
  'Gateway-observed proposed Skill calls and linked result facts; forwarded does not prove local endpoint execution.';
