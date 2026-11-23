-- Migration: 941_alert_groups_domain
-- Purpose: risk-domain dimension (content | tool | skill | mcp | access | system)
--          for alert groups, so the console alert views can slice alerts by
--          risk domain instead of reading everything under security_event.
--
-- ADD COLUMN with a constant default is metadata-only on PostgreSQL >= 11:
-- no row is rewritten. Existing groups keep 'content' until the backfill below
-- derives their domain from alert_type / body_json->>'event_type' (same rules
-- as alertDomainForSecurityEvent in internal/alert/secevent_bridge.go).

ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS domain text NOT NULL DEFAULT 'content';

CREATE INDEX IF NOT EXISTS idx_alert_groups_domain
    ON alert_groups (tenant_id, domain, last_seen_at DESC);

-- Backfill (one statement). Guarded by domain = 'content' so a re-run can never
-- clobber domains written at insert time by newer code.
UPDATE alert_groups
SET domain = CASE
    WHEN alert_type IN ('runtime_fault', 'security_mode_changed') THEN 'system'
    WHEN COALESCE(body_json->>'event_type', '') LIKE 'skill_%' THEN 'skill'
    WHEN COALESCE(body_json->>'event_type', '') LIKE 'mcp_%' THEN 'mcp'
    WHEN COALESCE(body_json->>'event_type', '') LIKE 'tool_%' THEN 'tool'
    WHEN COALESCE(body_json->>'event_type', '') IN
         ('access_denied', 'model_policy', 'quota', 'proxy_auth_denied', 'proxy_access_denied') THEN 'access'
    ELSE 'content'
END
WHERE domain = 'content';

COMMENT ON COLUMN alert_groups.domain IS
    'Risk domain of the alert group: content | tool | skill | mcp | access | system (941)';
