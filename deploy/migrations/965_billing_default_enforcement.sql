-- Monetary admission is unconditional for priced models. The old key is ignored.
DELETE FROM system_settings WHERE key = 'billing_budget_cutoff_enabled';
ALTER TABLE billing_usage_facts ADD COLUMN IF NOT EXISTS estimated BOOLEAN NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN billing_usage_facts.estimated IS 'Usage conservatively estimated when upstream omitted authoritative usage';

-- A read-only customer summary used to create empty wallet rows. Only
-- financially provisioned wallets participate in metering admission.
ALTER TABLE billing_wallets ADD COLUMN IF NOT EXISTS prepaid_configured BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE billing_wallets w SET prepaid_configured=TRUE WHERE NOT prepaid_configured AND (
 balance_micros<>0 OR reserved_micros<>0 OR EXISTS (
 SELECT 1 FROM billing_ledger_entries l WHERE l.wallet_id=w.id AND l.tenant_id=w.tenant_id
 AND l.event_type IN ('credit','adjustment','settle','refund')
 ));
COMMENT ON COLUMN billing_wallets.prepaid_configured IS 'Financially provisioned wallet; automatic empty read-model wallets are excluded';
