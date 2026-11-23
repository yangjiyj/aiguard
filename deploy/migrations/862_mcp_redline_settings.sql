-- W1 1.11: per-tenant disposition for built-in MCP redlines.
-- No row (or action='alert') keeps the baseline behaviour: redline hits are
-- recorded as evidence only. action='block' makes the gateway block in protect
-- mode (record mode still never interrupts).
CREATE TABLE IF NOT EXISTS mcp_redline_settings (
    tenant_id  VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name  VARCHAR(64) NOT NULL,
    action     VARCHAR(16) NOT NULL DEFAULT 'alert',
    updated_by VARCHAR(64) NOT NULL DEFAULT '',
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, rule_name)
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mcp_redline_settings_action_check') THEN
    ALTER TABLE mcp_redline_settings
      ADD CONSTRAINT mcp_redline_settings_action_check CHECK (action IN ('alert','block'));
  END IF;
END
$$;

COMMENT ON TABLE mcp_redline_settings IS
  'W1 1.11: per-tenant action for built-in MCP redlines (alert=evidence only, block=block in protect mode). Missing row = alert';
