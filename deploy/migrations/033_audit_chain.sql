-- 033_audit_chain.sql
-- WORM 审计链：链式签名防篡改 + DB 层只追加

CREATE TABLE IF NOT EXISTS audit_chain (
    seq BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    payload_json JSONB NOT NULL,
    prev_hash CHAR(64),
    payload_hash CHAR(64) NOT NULL,
    chain_hash CHAR(64) NOT NULL,
    signature VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_tenant ON audit_chain(tenant_id, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_chain_event ON audit_chain(event_type, event_id);

CREATE OR REPLACE FUNCTION audit_chain_worm() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain is WORM, % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_chain_no_update ON audit_chain;
CREATE TRIGGER audit_chain_no_update BEFORE UPDATE ON audit_chain
    FOR EACH ROW EXECUTE FUNCTION audit_chain_worm();
DROP TRIGGER IF EXISTS audit_chain_no_delete ON audit_chain;
CREATE TRIGGER audit_chain_no_delete BEFORE DELETE ON audit_chain
    FOR EACH ROW EXECUTE FUNCTION audit_chain_worm();

COMMENT ON TABLE audit_chain IS 'WORM 审计链，链式签名防篡改，DB 层禁止 UPDATE/DELETE';
