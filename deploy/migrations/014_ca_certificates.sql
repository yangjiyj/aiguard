-- 014_ca_certificates.sql
-- MITM Root CA 证书管理

CREATE TABLE IF NOT EXISTS ca_certificates (
    id VARCHAR(32) PRIMARY KEY DEFAULT 'ca_' || substr(gen_random_uuid()::text, 1, 8),
    tenant_id VARCHAR(32),
    ca_type VARCHAR(16) DEFAULT 'root',
    private_key_encrypted TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    status VARCHAR(16) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    encryption_key_id VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_ca_certificates_tenant
    ON ca_certificates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ca_certificates_status
    ON ca_certificates(status);

COMMENT ON TABLE ca_certificates IS 'MITM Root CA 证书管理';
COMMENT ON COLUMN ca_certificates.private_key_encrypted IS 'AES-256 加密的私钥 PEM';
COMMENT ON COLUMN ca_certificates.status IS 'active, deprecated, expired';

INSERT INTO system_settings (key, value) VALUES
    ('proxy_server_enabled', 'false'),
    ('proxy_default_port', '3128'),
    ('ca_validity_days', '365'),
    ('ca_auto_rotate', 'false')
ON CONFLICT (key) DO NOTHING;
