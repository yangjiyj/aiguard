-- 940_audit_chain_hash_alg.sql (W10)
-- Records the hash/HMAC algorithm used for each audit_chain row so a chain
-- can switch from SHA-256/HMAC-SHA256 to SM3/HMAC-SM3 without rewriting
-- WORM history. Existing and default rows are 'sha256-hmac'.
--
-- ADD COLUMN with a constant default is metadata-only on PostgreSQL >= 11:
-- no row is rewritten and the audit_chain_worm UPDATE trigger does not fire.
ALTER TABLE audit_chain
    ADD COLUMN IF NOT EXISTS hash_alg VARCHAR(16) NOT NULL DEFAULT 'sha256-hmac';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'audit_chain_hash_alg_known'
          AND conrelid = 'audit_chain'::regclass
    ) THEN
        ALTER TABLE audit_chain
            ADD CONSTRAINT audit_chain_hash_alg_known
            CHECK (hash_alg IN ('sha256-hmac', 'sm3-hmac'));
    END IF;
END $$;

COMMENT ON COLUMN audit_chain.hash_alg IS
    'W10: per-row chain algorithm (sha256-hmac | sm3-hmac); verification must use the recorded algorithm';
