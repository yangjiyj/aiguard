-- CA lifecycle: keep exactly one current root CA per tenant and stage replacements.

UPDATE ca_certificates
SET status = 'expired'
WHERE status IN ('active', 'pending')
  AND expires_at <= NOW();

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY COALESCE(tenant_id, ''), ca_type
               ORDER BY created_at DESC, id DESC
           ) AS position
    FROM ca_certificates
    WHERE status = 'active'
)
UPDATE ca_certificates AS ca
SET status = 'deprecated'
FROM ranked
WHERE ca.id = ranked.id
  AND ranked.position > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ca_certificates_one_active_root
    ON ca_certificates ((COALESCE(tenant_id, '')), ca_type)
    WHERE status = 'active';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_ca_certificates_status'
    ) THEN
        ALTER TABLE ca_certificates
            ADD CONSTRAINT chk_ca_certificates_status
            CHECK (status IN ('pending', 'active', 'deprecated', 'expired'));
    END IF;
END
$$;
