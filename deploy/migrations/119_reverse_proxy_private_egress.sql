-- 119_reverse_proxy_private_egress.sql
-- Route-scoped private upstream authorization. Safe defaults preserve the existing SSRF policy.

ALTER TABLE reverse_proxy_routes
    ADD COLUMN IF NOT EXISTS allow_private_egress BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS private_egress_cidrs TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_reverse_proxy_private_egress_cidrs'
          AND conrelid = 'reverse_proxy_routes'::regclass
    ) THEN
        ALTER TABLE reverse_proxy_routes
            ADD CONSTRAINT chk_reverse_proxy_private_egress_cidrs
            CHECK (NOT allow_private_egress OR cardinality(private_egress_cidrs) > 0);
    END IF;
END
$$;

COMMENT ON COLUMN reverse_proxy_routes.allow_private_egress IS
    'Whether this route may connect to explicitly allowlisted private IP addresses';
COMMENT ON COLUMN reverse_proxy_routes.private_egress_cidrs IS
    'Canonical CIDR allowlist for private DNS results; loopback, link-local, multicast, unspecified, and metadata addresses remain blocked';
