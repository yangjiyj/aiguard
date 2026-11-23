-- 890_three_officer_roles.sql  (W4: three-officer separation of duties)
--
-- 1) Register the two officer roles as builtin system roles.
-- 2) Map legacy console roles:
--      platform_admin -> platform_admin  (unchanged; displayed as system administrator)
--      admin          -> platform_admin  (legacy synonym, same privileges)
--    No auditor / security officer account is created automatically: the system
--    administrator creates them after upgrade (the upgrade notes say so).
-- 3) Guarantee at least one system administrator can log in after upgrade:
--    if no active platform_admin with a password exists, restore user_admin.
--
-- Idempotent: every statement can be re-run.
BEGIN;

INSERT INTO system_roles (id, name, code, description, is_builtin, is_system) VALUES
    ('role_security_officer', 'security_officer', 'security_officer', '安全保密管理员', TRUE, TRUE),
    ('role_auditor',          'auditor',          'auditor',          '审计员', TRUE, TRUE)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    is_builtin  = TRUE,
    is_system   = TRUE;

UPDATE system_roles SET description = '系统管理员' WHERE name = 'platform_admin';

-- Legacy "admin" users become system administrators. Keep an audit trail.
INSERT INTO audit_operations (id, tenant_id, user_id, action_type, action_detail, target_type, target_id, ip_address)
SELECT 'mig890_' || md5(u.id), u.tenant_id, NULL, 'role.migrated',
       jsonb_build_object('user_id', u.id, 'old_role', u.role, 'new_role', 'platform_admin', 'migration', '890'),
       'user', u.id, ''
FROM users u
WHERE u.role = 'admin'
ON CONFLICT (id) DO NOTHING;

UPDATE users SET role = 'platform_admin', updated_at = NOW() WHERE role = 'admin';
UPDATE permission_grants SET role = 'platform_admin' WHERE role = 'admin';

-- Break-glass: at least one active system administrator with a password.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM users
        WHERE role = 'platform_admin' AND status = 'active'
          AND COALESCE(password_hash, '') <> ''
    ) THEN
        UPDATE users
        SET role = 'platform_admin', status = 'active', updated_at = NOW()
        WHERE id = 'user_admin' AND COALESCE(password_hash, '') <> '';

        IF FOUND THEN
            INSERT INTO audit_operations (id, tenant_id, user_id, action_type, action_detail, target_type, target_id, ip_address)
            SELECT 'mig890_restore_user_admin', u.tenant_id, NULL, 'role.migrated',
                   jsonb_build_object('user_id', u.id, 'new_role', 'platform_admin',
                                      'reason', 'no_active_system_admin', 'migration', '890'),
                   'user', u.id, ''
            FROM users u WHERE u.id = 'user_admin'
            ON CONFLICT (id) DO NOTHING;
        ELSE
            RAISE WARNING '890: no active system administrator with a password; user_admin not restorable. Set BOOTSTRAP_ADMIN_PASSWORD to recover.';
        END IF;
    END IF;
END
$$;

COMMIT;
