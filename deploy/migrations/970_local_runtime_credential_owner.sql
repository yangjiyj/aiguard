-- An explicit credential-owner marker separates a real local IdP account
-- from a standalone CP local identity link or an enterprise OIDC identity.
ALTER TABLE user_identity_links ADD COLUMN IF NOT EXISTS local_runtime_managed BOOLEAN NOT NULL DEFAULT FALSE;
-- Existing official native-account creation and emergency demotion leave
-- durable identity-bound audit evidence. Do not infer ownership from issuer.
UPDATE user_identity_links link SET local_runtime_managed=TRUE
WHERE link.source_type='local' AND EXISTS (
 SELECT 1 FROM audit_operations audit WHERE audit.tenant_id=link.tenant_id AND audit.target_id=link.user_id
 AND ((audit.action_type='user.create' AND audit.action_detail->>'assignment_mode'='manual' AND COALESCE(audit.action_detail->>'credential_owner','native')='native')
   OR (audit.action_type='identity.department.changed' AND audit.action_detail->>'old_role'='platform_admin'
     AND audit.action_detail->>'new_role'<>'platform_admin' AND audit.action_detail->>'source_id'='admin' AND COALESCE(audit.action_detail->>'credential_owner','native')='native'))
);
