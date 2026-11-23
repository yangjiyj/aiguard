-- 870_revoke_user_keys_on_disable.sql
-- W2.2: disabling, deleting or directory-deactivating a user must revoke every
-- internal API key owned by that user in the same transaction.
--
-- Every writer of users.status (console lifecycle, directory sync full and
-- incremental activation, user retirement on delete) goes through
-- UPDATE users SET status=..., so an AFTER UPDATE OF status trigger closes all
-- paths at once. Hard DELETE of a user already cannot leave owned keys behind
-- (internal_keys.user_id has a plain FK, so the delete fails or the key was
-- detached first by an explicit statement).
--
-- Project-level keys (user_id IS NULL) are untouched. Re-activating a user
-- does NOT restore keys (W2.2 requirement): the trigger only fires on the
-- transition away from 'active'. proxy_access_keys has no user_id column; it is
-- a tenant-level credential and is out of scope for per-user revocation.
BEGIN;

CREATE OR REPLACE FUNCTION revoke_internal_keys_for_inactive_user()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  revoked_ids text[];
BEGIN
  IF NEW.status IN ('disabled', 'deleted')
     AND OLD.status IS DISTINCT FROM NEW.status THEN
    WITH revoked AS (
      UPDATE internal_keys
      SET status = 'revoked'
      WHERE user_id = NEW.id
        AND status <> 'revoked'
      RETURNING id
    )
    SELECT array_agg(id ORDER BY id) INTO revoked_ids FROM revoked;

    IF revoked_ids IS NOT NULL THEN
      INSERT INTO audit_operations (
        id, tenant_id, user_id, action_type, action_detail, target_type, target_id, ip_address
      ) VALUES (
        'audit-key-revoke-' || md5(NEW.id || clock_timestamp()::text || random()::text),
        NEW.tenant_id,
        NULL,
        'user.keys.revoke',
        jsonb_build_object(
          'user_id', NEW.id,
          'reason', 'user_status_' || NEW.status,
          'old_status', OLD.status,
          'new_status', NEW.status,
          'key_ids', to_jsonb(revoked_ids),
          'revoked_count', cardinality(revoked_ids)
        ),
        'user',
        NEW.id,
        ''
      );
    END IF;
  END IF;
  RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS trg_users_revoke_keys_on_inactive ON users;
CREATE TRIGGER trg_users_revoke_keys_on_inactive
  AFTER UPDATE OF status ON users
  FOR EACH ROW
  EXECUTE FUNCTION revoke_internal_keys_for_inactive_user();

-- Backfill: users already disabled/deleted before this migration still own
-- active keys (the gap this workflow closes). Revoke them once, with audit.
WITH revoked AS (
  UPDATE internal_keys ik
  SET status = 'revoked'
  FROM users u
  WHERE ik.user_id = u.id
    AND u.status IN ('disabled', 'deleted')
    AND ik.status <> 'revoked'
  RETURNING ik.id, u.id AS user_id, u.tenant_id, u.status AS user_status
),
per_user AS (
  SELECT user_id, tenant_id, user_status, array_agg(id ORDER BY id) AS key_ids
  FROM revoked
  GROUP BY user_id, tenant_id, user_status
)
INSERT INTO audit_operations (
  id, tenant_id, user_id, action_type, action_detail, target_type, target_id, ip_address
)
SELECT
  'audit-key-revoke-870-' || md5(user_id),
  tenant_id,
  NULL,
  'user.keys.revoke',
  jsonb_build_object(
    'user_id', user_id,
    'reason', 'migration_870_backfill',
    'user_status', user_status,
    'key_ids', to_jsonb(key_ids),
    'revoked_count', cardinality(key_ids)
  ),
  'user',
  user_id,
  ''
FROM per_user;

COMMIT;
