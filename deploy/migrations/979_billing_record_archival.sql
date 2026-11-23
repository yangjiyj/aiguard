-- Hide operator-deleted records without breaking accounting references.
ALTER TABLE billing_redemption_codes ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE billing_redemption_codes ADD COLUMN IF NOT EXISTS archived_by text;
ALTER TABLE internal_keys ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

-- Retain terminal states even when an older application is rolled back.
CREATE OR REPLACE FUNCTION prevent_archived_redemption_reactivation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.archived_at IS NOT NULL AND (NEW.archived_at IS DISTINCT FROM OLD.archived_at OR NEW.status IS DISTINCT FROM OLD.status) THEN
  RAISE EXCEPTION 'archived redemption is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.archived_at IS NOT NULL AND NEW.status NOT IN ('voided','redeemed') THEN
  RAISE EXCEPTION 'archived redemption must be voided or redeemed' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_redemption_archived_terminal ON billing_redemption_codes;
CREATE TRIGGER trg_redemption_archived_terminal BEFORE UPDATE OF archived_at,status ON billing_redemption_codes
 FOR EACH ROW EXECUTE FUNCTION prevent_archived_redemption_reactivation();

CREATE OR REPLACE FUNCTION prevent_deleted_key_reactivation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
  RAISE EXCEPTION 'deleted key cannot be restored' USING ERRCODE='23514';
 END IF;
 IF NEW.deleted_at IS NOT NULL AND (NEW.status<>'revoked' OR NEW.key_ciphertext IS NOT NULL) THEN
  RAISE EXCEPTION 'deleted key must remain revoked without credential material' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_internal_key_deleted_terminal ON internal_keys;
CREATE TRIGGER trg_internal_key_deleted_terminal BEFORE UPDATE OF deleted_at,status,key_ciphertext ON internal_keys
 FOR EACH ROW EXECUTE FUNCTION prevent_deleted_key_reactivation();
