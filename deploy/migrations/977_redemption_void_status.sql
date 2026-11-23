-- 977: permanent voiding of unused redemption codes, including after application rollback.
ALTER TABLE billing_redemption_codes DROP CONSTRAINT ck_billing_redemption_status;
ALTER TABLE billing_redemption_codes ADD CONSTRAINT ck_billing_redemption_status
 CHECK(status IN ('active','disabled','redeemed','voided'));
CREATE OR REPLACE FUNCTION prevent_redemption_void_reactivation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='voided' AND NEW.status<>'voided' THEN
  RAISE EXCEPTION 'voided redemption cannot be reactivated' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_redemption_void_terminal ON billing_redemption_codes;
CREATE TRIGGER trg_redemption_void_terminal BEFORE UPDATE OF status ON billing_redemption_codes
 FOR EACH ROW EXECUTE FUNCTION prevent_redemption_void_reactivation();
CREATE INDEX IF NOT EXISTS idx_redemption_batch_page ON billing_redemption_codes(tenant_id,label,created_at DESC,id DESC);
