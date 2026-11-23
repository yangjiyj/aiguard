-- Store only encrypted copies of newly generated codes; historic hashes remain intact.
ALTER TABLE billing_redemption_codes ADD COLUMN IF NOT EXISTS code_ciphertext text;
COMMENT ON COLUMN billing_redemption_codes.code_ciphertext IS 'Encrypted, tenant/id-bound redemption code; never expose in list responses';
