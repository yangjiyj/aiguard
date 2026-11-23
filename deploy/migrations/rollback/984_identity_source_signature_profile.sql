ALTER TABLE identity_sources DROP CONSTRAINT IF EXISTS identity_sources_signature_mode_check;
ALTER TABLE identity_sources DROP COLUMN IF EXISTS skip_profile_review;
ALTER TABLE identity_sources DROP COLUMN IF EXISTS signature_mode;
