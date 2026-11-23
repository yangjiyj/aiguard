-- Local Chat cookies carry this monotonic credential version. Updating a
-- password and revoking its prior version must be the same database write.
ALTER TABLE users ADD COLUMN IF NOT EXISTS local_credential_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE chat_login_tickets ADD COLUMN IF NOT EXISTS local_credential_version BIGINT NOT NULL DEFAULT 1;
