-- +goose Up
-- +goose StatementBegin

ALTER TABLE users
ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Force the bootstrap admin to rotate the default password on first login.
UPDATE users
SET must_change_password = TRUE
WHERE username = 'admin'
  AND role = 'platform_admin'
  AND password_hash = ('$2b$10$' || 'hyMP/JkdSNIIYctdZPsu2.c./RwQ/YsIPvuj0bYrPZYwhpd5gUGVu');

-- +goose StatementEnd
