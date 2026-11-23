-- +goose Up
-- +goose StatementBegin
ALTER TABLE directory_sources ADD COLUMN IF NOT EXISTS ca_cert_pem text NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE directory_sources DROP COLUMN IF EXISTS ca_cert_pem;
-- +goose StatementEnd

