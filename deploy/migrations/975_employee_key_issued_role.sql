-- +goose Up
-- +goose StatementBegin
-- Old credentials have no trustworthy role snapshot: keep them invalid until a
-- signed identity explicitly uses POST ensure to rotate to a verified role.
ALTER TABLE employee_api_keys ADD COLUMN IF NOT EXISTS issued_role varchar(64) NOT NULL DEFAULT '';
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
ALTER TABLE employee_api_keys DROP COLUMN IF EXISTS issued_role;
-- +goose StatementEnd
