-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS user_model_policies (
 tenant_id varchar(64) NOT NULL,
 user_id varchar(64) NOT NULL,
 mode varchar(16) NOT NULL DEFAULT 'inherit' CHECK (mode IN ('inherit','allowlist')),
 model_names jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(model_names)='array'),
 version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
 updated_by varchar(64) NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id,user_id),
 FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE,
 CHECK (mode <> 'inherit' OR model_names = '[]'::jsonb)
);
COMMENT ON TABLE user_model_policies IS 'Personal model allowlists narrow the current department ceiling';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_model_policies;
-- +goose StatementEnd
