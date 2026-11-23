-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS user_model_extra_grants (
 id varchar(64) PRIMARY KEY,
 tenant_id varchar(64) NOT NULL,
 user_id varchar(64) NOT NULL,
 model varchar(256) NOT NULL CHECK (length(btrim(model))>0),
 reason text NOT NULL CHECK (length(btrim(reason))>0 AND octet_length(reason)<=2000),
 expires_at timestamptz,
 created_by varchar(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz,
 revoked_by varchar(64),
 expiry_audited_at timestamptz,
 FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE,
 CHECK (expires_at IS NULL OR expires_at>created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_model_extra_current
 ON user_model_extra_grants(tenant_id,user_id,model)
 WHERE revoked_at IS NULL AND expiry_audited_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_model_extra_expiry
 ON user_model_extra_grants(expires_at) WHERE revoked_at IS NULL AND expiry_audited_at IS NULL;
COMMENT ON TABLE user_model_extra_grants IS 'Audited personal grants may add callable tenant models outside the department';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_model_extra_grants;
-- +goose StatementEnd
