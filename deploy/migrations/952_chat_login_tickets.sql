-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS chat_login_tickets (
 ticket_hash varchar(64) PRIMARY KEY CHECK (ticket_hash ~ '^[0-9a-f]{64}$'),
 tenant_id varchar(64) NOT NULL,
 user_id varchar(64) NOT NULL,
 identity_link_id varchar(64) NOT NULL REFERENCES user_identity_links(id) ON DELETE CASCADE,
 identity_issuer text NOT NULL,
 identity_subject text NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT (now() + interval '60 seconds'),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE,
 CHECK (expires_at <= created_at + interval '60 seconds')
);
CREATE INDEX IF NOT EXISTS idx_chat_login_tickets_expiry ON chat_login_tickets(expires_at);
COMMENT ON TABLE chat_login_tickets IS 'Hash-only, single-use local Chat handoff tickets; no password or admin token';
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'chat_user';
INSERT INTO system_roles(id,name,code,description,permissions,is_builtin,is_system)
VALUES ('role_chat_user','chat_user','chat_user','普通用户（仅 Chat，无后台管理权限）','[]'::jsonb,TRUE,TRUE)
ON CONFLICT (code) DO NOTHING;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS chat_login_tickets;
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'developer';
DELETE FROM system_roles WHERE id='role_chat_user' AND code='chat_user';
-- +goose StatementEnd
