-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS user_account_merges (
 tenant_id varchar(64) NOT NULL,
 source_user_id varchar(64) NOT NULL,
 target_user_id varchar(64) NOT NULL,
 merged_by varchar(64) NOT NULL,
 choices jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,source_user_id),
 FOREIGN KEY(tenant_id,source_user_id) REFERENCES users(tenant_id,id),
 FOREIGN KEY(tenant_id,target_user_id) REFERENCES users(tenant_id,id),
 CHECK(source_user_id<>target_user_id)
);
CREATE INDEX IF NOT EXISTS idx_user_account_merge_target ON user_account_merges(tenant_id,target_user_id);
COMMENT ON TABLE user_account_merges IS 'Historical ownership attribution only; settled amounts and ledger entries are immutable';
CREATE OR REPLACE FUNCTION reject_merged_account_reactivation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='active' AND EXISTS(SELECT 1 FROM user_account_merges WHERE tenant_id=NEW.tenant_id AND source_user_id=NEW.id) THEN
  RAISE EXCEPTION 'merged account cannot be reactivated' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_reject_merged_account_reactivation ON users;
CREATE TRIGGER trg_reject_merged_account_reactivation BEFORE UPDATE OF status ON users
 FOR EACH ROW EXECUTE FUNCTION reject_merged_account_reactivation();
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_reject_merged_account_reactivation ON users;
DROP FUNCTION IF EXISTS reject_merged_account_reactivation();
DROP TABLE IF EXISTS user_account_merges;
-- +goose StatementEnd
