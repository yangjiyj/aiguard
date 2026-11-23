-- +goose Up
-- +goose StatementBegin
-- New ordinary departments default to the dynamic catalog.
-- Every existing department keeps its model access mode and list, including empty lists.
ALTER TABLE teams ADD COLUMN IF NOT EXISTS model_access_configured boolean NOT NULL DEFAULT false;
ALTER TABLE teams ALTER COLUMN model_access_mode SET DEFAULT 'all_active';
CREATE OR REPLACE FUNCTION jjdguard_keep_unassigned_model_scope() RETURNS trigger
 LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.system_key='unassigned' THEN
  NEW.model_access_mode='allowlist';
  NEW.model_access_configured=true;
 END IF;
 RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS trg_teams_unassigned_model_scope ON teams;
CREATE TRIGGER trg_teams_unassigned_model_scope BEFORE INSERT OR UPDATE ON teams
 FOR EACH ROW EXECUTE FUNCTION jjdguard_keep_unassigned_model_scope();
-- Existing policies are authoritative even when an empty allowlist has no audit.
-- Only new ordinary departments receive the new default; no stored mode is changed.
UPDATE teams SET model_access_configured=true WHERE NOT model_access_configured;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Do not rewrite saved department policies on rollback.
DROP TRIGGER IF EXISTS trg_teams_unassigned_model_scope ON teams;
DROP FUNCTION IF EXISTS jjdguard_keep_unassigned_model_scope();
ALTER TABLE teams ALTER COLUMN model_access_mode SET DEFAULT 'allowlist';
ALTER TABLE teams DROP COLUMN IF EXISTS model_access_configured;
-- +goose StatementEnd
