-- 118_mcp_key_scope.sql
-- Legacy empty scopes historically meant "all routes".  MCP is a new privilege and
-- must never be inherited implicitly, so empty/null rows are conservatively
-- backfilled to the existing model API capabilities only.
BEGIN;

ALTER TABLE internal_keys
  ALTER COLUMN scopes_json
  SET DEFAULT '["chat","responses","embeddings","models"]'::jsonb;

UPDATE internal_keys
SET scopes_json = '["chat","responses","embeddings","models"]'::jsonb
WHERE scopes_json IS NULL
   OR scopes_json = '[]'::jsonb;

COMMIT;
