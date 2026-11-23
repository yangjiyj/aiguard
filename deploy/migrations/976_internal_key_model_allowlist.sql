-- 976: additive, rollback-compatible personal API Key model limits.
-- Empty inherits live user grants; the gateway always enforces their intersection.
ALTER TABLE internal_keys ADD COLUMN IF NOT EXISTS model_allowlist TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE internal_keys ADD CONSTRAINT internal_keys_model_allowlist_bounded
 CHECK (cardinality(model_allowlist)<=500 AND array_position(model_allowlist,NULL) IS NULL);
