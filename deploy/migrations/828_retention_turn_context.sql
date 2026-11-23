-- Compact, content-free evidence shared by API, reverse and forward ingress.
-- Deploy before binaries that write retention_turn_context.
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS retention_turn_context JSONB NOT NULL DEFAULT '{}'::jsonb;
COMMENT ON COLUMN request_logs.retention_turn_context IS 'Versioned hashes of human occurrences and replayed replies/tool IDs; never agent completion';
