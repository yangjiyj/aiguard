-- 113: Add upstream_model_id column to models table
-- Supports upstreams whose model id differs from the name clients use to call.
-- When non-empty, the gateway replaces the model field in the forwarded request
-- body with this value so the upstream receives the id it expects.
-- Standard OpenAI-compatible upstreams leave this NULL (zero behaviour change).

ALTER TABLE models ADD COLUMN IF NOT EXISTS upstream_model_id VARCHAR(255);
