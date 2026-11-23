-- 031_request_logs_governor_fields.sql
-- saving_calculator 依赖：标记缓存命中、governor 动作类型、降级前原 model_id

-- goose Up
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN DEFAULT FALSE;
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS governor_action VARCHAR(32);
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS original_model_id VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_request_logs_cache
    ON request_logs(cache_hit) WHERE cache_hit = TRUE;
CREATE INDEX IF NOT EXISTS idx_request_logs_governor
    ON request_logs(governor_action) WHERE governor_action IS NOT NULL;

COMMENT ON COLUMN request_logs.cache_hit IS '是否命中语义缓存（saving_calculator 用）';
COMMENT ON COLUMN request_logs.governor_action IS 'governor 决策动作；NULL 表示无干预';
COMMENT ON COLUMN request_logs.original_model_id IS '降级前原始 model_id（governor_action=downgrade_model 时填）';

-- goose Down
ALTER TABLE request_logs DROP COLUMN IF EXISTS cache_hit;
ALTER TABLE request_logs DROP COLUMN IF EXISTS governor_action;
ALTER TABLE request_logs DROP COLUMN IF EXISTS original_model_id;
DROP INDEX IF EXISTS idx_request_logs_cache;
DROP INDEX IF EXISTS idx_request_logs_governor;
