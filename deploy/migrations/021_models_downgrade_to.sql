-- 021_models_downgrade_to.sql
-- 加降级目标 model_id；空值 → 降级动作 fallback 为 alert

ALTER TABLE models
    ADD COLUMN IF NOT EXISTS downgrade_to VARCHAR(64) REFERENCES models(id) ON DELETE SET NULL;

COMMENT ON COLUMN models.downgrade_to IS
    '降级目标 model_id；为空时降级动作 fallback 为 alert';

CREATE INDEX IF NOT EXISTS idx_models_downgrade_to ON models(downgrade_to) WHERE downgrade_to IS NOT NULL;
