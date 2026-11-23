-- Migration: 074_quota_policies_downgrade_model
-- Purpose: keep gateway-core governor quota cache aligned with quota_policies schema.
-- Without this column, the hot path query fails and governor falls back to fail-open.

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS downgrade_model VARCHAR(128) NOT NULL DEFAULT '';

COMMENT ON COLUMN quota_policies.downgrade_model IS
    '预算超额动作为 downgrade_model 时的目标模型 ID；为空表示不降级';
