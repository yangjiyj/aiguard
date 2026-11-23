-- Add soft overage action configuration for quota policies.
-- Phase 1 stores the action for alerts and audit only; request hot-path enforcement is deferred.

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS overage_action VARCHAR(32) NOT NULL DEFAULT 'notify';

COMMENT ON COLUMN quota_policies.overage_action IS '预算或配额超额后的配置动作；一期仅保存和告警，不在请求热路径强制执行';
