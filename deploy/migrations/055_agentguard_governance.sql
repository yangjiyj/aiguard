-- Migration 055: AgentGuard false-positive governance and rollout records
-- Adds rollout tracking for scoped policy gray release. False-positive status reuses audit_dispositions.

CREATE TABLE IF NOT EXISTS agentguard_rollouts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id VARCHAR(64) NOT NULL REFERENCES agentguard_policies(id) ON DELETE CASCADE,
    scope_type VARCHAR(32) NOT NULL,
    scope_ref VARCHAR(128) NOT NULL DEFAULT '',
    rollout_mode VARCHAR(16) NOT NULL DEFAULT 'audit',
    traffic_percent INTEGER NOT NULL DEFAULT 100,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    CHECK (scope_type IN ('tenant', 'project', 'key', 'user', 'agent', 'session')),
    CHECK (rollout_mode IN ('observe', 'audit', 'strict')),
    CHECK (traffic_percent >= 1 AND traffic_percent <= 100),
    CHECK (status IN ('active', 'paused', 'completed'))
);

CREATE INDEX IF NOT EXISTS idx_agentguard_rollouts_tenant_status
    ON agentguard_rollouts(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentguard_rollouts_scope
    ON agentguard_rollouts(tenant_id, scope_type, scope_ref, status);
CREATE INDEX IF NOT EXISTS idx_agentguard_rollouts_policy
    ON agentguard_rollouts(tenant_id, policy_id);

COMMENT ON TABLE agentguard_rollouts IS 'AgentGuard 策略灰度发布记录：按应用、Key、用户、智能体或会话逐步切换治理模式';
COMMENT ON COLUMN agentguard_rollouts.traffic_percent IS '灰度比例，仅用于治理计划和模拟展示；一期不接请求热路径随机分流';
