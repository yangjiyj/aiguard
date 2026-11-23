-- Migration 054: AgentGuard policy governance
-- Adds configurable policies, immutable versions, scoped exceptions, and confirmation tasks.

CREATE TABLE IF NOT EXISTS agentguard_policies (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    scope_type VARCHAR(32) NOT NULL,
    scope_ref VARCHAR(128) NOT NULL DEFAULT '',
    mode VARCHAR(16) NOT NULL DEFAULT 'audit',
    default_action VARCHAR(16) NOT NULL DEFAULT 'audit',
    fail_policy VARCHAR(16) NOT NULL DEFAULT 'fail_closed',
    priority INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    template_id VARCHAR(64),
    rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    behavior_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    dlp_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by VARCHAR(64),
    updated_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CHECK (mode IN ('observe', 'audit', 'strict')),
    CHECK (default_action IN ('allow', 'audit', 'confirm', 'block')),
    CHECK (fail_policy IN ('fail_open', 'fail_closed'))
);
CREATE INDEX IF NOT EXISTS idx_agentguard_policies_scope
    ON agentguard_policies(tenant_id, scope_type, scope_ref, enabled);
CREATE INDEX IF NOT EXISTS idx_agentguard_policies_template
    ON agentguard_policies(template_id);

CREATE TABLE IF NOT EXISTS agentguard_policy_versions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id VARCHAR(64) NOT NULL REFERENCES agentguard_policies(id) ON DELETE CASCADE,
    policy_version VARCHAR(64) NOT NULL,
    snapshot_json JSONB NOT NULL,
    config_hash VARCHAR(128) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, policy_version)
);
CREATE INDEX IF NOT EXISTS idx_agentguard_policy_versions_policy
    ON agentguard_policy_versions(tenant_id, policy_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agentguard_policy_versions_active
    ON agentguard_policy_versions(policy_id) WHERE active = TRUE;

CREATE TABLE IF NOT EXISTS agentguard_exceptions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_type VARCHAR(32) NOT NULL,
    scope_ref VARCHAR(128) NOT NULL DEFAULT '',
    rule_id VARCHAR(128),
    target_pattern TEXT,
    decision VARCHAR(16) NOT NULL DEFAULT 'audit',
    reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    hard_floor BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CHECK (decision IN ('allow', 'audit')),
    CHECK (hard_floor = FALSE)
);
CREATE INDEX IF NOT EXISTS idx_agentguard_exceptions_active
    ON agentguard_exceptions(tenant_id, enabled, expires_at);
CREATE INDEX IF NOT EXISTS idx_agentguard_exceptions_scope
    ON agentguard_exceptions(tenant_id, scope_type, scope_ref);

CREATE TABLE IF NOT EXISTS agentguard_confirmations (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id VARCHAR(128),
    trace_id VARCHAR(128) NOT NULL,
    tool_name VARCHAR(256) NOT NULL,
    raw_decision VARCHAR(16) NOT NULL,
    effective_decision VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    timeout_action VARCHAR(16) NOT NULL DEFAULT 'block',
    reason TEXT,
    evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resolved_by VARCHAR(64),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_note TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    CHECK (timeout_action IN ('audit', 'block'))
);
CREATE INDEX IF NOT EXISTS idx_agentguard_confirmations_tenant_status
    ON agentguard_confirmations(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentguard_confirmations_trace
    ON agentguard_confirmations(trace_id);

COMMENT ON TABLE agentguard_policies IS 'AgentGuard 策略：模式、默认动作、规则、DLP 和行为阈值';
COMMENT ON TABLE agentguard_exceptions IS 'AgentGuard 误报例外：必须有作用域、原因和过期时间，不能解除 hard floor';
COMMENT ON TABLE agentguard_confirmations IS 'AgentGuard 人工确认任务：confirm 决策的可审计处理队列';
