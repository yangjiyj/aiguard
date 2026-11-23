-- Migration 062: 内容安全（数据安全 / 文件管控）例外规则
--
-- 形态对齐 agentguard_exceptions（054），但语义不同：
--   * agentguard_exceptions.rule_id 是热路径自由字符串（非外键）；
--   * 本表 rule_id 是对 rules.id 的真实外键 —— 方案A 下例外随规则包一同编译下发，
--     control-plane 编译时需要据此判定例外是否命中"硬底线规则"。
--
-- 硬底线类规则（私钥外发 / 系统凭证路径 / 恶意脚本外发 / 云元数据地址 / 内网高危地址）
-- 不允许被任何例外绕过，三重兜底：
--   1) 编译期：control-plane 丢弃命中硬底线规则的例外（Skipped: exception_targets_hard_floor）；
--   2) 运行期：security-engine 对 hard_floor 命中的 finding 拒绝降级；
--   3) 存储层：CHECK (hard_floor = FALSE) —— 从根上杜绝把例外本身标记成"硬底线豁免"。
--
-- decision 仅允许 allow / audit：例外只能把动作降级为放行或审计留痕，
-- 不能用例外把一条规则升级成 block（升级走策略中心规则本身）。

CREATE TABLE IF NOT EXISTS content_audit_exceptions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_type VARCHAR(32) NOT NULL DEFAULT 'tenant',
    scope_ref VARCHAR(255) NOT NULL DEFAULT '',
    rule_id VARCHAR(64) REFERENCES rules(id) ON DELETE CASCADE,
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
CREATE INDEX IF NOT EXISTS idx_content_audit_exceptions_active
    ON content_audit_exceptions(tenant_id, enabled, expires_at);
CREATE INDEX IF NOT EXISTS idx_content_audit_exceptions_rule
    ON content_audit_exceptions(tenant_id, rule_id);

COMMENT ON TABLE content_audit_exceptions IS '内容安全（数据安全/文件管控）误报例外：必须有原因和过期时间，命中硬底线规则的例外会被编译期丢弃，且不能解除 hard floor';
