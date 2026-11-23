-- 预置策略重新定级（policy_severity_relevel_v1）。
--
-- 按 docs/superpowers/specs/2026-11-13-site-alert-severity-design.md 附录 A 调整 44 条预置策略的
-- 基准级别。只改 rules.severity，且只在当前值仍等于旧级别时改（不覆盖人工调整）；
-- 处置动作、启用状态、能力绑定一概不动。改动前的值写入备份表，回滚按备份表还原。
-- 租户在 builtin_rule_overrides.severity 上的覆盖不受影响，运行时仍优先于基准级别。
-- 回滚：deploy/migrations/rollback/997_relevel_preloaded_policy_severity.sql。
BEGIN;

CREATE TABLE IF NOT EXISTS policy_severity_relevel_backup (
    rule_id VARCHAR(64) PRIMARY KEY,
    policy_code VARCHAR(128) NOT NULL,
    old_severity VARCHAR(16) NOT NULL,
    new_severity VARCHAR(16) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

WITH relevel(policy_code, old_severity, new_severity) AS (
    VALUES
        ('builtin.agent_detect.12438c4c568f8c24','medium','low'),
        ('builtin.agent_detect.1d449b7a84677bb2','medium','low'),
        ('builtin.agent_detect.223c40ba05f83647','medium','low'),
        ('builtin.agent_detect.3b83737794508b03','medium','low'),
        ('builtin.agent_detect.60879276c451279a','medium','low'),
        ('builtin.agent_detect.a5d24299196cf4f3','medium','low'),
        ('builtin.agent_detect.b620fc06d06c1fc7','medium','low'),
        ('builtin.agent_detect.c1896e0995119428','medium','low'),
        ('builtin.agent_detect.e2d7dcc63727dab9','medium','low'),
        ('builtin.agent_detect.f539af0c43cb3787','medium','low'),
        ('builtin.agent_detect.f93768ab6617606e','medium','low'),
        ('builtin.code_security.2da958a010ca4303','high','medium'),
        ('builtin.code_security.2e8190e3871e45d6','critical','medium'),
        ('builtin.code_security.389ee9cb3cb7c789','high','medium'),
        ('builtin.code_security.3f67649cc24121a3','high','medium'),
        ('builtin.code_security.46a74885f15123bb','high','medium'),
        ('builtin.code_security.4f2a28590d7747f6','high','medium'),
        ('builtin.code_security.83c72801873c89c6','high','medium'),
        ('builtin.code_security.9640acf0d1083905','high','medium'),
        ('builtin.code_security.c0bf948ca3c9ebe2','high','medium'),
        ('builtin.code_security.d4bd0d8e0c6c9857','high','medium'),
        ('builtin.code_security.d6121b4e9c6b3639','high','medium'),
        ('builtin.code_security.d82567ae4c6cba2a','critical','medium'),
        ('builtin.code_security.eea7475d95f58dd5','high','medium'),
        ('builtin.copyright_protect.1107170cb2c8407a','critical','high'),
        ('builtin.data_leak.85d7d239c670bab5','high','medium'),
        ('builtin.data_leak.f21dc3ac3d94c0f3','critical','high'),
        ('builtin.dos_protection.26b5a56593b2a884','high','medium'),
        ('builtin.dos_protection.4290e5f12c4f81a4','high','medium'),
        ('builtin.dos_protection.6e61ea7c8d2d9a07','high','medium'),
        ('builtin.dos_protection.6f6907dfdbc2ee17','high','medium'),
        ('builtin.dos_protection.762fbe86a6615238','high','medium'),
        ('builtin.dos_protection.c49a1dd5605cb6d1','high','medium'),
        ('builtin.fraud_detect.31114886164ee6ac','critical','high'),
        ('builtin.fraud_detect.6ff312032520747d','critical','high'),
        ('builtin.fraud_detect.eafd99decc56bca2','critical','high'),
        ('builtin.plugin_security.b5f7907c68e5bf34','high','medium'),
        ('builtin.prompt_injection.4fb2be0130d3f3f1','high','medium'),
        ('builtin.prompt_injection.57767f0750a92dfa','high','medium'),
        ('builtin.prompt_injection.8a4cfd4d54e80e99','high','medium'),
        ('builtin.prompt_injection.9f67a6da54bce276','high','medium'),
        ('builtin.prompt_injection.ac6042efdf14b49c','high','medium'),
        ('builtin.prompt_injection.f4809d017dfbf3a6','high','medium'),
        ('builtin.prompt_leak.7e8a7b334134633b','high','medium')
), changed AS (
    UPDATE rules r
    SET severity = relevel.new_severity
    FROM relevel
    WHERE r.policy_code = relevel.policy_code
      AND r.severity = relevel.old_severity
    RETURNING r.id, r.policy_code, relevel.old_severity, relevel.new_severity
)
INSERT INTO policy_severity_relevel_backup(rule_id, policy_code, old_severity, new_severity)
SELECT id, policy_code, old_severity, new_severity FROM changed
ON CONFLICT (rule_id) DO NOTHING;

COMMIT;
