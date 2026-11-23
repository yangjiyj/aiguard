-- Upgrades must not change an administrator's rule actions. Migrations 814 and
-- 848 turned the built-in "硬编码凭据示例" rule into a block rule on legacy
-- near-all-audit profiles without anyone choosing it; 849 reverted 848's 16
-- mask changes but left that block. Field report (2026-09-23): the console
-- showed nearly every rule as 告警 while this one silently blocked.
--
-- Restore audit only where the fingerprint proves the upgrade did it: a rule
-- set with >=230 built-in rules, no mask, and this rule as its single block,
-- and no console audit operation ever touched the rule. Customised rule sets,
-- fresh installs (many blocks), and administrator edits are left untouched.
-- A single statement: it touches at most one small rules row per rule set.
UPDATE rules r
SET action = 'audit',
    description = '检测代码中的硬编码凭据示例，告警记录'
WHERE r.policy_code = 'builtin.code_security.9640acf0d1083905'
  AND r.action = 'block'
  AND r.rule_set_id IN (
    SELECT candidate.rule_set_id
    FROM rules candidate
    WHERE candidate.policy_code LIKE 'builtin.%'
    GROUP BY candidate.rule_set_id
    HAVING COUNT(*) >= 230
       AND COUNT(*) FILTER (WHERE candidate.action = 'mask') = 0
       AND COUNT(*) FILTER (WHERE candidate.action = 'block') = 1
       AND COUNT(*) FILTER (
         WHERE candidate.action = 'block'
           AND candidate.policy_code = 'builtin.code_security.9640acf0d1083905'
       ) = 1
  )
  AND NOT EXISTS (
    SELECT 1
    FROM audit_operations edit
    WHERE edit.target_id = r.id
      AND edit.action_type IN (
        'create_rule', 'update_rule', 'update_builtin_policy_action', 'security_policy.update'
      )
  );
