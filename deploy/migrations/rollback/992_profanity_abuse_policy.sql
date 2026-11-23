BEGIN;
-- 先回退应用版本，再执行本文件。只删除迁移 992 创建的“辱骂脏话”内置策略及其能力登记，
-- 不触及其他策略；客户在该策略上改过的动作随策略一并移除。
-- 策略命中过就有 security_events.rule_id 指向它（外键，无级联）：先把这些事件的 rule_id 置空，
-- 事件本身保留（仍可按请求、类别追溯），只处理指向本策略的事件，其他事件不动。
UPDATE security_events SET rule_id = NULL
WHERE rule_id IN (SELECT id FROM rules WHERE policy_code = 'builtin.content_safety.ffbbdfb2e823022d');
DELETE FROM rules WHERE policy_code = 'builtin.content_safety.ffbbdfb2e823022d';
DELETE FROM security_capabilities
WHERE category IN ('content_profanity_abuse', 'harassment_profanity_cn')
  AND NOT EXISTS (
      SELECT 1 FROM rule_capability_bindings b
      WHERE b.capability_id = security_capabilities.id
  );
COMMIT;
