-- 109_content_exception_rule_ref.sql
-- 安全三视图重构 P1-D（契约第 7 条）：误报闭环补全的数据模型。
--  * rule_ref TEXT：统一命名空间的规则引用字符串（兼容内置规则 ID，如 secret_openai_key），
--    与旧 rule_id（rules(id) 外键，仅自定义规则）并存；读取优先 rule_ref。
--    本迁移必须先于 P3 的 255 条种子行删除落地（外键级联风险，见设计 4a）。
--  * expires_at 改可空：NULL=永久例外。ALTER ... DROP NOT NULL 天然幂等。
-- 存量回填：rule_ref 为空的行用旧 rule_id 补上（WHERE 子句使重复执行自然跳过）。

ALTER TABLE content_audit_exceptions ADD COLUMN IF NOT EXISTS rule_ref TEXT;
ALTER TABLE content_audit_exceptions ALTER COLUMN expires_at DROP NOT NULL;

UPDATE content_audit_exceptions SET rule_ref = rule_id WHERE rule_ref IS NULL AND rule_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_content_audit_exceptions_rule_ref
    ON content_audit_exceptions(tenant_id, rule_ref);

COMMENT ON COLUMN content_audit_exceptions.rule_ref IS '统一命名空间规则引用（内置规则英文 ID 或 rules.id），读取优先于 rule_id';
