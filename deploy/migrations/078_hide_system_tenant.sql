-- 078_hide_system_tenant.sql
-- +goose Up
-- 系统保留租户 tenant_system（迁移 068 建，承载全平台共用的内置数据安全规则包 ruleset_builtin_*）
-- 不是业务单位，不应出现在「组织管理 > 单位列表」里被编辑/删除。
-- 按既有机制标记 is_test=TRUE 即从列表隐藏（List 查询 WHERE is_test=FALSE）。
-- 不影响内置规则解析：rules 按 rule_sets.tenant_id 取，与 tenants.is_test 无关。
UPDATE tenants SET is_test = TRUE WHERE id = 'tenant_system';

-- +goose Down
UPDATE tenants SET is_test = FALSE WHERE id = 'tenant_system';
