-- 811_hide_onboarding_test_tenants.sql
-- +goose Up
-- onboarding 集成测试(apps/control-plane/internal/onboarding/service_test.go)以
-- init_t_<UnixNano> / upgrade_t_<UnixNano> 命名建临时租户，并各插一个 platform_admin 用户。
-- 测试进程被中断时 t.Cleanup 不会跑完，这些 fixture 会残留在库里，出现在
-- 「组织管理 > 单位列表」中；因为带用户，删除会被 unit_not_empty(409) 拒绝，管理员无法清理。
--
-- 按既有机制标记 is_test=TRUE 即从列表隐藏（List 查询 WHERE is_test = FALSE），
-- 与迁移 078 处理 tenant_system 的方式一致。不删数据，仅隐藏，可回滚。
-- 命名严格锚定 '^(init|upgrade)_t_\d+$'，避免误伤真实单位。
UPDATE tenants
SET is_test = TRUE
WHERE id ~ '^(init|upgrade)_t_[0-9]+$'
  AND is_test = FALSE;

-- +goose Down
UPDATE tenants
SET is_test = FALSE
WHERE id ~ '^(init|upgrade)_t_[0-9]+$'
  AND is_test = TRUE;
