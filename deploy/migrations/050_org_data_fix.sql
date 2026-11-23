-- 050_org_data_fix.sql — 一次性数据订正：默认租户→默认单位、子部门上提、隐藏测试租户
-- 幂等：全部带存在性判断；可重复执行无副作用
BEGIN;

-- 1. 默认租户改名为客户可理解的默认单位
UPDATE tenants SET name = '默认单位', updated_at = NOW()
WHERE id = 'tenant_default' AND name = '默认租户';

-- 2. 误建到历史冗余根部门(team_f1cdad3d)下的子部门 → 上提为一级部门
UPDATE teams SET parent_team_id = NULL, path = '/' || id
WHERE parent_team_id = 'team_f1cdad3d';

-- 3. 删除历史冗余根 team 与测试 team「IAM-UI-Test」
DELETE FROM teams WHERE id IN ('team_f1cdad3d', 'team_b37e2dd2');

-- 4. 测试租户标记 is_test=true（隐藏而非删除，零 FK 风险、可回滚）
UPDATE tenants SET is_test = TRUE
WHERE is_test = FALSE
  AND (id LIKE 'tenant_rp_test_%' OR id LIKE 'tenant_content_%' OR id LIKE 'tfx_%');

COMMIT;
