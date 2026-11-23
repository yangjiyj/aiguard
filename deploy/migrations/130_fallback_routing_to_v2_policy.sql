-- 130_fallback_routing_to_v2_policy.sql
-- 迁移遗留「备用路由」配置（models.capabilities_json->routing.fallback_provider_id，
-- 即模型管理页备用路由弹窗写入的数据）为 v2 模型级 priority（稳定优先）路由策略。
--
-- 规则：
--   主线路 = 配置了备用渠道的模型行所属渠道；备用线路 = fallback_provider_id；
--   仅当主/备渠道均启用、均有有效凭据、且备用渠道存在同名启用模型时迁移；
--   已存在 v2/v3 模型级策略的 (tenant, model) 跳过，不覆盖管理员新配置。
-- 迁移完成后，网关对这类模型的选路由 v2 引擎接管，备用弹窗可从 UI 下线。
-- 本迁移可重复执行：迁移后 NOT EXISTS 守卫使再次运行为空操作。

WITH legacy AS (
    SELECT p.tenant_id, m.model_name,
           m.provider_id AS primary_provider,
           m.capabilities_json #>> '{routing,fallback_provider_id}' AS backup_provider,
           m.id AS model_row_id
    FROM models m
    JOIN providers p ON p.id = m.provider_id
    WHERE m.capabilities_json #>> '{routing,fallback_provider_id}' IS NOT NULL
      AND btrim(m.capabilities_json #>> '{routing,fallback_provider_id}') <> ''
),
pairs AS (
    -- 同一 (tenant, model) 可能有多行各自配置了备用渠道，确定性地取一行
    SELECT DISTINCT ON (tenant_id, model_name)
        tenant_id, model_name, primary_provider, backup_provider
    FROM legacy
    ORDER BY tenant_id, model_name, model_row_id
),
valid AS (
    SELECT pr.tenant_id, pr.model_name, pr.primary_provider, pr.backup_provider
    FROM pairs pr
    WHERE pr.backup_provider <> pr.primary_provider
      AND EXISTS (
          SELECT 1 FROM providers pp
          WHERE pp.id = pr.primary_provider AND pp.tenant_id = pr.tenant_id AND pp.status = 'active'
            AND EXISTS (SELECT 1 FROM provider_credentials pc WHERE pc.provider_id = pp.id AND pc.status = 'active')
      )
      AND EXISTS (
          SELECT 1 FROM providers bp
          WHERE bp.id = pr.backup_provider AND bp.tenant_id = pr.tenant_id AND bp.status = 'active'
            AND EXISTS (SELECT 1 FROM provider_credentials pc WHERE pc.provider_id = bp.id AND pc.status = 'active')
      )
      AND EXISTS (
          SELECT 1 FROM models bm
          WHERE bm.provider_id = pr.backup_provider AND bm.model_name = pr.model_name AND bm.status = 'active'
      )
      AND NOT EXISTS (
          SELECT 1 FROM routing_policies rp
          WHERE rp.tenant_id = pr.tenant_id AND rp.scope_type = 'model'
            AND rp.scope_ref = pr.model_name AND rp.layer = 'provider'
            AND rp.schema_version IN (2, 3)
      )
)
INSERT INTO routing_policies
    (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version)
SELECT
    'rpv2_mig_' || md5(v.tenant_id || ':' || v.model_name),
    v.tenant_id,
    'model',
    v.model_name,
    'provider',
    'priority',
    jsonb_build_object(
        'strategy', 'priority',
        'cost_basis', 'none',
        'providers', jsonb_build_array(
            jsonb_build_object('provider_id', v.primary_provider, 'enabled', true, 'priority', 1, 'weight', 0),
            jsonb_build_object('provider_id', v.backup_provider,  'enabled', true, 'priority', 2, 'weight', 0)
        )
    ),
    true,
    2,
    1
FROM valid v;
