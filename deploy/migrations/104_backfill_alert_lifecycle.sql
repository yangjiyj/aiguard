-- 104_backfill_alert_lifecycle.sql
-- 一次性回填存量 alert_groups 的 P0-A 生命周期列，从 body_json.matched 反推：
--   is_canary / hard_floor / stage / class_key / effective_severity / disposition_class。
-- 必须在启用 ALERT_TTL_ENABLED 之前完成——否则 TTL 三闸对存量组失效（评审 M2）。
-- 幂等：仅处理 class_key 仍为 NULL 的行（回填后 class_key 必非空，再跑即跳过）；
--       只填新列、绝不改 status/severity，无回滚风险（纯附加）。
-- 事务型（无 CONCURRENTLY），由 migration-runner 包裹。存量约数百行，开销可忽略。

WITH src AS (
  SELECT
    ag.id,
    (ag.body_json->'matched'->>'stage') AS stage,
    EXISTS (
      SELECT 1 FROM jsonb_array_elements(COALESCE(ag.body_json->'matched'->'findings','[]'::jsonb)) f
      WHERE f->>'category' LIKE 'agent_canary%'
    ) AS is_canary,
    EXISTS (
      SELECT 1 FROM jsonb_array_elements(COALESCE(ag.body_json->'matched'->'findings','[]'::jsonb)) f
      WHERE (f->>'hard_floor')::boolean IS TRUE
    ) AS hard_floor,
    (
      SELECT f->>'category'
      FROM jsonb_array_elements(COALESCE(ag.body_json->'matched'->'findings','[]'::jsonb)) f
      WHERE COALESCE(f->>'category','') <> ''
      ORDER BY (CASE f->>'severity'
                  WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                  WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) DESC,
               COALESCE((f->>'confidence')::float, 0) DESC
      LIMIT 1
    ) AS dominant_cat
  FROM alert_groups ag
  WHERE ag.class_key IS NULL
)
UPDATE alert_groups ag SET
  is_canary = src.is_canary,
  hard_floor = src.hard_floor,
  stage = NULLIF(src.stage, ''),
  class_key = COALESCE(NULLIF(src.dominant_cat, ''), ag.alert_type),
  effective_severity = CASE WHEN ag.severity IN ('low','medium','high','critical') THEN ag.severity ELSE NULL END,
  disposition_class = CASE
    WHEN src.is_canary OR src.hard_floor OR src.stage = 'output' OR ag.severity IN ('high','critical')
      THEN 'action_required'
    ELSE 'informational'
  END
FROM src
WHERE ag.id = src.id;
