-- alert_group_backlog_stats.sql —— 告警组积压只读统计（仅 SELECT，不写任何数据）
--
-- 用途：在决定是否开启“自动关闭陈旧告警”（系统设置 alert_ttl_enabled，或环境变量
-- ALERT_TTL_ENABLED）之前，先看清积压分布，以及按 N 天开启后 AutoCloseStale 会关掉多少组。
--
-- 用法（建议连只读账号或备库；整份在只读事务内执行）：
--   psql "$DATABASE_URL" -v ttl_days=14 -f deploy/sql/readonly/alert_group_backlog_stats.sql
-- 不传 ttl_days 时默认 14 天。
--
-- 第 3 段的条件与 apps/control-plane/internal/repository/alert_groups.go 中
-- AutoCloseStale 完全一致（含 runtime_fault 故障静默分支，故障静默窗 = FaultQuietTTL = 6 小时，
-- 以及 redlineFindingGuardSQL 高价值 finding 护栏）。仓储层改条件时必须同步本文件。
-- 注意：AutoCloseStale 单次最多关 1000 行、每小时一次；这里统计的是“总共会被关的数量”，不受批量上限影响。

\set ON_ERROR_STOP on
\if :{?ttl_days}
\else
\set ttl_days 14
\endif

BEGIN TRANSACTION READ ONLY;

-- 1) 积压分布：租户 × 类型 × 状态 × 阶段 × 是否诱饵 × 陈旧天数分桶（按 last_seen_at 距今）
SELECT
    ag.tenant_id,
    ag.alert_type,
    ag.status,
    COALESCE(NULLIF(ag.stage, ''), '(未知)')           AS stage,
    ag.is_canary,
    CASE
        WHEN ag.last_seen_at >= now() - interval '7 days'  THEN '1_<7天'
        WHEN ag.last_seen_at >= now() - interval '14 days' THEN '2_7-14天'
        WHEN ag.last_seen_at >= now() - interval '30 days' THEN '3_14-30天'
        ELSE '4_>30天'
    END                                                AS stale_bucket,
    COUNT(*)                                           AS group_count
FROM alert_groups ag
GROUP BY 1, 2, 3, 4, 5, 6
ORDER BY 1, 2, 3, 4, 5, 6;

-- 2) 按租户 × 状态的汇总，便于和控制台待处置数对账
SELECT
    ag.tenant_id,
    ag.status,
    COUNT(*)                                                            AS group_count,
    COUNT(*) FILTER (WHERE ag.last_seen_at < now() - interval '7 days') AS stale_7d_plus,
    COUNT(*) FILTER (WHERE ag.acknowledged_at IS NOT NULL)              AS ever_acknowledged
FROM alert_groups ag
GROUP BY 1, 2
ORDER BY 1, 2;

-- 3) 若开启 TTL = :ttl_days 天，AutoCloseStale 会关闭的组（条件逐字对应仓储层）
WITH params AS (
    SELECT now() - make_interval(days => :'ttl_days'::int) AS cutoff,
           now() - interval '6 hours'                     AS fault_cutoff
),
would_close AS (
    -- branch 取值与 AutoCloseStale 写入的 disposition_note 一致（只按 alert_type 区分）。
    SELECT ag.tenant_id, ag.alert_type,
           CASE WHEN ag.alert_type = 'runtime_fault'
                THEN 'auto_closed_fault_quiet' ELSE 'auto_closed_ttl' END AS branch
    FROM alert_groups ag CROSS JOIN params p
    WHERE ag.status IN ('open', 'acknowledged')
      AND (
            (
                ag.last_seen_at < p.cutoff
                AND ag.stage = 'input'
                AND NOT ag.is_canary
                AND NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(
                        COALESCE(ag.body_json->'matched'->'findings', '[]'::jsonb)) AS f
                    WHERE f->>'type' IN ('secret', 'data_leak')
                       OR f->>'category' = 'illegal_system_command_instructions'
                       OR f->>'category' LIKE 'agent_canary%'
                       OR f->>'category' LIKE 'classified%'
                )
            )
            OR (
                ag.alert_type = 'runtime_fault'
                AND ag.last_seen_at < p.fault_cutoff
                AND NOT ag.is_canary
                AND NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(
                        COALESCE(ag.body_json->'matched'->'findings', '[]'::jsonb)) AS f
                    WHERE f->>'type' IN ('secret', 'data_leak')
                       OR f->>'category' = 'illegal_system_command_instructions'
                       OR f->>'category' LIKE 'agent_canary%'
                       OR f->>'category' LIKE 'classified%'
                )
            )
          )
)
SELECT :'ttl_days'::int AS ttl_days, tenant_id, alert_type, branch, COUNT(*) AS would_close_count
FROM would_close
GROUP BY ROLLUP (tenant_id, alert_type, branch)
ORDER BY tenant_id NULLS LAST, alert_type NULLS LAST, branch NULLS LAST;

-- 4) 陈旧（超过 :ttl_days 天）但受护栏保护、不会被自动关闭的待处置组，按原因归类
--    （runtime_fault 走 6 小时故障静默分支，其关闭数量已含在第 3 段，这里不重复统计）
SELECT
    ag.tenant_id,
    CASE
        WHEN ag.is_canary THEN '诱饵命中（永不自动关）'
        WHEN EXISTS (
            SELECT 1 FROM jsonb_array_elements(COALESCE(ag.body_json->'matched'->'findings', '[]'::jsonb)) AS f
            WHERE f->>'type' IN ('secret', 'data_leak')
               OR f->>'category' = 'illegal_system_command_instructions'
               OR f->>'category' LIKE 'agent_canary%'
               OR f->>'category' LIKE 'classified%'
        ) THEN '高价值发现（密钥/数据泄露/涉密等）'
        WHEN ag.stage IS NULL OR ag.stage = '' THEN '阶段未知（未回填）'
        ELSE '非输入侧（' || ag.stage || '）'
    END AS protected_reason,
    COUNT(*) AS group_count
FROM alert_groups ag
WHERE ag.status IN ('open', 'acknowledged')
  AND ag.last_seen_at < now() - make_interval(days => :'ttl_days'::int)
  AND ag.alert_type <> 'runtime_fault'
  AND NOT (
        COALESCE(ag.stage, '') = 'input'
        AND NOT ag.is_canary
        AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(COALESCE(ag.body_json->'matched'->'findings', '[]'::jsonb)) AS f
            WHERE f->>'type' IN ('secret', 'data_leak')
               OR f->>'category' = 'illegal_system_command_instructions'
               OR f->>'category' LIKE 'agent_canary%'
               OR f->>'category' LIKE 'classified%'
        )
  )
GROUP BY 1, 2
ORDER BY 1, 3 DESC;

ROLLBACK;
