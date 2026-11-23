#!/bin/sh
# alert_volume_reconcile.sh — 升级前后 7 天安全事件量对账（按 category 分组，输出降幅归因）
# 用法: sh alert_volume_reconcile.sh <upgrade_ts_iso> [compose_dir]
#   upgrade_ts_iso: 升级时刻（如 2026-07-05T00:00:00Z），脚本比对 [ts-7d, ts) 与 [ts, ts+7d)
# 依赖: 在 compose 目录下经 postgres 容器执行；须升级后满 7 天再跑（after 窗需累积）。
set -eu

TS="${1:?用法: sh alert_volume_reconcile.sh <upgrade_ts_iso> [compose_dir]}"
DC_DIR="${2:-$(CDPATH= cd -- "$(dirname "$0")/../../deploy/docker-compose" && pwd)}"
cd "$DC_DIR"

# 读 .env 不能用 source：含空格的未加引号值会被当命令执行（见 deploy/lib/jjd-env.sh）。
JJD_ENV_LIB=../lib/jjd-env.sh
[ -f "$JJD_ENV_LIB" ] || { echo "[error] 缺少安全读取 .env 的库: $DC_DIR/$JJD_ENV_LIB" >&2; exit 2; }
# shellcheck source=../../deploy/lib/jjd-env.sh
. "$JJD_ENV_LIB"
if [ -f ./.env ]; then jjd_load_env_file ./.env; fi
PGUSER="${POSTGRES_USER:-newapi}"
PGDB="${POSTGRES_DB:-newapi}"

psql() {
  sh ./compose-wrapper.sh exec -T postgres psql -U "$PGUSER" -d "$PGDB" -tAF'|' -c "$1"
}

echo "[reconcile] 升级时刻 $TS；对账窗 before=[ts-7d,ts) after=[ts,ts+7d)"
echo "category|before_7d|after_7d|delta|pct"

# 分组口径：优先 matched_summary->>'category'，回退 event_type。
psql "
WITH win AS (
  SELECT
    COALESCE(NULLIF(matched_summary->>'category',''), event_type) AS category,
    CASE WHEN created_at >= (TIMESTAMPTZ '$TS' - INTERVAL '7 days') AND created_at < TIMESTAMPTZ '$TS' THEN 1 ELSE 0 END AS is_before,
    CASE WHEN created_at >= TIMESTAMPTZ '$TS' AND created_at < (TIMESTAMPTZ '$TS' + INTERVAL '7 days') THEN 1 ELSE 0 END AS is_after
  FROM security_events
  WHERE created_at >= (TIMESTAMPTZ '$TS' - INTERVAL '7 days')
    AND created_at <  (TIMESTAMPTZ '$TS' + INTERVAL '7 days')
)
SELECT category,
       SUM(is_before) AS before_7d,
       SUM(is_after)  AS after_7d,
       SUM(is_after) - SUM(is_before) AS delta,
       CASE WHEN SUM(is_before) = 0 THEN 'n/a'
            ELSE ROUND(100.0 * (SUM(is_after) - SUM(is_before)) / SUM(is_before), 1) || '%'
       END AS pct
FROM win
GROUP BY category
ORDER BY before_7d DESC;
"
echo "[reconcile] 完成。负 delta = 误报下降（默认翻转预期效果）；正 delta 需人工核查是否漏检。"
