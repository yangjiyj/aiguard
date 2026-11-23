#!/bin/sh
# Reclassify historical passive semantic audit groups without touching raw events.
# Defaults to a read-only preview. Apply creates a durable snapshot that --restore can use.
set -eu

MODE=dry-run
CAMPAIGN=20260728_passive_output_semantic_v1
COMPOSE_DIR=
POSTGRES_CONTAINER=

usage() {
  cat <<'EOF'
Usage:
  reclassify_passive_semantic_alerts.sh [--dry-run] [--postgres-container NAME] [compose_dir]
  reclassify_passive_semantic_alerts.sh --apply [--campaign ID] [--postgres-container NAME] [compose_dir]
  reclassify_passive_semantic_alerts.sh --restore [--campaign ID] [--postgres-container NAME] [compose_dir]

Only groups whose complete linked event set is semantic-only and audit-only are
selected. Input/output can share one historical group, so stage is deliberately
not used as a group predicate. Raw security_events and evidence are never modified.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) MODE=dry-run ;;
    --apply) MODE=apply ;;
    --restore) MODE=restore ;;
    --campaign)
      shift
      [ "$#" -gt 0 ] || { echo "[error] --campaign requires a value" >&2; exit 2; }
      CAMPAIGN=$1
      ;;
    --postgres-container)
      shift
      [ "$#" -gt 0 ] || { echo "[error] --postgres-container requires a value" >&2; exit 2; }
      POSTGRES_CONTAINER=$1
      ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "[error] unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)
      [ -z "$COMPOSE_DIR" ] || { echo "[error] compose_dir supplied more than once" >&2; exit 2; }
      COMPOSE_DIR=$1
      ;;
  esac
  shift
done

case "$CAMPAIGN" in
  *[!A-Za-z0-9_.:-]*|'') echo "[error] campaign contains unsafe characters" >&2; exit 2 ;;
esac
case "$POSTGRES_CONTAINER" in
  *[!A-Za-z0-9_.:-]*) echo "[error] postgres container contains unsafe characters" >&2; exit 2 ;;
esac

if [ -z "$COMPOSE_DIR" ]; then
  COMPOSE_DIR=$(CDPATH= cd -- "$(dirname "$0")/../../deploy/docker-compose" && pwd)
else
  COMPOSE_DIR=$(CDPATH= cd -- "$COMPOSE_DIR" && pwd)
fi

cd "$COMPOSE_DIR"
[ -x ./compose-wrapper.sh ] || { echo "[error] compose-wrapper.sh not found in $COMPOSE_DIR" >&2; exit 2; }
if [ -z "${COMPOSE_FILE:-}" ] && [ ! -f ./docker-compose.yml ] && [ -f ./docker-compose.offline.yml ]; then
  COMPOSE_FILE=docker-compose.offline.yml
  export COMPOSE_FILE
fi
# 读 .env 不能用 source：含空格的未加引号值会被当命令执行（见 deploy/lib/jjd-env.sh）。
# 此时已 cd 到 compose 目录，共享库在 ../lib。
JJD_ENV_LIB=../lib/jjd-env.sh
[ -f "$JJD_ENV_LIB" ] || { echo "[error] 缺少安全读取 .env 的库: $COMPOSE_DIR/$JJD_ENV_LIB" >&2; exit 2; }
# shellcheck source=../../deploy/lib/jjd-env.sh
. "$JJD_ENV_LIB"
if [ -f ./.env ]; then
  jjd_load_env_file ./.env
fi
PGUSER=${POSTGRES_USER:-jjdguard}
PGDB=${POSTGRES_DB:-jjdguard}

run_psql() {
  if [ -n "$POSTGRES_CONTAINER" ]; then
    docker exec -i "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$PGUSER" -d "$PGDB" "$@"
  else
    sh ./compose-wrapper.sh exec -T postgres psql -X -v ON_ERROR_STOP=1 -U "$PGUSER" -d "$PGDB" "$@"
  fi
}

# A candidate must have at least one linked event and every linked event must
# satisfy this predicate. Malformed/missing findings fail closed and are kept.
candidate_cte="
WITH group_events AS (
  SELECT ag.id AS group_id, se.id AS event_id, se.event_type, se.action_taken,
         se.matched_summary
    FROM alert_groups ag
    JOIN security_events se
      ON se.tenant_id = ag.tenant_id
     AND (se.alert_group_id = ag.id OR se.id = ag.representative_event_id)
   WHERE ag.status IN ('open', 'acknowledged')
), candidates AS (
  SELECT ag.id
    FROM alert_groups ag
   WHERE ag.status IN ('open', 'acknowledged')
     AND EXISTS (SELECT 1 FROM group_events ge WHERE ge.group_id = ag.id)
     AND NOT EXISTS (
       SELECT 1
         FROM group_events ge
        WHERE ge.group_id = ag.id
          AND (
            ge.event_type NOT IN ('semantic_attack', 'semantic_telemetry')
            OR ge.action_taken NOT IN ('audit', 'security_audit_only')
            OR jsonb_typeof(ge.matched_summary->'findings') IS DISTINCT FROM 'array'
            OR jsonb_array_length(COALESCE(ge.matched_summary->'findings', '[]'::jsonb)) = 0
            OR EXISTS (
              SELECT 1
                FROM jsonb_array_elements(COALESCE(ge.matched_summary->'findings', '[]'::jsonb)) finding
               WHERE COALESCE(finding->>'type', '') NOT IN ('semantic_attack', 'semantic_telemetry')
                  OR COALESCE(finding->>'action', 'audit') NOT IN ('audit', 'allow', 'record', 'none')
            )
          )
     )
)"

if [ "$MODE" = dry-run ]; then
  echo "[preview] no database rows will be changed"
  run_psql <<SQL
${candidate_cte}
SELECT ag.id, ag.status, ag.disposition_class, ag.stage, ag.occurrence_count,
       ag.last_seen_at, ag.title
  FROM alert_groups ag
  JOIN candidates c ON c.id = ag.id
 ORDER BY ag.last_seen_at DESC;
${candidate_cte}
SELECT COUNT(*) AS candidate_groups FROM candidates;
SQL
  exit 0
fi

if [ "$MODE" = restore ]; then
  echo "[restore] campaign=$CAMPAIGN"
  run_psql -v campaign="$CAMPAIGN" <<'SQL'
BEGIN;
DO $$
BEGIN
  IF to_regclass('public.alert_group_reclassification_snapshots') IS NULL THEN
    RAISE EXCEPTION 'snapshot table does not exist; nothing can be restored';
  END IF;
  IF to_regclass('public.alert_inbox_reclassification_snapshots') IS NULL THEN
    RAISE EXCEPTION 'inbox snapshot table does not exist; nothing can be restored';
  END IF;
END $$;

WITH restored AS (
  UPDATE alert_groups ag
     SET status = snap.status,
         disposition_class = snap.disposition_class,
         acknowledged_at = snap.acknowledged_at,
         resolved_at = snap.resolved_at,
         false_positive_at = snap.false_positive_at,
         closed_at = snap.closed_at,
         disposition_by = snap.disposition_by,
         disposition_note = snap.disposition_note,
         updated_at = snap.updated_at
    FROM alert_group_reclassification_snapshots snap
   WHERE snap.campaign = :'campaign'
     AND snap.group_id = ag.id
  RETURNING ag.id
)
SELECT COUNT(*) AS restored_groups FROM restored;

WITH restored_inbox AS (
  UPDATE alert_inbox ai
     SET read_at = snap.read_at
    FROM alert_inbox_reclassification_snapshots snap
   WHERE snap.campaign = :'campaign'
     AND snap.inbox_id = ai.id
  RETURNING ai.id
)
SELECT COUNT(*) AS restored_inbox_items FROM restored_inbox;
COMMIT;
SQL
  exit 0
fi

echo "[apply] campaign=$CAMPAIGN"
run_psql -v campaign="$CAMPAIGN" <<SQL
BEGIN;
CREATE TABLE IF NOT EXISTS alert_group_reclassification_snapshots (
  campaign VARCHAR(96) NOT NULL,
  group_id VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  disposition_class VARCHAR(24),
  acknowledged_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  false_positive_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  disposition_by VARCHAR(64),
  disposition_note TEXT,
  updated_at TIMESTAMPTZ NOT NULL,
  snapshotted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (campaign, group_id)
);
CREATE TABLE IF NOT EXISTS alert_inbox_reclassification_snapshots (
  campaign VARCHAR(96) NOT NULL,
  inbox_id VARCHAR(64) NOT NULL,
  read_at TIMESTAMPTZ,
  snapshotted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (campaign, inbox_id)
);

${candidate_cte}, inserted AS (
  INSERT INTO alert_group_reclassification_snapshots (
    campaign, group_id, status, disposition_class, acknowledged_at,
    resolved_at, false_positive_at, closed_at, disposition_by,
    disposition_note, updated_at
  )
  SELECT :'campaign', ag.id, ag.status, ag.disposition_class, ag.acknowledged_at,
         ag.resolved_at, ag.false_positive_at, ag.closed_at, ag.disposition_by,
         ag.disposition_note, ag.updated_at
    FROM alert_groups ag
    JOIN candidates c ON c.id = ag.id
  ON CONFLICT (campaign, group_id) DO NOTHING
  RETURNING group_id
), updated AS (
  UPDATE alert_groups ag
     SET status = 'resolved',
         disposition_class = 'informational',
         resolved_at = COALESCE(ag.resolved_at, NOW()),
         closed_at = COALESCE(ag.closed_at, NOW()),
         disposition_by = 'system:passive-semantic-v1',
         disposition_note = '历史纯语义审计线索自动降级；原始证据保留在指令告警',
         updated_at = NOW()
    FROM inserted i
   WHERE ag.id = i.group_id
  RETURNING ag.id
)
SELECT COUNT(*) AS reclassified_groups FROM updated;

WITH inserted_inbox AS (
  INSERT INTO alert_inbox_reclassification_snapshots (campaign, inbox_id, read_at)
  SELECT DISTINCT :'campaign', ai.id, ai.read_at
    FROM alert_inbox ai
    JOIN alert_groups ag
      ON ai.tenant_id = ag.tenant_id
     AND (
       ai.body_json->>'alert_group_id' = ag.id
       OR ai.body_json->>'event_id' = ag.representative_event_id
       OR ai.target_url = '/security-events/' || ag.representative_event_id
     )
    JOIN alert_group_reclassification_snapshots snap
      ON snap.campaign = :'campaign'
     AND snap.group_id = ag.id
   WHERE ai.read_at IS NULL
  ON CONFLICT (campaign, inbox_id) DO NOTHING
  RETURNING inbox_id
), eligible_inbox AS (
  SELECT inbox_id FROM inserted_inbox
  UNION
  SELECT inbox_id
    FROM alert_inbox_reclassification_snapshots
   WHERE campaign = :'campaign'
), updated_inbox AS (
  UPDATE alert_inbox ai
     SET read_at = NOW()
    FROM eligible_inbox eligible
   WHERE ai.id = eligible.inbox_id
     AND ai.read_at IS NULL
  RETURNING ai.id
)
SELECT COUNT(*) AS marked_read_inbox_items FROM updated_inbox;
COMMIT;
SQL

echo "[apply] complete; restore with --restore --campaign $CAMPAIGN"
