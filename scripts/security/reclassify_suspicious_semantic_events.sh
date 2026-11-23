#!/bin/sh
# Reclassify unconfirmed semantic opinions as observations while preserving evidence.
set -eu

MODE=dry-run
CAMPAIGN=20260729_suspicious_semantic_observation_v1
COMPOSE_DIR=
POSTGRES_CONTAINER=

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
    -*) echo "[error] unknown option: $1" >&2; exit 2 ;;
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

candidate_cte="
WITH candidates AS (
  SELECT se.id
  FROM security_events se
  WHERE se.event_type = 'semantic_attack'
    AND se.action_taken IN ('audit', 'security_audit', 'security_audit_only')
    AND jsonb_typeof(se.matched_summary->'findings') = 'array'
    AND jsonb_array_length(se.matched_summary->'findings') > 0
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(se.matched_summary->'findings') finding
      WHERE COALESCE(finding->>'type', '') <> 'semantic_attack'
         OR COALESCE(finding->>'severity', '') <> 'medium'
         OR jsonb_typeof(finding->'confidence') IS DISTINCT FROM 'number'
         OR (finding->>'confidence')::numeric > 0.5
         OR COALESCE(finding->>'redacted_evidence', '') NOT LIKE '%suspicious%'
    )
)"

if [ "$MODE" = dry-run ]; then
  echo "[preview] no database rows will be changed"
  run_psql <<SQL
${candidate_cte}
SELECT COUNT(*) AS candidate_events FROM candidates;
${candidate_cte}
SELECT se.matched_summary->>'category' AS category,
       COUNT(*) AS events,
       MIN(se.created_at) AS first_at,
       MAX(se.created_at) AS last_at
FROM security_events se
JOIN candidates c ON c.id = se.id
GROUP BY se.matched_summary->>'category'
ORDER BY events DESC;
SQL
  exit 0
fi

if [ "$MODE" = restore ]; then
  echo "[restore] campaign=$CAMPAIGN"
  run_psql -v campaign="$CAMPAIGN" <<'SQL'
BEGIN;
DO $$
BEGIN
  IF to_regclass('public.security_event_reclassification_snapshots') IS NULL THEN
    RAISE EXCEPTION 'snapshot table does not exist; nothing can be restored';
  END IF;
END $$;
WITH restored AS (
  UPDATE security_events se
     SET event_type = snap.event_type,
         severity = snap.severity,
         matched_summary = snap.matched_summary
    FROM security_event_reclassification_snapshots snap
   WHERE snap.campaign = :'campaign'
     AND snap.event_id = se.id
  RETURNING se.id
)
SELECT COUNT(*) AS restored_events FROM restored;
COMMIT;
SQL
  exit 0
fi

echo "[apply] campaign=$CAMPAIGN"
run_psql -v campaign="$CAMPAIGN" <<SQL
BEGIN;
CREATE TABLE IF NOT EXISTS security_event_reclassification_snapshots (
  campaign VARCHAR(96) NOT NULL,
  event_id VARCHAR(64) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  matched_summary JSONB NOT NULL,
  snapshotted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (campaign, event_id)
);

${candidate_cte}, inserted AS (
  INSERT INTO security_event_reclassification_snapshots (
    campaign, event_id, event_type, severity, matched_summary
  )
  SELECT :'campaign', se.id, se.event_type, se.severity, se.matched_summary
  FROM security_events se
  JOIN candidates c ON c.id = se.id
  ON CONFLICT (campaign, event_id) DO NOTHING
  RETURNING event_id
), updated AS (
  UPDATE security_events se
     SET event_type = 'semantic_telemetry',
         severity = 'low',
         matched_summary = jsonb_set(
           se.matched_summary || jsonb_build_object(
             'review_state', 'observation',
             'effective_severity', 'low'
           ),
           '{findings}',
           (
             SELECT jsonb_agg(
               finding || jsonb_build_object(
                 'action', 'allow',
                 'counts_as_security_finding', false,
                 'triage', COALESCE(finding->'triage', '{}'::jsonb) || jsonb_build_object(
                   'disposition', 'observation',
                   'disposition_reason', 'semantic_suspicious_unconfirmed'
                 )
               )
             )
             FROM jsonb_array_elements(se.matched_summary->'findings') finding
           )
         ) || jsonb_build_object('findings_count', 0)
    FROM inserted i
   WHERE i.event_id = se.id
  RETURNING se.id
)
SELECT COUNT(*) AS reclassified_events FROM updated;
COMMIT;
SQL

echo "[apply] complete; restore with --restore --campaign $CAMPAIGN"
