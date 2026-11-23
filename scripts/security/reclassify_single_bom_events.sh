#!/bin/sh
# Reclassify a lone line-boundary UTF-8 BOM as observation evidence.
set -eu

MODE=dry-run
CAMPAIGN=20260729_single_bom_observation_v1
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
  SELECT se.id, se.alert_group_id
  FROM security_events se
  WHERE se.event_type = 'security_check'
    AND se.action_taken IN ('allow', 'audit', 'security_audit', 'security_audit_only')
    AND COALESCE(se.matched_summary->>'review_state', '') <> 'observation'
    AND jsonb_typeof(se.matched_summary->'findings') = 'array'
    AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(se.matched_summary->'findings') finding
      WHERE finding->>'category' = 'zero_width_char'
        AND finding->>'raw_evidence' = chr(65279)
        AND finding->>'matched_location' LIKE 'count=1,%'
    )
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(se.matched_summary->'findings') finding
      WHERE COALESCE((finding->>'counts_as_security_finding')::boolean, true)
        AND NOT (
          finding->>'category' IN ('encoding_zero_width', 'zero_width_char')
          AND finding->>'raw_evidence' = chr(65279)
        )
    )
)"

if [ "$MODE" = dry-run ]; then
  echo "[preview] no database rows will be changed"
  run_psql <<SQL
${candidate_cte}
SELECT COUNT(*) AS candidate_events FROM candidates;
${candidate_cte}
SELECT COALESCE(alert_group_id, '(none)') AS alert_group_id, COUNT(*) AS events
FROM candidates
GROUP BY alert_group_id
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
  IF to_regclass('public.security_bom_event_snapshots') IS NULL THEN
    RAISE EXCEPTION 'event snapshot table does not exist; nothing can be restored';
  END IF;
END $$;
WITH restored AS (
  UPDATE security_events se
     SET severity = snap.severity,
         effective_severity = snap.effective_severity,
         matched_summary = snap.matched_summary
    FROM security_bom_event_snapshots snap
   WHERE snap.campaign = :'campaign'
     AND snap.event_id = se.id
  RETURNING se.id
)
SELECT COUNT(*) AS restored_events FROM restored;

DO $$
BEGIN
  IF to_regclass('public.security_bom_alert_group_snapshots') IS NULL THEN
    RAISE EXCEPTION 'alert-group snapshot table does not exist; nothing can be restored';
  END IF;
END $$;
WITH restored AS (
  UPDATE alert_groups ag
     SET status = snap.status,
         severity = snap.severity,
         effective_severity = snap.effective_severity,
         disposition_class = snap.disposition_class,
         false_positive_at = snap.false_positive_at,
         closed_at = snap.closed_at,
         updated_at = snap.updated_at
    FROM security_bom_alert_group_snapshots snap
   WHERE snap.campaign = :'campaign'
     AND snap.alert_group_id = ag.id
  RETURNING ag.id
)
SELECT COUNT(*) AS restored_alert_groups FROM restored;
COMMIT;
SQL
  exit 0
fi

echo "[apply] campaign=$CAMPAIGN"
run_psql -v campaign="$CAMPAIGN" <<SQL
BEGIN;
CREATE TABLE IF NOT EXISTS security_bom_event_snapshots (
  campaign VARCHAR(96) NOT NULL,
  event_id VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  effective_severity VARCHAR(16),
  matched_summary JSONB NOT NULL,
  snapshotted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (campaign, event_id)
);
CREATE TABLE IF NOT EXISTS security_bom_alert_group_snapshots (
  campaign VARCHAR(96) NOT NULL,
  alert_group_id VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  effective_severity VARCHAR(16),
  disposition_class VARCHAR(24),
  false_positive_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL,
  snapshotted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (campaign, alert_group_id)
);

CREATE TEMP TABLE bom_candidates ON COMMIT DROP AS
${candidate_cte}
SELECT * FROM candidates;

INSERT INTO security_bom_event_snapshots (
  campaign, event_id, severity, effective_severity, matched_summary
)
SELECT :'campaign', se.id, se.severity, se.effective_severity, se.matched_summary
FROM security_events se
JOIN bom_candidates c ON c.id = se.id
ON CONFLICT (campaign, event_id) DO NOTHING;

CREATE TEMP TABLE bom_groups ON COMMIT DROP AS
SELECT DISTINCT c.alert_group_id AS id
FROM bom_candidates c
WHERE c.alert_group_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM security_events other
    WHERE other.alert_group_id = c.alert_group_id
      AND NOT EXISTS (SELECT 1 FROM bom_candidates own WHERE own.id = other.id)
  );

INSERT INTO security_bom_alert_group_snapshots (
  campaign, alert_group_id, status, severity, effective_severity,
  disposition_class, false_positive_at, closed_at, updated_at
)
SELECT :'campaign', ag.id, ag.status, ag.severity, ag.effective_severity,
       ag.disposition_class, ag.false_positive_at, ag.closed_at, ag.updated_at
FROM alert_groups ag
JOIN bom_groups bg ON bg.id = ag.id
ON CONFLICT (campaign, alert_group_id) DO NOTHING;

WITH updated AS (
  UPDATE security_events se
     SET severity = 'low',
         effective_severity = 'low',
         matched_summary = jsonb_set(
           se.matched_summary || jsonb_build_object(
             'category', 'zero_width_char',
             'findings_count', 0,
             'review_state', 'observation',
             'effective_severity', 'low'
           ),
           '{findings}',
           (
             SELECT jsonb_agg(
               CASE
                 WHEN finding->>'category' IN ('encoding_zero_width', 'zero_width_char')
                  AND finding->>'raw_evidence' = chr(65279)
                 THEN finding || jsonb_build_object(
                   'severity', 'low',
                   'confidence', 0.2,
                   'action', 'allow',
                   'counts_as_security_finding', false,
                   'triage', COALESCE(finding->'triage', '{}'::jsonb) || jsonb_build_object(
                     'disposition', 'observation',
                     'disposition_reason', 'single_bom_at_text_boundary'
                   )
                 )
                 ELSE finding
               END
               ORDER BY ordinality
             )
             FROM jsonb_array_elements(se.matched_summary->'findings')
                  WITH ORDINALITY AS item(finding, ordinality)
           )
         )
    FROM bom_candidates c
   WHERE c.id = se.id
  RETURNING se.id
)
SELECT COUNT(*) AS reclassified_events FROM updated;

WITH updated AS (
  UPDATE alert_groups ag
     SET status = 'false_positive',
         effective_severity = 'low',
         disposition_class = 'informational',
         false_positive_at = COALESCE(ag.false_positive_at, NOW()),
         closed_at = COALESCE(ag.closed_at, NOW()),
         updated_at = NOW()
    FROM bom_groups bg
   WHERE bg.id = ag.id
  RETURNING ag.id
)
SELECT COUNT(*) AS closed_alert_groups FROM updated;
COMMIT;
SQL

echo "[apply] complete; restore with --restore --campaign $CAMPAIGN"
