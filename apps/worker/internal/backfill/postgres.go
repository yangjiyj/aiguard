package backfill

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	db *pgxpool.Pool
}

func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Claim(ctx context.Context, owner string, lease time.Duration) (*Task, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	task := &Task{}
	var lockTimeoutMS, statementTimeoutMS int
	err = tx.QueryRow(ctx, `
SELECT task_name, task_version, batch_size, rate_limit_rows_per_second,
       lock_timeout_ms, statement_timeout_ms, max_retries, estimated_rows,
       NULLIF(checkpoint->>'created_at','')::timestamptz,
       COALESCE(checkpoint->>'id',''),
       NULLIF(scan_upper_bound->>'created_at','')::timestamptz,
       COALESCE(scan_upper_bound->>'id','')
FROM migration_backfill_tasks
WHERE state IN ('pending','running')
  AND NOT pause_requested AND NOT cancel_requested
  AND (lease_expires_at IS NULL OR lease_expires_at < NOW() OR lease_owner = $1)
ORDER BY priority, updated_at, task_name
FOR UPDATE SKIP LOCKED
LIMIT 1`, owner).Scan(
		&task.Name, &task.Version, &task.BatchSize, &task.RateLimitRowsPerSecond,
		&lockTimeoutMS, &statementTimeoutMS, &task.MaxRetries, &task.EstimatedRows,
		&task.CheckpointCreatedAt, &task.CheckpointID,
		&task.UpperCreatedAt, &task.UpperID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	task.LockTimeout = time.Duration(lockTimeoutMS) * time.Millisecond
	task.StatementTimeout = time.Duration(statementTimeoutMS) * time.Millisecond

	if task.UpperCreatedAt == nil {
		var upperTime time.Time
		var upperID string
		upperBoundSQL, _ := taskSourceQueries(task.Name)
		err = tx.QueryRow(ctx, upperBoundSQL).Scan(&upperTime, &upperID)
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		} else if err != nil {
			return nil, err
		} else {
			task.UpperCreatedAt = &upperTime
			task.UpperID = upperID
		}
	}
	if task.EstimatedRows <= 0 {
		_, estimatedRowsSQL := taskSourceQueries(task.Name)
		if err = tx.QueryRow(ctx, estimatedRowsSQL).Scan(&task.EstimatedRows); err != nil {
			return nil, err
		}
	}

	_, err = tx.Exec(ctx, `
UPDATE migration_backfill_tasks
SET state='running', started_at=COALESCE(started_at,NOW()), updated_at=NOW(),
    heartbeat_at=NOW(), lease_owner=$3, lease_expires_at=NOW()+$4::interval,
    scan_upper_bound=CASE WHEN $5::timestamptz IS NULL THEN '{}'::jsonb
      ELSE jsonb_build_object('created_at',$5::timestamptz,'id',$6::text) END,
    estimated_rows=$7
WHERE task_name=$1 AND task_version=$2`,
		task.Name, task.Version, owner, intervalLiteral(lease), task.UpperCreatedAt, task.UpperID,
		task.EstimatedRows)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return task, nil
}

func taskSourceQueries(taskName string) (string, string) {
	if taskName == SecurityEventDeliveryTask {
		return `
SELECT COALESCE(created_at,'0001-01-01 00:00:00+00'::timestamptz),id FROM security_events
ORDER BY COALESCE(created_at,'0001-01-01 00:00:00+00'::timestamptz) DESC,id DESC LIMIT 1`,
			`SELECT GREATEST(COALESCE(reltuples,0)::bigint,0)
FROM pg_class WHERE oid='security_events'::regclass`
	}
	if taskName == EvidenceTitleNoiseTask {
		return `
SELECT created_at,request_log_id FROM evidence_run_request_index
ORDER BY created_at DESC,request_log_id DESC LIMIT 1`,
			`SELECT GREATEST(COALESCE(reltuples,0)::bigint,0)
FROM pg_class WHERE oid='evidence_run_request_index'::regclass`
	}
	return `
SELECT created_at,id FROM request_logs
ORDER BY created_at DESC,id DESC LIMIT 1`,
		`SELECT GREATEST(COALESCE(reltuples,0)::bigint,0)
FROM pg_class WHERE oid='request_logs'::regclass`
}

const customerContentProjectionBatchSQL = `
-- Each caller transaction executes SET LOCAL lock_timeout and
-- SET LOCAL statement_timeout before this bounded statement.
WITH candidates AS MATERIALIZED (
    SELECT rl.id, rl.created_at
    FROM request_logs rl
    WHERE CASE WHEN $6::boolean THEN
        EXISTS (
            SELECT 1 FROM migration_backfill_retry_rows retry
            WHERE retry.task_name=$2 AND retry.task_version=$3
              AND retry.row_id=rl.id AND retry.next_retry_at <= NOW()
        )
    ELSE
        ($4::timestamptz IS NULL OR (rl.created_at, rl.id) > ($4::timestamptz, $5::text))
        AND (rl.created_at, rl.id) <= ($7::timestamptz, $8::text)
    END
    ORDER BY rl.created_at, rl.id
    LIMIT $1
), locked AS MATERIALIZED (
    SELECT rl.*
    FROM request_logs rl
    JOIN candidates candidate ON candidate.id=rl.id
    ORDER BY rl.created_at, rl.id
    FOR NO KEY UPDATE OF rl SKIP LOCKED
), projected AS MATERIALIZED (
    SELECT rl.id,
      (
        EXISTS (
          SELECT 1 FROM access_content_logs acl
          WHERE acl.tenant_id=rl.tenant_id AND acl.request_id=rl.request_id
            AND (jjdguard_customer_content_text(acl.request_content_redacted)
              OR jjdguard_customer_content_text(acl.response_content_redacted)
              OR COALESCE(acl.file_metadata_json,'[]'::jsonb) <> '[]'::jsonb)
        ) OR (
          COALESCE(rl.proxy_mode,'') <> 'forward' AND EXISTS (
            SELECT 1 FROM content_logs cl
            WHERE cl.tenant_id=rl.tenant_id AND cl.request_id=rl.id
              AND cl.role IN ('user','assistant')
              AND jjdguard_customer_content_text(cl.content)
          )
        )
      ) AS has_content,
      (
        EXISTS (
          SELECT 1 FROM access_content_logs acl
          WHERE acl.tenant_id=rl.tenant_id AND acl.request_id=rl.request_id
            AND jjdguard_customer_content_text(acl.request_content_redacted)
        ) OR (
          COALESCE(rl.proxy_mode,'') <> 'forward' AND EXISTS (
            SELECT 1 FROM content_logs cl
            WHERE cl.tenant_id=rl.tenant_id AND cl.request_id=rl.id
              AND cl.role='user' AND jjdguard_customer_content_text(cl.content)
          )
        )
      ) AS has_request,
      (
        EXISTS (
          SELECT 1 FROM access_content_logs acl
          WHERE acl.tenant_id=rl.tenant_id AND acl.request_id=rl.request_id
            AND jjdguard_customer_content_text(acl.response_content_redacted)
        ) OR (
          COALESCE(rl.proxy_mode,'') <> 'forward' AND EXISTS (
            SELECT 1 FROM content_logs cl
            WHERE cl.tenant_id=rl.tenant_id AND cl.request_id=rl.id
              AND cl.role='assistant' AND jjdguard_customer_content_text(cl.content)
          )
        )
      ) AS has_response
    FROM locked rl
), changed AS (
    UPDATE request_logs rl
    SET has_customer_content=projected.has_content,
        has_customer_request_body=projected.has_request,
        has_customer_response_body=projected.has_response,
        customer_content_rule_version=1
    FROM projected
    WHERE rl.id=projected.id
      AND (rl.has_customer_content,rl.has_customer_request_body,
           rl.has_customer_response_body,rl.customer_content_rule_version)
          IS DISTINCT FROM
          (projected.has_content,projected.has_request,projected.has_response,1::smallint)
    RETURNING rl.id
), retry_saved AS (
    INSERT INTO migration_backfill_retry_rows(
      task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
    )
    SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
    FROM candidates candidate
    LEFT JOIN locked ON locked.id=candidate.id
    WHERE locked.id IS NULL
    ON CONFLICT (task_name,task_version,row_id) DO UPDATE
      SET attempts=migration_backfill_retry_rows.attempts+1,
          next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
    RETURNING row_id
), retry_cleared AS (
    DELETE FROM migration_backfill_retry_rows retry
    USING locked
    WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
    RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),
       (SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),
       (SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const requestLogCompatibilityBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
    SELECT rl.id,rl.created_at
    FROM request_logs rl
    WHERE CASE WHEN $6::boolean THEN
      EXISTS (
        SELECT 1 FROM migration_backfill_retry_rows retry
        WHERE retry.task_name=$2 AND retry.task_version=$3
          AND retry.row_id=rl.id AND retry.next_retry_at<=NOW()
      )
    ELSE
      ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
      AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
    END
    ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
    SELECT rl.*
    FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
    ORDER BY rl.created_at,rl.id
    FOR NO KEY UPDATE OF rl SKIP LOCKED
), derived AS MATERIALIZED (
    SELECT rl.id,
      CASE WHEN rl.proxy_mode='reverse'
             AND COALESCE(rl.proxy_target_host,'')=''
             AND COALESCE(rl.model_id,'')<>''
           THEN 'chat_completion' ELSE rl.proxy_mode END AS proxy_mode,
      retention.retention_until,
      CASE WHEN COALESCE(rl.agent_type,'') IN ('','agent-tool-call','vscode')
             AND COALESCE(rl.agent_detection_source,'') NOT IN ('explicit_header','client_header')
             AND EXISTS (SELECT 1 FROM unnest($9::text[]) ua_pattern WHERE strpos(LOWER(COALESCE(rl.proxy_user_agent,'')),ua_pattern)>0)
           THEN 'openai-codex' ELSE rl.agent_type END AS agent_type,
      CASE WHEN COALESCE(rl.agent_type,'') IN ('','agent-tool-call','vscode')
             AND COALESCE(rl.agent_detection_source,'') NOT IN ('explicit_header','client_header')
             AND EXISTS (SELECT 1 FROM unnest($9::text[]) ua_pattern WHERE strpos(LOWER(COALESCE(rl.proxy_user_agent,'')),ua_pattern)>0)
           THEN 'user_agent' ELSE rl.agent_detection_source END AS detection_source,
      CASE WHEN COALESCE(rl.agent_type,'') IN ('','agent-tool-call','vscode')
             AND COALESCE(rl.agent_detection_source,'') NOT IN ('explicit_header','client_header')
             AND EXISTS (SELECT 1 FROM unnest($9::text[]) ua_pattern WHERE strpos(LOWER(COALESCE(rl.proxy_user_agent,'')),ua_pattern)>0)
           THEN 0.85 ELSE rl.agent_detection_confidence END AS detection_confidence
    FROM locked rl
    LEFT JOIN LATERAL (
      SELECT MAX(acl.retention_until) AS retention_until
      FROM access_content_logs acl
      WHERE acl.tenant_id=rl.tenant_id AND acl.request_id=rl.request_id
        AND acl.retention_until IS NOT NULL
    ) retention ON TRUE
), changed AS (
    UPDATE request_logs rl SET
      proxy_mode=derived.proxy_mode,
      content_evidence_retention_until=COALESCE(derived.retention_until,rl.content_evidence_retention_until),
      agent_type=derived.agent_type,
      agent_detection_source=derived.detection_source,
      agent_detection_confidence=derived.detection_confidence
    FROM derived WHERE rl.id=derived.id
      AND (rl.proxy_mode,rl.content_evidence_retention_until,rl.agent_type,
           rl.agent_detection_source,rl.agent_detection_confidence)
          IS DISTINCT FROM
          (derived.proxy_mode,COALESCE(derived.retention_until,rl.content_evidence_retention_until),
           derived.agent_type,derived.detection_source,derived.detection_confidence)
    RETURNING rl.id
), retry_saved AS (
    INSERT INTO migration_backfill_retry_rows(
      task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
    )
    SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
    FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
    WHERE locked.id IS NULL
    ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
      attempts=migration_backfill_retry_rows.attempts+1,
      next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
    RETURNING row_id
), retry_cleared AS (
    DELETE FROM migration_backfill_retry_rows retry USING locked
    WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
    RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const customerEnvironmentScopeBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT rl.id,rl.request_id,rl.tenant_id,rl.created_at
  FROM request_logs rl
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=rl.id AND retry.next_retry_at<=NOW())
  ELSE
    ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
    AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
  END
  ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
  SELECT rl.*
  FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
  ORDER BY rl.created_at,rl.id
  FOR NO KEY UPDATE OF rl SKIP LOCKED
), access_candidates AS MATERIALIZED (
  SELECT acl.id,candidate.id AS parent_id
  FROM access_content_logs acl JOIN locked candidate
    ON candidate.tenant_id=acl.tenant_id AND candidate.request_id=acl.request_id
  WHERE COALESCE(acl.environment_scope,'') IN ('','legacy-unclassified')
), access_locked AS MATERIALIZED (
  SELECT acl.id,candidate.parent_id FROM access_content_logs acl
  JOIN access_candidates candidate ON candidate.id=acl.id
  FOR NO KEY UPDATE OF acl SKIP LOCKED
), content_candidates AS MATERIALIZED (
  SELECT cl.id,candidate.id AS parent_id
  FROM content_logs cl JOIN locked candidate
    ON candidate.tenant_id=cl.tenant_id AND candidate.id=cl.request_id
  WHERE COALESCE(cl.environment_scope,'') IN ('','legacy-unclassified')
), content_locked AS MATERIALIZED (
  SELECT cl.id,candidate.parent_id FROM content_logs cl
  JOIN content_candidates candidate ON candidate.id=cl.id
  FOR NO KEY UPDATE OF cl SKIP LOCKED
), artifact_candidates AS MATERIALIZED (
  SELECT artifact.id,candidate.id AS parent_id
  FROM retained_artifacts artifact JOIN locked candidate
    ON candidate.tenant_id=artifact.tenant_id AND candidate.request_id=artifact.source_request_id
  WHERE COALESCE(artifact.environment_scope,'') IN ('','legacy-unclassified')
), artifact_locked AS MATERIALIZED (
  SELECT artifact.id,candidate.parent_id FROM retained_artifacts artifact
  JOIN artifact_candidates candidate ON candidate.id=artifact.id
  FOR NO KEY UPDATE OF artifact SKIP LOCKED
), link_candidates AS MATERIALIZED (
  SELECT link.id,candidate.id AS parent_id
  FROM access_content_artifact_links link JOIN locked candidate
    ON candidate.tenant_id=link.tenant_id AND candidate.request_id=link.request_id
  WHERE COALESCE(link.environment_scope,'') IN ('','legacy-unclassified')
), link_locked AS MATERIALIZED (
  SELECT link.id,candidate.parent_id FROM access_content_artifact_links link
  JOIN link_candidates candidate ON candidate.id=link.id
  FOR NO KEY UPDATE OF link SKIP LOCKED
), blocked_parents AS MATERIALIZED (
  SELECT parent_id FROM access_candidates EXCEPT SELECT parent_id FROM access_locked
  UNION
  SELECT parent_id FROM content_candidates EXCEPT SELECT parent_id FROM content_locked
  UNION
  SELECT parent_id FROM artifact_candidates EXCEPT SELECT parent_id FROM artifact_locked
  UNION
  SELECT parent_id FROM link_candidates EXCEPT SELECT parent_id FROM link_locked
), request_changed AS (
  UPDATE request_logs rl SET environment_scope='customer'
  FROM locked WHERE rl.id=locked.id
    AND COALESCE(rl.environment_scope,'') IN ('','legacy-unclassified')
  RETURNING rl.id
), access_changed AS (
  UPDATE access_content_logs acl SET environment_scope='customer'
  FROM access_locked WHERE acl.id=access_locked.id RETURNING acl.id
), content_changed AS (
  UPDATE content_logs cl SET environment_scope='customer'
  FROM content_locked WHERE cl.id=content_locked.id RETURNING cl.id
), artifact_changed AS (
  UPDATE retained_artifacts artifact SET environment_scope='customer'
  FROM artifact_locked WHERE artifact.id=artifact_locked.id RETURNING artifact.id
), link_changed AS (
  UPDATE access_content_artifact_links link SET environment_scope='customer'
  FROM link_locked WHERE link.id=link_locked.id RETURNING link.id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL OR EXISTS (
    SELECT 1 FROM blocked_parents blocked WHERE blocked.parent_id=candidate.id
  )
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
    AND NOT EXISTS (SELECT 1 FROM blocked_parents blocked WHERE blocked.parent_id=locked.id)
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),
       (SELECT COUNT(*) FROM request_changed)+(SELECT COUNT(*) FROM access_changed)+
       (SELECT COUNT(*) FROM content_changed)+(SELECT COUNT(*) FROM artifact_changed)+
       (SELECT COUNT(*) FROM link_changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

// customerEnvironmentScopeDedupBatchSQL 用于迁移 987 之后：content_logs 变成
// content_log_entries ⋈ content_log_bodies ∪ content_logs_legacy 的兼容视图，视图上不能加行锁，
// 所以分别锁两张底表、分别更新，语义与单表版本完全一致（正文表不含 environment_scope，不需要动）。
const customerEnvironmentScopeDedupBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT rl.id,rl.request_id,rl.tenant_id,rl.created_at
  FROM request_logs rl
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=rl.id AND retry.next_retry_at<=NOW())
  ELSE
    ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
    AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
  END
  ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
  SELECT rl.*
  FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
  ORDER BY rl.created_at,rl.id
  FOR NO KEY UPDATE OF rl SKIP LOCKED
), access_candidates AS MATERIALIZED (
  SELECT acl.id,candidate.id AS parent_id
  FROM access_content_logs acl JOIN locked candidate
    ON candidate.tenant_id=acl.tenant_id AND candidate.request_id=acl.request_id
  WHERE COALESCE(acl.environment_scope,'') IN ('','legacy-unclassified')
), access_locked AS MATERIALIZED (
  SELECT acl.id,candidate.parent_id FROM access_content_logs acl
  JOIN access_candidates candidate ON candidate.id=acl.id
  FOR NO KEY UPDATE OF acl SKIP LOCKED
), content_entry_candidates AS MATERIALIZED (
  SELECT cl.id,candidate.id AS parent_id
  FROM content_log_entries cl JOIN locked candidate
    ON candidate.tenant_id=cl.tenant_id AND candidate.id=cl.request_id
  WHERE COALESCE(cl.environment_scope,'') IN ('','legacy-unclassified')
), content_entry_locked AS MATERIALIZED (
  SELECT cl.id,candidate.parent_id FROM content_log_entries cl
  JOIN content_entry_candidates candidate ON candidate.id=cl.id
  FOR NO KEY UPDATE OF cl SKIP LOCKED
), content_legacy_candidates AS MATERIALIZED (
  SELECT cl.id,candidate.id AS parent_id
  FROM content_logs_legacy cl JOIN locked candidate
    ON candidate.tenant_id=cl.tenant_id AND candidate.id=cl.request_id
  WHERE COALESCE(cl.environment_scope,'') IN ('','legacy-unclassified')
), content_legacy_locked AS MATERIALIZED (
  SELECT cl.id,candidate.parent_id FROM content_logs_legacy cl
  JOIN content_legacy_candidates candidate ON candidate.id=cl.id
  FOR NO KEY UPDATE OF cl SKIP LOCKED
), content_candidates AS MATERIALIZED (
  SELECT id,parent_id FROM content_entry_candidates
  UNION ALL SELECT id,parent_id FROM content_legacy_candidates
), content_locked AS MATERIALIZED (
  SELECT id,parent_id FROM content_entry_locked
  UNION ALL SELECT id,parent_id FROM content_legacy_locked
), artifact_candidates AS MATERIALIZED (
  SELECT artifact.id,candidate.id AS parent_id
  FROM retained_artifacts artifact JOIN locked candidate
    ON candidate.tenant_id=artifact.tenant_id AND candidate.request_id=artifact.source_request_id
  WHERE COALESCE(artifact.environment_scope,'') IN ('','legacy-unclassified')
), artifact_locked AS MATERIALIZED (
  SELECT artifact.id,candidate.parent_id FROM retained_artifacts artifact
  JOIN artifact_candidates candidate ON candidate.id=artifact.id
  FOR NO KEY UPDATE OF artifact SKIP LOCKED
), link_candidates AS MATERIALIZED (
  SELECT link.id,candidate.id AS parent_id
  FROM access_content_artifact_links link JOIN locked candidate
    ON candidate.tenant_id=link.tenant_id AND candidate.request_id=link.request_id
  WHERE COALESCE(link.environment_scope,'') IN ('','legacy-unclassified')
), link_locked AS MATERIALIZED (
  SELECT link.id,candidate.parent_id FROM access_content_artifact_links link
  JOIN link_candidates candidate ON candidate.id=link.id
  FOR NO KEY UPDATE OF link SKIP LOCKED
), blocked_parents AS MATERIALIZED (
  SELECT parent_id FROM access_candidates EXCEPT SELECT parent_id FROM access_locked
  UNION
  SELECT parent_id FROM content_candidates EXCEPT SELECT parent_id FROM content_locked
  UNION
  SELECT parent_id FROM artifact_candidates EXCEPT SELECT parent_id FROM artifact_locked
  UNION
  SELECT parent_id FROM link_candidates EXCEPT SELECT parent_id FROM link_locked
), request_changed AS (
  UPDATE request_logs rl SET environment_scope='customer'
  FROM locked WHERE rl.id=locked.id
    AND COALESCE(rl.environment_scope,'') IN ('','legacy-unclassified')
  RETURNING rl.id
), access_changed AS (
  UPDATE access_content_logs acl SET environment_scope='customer'
  FROM access_locked WHERE acl.id=access_locked.id RETURNING acl.id
), content_entry_changed AS (
  UPDATE content_log_entries cl SET environment_scope='customer'
  FROM content_entry_locked WHERE cl.id=content_entry_locked.id RETURNING cl.id
), content_legacy_changed AS (
  UPDATE content_logs_legacy cl SET environment_scope='customer'
  FROM content_legacy_locked WHERE cl.id=content_legacy_locked.id RETURNING cl.id
), content_changed AS (
  SELECT id FROM content_entry_changed UNION ALL SELECT id FROM content_legacy_changed
), artifact_changed AS (
  UPDATE retained_artifacts artifact SET environment_scope='customer'
  FROM artifact_locked WHERE artifact.id=artifact_locked.id RETURNING artifact.id
), link_changed AS (
  UPDATE access_content_artifact_links link SET environment_scope='customer'
  FROM link_locked WHERE link.id=link_locked.id RETURNING link.id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL OR EXISTS (
    SELECT 1 FROM blocked_parents blocked WHERE blocked.parent_id=candidate.id
  )
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
    AND NOT EXISTS (SELECT 1 FROM blocked_parents blocked WHERE blocked.parent_id=locked.id)
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),
       (SELECT COUNT(*) FROM request_changed)+(SELECT COUNT(*) FROM access_changed)+
       (SELECT COUNT(*) FROM content_changed)+(SELECT COUNT(*) FROM artifact_changed)+
       (SELECT COUNT(*) FROM link_changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const evidenceAgentProjectionBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT rl.id,rl.created_at
  FROM request_logs rl
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=rl.id AND retry.next_retry_at<=NOW())
  ELSE
    ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
    AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
  END
  ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
  SELECT rl.*
  FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
  ORDER BY rl.created_at,rl.id
  FOR NO KEY UPDATE OF rl SKIP LOCKED
), changed AS (
  UPDATE evidence_run_request_index eri SET
    effective_agent_type=COALESCE(rl.agent_type,''),
    effective_agent_runtime=COALESCE(NULLIF(rl.agent_runtime,''),
      CASE WHEN LOWER(BTRIM(COALESCE(rl.agent_type,'')))='vscode' THEN 'vscode' ELSE '' END),
    effective_detection_source=COALESCE(rl.agent_detection_source,''),
    effective_detection_confidence=COALESCE(rl.agent_detection_confidence,0),
    session_id=COALESCE(rl.session_id,''),
    evidence_run_id=CASE WHEN COALESCE(rl.evidence_run_source,'') IN (
      'responses_prompt_cache_key','responses_prompt_cache_key_candidate'
    ) THEN '' ELSE COALESCE(rl.evidence_run_id,'') END,
    evidence_run_source=COALESCE(rl.evidence_run_source,''),
    chain_dirty=TRUE,updated_at=NOW()
  FROM locked rl
  WHERE rl.tenant_id=eri.tenant_id AND rl.id=eri.request_log_id
    AND eri.effective_agent_type='openai-codex'
    AND LOWER(BTRIM(COALESCE(rl.agent_type,''))) NOT IN (
      '','main','default','agent','assistant','unknown','electron','vscode',
      'openai-codex','codex','codex-cli','openai codex'
    )
  RETURNING eri.request_log_id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const securityEventDeliveryBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT se.id,COALESCE(se.created_at,'0001-01-01 00:00:00+00'::timestamptz) AS created_at
  FROM security_events se
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=se.id AND retry.next_retry_at<=NOW())
  ELSE
    se.alerted_at IS NOT NULL
    AND (se.processed_at IS NULL OR se.delivery IS NULL)
    AND ($4::timestamptz IS NULL OR
      (COALESCE(se.created_at,'0001-01-01 00:00:00+00'::timestamptz),se.id)>($4::timestamptz,$5::text))
    AND (COALESCE(se.created_at,'0001-01-01 00:00:00+00'::timestamptz),se.id)
      <=($7::timestamptz,$8::text)
  END
  ORDER BY COALESCE(se.created_at,'0001-01-01 00:00:00+00'::timestamptz),se.id
  LIMIT $1
), locked AS MATERIALIZED (
  SELECT se.*
  FROM security_events se JOIN candidates candidate ON candidate.id=se.id
  ORDER BY COALESCE(se.created_at,'0001-01-01 00:00:00+00'::timestamptz),se.id
  FOR NO KEY UPDATE OF se SKIP LOCKED
), changed AS (
  UPDATE security_events se SET
    processed_at=COALESCE(se.processed_at,se.alerted_at),
    delivery=COALESCE(se.delivery,'delivered')
  FROM locked
  WHERE se.id=locked.id AND se.alerted_at IS NOT NULL
    AND (se.processed_at IS NULL OR se.delivery IS NULL)
  RETURNING se.id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const evidenceTitleNoiseBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT eri.request_log_id AS id,eri.created_at
  FROM evidence_run_request_index eri
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=eri.request_log_id AND retry.next_retry_at<=NOW())
  ELSE
    eri.evidence_run_source IN (
      'responses_prompt_cache_key','responses_prompt_cache_key_candidate'
    )
    AND ($4::timestamptz IS NULL OR
      (eri.created_at,eri.request_log_id)>($4::timestamptz,$5::text))
    AND (eri.created_at,eri.request_log_id)<=($7::timestamptz,$8::text)
  END
  ORDER BY eri.created_at,eri.request_log_id LIMIT $1
), locked AS MATERIALIZED (
  SELECT eri.*
  FROM evidence_run_request_index eri
  JOIN candidates candidate ON candidate.id=eri.request_log_id
  ORDER BY eri.created_at,eri.request_log_id
  FOR NO KEY UPDATE OF eri SKIP LOCKED
), derived AS MATERIALIZED (
  SELECT eri.tenant_id,eri.request_log_id,
    md5(COALESCE(
      NULLIF(BTRIM(title_cl.content, '"'), ''),
      NULLIF(acl.request_content_redacted, ''),
      ''
    )) AS title_hash
  FROM locked eri
  JOIN request_logs rl
    ON rl.tenant_id=eri.tenant_id AND rl.id=eri.request_log_id
  LEFT JOIN LATERAL (
    SELECT cl.content
    FROM content_logs cl
    WHERE cl.tenant_id=rl.tenant_id AND cl.request_id=rl.id
      AND cl.role='user' AND jjdguard_customer_content_text(cl.content)
    ORDER BY cl.created_at,cl.id LIMIT 1
  ) title_cl ON TRUE
  LEFT JOIN LATERAL (
    SELECT acl_inner.request_content_redacted
    FROM access_content_logs acl_inner
    WHERE acl_inner.tenant_id=rl.tenant_id
      AND acl_inner.request_id=rl.request_id
      AND jjdguard_customer_content_text(acl_inner.request_content_redacted)
    ORDER BY acl_inner.created_at,acl_inner.id LIMIT 1
  ) acl ON TRUE
), changed AS (
  UPDATE evidence_run_request_index eri SET
    title_hash=derived.title_hash,
    chain_dirty=eri.chain_dirty OR eri.title_hash IS DISTINCT FROM derived.title_hash,
    updated_at=NOW()
  FROM derived
  WHERE eri.tenant_id=derived.tenant_id
    AND eri.request_log_id=derived.request_log_id
    AND eri.title_hash IS DISTINCT FROM derived.title_hash
  RETURNING eri.request_log_id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.request_log_id=candidate.id
  WHERE locked.request_log_id IS NULL
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3
    AND retry.row_id=locked.request_log_id
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const workBuddyIdentityBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT rl.id,rl.created_at
  FROM request_logs rl
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=rl.id AND retry.next_retry_at<=NOW())
  ELSE
    ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
    AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
  END
  ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
  SELECT rl.*
  FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
  ORDER BY rl.created_at,rl.id
  FOR NO KEY UPDATE OF rl SKIP LOCKED
), derived AS MATERIALIZED (
  SELECT rl.*,
    COALESCE(exact_workspace.workspace,generic_workspace.workspace) AS workspace,
    exact_workspace.workspace IS NOT NULL AS product_match,
    jsonb_build_object(
      'agent_type',rl.agent_type,
      'source',rl.agent_detection_source,
      'confidence',rl.agent_detection_confidence,
      'evidence_run_id',rl.evidence_run_id,
      'evidence_run_source',rl.evidence_run_source
    ) AS previous_identity
  FROM locked rl
  LEFT JOIN LATERAL (
    SELECT MIN(match.workspace) AS workspace
    FROM (
      SELECT BTRIM((regexp_match(
        cl.content,
        '(?s)^\s*<system-reminder\s+data-role=["'']user-context["'']>\s*<user_info>.*?Workspace Folder:[ \t]*([^\r\n<]+).*?</user_info>.*?<product_identity>\s*You are WorkBuddy,.*?</product_identity>.*?</system-reminder>\s*<user_query>.*?</user_query>\s*$'
      ))[1]) AS workspace
      FROM content_logs cl
      WHERE cl.request_id=rl.id AND cl.tenant_id=rl.tenant_id
        AND cl.environment_scope=rl.environment_scope AND cl.role='user'
    ) match
    WHERE match.workspace IS NOT NULL AND match.workspace<>''
    HAVING COUNT(DISTINCT match.workspace)=1
  ) exact_workspace ON
    rl.created_at >= (
      SELECT started_at-INTERVAL '7 days' FROM migration_backfill_tasks
      WHERE task_name=$2 AND task_version=$3
    )
    AND rl.agent_identity_rule_id IS NULL
    AND (
      COALESCE(rl.agent_detection_source,'') IN (
        '','message_protocol','content','user_agent_runtime'
      )
      OR (
        rl.agent_type IN ('main','default','agent','assistant','unknown')
        AND rl.agent_detection_source IN ('client_header','explicit_header')
      )
    )
    AND COALESCE(rl.session_id,'')=''
  LEFT JOIN LATERAL (
    SELECT MIN(match.workspace) AS workspace
    FROM (
      SELECT BTRIM((regexp_match(
        cl.content,E'(^|\\n)Workspace Folder:[ \\t]*([^\\r\\n<]+)','n'
      ))[2]) AS workspace
      FROM content_logs cl
      WHERE cl.request_id=rl.id AND cl.tenant_id=rl.tenant_id
        AND cl.environment_scope=rl.environment_scope AND cl.role='user'
    ) match
    WHERE match.workspace IS NOT NULL AND match.workspace<>''
    HAVING COUNT(DISTINCT match.workspace)=1
  ) generic_workspace ON
    LOWER(COALESCE(rl.agent_type,''))='workbuddy'
    AND COALESCE(rl.evidence_run_id,'')=''
), repair_saved AS (
  INSERT INTO agent_protocol_repairs(
    migration,tenant_id,request_id,previous_identity
  )
  SELECT '831',tenant_id,request_id,previous_identity
  FROM derived WHERE product_match
  ON CONFLICT DO NOTHING
  RETURNING request_id
), changed AS (
  UPDATE request_logs rl SET
    agent_type=CASE WHEN derived.product_match THEN 'workbuddy' ELSE rl.agent_type END,
    agent_detection_source=CASE
      WHEN derived.product_match THEN 'product_identity'
      ELSE rl.agent_detection_source
    END,
    agent_detection_confidence=CASE
      WHEN derived.product_match THEN 0.98
      ELSE rl.agent_detection_confidence
    END,
    evidence_run_source=CASE
      WHEN derived.workspace IS NOT NULL THEN 'workbuddy_workspace'
      ELSE rl.evidence_run_source
    END,
    evidence_run_id=CASE WHEN derived.workspace IS NOT NULL THEN
      'run_' || SUBSTR(ENCODE(SHA256(
        CONVERT_TO(rl.tenant_id,'UTF8') || DECODE('00','hex') ||
        CONVERT_TO('workbuddy_workspace','UTF8') || DECODE('00','hex') ||
        CONVERT_TO(derived.workspace,'UTF8')
      ),'hex'),1,32)
      ELSE rl.evidence_run_id
    END
  FROM derived CROSS JOIN (SELECT COUNT(*) FROM repair_saved) audit_barrier
  WHERE rl.id=derived.id AND derived.workspace IS NOT NULL
  RETURNING rl.id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

const usageRollupDimensionsBatchSQL = `
-- SET LOCAL lock_timeout and SET LOCAL statement_timeout are applied by caller.
WITH candidates AS MATERIALIZED (
  SELECT rl.id,rl.created_at
  FROM request_logs rl
  WHERE CASE WHEN $6::boolean THEN
    EXISTS (SELECT 1 FROM migration_backfill_retry_rows retry
      WHERE retry.task_name=$2 AND retry.task_version=$3
        AND retry.row_id=rl.id AND retry.next_retry_at<=NOW())
  ELSE
    ($4::timestamptz IS NULL OR (rl.created_at,rl.id)>($4::timestamptz,$5::text))
    AND (rl.created_at,rl.id)<=($7::timestamptz,$8::text)
  END
  ORDER BY rl.created_at,rl.id LIMIT $1
), locked AS MATERIALIZED (
  SELECT rl.*
  FROM request_logs rl JOIN candidates candidate ON candidate.id=rl.id
  ORDER BY rl.created_at,rl.id
  FOR KEY SHARE OF rl SKIP LOCKED
), affected AS MATERIALIZED (
  SELECT DISTINCT tenant_id,date_trunc('hour',created_at) AS bucket_start,
    COALESCE(project_id,'') AS project_id,COALESCE(user_id,'') AS user_id,
    COALESCE(client_id,'') AS client_id,COALESCE(provider_id,'') AS provider_id,
    COALESCE(model_id,'') AS model_id
  FROM locked
), aggregated AS MATERIALIZED (
  SELECT rl.tenant_id,date_trunc('hour',rl.created_at) AS bucket_start,
    COALESCE(rl.project_id,'') AS project_id,COALESCE(rl.user_id,'') AS user_id,
    COALESCE(rl.client_id,'') AS client_id,COALESCE(rl.provider_id,'') AS provider_id,
    COALESCE(rl.model_id,'') AS model_id,
    COUNT(*) FILTER (WHERE rl.latency_ms IS NOT NULL) AS latency_count,
    MIN(rl.created_at) FILTER (WHERE rl.total_cost IS NOT NULL) AS first_priced_at
  FROM request_logs rl JOIN affected a
    ON a.tenant_id=rl.tenant_id
    AND a.bucket_start=date_trunc('hour',rl.created_at)
    AND a.project_id=COALESCE(rl.project_id,'')
    AND a.user_id=COALESCE(rl.user_id,'')
    AND a.client_id=COALESCE(rl.client_id,'')
    AND a.provider_id=COALESCE(rl.provider_id,'')
    AND a.model_id=COALESCE(rl.model_id,'')
  GROUP BY 1,2,3,4,5,6,7
), changed AS (
  UPDATE usage_rollup_hourly ur SET
    latency_count=aggregated.latency_count,
    first_priced_at=aggregated.first_priced_at
  FROM aggregated
  WHERE ur.tenant_id=aggregated.tenant_id
    AND ur.bucket_start=aggregated.bucket_start
    AND ur.project_id=aggregated.project_id
    AND ur.user_id=aggregated.user_id
    AND ur.client_id=aggregated.client_id
    AND ur.provider_id=aggregated.provider_id
    AND ur.model_id=aggregated.model_id
    AND (ur.latency_count,ur.first_priced_at)
      IS DISTINCT FROM (aggregated.latency_count,aggregated.first_priced_at)
  RETURNING ur.tenant_id
), retry_saved AS (
  INSERT INTO migration_backfill_retry_rows(
    task_name,task_version,row_id,row_created_at,attempts,next_retry_at,updated_at
  )
  SELECT $2,$3,candidate.id,candidate.created_at,1,NOW()+INTERVAL '5 seconds',NOW()
  FROM candidates candidate LEFT JOIN locked ON locked.id=candidate.id
  WHERE locked.id IS NULL
  ON CONFLICT(task_name,task_version,row_id) DO UPDATE SET
    attempts=migration_backfill_retry_rows.attempts+1,
    next_retry_at=NOW()+INTERVAL '5 seconds',updated_at=NOW()
  RETURNING row_id
), retry_cleared AS (
  DELETE FROM migration_backfill_retry_rows retry USING locked
  WHERE retry.task_name=$2 AND retry.task_version=$3 AND retry.row_id=locked.id
  RETURNING retry.row_id
)
SELECT (SELECT COUNT(*) FROM candidates),(SELECT COUNT(*) FROM changed),
       (SELECT COUNT(*) FROM retry_saved),(SELECT MAX(created_at) FROM candidates),
       COALESCE((SELECT id FROM candidates ORDER BY created_at DESC,id DESC LIMIT 1),'')
`

func (s *PostgresStore) RunBatch(ctx context.Context, task *Task, owner string, lease time.Duration) (BatchResult, error) {
	if task.UpperCreatedAt == nil {
		return BatchResult{Done: true}, nil
	}
	retryPhase := task.CheckpointCreatedAt != nil &&
		(!task.CheckpointCreatedAt.Before(*task.UpperCreatedAt) &&
			task.CheckpointID >= task.UpperID)

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return BatchResult{}, err
	}
	defer tx.Rollback(ctx)
	started := time.Now()
	if _, err = tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true),
set_config('statement_timeout',$2,true),set_config('idle_in_transaction_session_timeout',$3,true)`,
		millisLiteral(task.LockTimeout), millisLiteral(task.StatementTimeout),
		millisLiteral(task.StatementTimeout+5*time.Second)); err != nil {
		return BatchResult{}, err
	}

	var result BatchResult
	var cursorTime *time.Time
	var cursorID string
	batchSQL := customerContentProjectionBatchSQL
	if task.Name == RequestLogCompatibilityTask {
		batchSQL = requestLogCompatibilityBatchSQL
	} else if task.Name == CustomerEnvironmentScopeTask {
		batchSQL = customerEnvironmentScopeBatchSQL
		var dedup bool
		if err = tx.QueryRow(ctx, `SELECT to_regclass('content_log_entries') IS NOT NULL`).Scan(&dedup); err != nil {
			return BatchResult{}, err
		}
		if dedup {
			batchSQL = customerEnvironmentScopeDedupBatchSQL
		}
	} else if task.Name == EvidenceAgentProjectionTask {
		batchSQL = evidenceAgentProjectionBatchSQL
	} else if task.Name == SecurityEventDeliveryTask {
		batchSQL = securityEventDeliveryBatchSQL
	} else if task.Name == EvidenceTitleNoiseTask {
		batchSQL = evidenceTitleNoiseBatchSQL
	} else if task.Name == WorkBuddyIdentityTask {
		batchSQL = workBuddyIdentityBatchSQL
	} else if task.Name == UsageRollupDimensionsTask {
		batchSQL = usageRollupDimensionsBatchSQL
	}
	if task.Name == AgentUAIdentityTask || task.Name == AgentUAIdentityCodexTask {
		result, cursorTime, cursorID, err = runAgentUAIdentityBatch(ctx, tx, task, retryPhase)
	} else {
		args := []any{task.BatchSize, task.Name, task.Version, task.CheckpointCreatedAt,
			task.CheckpointID, retryPhase, task.UpperCreatedAt, task.UpperID}
		if task.Name == RequestLogCompatibilityTask {
			// Codex 的 UA 特征与网关识别同源（agent-registry.json），不在 SQL 里手写正则。
			args = append(args, agentdetect.ProductPatterns("openai-codex"))
		}
		err = tx.QueryRow(ctx, batchSQL, args...).Scan(&result.Scanned, &result.Updated, &result.Skipped, &cursorTime, &cursorID)
	}
	if err != nil {
		return result, err
	}

	if !retryPhase {
		if result.Scanned == 0 {
			cursorTime = task.UpperCreatedAt
			cursorID = task.UpperID
		}
		if cursorTime != nil {
			task.CheckpointCreatedAt = cursorTime
			task.CheckpointID = cursorID
		}
	}
	var retryCount int64
	if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM migration_backfill_retry_rows
WHERE task_name=$1 AND task_version=$2`, task.Name, task.Version).Scan(&retryCount); err != nil {
		return result, err
	}
	result.Done = retryPhase && result.Scanned == 0 && retryCount == 0
	elapsedSeconds := time.Since(started).Seconds()
	if elapsedSeconds < 0.001 {
		elapsedSeconds = 0.001
	}

	_, err = tx.Exec(ctx, `
UPDATE migration_backfill_tasks SET
 checkpoint=CASE WHEN $4::timestamptz IS NULL THEN checkpoint
   ELSE jsonb_build_object('created_at',$4::timestamptz,'id',$5::text) END,
 scanned=scanned+$6, updated=updated+$7, skipped=skipped+$8,
 current_rate=$6::double precision/$9::double precision,
 eta_seconds=CASE WHEN $6 > 0 THEN
   CEIL(GREATEST(estimated_rows-(scanned+$6),0)/($6::double precision/$9::double precision))::bigint
   ELSE eta_seconds END,
 heartbeat_at=NOW(), updated_at=NOW(), lease_expires_at=NOW()+$10::interval
WHERE task_name=$1 AND task_version=$2 AND lease_owner=$3`,
		task.Name, task.Version, owner, task.CheckpointCreatedAt, task.CheckpointID,
		result.Scanned, result.Updated, result.Skipped, elapsedSeconds, intervalLiteral(lease))
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func (s *PostgresStore) Complete(ctx context.Context, task *Task, owner string, result BatchResult) error {
	_, err := s.db.Exec(ctx, `
WITH completed AS (
 UPDATE migration_backfill_tasks SET state='completed',validation_status='passed',
   completed_at=NOW(),updated_at=NOW(),heartbeat_at=NOW(),
   lease_owner=NULL,lease_expires_at=NULL,error_summary=''
 WHERE task_name=$1 AND task_version=$2 AND lease_owner=$3
 RETURNING task_name,task_version,state
)
INSERT INTO migration_backfill_events(task_name,task_version,event_type,state,summary,metrics)
SELECT task_name,task_version,'completed',state,'Background validation passed',
 jsonb_build_object('batch_scanned',$4::bigint,'batch_updated',$5::bigint)
FROM completed`, task.Name, task.Version, owner, result.Scanned, result.Updated)
	return err
}

func (s *PostgresStore) Release(ctx context.Context, task *Task, owner string, result BatchResult, cause error) error {
	summary := "unknown failure"
	if cause != nil {
		summary = cause.Error()
	}
	if len(summary) > 500 {
		summary = summary[:500]
	}
	_, err := s.db.Exec(ctx, `
WITH released AS (
 UPDATE migration_backfill_tasks SET
   retry_count=retry_count+1, failed=failed+$4,
   state=CASE WHEN retry_count+1 >= max_retries THEN 'failed' ELSE 'pending' END,
   error_summary=$5,updated_at=NOW(),heartbeat_at=NOW(),
   lease_owner=NULL,lease_expires_at=NULL
 WHERE task_name=$1 AND task_version=$2 AND lease_owner=$3
 RETURNING task_name,task_version,state
)
INSERT INTO migration_backfill_events(task_name,task_version,event_type,state,summary,metrics)
SELECT task_name,task_version,'batch_failed',state,$5,
 jsonb_build_object('scanned',$6::bigint,'updated',$7::bigint,'skipped',$8::bigint)
FROM released`, task.Name, task.Version, owner, result.Failed, summary,
		result.Scanned, result.Updated, result.Skipped)
	return err
}

func intervalLiteral(duration time.Duration) string {
	return fmt.Sprintf("%d milliseconds", duration.Milliseconds())
}

func millisLiteral(duration time.Duration) string {
	return fmt.Sprintf("%dms", duration.Milliseconds())
}

var _ Store = (*PostgresStore)(nil)
