package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/jackc/pgx/v5"
)

const maxIdentityCacheInvalidationAttempts = 10

func (r *UserIdentityLinkRepository) ClaimNextInvalidation(
	ctx context.Context,
	workerID string,
) (*identitybinding.CacheInvalidationEvent, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" || len(workerID) > 128 {
		return nil, identitybinding.ErrConflict
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin identity cache invalidation claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var event identitybinding.CacheInvalidationEvent
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id
			FROM identity_cache_invalidation_outbox
			WHERE (
				status IN ('pending','failed')
				AND next_attempt_at <= NOW()
			) OR (
				status = 'processing'
				AND locked_at < NOW() - INTERVAL '5 minutes'
			)
			ORDER BY
				CASE WHEN status='processing' THEN 0 ELSE 1 END,
				next_attempt_at ASC,
				created_at ASC,
				id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE identity_cache_invalidation_outbox event
		SET status='processing',
		    attempt_count=event.attempt_count+1,
		    locked_at=NOW(),
		    locked_by=$1,
		    last_error='',
		    updated_at=NOW()
		FROM candidate
		WHERE event.id=candidate.id
		RETURNING event.id,event.tenant_id,event.user_id,
		          event.old_department_id,event.new_department_id,event.attempt_count
	`, workerID).Scan(
		&event.ID,
		&event.TenantID,
		&event.UserID,
		&event.OldDepartmentID,
		&event.NewDepartmentID,
		&event.AttemptCount,
	)
	if err == pgx.ErrNoRows {
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit empty identity cache invalidation claim: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim identity cache invalidation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit identity cache invalidation claim: %w", err)
	}
	return &event, nil
}

func (r *UserIdentityLinkRepository) MarkInvalidationProcessed(
	ctx context.Context,
	eventID, workerID string,
) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE identity_cache_invalidation_outbox
		SET status='processed', processed_at=NOW(), updated_at=NOW(),
		    locked_at=NULL, locked_by='', last_error=''
		WHERE id=$1 AND status='processing' AND locked_by=$2
	`, eventID, workerID)
	if err != nil {
		return fmt.Errorf("mark identity cache invalidation processed: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identitybinding.ErrNotFound
	}
	return nil
}

func (r *UserIdentityLinkRepository) MarkInvalidationFailed(
	ctx context.Context,
	eventID, workerID, safeError string,
	nextAttempt time.Time,
) error {
	safeError = strings.TrimSpace(safeError)
	if eventID == "" || workerID == "" || safeError == "" || nextAttempt.IsZero() {
		return identitybinding.ErrConflict
	}
	safeErrorRunes := []rune(safeError)
	if len(safeErrorRunes) > 512 {
		safeError = string(safeErrorRunes[:512])
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE identity_cache_invalidation_outbox
		SET status=CASE
		      WHEN attempt_count >= $5 THEN 'dead_letter'
		      ELSE 'failed'
		    END,
		    next_attempt_at=$3, updated_at=NOW(),
		    locked_at=NULL, locked_by='', last_error=$4
		WHERE id=$1 AND status='processing' AND locked_by=$2
	`, eventID, workerID, nextAttempt, safeError, maxIdentityCacheInvalidationAttempts)
	if err != nil {
		return fmt.Errorf("mark identity cache invalidation failed: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identitybinding.ErrNotFound
	}
	return nil
}

func (r *UserIdentityLinkRepository) CleanupProcessedInvalidations(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	if before.IsZero() || limit <= 0 || limit > 10_000 {
		return 0, identitybinding.ErrConflict
	}
	tag, err := r.db.Exec(ctx, `
		WITH expired AS (
			SELECT id
			FROM identity_cache_invalidation_outbox
			WHERE status='processed' AND processed_at < $1
			ORDER BY processed_at ASC, id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM identity_cache_invalidation_outbox event
		USING expired
		WHERE event.id=expired.id
	`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("cleanup processed identity cache invalidations: %w", err)
	}
	return tag.RowsAffected(), nil
}
