package repository

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	agentAuthorizationCleanupBatchSize  = 100
	agentAuthorizationCleanupMaxBatches = 10
)

// AgentAuthorizationCleanupResult describes one bounded cleanup run.
type AgentAuthorizationCleanupResult struct {
	DeletedRequests int64
	DeletedUsage    int64
	Batches         int
	Backlog         bool
}

const agentAuthorizationCleanupClockSQL = "SELECT clock_timestamp()"

const deleteExpiredAgentAuthorizationRequestsBatchSQL = `
WITH stale AS (
	SELECT ctid
	FROM agent_authorization_requests
	WHERE expires_at <= $1
	ORDER BY expires_at
	FOR UPDATE SKIP LOCKED
	LIMIT $2
)
DELETE FROM agent_authorization_requests AS requests
USING stale
WHERE requests.ctid = stale.ctid
`

const deleteOldAgentAuthorizationUsageBatchSQL = `
WITH stale AS (
	SELECT ctid
	FROM agent_authorization_usage
	WHERE window_start <= $1::timestamptz - ($2::double precision * interval '1 second')
	ORDER BY window_start
	FOR UPDATE SKIP LOCKED
	LIMIT $3
)
DELETE FROM agent_authorization_usage AS usage
USING stale
WHERE usage.ctid = stale.ctid
`

const hasExpiredAgentAuthorizationRequestsSQL = `
SELECT EXISTS (
	SELECT 1 FROM agent_authorization_requests
	WHERE expires_at <= $1
)
`

const hasOldAgentAuthorizationUsageSQL = `
SELECT EXISTS (
	SELECT 1 FROM agent_authorization_usage
	WHERE window_start <= $1::timestamptz - ($2::double precision * interval '1 second')
)
`

// PruneExpiredData removes only expired idempotency receipts and quota buckets
// that are older than the maximum supported quota window. Each DELETE is one
// atomic, bounded statement and skips rows being changed by active requests or
// another cleanup worker. One DB-clock sample fixes the cutoff for the entire
// run; rows that expire after that sample are eligible on the next scheduled run.
func (r *AgentAuthorizationRepository) PruneExpiredData(ctx context.Context) (AgentAuthorizationCleanupResult, error) {
	result := AgentAuthorizationCleanupResult{}
	if r == nil || r.db == nil {
		return result, errors.New("agent authorization cleanup repository is not initialized")
	}

	if err := ctx.Err(); err != nil {
		result.Backlog = true
		return result, err
	}
	var cleanupAt time.Time
	if err := r.db.QueryRow(ctx, agentAuthorizationCleanupClockSQL).Scan(&cleanupAt); err != nil {
		result.Backlog = true
		return result, fmt.Errorf("sample agent authorization cleanup clock: %w", err)
	}

	for result.Batches < agentAuthorizationCleanupMaxBatches {
		if err := ctx.Err(); err != nil {
			result.Backlog = true
			return result, err
		}
		result.Batches++

		requestTag, err := r.db.Exec(ctx, deleteExpiredAgentAuthorizationRequestsBatchSQL, cleanupAt, agentAuthorizationCleanupBatchSize)
		if err != nil {
			result.Backlog = true
			return result, fmt.Errorf("delete expired agent authorization requests: %w", err)
		}
		deletedRequests := requestTag.RowsAffected()
		result.DeletedRequests += deletedRequests

		usageTag, err := r.db.Exec(ctx, deleteOldAgentAuthorizationUsageBatchSQL,
			cleanupAt, float64(AgentAuthorizationMaxQuotaWindowSeconds), agentAuthorizationCleanupBatchSize)
		if err != nil {
			result.Backlog = true
			return result, fmt.Errorf("delete old agent authorization usage: %w", err)
		}
		deletedUsage := usageTag.RowsAffected()
		result.DeletedUsage += deletedUsage

		if deletedRequests < agentAuthorizationCleanupBatchSize && deletedUsage < agentAuthorizationCleanupBatchSize {
			break
		}
	}

	if err := ctx.Err(); err != nil {
		result.Backlog = true
		return result, err
	}
	var requestsRemain, usageRemain bool
	if err := r.db.QueryRow(ctx, hasExpiredAgentAuthorizationRequestsSQL, cleanupAt).Scan(&requestsRemain); err != nil {
		result.Backlog = true
		return result, fmt.Errorf("check expired agent authorization requests: %w", err)
	}
	if err := r.db.QueryRow(ctx, hasOldAgentAuthorizationUsageSQL,
		cleanupAt, float64(AgentAuthorizationMaxQuotaWindowSeconds)).Scan(&usageRemain); err != nil {
		result.Backlog = true
		return result, fmt.Errorf("check old agent authorization usage: %w", err)
	}
	result.Backlog = requestsRemain || usageRemain
	return result, nil
}
