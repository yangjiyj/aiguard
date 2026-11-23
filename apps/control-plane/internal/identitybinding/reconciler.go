package identitybinding

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrCacheInvalidation = errors.New("identity cache invalidation failed")

type CacheInvalidationEvent struct {
	ID              string
	TenantID        string
	UserID          string
	OldDepartmentID string
	NewDepartmentID string
	AttemptCount    int
}

type InvalidationOutbox interface {
	ClaimNextInvalidation(ctx context.Context, workerID string) (*CacheInvalidationEvent, error)
	MarkInvalidationProcessed(ctx context.Context, eventID, workerID string) error
	MarkInvalidationFailed(
		ctx context.Context,
		eventID, workerID, safeError string,
		nextAttempt time.Time,
	) error
}

type PermissionCacheInvalidator interface {
	InvalidateUserCache(ctx context.Context, userID string) error
}

type ModelAuthorizationCacheInvalidator interface {
	InvalidateUserModelAuthorizationCache(ctx context.Context, userID string) error
}

type Reconciler struct {
	outbox     InvalidationOutbox
	permission PermissionCacheInvalidator
	model      ModelAuthorizationCacheInvalidator
	workerID   string
	now        func() time.Time
}

func NewReconciler(
	outbox InvalidationOutbox,
	permission PermissionCacheInvalidator,
	model ModelAuthorizationCacheInvalidator,
) *Reconciler {
	return &Reconciler{
		outbox: outbox, permission: permission, model: model,
		workerID: "identity-cache-" + uuid.NewString(),
		now:      time.Now,
	}
}

func (r *Reconciler) ProcessOne(ctx context.Context) (bool, error) {
	if r == nil || r.outbox == nil || r.permission == nil || r.model == nil {
		return false, fmt.Errorf("%w: reconciler dependency missing", ErrCacheInvalidation)
	}
	event, err := r.outbox.ClaimNextInvalidation(ctx, r.workerID)
	if err != nil {
		return false, fmt.Errorf("claim identity cache invalidation: %w", err)
	}
	if event == nil {
		return false, nil
	}

	permissionErr := r.permission.InvalidateUserCache(ctx, event.UserID)
	modelErr := r.model.InvalidateUserModelAuthorizationCache(ctx, event.UserID)
	if permissionErr == nil && modelErr == nil {
		if err := r.outbox.MarkInvalidationProcessed(ctx, event.ID, r.workerID); err != nil {
			return false, fmt.Errorf("mark identity cache invalidation processed: %w", err)
		}
		return true, nil
	}

	safeError := sanitizedInvalidationError(permissionErr, modelErr)
	nextAttempt := r.now().Add(invalidationRetryDelay(event.AttemptCount))
	if err := r.outbox.MarkInvalidationFailed(
		ctx, event.ID, r.workerID, safeError, nextAttempt,
	); err != nil {
		return false, fmt.Errorf("mark identity cache invalidation retryable: %w", err)
	}
	return false, fmt.Errorf("%w: %s", ErrCacheInvalidation, safeError)
}

func sanitizedInvalidationError(permissionErr, modelErr error) string {
	switch {
	case permissionErr != nil && modelErr != nil:
		return "permission and model authorization cache invalidation failed"
	case permissionErr != nil:
		return "permission cache invalidation failed"
	default:
		return "model authorization cache invalidation failed"
	}
}

func invalidationRetryDelay(attemptCount int) time.Duration {
	if attemptCount < 1 {
		attemptCount = 1
	}
	if attemptCount > 9 {
		attemptCount = 9
	}
	delay := time.Second * time.Duration(1<<(attemptCount-1))
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
