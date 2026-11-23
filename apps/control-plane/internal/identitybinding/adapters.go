package identitybinding

import (
	"context"
)

type permissionCache interface {
	InvalidateUserCache(userID string)
}

type PermissionCacheInvalidatorAdapter struct {
	cache permissionCache
}

func NewPermissionCacheInvalidatorAdapter(cache permissionCache) *PermissionCacheInvalidatorAdapter {
	return &PermissionCacheInvalidatorAdapter{cache: cache}
}

func (a *PermissionCacheInvalidatorAdapter) InvalidateUserCache(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || a.cache == nil || userID == "" {
		return ErrConflict
	}
	a.cache.InvalidateUserCache(userID)
	return nil
}

// UncachedModelAuthorizationInvalidator documents the current runtime boundary:
// user-level model authorization has no cache to invalidate. Gateway model
// policies and project-to-team resolution are read from PostgreSQL per request;
// the separate gateway team_models cache is keyed by project team, not user.
// Replace this adapter when a user-level model authorization cache is introduced.
type UncachedModelAuthorizationInvalidator struct{}

func NewUncachedModelAuthorizationInvalidator() *UncachedModelAuthorizationInvalidator {
	return &UncachedModelAuthorizationInvalidator{}
}

func (*UncachedModelAuthorizationInvalidator) InvalidateUserModelAuthorizationCache(
	ctx context.Context,
	userID string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if userID == "" {
		return ErrConflict
	}
	return nil
}
