package identitybinding

import (
	"context"
	"testing"
)

type recordingPermissionCache struct {
	users []string
}

func (c *recordingPermissionCache) InvalidateUserCache(userID string) {
	c.users = append(c.users, userID)
}

func TestPermissionCacheInvalidatorAdapterUsesProductionCheckerContract(t *testing.T) {
	cache := &recordingPermissionCache{}
	adapter := NewPermissionCacheInvalidatorAdapter(cache)
	if err := adapter.InvalidateUserCache(context.Background(), "user-a"); err != nil {
		t.Fatal(err)
	}
	if len(cache.users) != 1 || cache.users[0] != "user-a" {
		t.Fatalf("invalidated=%v", cache.users)
	}
}

func TestUncachedModelAuthorizationInvalidatorIsExplicit(t *testing.T) {
	adapter := NewUncachedModelAuthorizationInvalidator()
	if err := adapter.InvalidateUserModelAuthorizationCache(context.Background(), "user-a"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.InvalidateUserModelAuthorizationCache(context.Background(), ""); err == nil {
		t.Fatal("empty user id must not be silently accepted")
	}
}
