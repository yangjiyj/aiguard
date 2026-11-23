package auth

import (
	"context"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"testing"
)

func TestKeyModelAllowlistIntersectsLiveUserAccess(t *testing.T) {
	a := &modelaccess.Access{ChatAllowed: true, EffectiveModels: []string{"model-a", "model-b"}, KnownModelNames: []string{"model-a", "model-b"}, ModelReferences: map[string]string{"internal-a": "model-a", "internal-b": "model-b"}}
	ctx := context.WithValue(context.Background(), modelAccessContextKey{}, a)
	ctx = context.WithValue(ctx, KeyModelAllowlistKey, []string{"model-a", "revoked-model"})
	if !UserModelAllowed(ctx, "model-a") || UserModelAllowed(ctx, "model-b") || UserModelAllowed(ctx, "revoked-model") {
		t.Fatal("key and user intersection not enforced")
	}
	if !UserFinalModelAllowed(ctx, "internal-a") || UserFinalModelAllowed(ctx, "internal-b") {
		t.Fatal("routing ID bypasses key restriction")
	}
	a.EffectiveModels = []string{"model-b"}
	if UserModelAllowed(ctx, "model-a") {
		t.Fatal("user revocation must immediately narrow existing key")
	}
}
func TestEmptyKeyModelAllowlistInheritsUserAccess(t *testing.T) {
	a := &modelaccess.Access{ChatAllowed: true, EffectiveModels: []string{"model-a"}}
	ctx := context.WithValue(context.Background(), modelAccessContextKey{}, a)
	ctx = context.WithValue(ctx, KeyModelAllowlistKey, []string{})
	if !UserModelAllowed(ctx, "model-a") || UserModelAllowed(ctx, "model-b") {
		t.Fatal("inheritance changed")
	}
}
func TestUnownedRestrictedKeyCannotBypassModelLimit(t *testing.T) {
	ctx := context.WithValue(context.Background(), KeyModelAllowlistKey, []string{"model-a"})
	if !UserModelAllowed(ctx, "model-a") || UserModelAllowed(ctx, "model-b") {
		t.Fatal("unowned key bypass")
	}
}
