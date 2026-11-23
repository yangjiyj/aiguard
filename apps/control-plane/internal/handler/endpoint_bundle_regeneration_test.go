package handler

import (
	"context"
	"errors"
	"testing"
)

type fakeEndpointBundleRegenerator struct {
	calls         int
	tenant, actor string
	err           error
}

func (f *fakeEndpointBundleRegenerator) RegenerateIfChanged(_ context.Context, tenant, actor string) (int64, error) {
	f.calls++
	f.tenant = tenant
	f.actor = actor
	return 1, f.err
}

func TestRegenerateEndpointBundleDoesNotRollbackSourceWrite(t *testing.T) {
	f := &fakeEndpointBundleRegenerator{err: errors.New("bundle unavailable")}
	regenerateEndpointBundle(context.Background(), &Dependencies{AgentEndpointBundleRepo: f}, "tenant-1", "actor-1")
	if f.calls != 1 || f.tenant != "tenant-1" || f.actor != "actor-1" {
		t.Fatalf("wrong regeneration: %+v", f)
	}
	regenerateEndpointBundle(context.Background(), &Dependencies{}, "tenant-1", "actor-1")
}
