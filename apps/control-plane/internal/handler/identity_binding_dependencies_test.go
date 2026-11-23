package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
)

type identityBindingServiceStub struct{}

func (identityBindingServiceStub) BindAndResolve(
	context.Context,
	identitybinding.ExternalIdentity,
) (identitybinding.Resolution, error) {
	return identitybinding.Resolution{}, nil
}

func (identityBindingServiceStub) AssignManually(
	context.Context,
	string,
	string,
	string,
	string,
) error {
	return nil
}

func (identityBindingServiceStub) AssignManyManually(
	context.Context,
	string,
	[]string,
	string,
	string,
	string,
) error {
	return nil
}

func (identityBindingServiceStub) SetAutomatic(
	context.Context,
	string,
	string,
	string,
) error {
	return nil
}

func (identityBindingServiceStub) Unassign(
	context.Context,
	string,
	string,
	string,
) error {
	return nil
}

type identityCacheInvalidationReconcilerStub struct{}

func (identityCacheInvalidationReconcilerStub) ProcessOne(context.Context) (bool, error) {
	return false, nil
}

func TestDependenciesExposeIdentityBindingService(t *testing.T) {
	var service IdentityBindingService = identityBindingServiceStub{}
	var reconciler IdentityCacheInvalidationReconciler = identityCacheInvalidationReconcilerStub{}
	deps := &Dependencies{
		IdentityBindingService:              service,
		IdentityCacheInvalidationReconciler: reconciler,
	}
	if deps.IdentityBindingService == nil {
		t.Fatal("identity binding service dependency is not wired")
	}
	if deps.IdentityCacheInvalidationReconciler == nil {
		t.Fatal("identity cache invalidation reconciler dependency is not exposed")
	}
}
