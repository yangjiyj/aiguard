package main

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
)

func TestNewIdentityBindingRuntimeWiresProductionComponents(t *testing.T) {
	checker := permission.NewChecker(nil, permission.NewGrantsCache())
	runtime := newIdentityBindingRuntime(nil, checker)
	if runtime.Service == nil || runtime.Reconciler == nil || runtime.WorkerConfig.ErrorObserver == nil {
		t.Fatalf("runtime=%+v", runtime)
	}
}
