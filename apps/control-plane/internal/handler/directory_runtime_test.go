package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestPublishDirectorySourceMapsTestedSourceToRuntime(t *testing.T) {
	runtime := &fakeDirectoryRuntime{}
	source := &repository.DirectorySource{
		Kind:          repository.DirectoryKindLDAP,
		ConnectionURL: "ldaps://ldap-sim.jjdguard.test:636",
		BindDN:        "cn=reader,dc=jjdguard,dc=test",
		UsersDN:       "ou=People,dc=jjdguard,dc=test",
	}

	err := publishDirectorySource(context.Background(), runtime, source, "bind-secret")
	if err != nil {
		t.Fatalf("publish directory source: %v", err)
	}
	if runtime.calls != 1 {
		t.Fatalf("expected one runtime publish, got %d", runtime.calls)
	}
	if runtime.last.Kind != directoryruntime.KindLDAP || runtime.last.ConnectionURL != source.ConnectionURL || runtime.last.BindDN != source.BindDN || runtime.last.UsersDN != source.UsersDN || runtime.last.BindPassword != "bind-secret" {
		t.Fatalf("unexpected runtime config: %+v", runtime.last)
	}
}

type fakeDirectoryRuntime struct {
	calls int
	last  directoryruntime.DirectoryConfig
	err   error
}

func (runtime *fakeDirectoryRuntime) Publish(_ context.Context, config directoryruntime.DirectoryConfig) (directoryruntime.Publication, error) {
	runtime.calls++
	runtime.last = config
	return directoryruntime.Publication{}, runtime.err
}
func (runtime *fakeDirectoryRuntime) FullSync(context.Context) error {
	return runtime.err
}

func (runtime *fakeDirectoryRuntime) Status(context.Context) (directoryruntime.RuntimeStatus, error) {
	return directoryruntime.RuntimeStatus{}, runtime.err
}
