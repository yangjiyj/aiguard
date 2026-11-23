package handler

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// failingGetSystemRepo 对 failKeys 里的键读设置返回错误（区别于缺键返回 nil）。
type failingGetSystemRepo struct {
	capturingSystemRepo
	failKeys map[string]bool
}

func (r *failingGetSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	if r.failKeys[key] {
		return nil, errors.New("system settings unavailable")
	}
	return r.capturingSystemRepo.Get(ctx, key)
}

func TestIdentityEgressSettingsSourceTreatsReadErrorAsStrictest(t *testing.T) {
	repo := &failingGetSystemRepo{failKeys: map[string]bool{"idp_block_private": true, "idp_allowed_cidrs": true}}
	got := IdentityEgressSettingsSource(&Dependencies{SystemRepo: repo})()
	want := map[string]string{"idp_block_private": "true", "idp_allowed_cidrs": "[]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read error must not fall back to environment: got %v, want %v", got, want)
	}
}

func TestIdentityEgressSettingsSourceLeavesMissingKeysToEnvironment(t *testing.T) {
	repo := &failingGetSystemRepo{
		capturingSystemRepo: capturingSystemRepo{settings: map[string]string{"idp_allowed_cidrs": `["10.0.0.0/8"]`}},
		failKeys:            map[string]bool{},
	}
	got := IdentityEgressSettingsSource(&Dependencies{SystemRepo: repo})()
	want := map[string]string{"idp_allowed_cidrs": `["10.0.0.0/8"]`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing key must stay absent so the environment applies: got %v, want %v", got, want)
	}
}

func TestDirectoryTargetPolicyForReadErrorAllowsNoTargets(t *testing.T) {
	base, err := directoryldap.ParseTargetPolicy("dc.corp.test:636", "10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticDirectoryResolver{"dc.corp.test": "10.20.0.6"}
	deps := &Dependencies{DirectoryTargetPolicy: base, SystemRepo: &failingGetSystemRepo{failKeys: map[string]bool{directoryldap.LDAPAllowedTargetsSetting: true}}}
	policy := DirectoryTargetPolicyFor(context.Background(), deps).WithResolver(resolver)
	if _, err := directoryldap.ValidateConfigWithPolicy(context.Background(), directoryldap.Config{ConnectionURL: "ldaps://dc.corp.test:636"}, policy); !errors.Is(err, directoryldap.ErrTargetNotAllowed) {
		t.Fatalf("read error must not fall back to the deployment list: err=%v", err)
	}
}

func TestIdentityEgressLoosenedBlockPrivateOnlyWhenPreviouslyTrue(t *testing.T) {
	after := map[string]string{"idp_block_private": "false"}
	if keys := identityEgressLoosened(map[string]string{}, after); len(keys) != 0 {
		t.Fatalf("missing previous value is not a loosening: %v", keys)
	}
	if keys := identityEgressLoosened(map[string]string{"idp_block_private": "false"}, after); len(keys) != 0 {
		t.Fatalf("false to false is not a loosening: %v", keys)
	}
	if keys := identityEgressLoosened(map[string]string{"idp_block_private": "true"}, after); !reflect.DeepEqual(keys, []string{"idp_block_private"}) {
		t.Fatalf("true to false is a loosening: %v", keys)
	}
}
