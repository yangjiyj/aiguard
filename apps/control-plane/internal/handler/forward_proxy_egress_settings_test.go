package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

func TestForwardProxyEgressProjectionDefaultsDenyAndIsGatewayOnly(t *testing.T) {
	configs, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"judge_backend": "bundled"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{egresspolicy.KeyAllowPrivate, egresspolicy.KeyAllowLoopback, egresspolicy.KeyAllowMetadata} {
		if configs.Gateway[key] != false {
			t.Errorf("gateway %s = %v, want false", key, configs.Gateway[key])
		}
	}
	for _, key := range []string{egresspolicy.KeyAllowedCIDRs, egresspolicy.KeyAllowedHosts} {
		if configs.Gateway[key] != "[]" {
			t.Errorf("gateway %s = %v, want []", key, configs.Gateway[key])
		}
	}
	// 库里没有这两个键时不下发，让网关用部署环境变量作初值。
	for _, key := range []string{egresspolicy.KeyUnlistedAction, egresspolicy.KeyWhitelistFailMode} {
		if _, ok := configs.Gateway[key]; ok {
			t.Errorf("gateway must not carry %s when the key is not stored", key)
		}
	}
	for _, key := range egresspolicy.Keys {
		if _, ok := configs.Engine[key]; ok {
			t.Errorf("engine projection must not carry %s", key)
		}
	}
}

func TestForwardProxyEgressProjectionFollowsStoredSettings(t *testing.T) {
	off, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{"judge_backend": "bundled"}))
	if err != nil {
		t.Fatal(err)
	}
	on, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{
		"judge_backend": "bundled", egresspolicy.KeyAllowPrivate: "true",
		egresspolicy.KeyAllowedCIDRs: `["10.0.0.0/8"]`, egresspolicy.KeyUnlistedAction: "allow_audit", egresspolicy.KeyWhitelistFailMode: "open",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if on.Gateway[egresspolicy.KeyAllowPrivate] != true || on.Gateway[egresspolicy.KeyAllowedCIDRs] != `["10.0.0.0/8"]` ||
		on.Gateway[egresspolicy.KeyUnlistedAction] != "allow_audit" || on.Gateway[egresspolicy.KeyWhitelistFailMode] != "open" {
		t.Fatalf("gateway projection = %v", on.Gateway)
	}
	if on.GatewayRevision == off.GatewayRevision || on.EngineRevision != off.EngineRevision {
		t.Fatal("forward proxy settings must change only the gateway revision")
	}
	// 库里存了坏值：下发默认（拒绝），不让整份配置失败。
	bad, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(map[string]string{
		"judge_backend": "bundled", egresspolicy.KeyAllowedCIDRs: `not-json`, egresspolicy.KeyUnlistedAction: "bogus",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bad.Gateway[egresspolicy.KeyAllowedCIDRs] != "[]" || bad.Gateway[egresspolicy.KeyUnlistedAction] != "deny" {
		t.Fatalf("bad stored values projected as %v / %v", bad.Gateway[egresspolicy.KeyAllowedCIDRs], bad.Gateway[egresspolicy.KeyUnlistedAction])
	}
}

func TestUpdateSystemSettingsValidatesForwardProxyEgressSettings(t *testing.T) {
	for _, body := range []map[string]any{
		{egresspolicy.KeyAllowPrivate: "maybe"},
		{egresspolicy.KeyAllowedCIDRs: []string{"10.0.0.1"}},
		{egresspolicy.KeyAllowedHosts: []string{"bad host"}},
		{egresspolicy.KeyUnlistedAction: "allow"},
		{egresspolicy.KeyWhitelistFailMode: "half"},
	} {
		repo := &capturingSystemRepo{}
		encoded, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", encoded))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%v: status=%d body=%s", body, w.Code, w.Body.String())
		}
		if len(repo.settings) != 0 {
			t.Errorf("%v: invalid settings were stored: %v", body, repo.settings)
		}
	}
}

func TestUpdateSystemSettingsAuditsForwardProxyEgressLoosening(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{egresspolicy.KeyAllowedCIDRs: `["10.0.0.0/8"]`}}
	body, _ := json.Marshal(map[string]any{
		egresspolicy.KeyAllowPrivate: true, egresspolicy.KeyAllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.10/32"},
	})
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.settings[egresspolicy.KeyAllowedCIDRs] != `["10.0.0.0/8","192.168.1.10/32"]` || repo.settings[egresspolicy.KeyAllowPrivate] != "true" {
		t.Fatalf("stored = %v", repo.settings)
	}
	var loosening map[string]any
	for _, op := range repo.auditOps {
		if op.ActionType == "egress_override.enable" {
			loosening = op.ActionDetail
		}
	}
	if loosening == nil {
		t.Fatalf("no egress_override.enable audit among %d operations", len(repo.auditOps))
	}
	keys, _ := loosening["keys"].([]string)
	if len(keys) != 2 || loosening["scope"] != "forward_proxy" {
		t.Fatalf("loosening detail = %v", loosening)
	}
	// 收紧不写放行审计。
	repo.auditOps = nil
	body, _ = json.Marshal(map[string]any{egresspolicy.KeyAllowPrivate: false})
	w = httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	for _, op := range repo.auditOps {
		if op.ActionType == "egress_override.enable" {
			t.Fatal("tightening must not write a loosening audit")
		}
	}
}

func TestUpdateSystemSettingsIdentityEgressKeysValidatedAndLooseningAudited(t *testing.T) {
	for _, body := range []map[string]any{
		{"idp_block_private": "maybe"},
		{"idp_allowed_cidrs": []string{"10.0.0.1"}},
		{"ldap_allowed_targets": []string{"10.0.0.1"}},
	} {
		repo := &capturingSystemRepo{}
		encoded, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", encoded))
		if w.Code != http.StatusBadRequest || len(repo.settings) != 0 {
			t.Errorf("%v: status=%d stored=%v", body, w.Code, repo.settings)
		}
	}
	repo := &capturingSystemRepo{settings: map[string]string{"idp_block_private": "true"}}
	encoded, _ := json.Marshal(map[string]any{"idp_block_private": false, "idp_allowed_cidrs": "10.0.0.0/8, 192.168.1.9/24", "ldap_allowed_targets": []string{"DC.corp.test"}})
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", encoded))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.settings["idp_allowed_cidrs"] != `["10.0.0.0/8","192.168.1.0/24"]` || repo.settings["ldap_allowed_targets"] != `["dc.corp.test:636"]` {
		t.Fatalf("stored = %v", repo.settings)
	}
	var detail map[string]any
	for _, op := range repo.auditOps {
		if op.ActionType == "egress_override.enable" && op.ActionDetail["scope"] == "identity" {
			detail = op.ActionDetail
		}
	}
	if keys, _ := detail["keys"].([]string); len(keys) != 3 {
		t.Fatalf("identity loosening audit = %v", detail)
	}
}

func TestDirectoryTargetPolicyForUsesStoredTargetsOnlyWhenPresent(t *testing.T) {
	base, err := directoryldap.ParseTargetPolicy("dc.corp.test:636", "10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticDirectoryResolver{"dc.corp.test": "10.20.0.6", "ldap.corp.test": "10.20.0.5"}
	check := func(policy directoryldap.TargetPolicy, url string) error {
		_, err := directoryldap.ValidateConfigWithPolicy(context.Background(), directoryldap.Config{ConnectionURL: url}, policy.WithResolver(resolver))
		return err
	}
	deps := &Dependencies{DirectoryTargetPolicy: base, SystemRepo: &capturingSystemRepo{settings: map[string]string{}}}
	if err := check(DirectoryTargetPolicyFor(context.Background(), deps), "ldaps://dc.corp.test:636"); err != nil {
		t.Fatalf("deployment list must apply without a stored key: %v", err)
	}
	deps.SystemRepo = &capturingSystemRepo{settings: map[string]string{"ldap_allowed_targets": `["ldap.corp.test:636"]`}}
	if err := check(DirectoryTargetPolicyFor(context.Background(), deps), "ldaps://ldap.corp.test:636"); err != nil {
		t.Fatalf("stored target rejected: %v", err)
	}
	if err := check(DirectoryTargetPolicyFor(context.Background(), deps), "ldaps://dc.corp.test:636"); err == nil {
		t.Fatal("stored list must replace the deployment list")
	}
}

type staticDirectoryResolver map[string]string

func (r staticDirectoryResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ip, ok := r[host]; ok {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

func TestNotifyChannelPrivateTargetAuditOnlyWhenTurnedOn(t *testing.T) {
	audit := &egressAuditRepo{}
	deps := &Dependencies{SystemRepo: audit}
	r := reverseProxyTestRequest(http.MethodPut, "/admin/v1/notify-channels/nc_1", "", reverseProxyAdmin)
	auditNotifyChannelPrivateTarget(r, deps, "nc_1", map[string]any{}, map[string]any{"allow_private_target": true})
	auditNotifyChannelPrivateTarget(r, deps, "nc_1", map[string]any{"allow_private_target": true}, map[string]any{"allow_private_target": true})
	auditNotifyChannelPrivateTarget(r, deps, "nc_1", nil, map[string]any{"allow_private_target": "true"})
	if len(audit.ops) != 1 || audit.ops[0].ActionType != "egress_override.enable" {
		t.Fatalf("ops = %d", len(audit.ops))
	}
}
