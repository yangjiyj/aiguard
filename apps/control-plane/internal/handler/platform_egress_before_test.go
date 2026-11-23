package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
)

func egressLooseningAudit(repo *capturingSystemRepo, scope string) map[string]any {
	for _, op := range repo.auditOps {
		if op.ActionType == "egress_override.enable" && op.ActionDetail["scope"] == scope {
			return op.ActionDetail
		}
	}
	return nil
}

func putEgressSettings(t *testing.T, repo *capturingSystemRepo, body map[string]any) {
	t.Helper()
	encoded, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", encoded))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

// 待决 ①：库里缺键时，以环境变量折算出的生效值为“改前”判断是否放宽。
func TestPlatformEgressLooseningComparesAgainstEnvironmentEffectiveValue(t *testing.T) {
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "true")
	repo := &capturingSystemRepo{}
	putEgressSettings(t, repo, map[string]any{"idp_block_private": false})
	if keys, _ := egressLooseningAudit(repo, "identity")["keys"].([]string); !reflect.DeepEqual(keys, []string{"idp_block_private"}) {
		t.Fatalf("env true → stored false must be audited as loosening, got %v", keys)
	}

	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "")
	repo = &capturingSystemRepo{}
	putEgressSettings(t, repo, map[string]any{"idp_block_private": false})
	if detail := egressLooseningAudit(repo, "identity"); detail != nil {
		t.Fatalf("env unset (effective false) → false is not a loosening: %v", detail)
	}

	// 环境变量里已有的网段、LDAP 目标、未登记目标处置写进库不算放宽；新增的才算。
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	t.Setenv("DIRECTORY_LDAP_TARGET_ALLOWLIST", "DC.corp.test")
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "tunnel_audit")
	repo = &capturingSystemRepo{}
	putEgressSettings(t, repo, map[string]any{
		"idp_allowed_cidrs": []string{"10.0.0.0/8"}, "ldap_allowed_targets": []string{"dc.corp.test"},
		"forward_proxy_unlisted_action": "allow_audit",
	})
	if detail := egressLooseningAudit(repo, "identity"); detail != nil {
		t.Fatalf("persisting the environment lists is not a loosening: %v", detail)
	}
	if detail := egressLooseningAudit(repo, "forward_proxy"); detail != nil {
		t.Fatalf("persisting the environment unlisted action is not a loosening: %v", detail)
	}
	repo = &capturingSystemRepo{}
	putEgressSettings(t, repo, map[string]any{"idp_allowed_cidrs": []string{"10.0.0.0/8", "172.16.0.0/12"}})
	if keys, _ := egressLooseningAudit(repo, "identity")["keys"].([]string); !reflect.DeepEqual(keys, []string{"idp_allowed_cidrs"}) {
		t.Fatalf("a CIDR beyond the environment list is a loosening, got %v", keys)
	}
}

// 读改前值失败时按最严处理（拦私网、名单为空），改松照记放宽。
func TestPlatformEgressBeforeReadFailureCountsAsStrictest(t *testing.T) {
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "")
	repo := &failingGetSystemRepo{failKeys: map[string]bool{"idp_block_private": true}}
	before := platformEgressSettingsBefore(context.Background(), &Dependencies{SystemRepo: repo}, map[string]string{"idp_block_private": "false"})
	if keys := identityEgressLoosened(before, map[string]string{"idp_block_private": "false"}); !reflect.DeepEqual(keys, []string{"idp_block_private"}) {
		t.Fatalf("unreadable previous value must count as strictest, got %v (before=%v)", keys, before)
	}
}

// 待决 ②：库里 LDAP 目标名单坏了照旧回落部署名单，但记错误日志，GET 返回该键来源为 invalid。
func TestStoredInvalidLDAPTargetsReportedAsInvalid(t *testing.T) {
	t.Setenv("DIRECTORY_LDAP_TARGET_ALLOWLIST", "dc.corp.test")
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	repo := &capturingSystemRepo{settings: map[string]string{directoryldap.LDAPAllowedTargetsSetting: "not json"}}
	w := httptest.NewRecorder()
	GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	sources, _ := data["egress_setting_sources"].(map[string]any)
	if sources[directoryldap.LDAPAllowedTargetsSetting] != "invalid" {
		t.Fatalf("source = %v, want invalid", sources[directoryldap.LDAPAllowedTargetsSetting])
	}
	if data[directoryldap.LDAPAllowedTargetsSetting] != `["dc.corp.test:636"]` {
		t.Fatalf("effective value must be the deployment list, got %v", data[directoryldap.LDAPAllowedTargetsSetting])
	}
	if !strings.Contains(logs.String(), directoryldap.LDAPAllowedTargetsSetting) {
		t.Fatalf("invalid stored value must be logged, got %q", logs.String())
	}
	logs.Reset()
	base, err := directoryldap.ParseTargetPolicy("dc.corp.test:636", "10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	policy := DirectoryTargetPolicyFor(context.Background(), &Dependencies{DirectoryTargetPolicy: base, SystemRepo: repo})
	if _, err := directoryldap.ValidateConfigWithPolicy(context.Background(), directoryldap.Config{ConnectionURL: "ldaps://dc.corp.test:636"}, policy.WithResolver(staticDirectoryResolver{"dc.corp.test": "10.20.0.6"})); err != nil {
		t.Fatalf("invalid stored value keeps the deployment list: %v", err)
	}
	if !strings.Contains(logs.String(), "ERROR") {
		t.Fatalf("runtime fallback must log an error, got %q", logs.String())
	}
}
