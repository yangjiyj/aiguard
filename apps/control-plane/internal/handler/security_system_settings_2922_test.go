package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type securitySettingsRepo struct {
	behaviorAuditRepo
	written map[string]string
}

func (f *securitySettingsRepo) SetMultiple(_ context.Context, settings map[string]string) error {
	if f.written == nil {
		f.written = map[string]string{}
	}
	for k, v := range settings {
		f.written[k] = v
	}
	return nil
}

// 批次 2B：“允许本人批准”由安全员与平台管理员都能改（D8），白名单外的键 400，全平台共享所以
// 租户级账号不能改；写操作审计。
func TestUpdateSecuritySystemSettingsAllowSelfApproval(t *testing.T) {
	for _, tc := range []struct {
		name, role, tenant, body string
		want                     int
		value                    string
	}{
		{"platform security officer", "security_officer", repository.SystemTenantID, `{"agentguard_allow_self_approval":true}`, http.StatusOK, "true"},
		{"platform admin", "platform_admin", repository.SystemTenantID, `{"agentguard_allow_self_approval":"false"}`, http.StatusOK, "false"},
		{"auditor", "auditor", repository.SystemTenantID, `{"agentguard_allow_self_approval":true}`, http.StatusForbidden, ""},
		{"tenant security officer", "security_officer", "tenant-a", `{"agentguard_allow_self_approval":true}`, http.StatusForbidden, ""},
		{"key outside the whitelist", "security_officer", repository.SystemTenantID, `{"security_audit_only":true}`, http.StatusBadRequest, ""},
		{"invalid value", "security_officer", repository.SystemTenantID, `{"agentguard_allow_self_approval":"yes"}`, http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &securitySettingsRepo{}
			deps := &Dependencies{SystemRepo: repo}
			user := &repository.User{ID: "u1", TenantID: tc.tenant, Role: tc.role}
			rec := httptest.NewRecorder()
			UpdateSecuritySystemSettings(deps).ServeHTTP(rec, withBehaviorUser(http.MethodPut, "/admin/v1/security/system-settings", tc.body, user))
			if rec.Code != tc.want {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if tc.want != http.StatusOK {
				if len(repo.written) != 0 {
					t.Fatalf("a refused write must not persist: %+v", repo.written)
				}
				return
			}
			if value := repo.written[agentGuardAllowSelfApprovalSettingKey]; value != tc.value || len(repo.written) != 1 {
				t.Fatalf("want only %s=%q written, got %+v", agentGuardAllowSelfApprovalSettingKey, tc.value, repo.written)
			}
			audited := false
			for _, op := range repo.operations {
				if op.ActionType == "update_security_system_settings" {
					audited = true
				}
			}
			if !audited {
				t.Fatalf("the write must be audited: %+v", repo.operations)
			}
		})
	}
	if !strings.Contains(agentGuardAllowSelfApprovalSettingKey, "self_approval") || !securityOfficerSettingKeys[agentGuardAllowSelfApprovalSettingKey] {
		t.Fatal("security officers must be able to read the switch back")
	}
}
