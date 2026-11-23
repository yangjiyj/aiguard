package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validReplyPolicyJSON = `{
  "enabled": true,
  "templates": {
    "default": "安全策略已阻断请求",
    "prompt_injection": "检测到异常指令",
    "content_safety": "无法回答违规内容",
    "data_leak": "检测到敏感信息"
  }
}`

func replyPolicyRequest(method, body, tenantID, role string) *http.Request {
	req := httptest.NewRequest(method, "/admin/v1/security/reply-policy", strings.NewReader(body))
	return withContentConfigUser(req, role, tenantID)
}

func TestPutSecurityReplyPolicyStoresTenantScopedValidatedPolicy(t *testing.T) {
	repo := &contentConfigSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	deps := &Dependencies{SystemRepo: repo}
	recorder := httptest.NewRecorder()

	PutSecurityReplyPolicy(deps).ServeHTTP(recorder, replyPolicyRequest(http.MethodPut, validReplyPolicyJSON, "tenant-a", "platform_admin"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	saved := repo.settings["security_reply_policy:tenant-a"]
	if !strings.Contains(saved, `"schema_version":1`) || !strings.Contains(saved, `"prompt_injection":"检测到异常指令"`) {
		t.Fatalf("saved=%s", saved)
	}
	if _, exists := repo.settings["security_reply_policy:tenant-b"]; exists {
		t.Fatal("request must not write another tenant key")
	}
	if len(repo.audits) != 1 {
		t.Fatalf("audits=%d, want 1", len(repo.audits))
	}
	audit := fmt.Sprint(repo.audits[0].ActionDetail)
	for _, secretText := range []string{"安全策略已阻断请求", "检测到异常指令", "无法回答违规内容", "检测到敏感信息"} {
		if strings.Contains(audit, secretText) {
			t.Fatalf("audit leaked template %q: %s", secretText, audit)
		}
	}
}

func TestGetSecurityReplyPolicyReadsOnlyAuthenticatedTenantAndAuditMode(t *testing.T) {
	repo := &contentConfigSystemRepo{settings: map[string]string{
		"security_reply_policy:tenant-a": `{"schema_version":1,"enabled":true,"templates":{"default":"A-default","prompt_injection":"A-prompt","content_safety":"A-content","data_leak":"A-data"}}`,
		"security_reply_policy:tenant-b": `{"schema_version":1,"enabled":true,"templates":{"default":"B-default","prompt_injection":"B-prompt","content_safety":"B-content","data_leak":"B-data"}}`,
		"security_audit_only":            "true",
	}}
	recorder := httptest.NewRecorder()

	GetSecurityReplyPolicy(&Dependencies{SystemRepo: repo}).ServeHTTP(recorder, replyPolicyRequest(http.MethodGet, "", "tenant-a", "tenant_owner"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		SecurityReplyPolicy
		SecurityAuditOnly bool `json:"security_audit_only"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Templates["default"] != "A-default" || strings.Contains(recorder.Body.String(), "B-default") {
		t.Fatalf("cross-tenant response=%s", recorder.Body.String())
	}
	if !response.SecurityAuditOnly {
		t.Fatal("security_audit_only must be returned for execution warning")
	}
}

func TestGetSecurityReplyPolicyUsesEffectiveAuditModeDefaultsAndOverrides(t *testing.T) {
	tests := []struct {
		name     string
		setting  *string
		envValue string
		want     bool
	}{
		{name: "missing setting and env use safe default", envValue: "", want: true},
		{name: "environment fallback can enable audit", envValue: "true", want: true},
		{name: "environment false without DB uses safe record default", envValue: "false", want: true},
		{name: "database true overrides environment", setting: stringPointer("true"), envValue: "false", want: true},
		{name: "deployment true overrides database false", setting: stringPointer("false"), envValue: "true", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.envValue)
			settings := map[string]string{}
			if tc.setting != nil {
				settings["security_audit_only"] = *tc.setting
			}
			recorder := httptest.NewRecorder()
			GetSecurityReplyPolicy(&Dependencies{SystemRepo: &contentConfigSystemRepo{settings: settings}}).ServeHTTP(
				recorder,
				replyPolicyRequest(http.MethodGet, "", "tenant-a", "tenant_owner"),
			)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var response struct {
				SecurityAuditOnly bool `json:"security_audit_only"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.SecurityAuditOnly != tc.want {
				t.Fatalf("security_audit_only=%t want=%t body=%s", response.SecurityAuditOnly, tc.want, recorder.Body.String())
			}
		})
	}
}

func stringPointer(value string) *string { return &value }

func TestPutSecurityReplyPolicyRequiresPlatformAdmin(t *testing.T) {
	for _, role := range []string{"tenant_owner", "security_admin", "dept_manager"} {
		t.Run(role, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			PutSecurityReplyPolicy(&Dependencies{SystemRepo: &contentConfigSystemRepo{}}).ServeHTTP(
				recorder,
				replyPolicyRequest(http.MethodPut, validReplyPolicyJSON, "tenant-a", role),
			)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPutSecurityReplyPolicyRejectsInvalidPayloads(t *testing.T) {
	longTemplate := strings.Repeat("界", maxSecurityReplyTemplateRunes+1)
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "unknown field", body: strings.Replace(validReplyPolicyJSON, `"enabled": true`, `"enabled": true, "tenant_id": "tenant-b"`, 1), want: http.StatusBadRequest},
		{name: "missing template", body: `{"enabled":true,"templates":{"default":"a","prompt_injection":"b","content_safety":"c"}}`, want: http.StatusBadRequest},
		{name: "blank template", body: `{"enabled":true,"templates":{"default":" ","prompt_injection":"b","content_safety":"c","data_leak":"d"}}`, want: http.StatusBadRequest},
		{name: "extra template", body: `{"enabled":true,"templates":{"default":"a","prompt_injection":"b","content_safety":"c","data_leak":"d","agent":"e"}}`, want: http.StatusBadRequest},
		{name: "long template", body: fmt.Sprintf(`{"enabled":true,"templates":{"default":%q,"prompt_injection":"b","content_safety":"c","data_leak":"d"}}`, longTemplate), want: http.StatusBadRequest},
		{name: "trailing JSON", body: validReplyPolicyJSON + `{}`, want: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			PutSecurityReplyPolicy(&Dependencies{SystemRepo: &contentConfigSystemRepo{}}).ServeHTTP(
				recorder,
				replyPolicyRequest(http.MethodPut, tc.body, "tenant-a", "platform_admin"),
			)
			if recorder.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

func TestPutSecurityReplyPolicyRejectsOversizedBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := []byte(fmt.Sprintf(
		`{"enabled":true,"templates":{"default":"%s","prompt_injection":"b","content_safety":"c","data_leak":"d"}}`,
		strings.Repeat("x", maxSecurityReplyPolicyBodyBytes),
	))

	PutSecurityReplyPolicy(&Dependencies{SystemRepo: &contentConfigSystemRepo{}}).ServeHTTP(
		recorder,
		withContentConfigUser(httptest.NewRequest(http.MethodPut, "/admin/v1/security/reply-policy", bytes.NewReader(body)), "platform_admin", "tenant-a"),
	)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
