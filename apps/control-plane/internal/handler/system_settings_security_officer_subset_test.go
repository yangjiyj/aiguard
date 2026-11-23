package handler

// L-2：GET /admin/v1/system/settings 对 security_officer 返回了全量，包括 console_admin_ip_allowlist、登录策略、锁定阈值、
// 出口代理、许可证等系统类配置。按三员分立（docs/design/ws4-rbac-matrix.md），`/system/settings` 页面只对系统管理员开放，
// 这个 GET 在 SoD 里归 common 的理由是「非系统管理员只拿到精简视图」（permission/middleware.go 的注释）。
// 安全员确实需要其中与安全相关的一小部分（执行模式、语义检测、文件 DLP、拦截应答、网关入口，供 MCP 三页与语义检测/文件策略页使用），
// 所以给安全员一份「安全相关子集」，而不是全量；审计员与其他非管理员角色仍只拿精简版。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type settingsRepoStub struct{ items map[string]string }

func (s settingsRepoStub) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	if v, ok := s.items[key]; ok {
		return &repository.SystemSetting{Key: key, Value: v}, nil
	}
	return nil, nil
}
func (s settingsRepoStub) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	var out []*repository.SystemSetting
	for k, v := range s.items {
		out = append(out, &repository.SystemSetting{Key: k, Value: v})
	}
	return out, nil
}
func (s settingsRepoStub) Set(context.Context, string, string) error            { return nil }
func (s settingsRepoStub) SetMultiple(context.Context, map[string]string) error { return nil }
func (s settingsRepoStub) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return nil
}
func (s settingsRepoStub) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (s settingsRepoStub) GetBool(context.Context, string) (bool, error) { return false, nil }

func fetchSettingsAs(t *testing.T, role string, items map[string]string) map[string]any {
	t.Helper()
	deps := &Dependencies{SystemRepo: settingsRepoStub{items}}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/settings", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "t", Role: role}))
	w := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", role, w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

var systemOnlySettings = map[string]string{
	"console_admin_ip_allowlist":      "10.0.0.0/8",
	"console_login_lockout_threshold": "5",
	"console_login_lockout_minutes":   "30",
	"console_password_min_length":     "12",
	"console_session_idle_minutes":    "30",
	"console_admin_totp_required":     "true",
	"outbound_proxy_url":              "http://user:pw@proxy.corp:3128",
	"enterprise_license":              "LICENSE-BLOB",
	"billing_prepaid_tools_visible":   "true",
	"notify_smtp_host":                "smtp.corp",
}

var securityRelatedSettings = map[string]string{
	"security_execution_mode":       "record",
	"semantic_enabled":              "true",
	"inspect_user_input":            "true",
	"fp_suppression_enabled":        "true",
	"judge_backend":                 "provider",
	"file_content_dlp_enabled":      "true",
	"guardrail_fail_closed_enabled": "false",
	"security_block_response_mode":  "error",
	"gateway_public_base_url":       "https://gw.example.com",
	"agentguard_dual_approval":      "false",
	"content_file_policy_json":      "{}",
}

func merged() map[string]string {
	m := map[string]string{}
	for k, v := range systemOnlySettings {
		m[k] = v
	}
	for k, v := range securityRelatedSettings {
		m[k] = v
	}
	return m
}

func TestSecurityOfficerGetsOnlyTheSecurityRelatedSettingsSubset(t *testing.T) {
	got := fetchSettingsAs(t, "security_officer", merged())
	for k := range systemOnlySettings {
		if _, leaked := got[k]; leaked {
			t.Fatalf("系统类配置 %s 不得出现在安全员的响应里: %v", k, got[k])
		}
	}
	for _, k := range []string{"semantic_enabled", "file_content_dlp_enabled", "security_block_response_mode", "gateway_public_base_url", "judge_backend"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("安全员需要的安全相关配置 %s 缺失（MCP 三页/语义检测/文件策略页依赖）", k)
		}
	}
	if effectiveMode(got) != "record" {
		t.Fatalf("执行模式必须返回: %v", got["security_execution_mode"])
	}
}

func TestSecurityOfficerSubsetNeverContainsSecrets(t *testing.T) {
	items := merged()
	items["judge_api_key"] = "sk-very-secret"
	got := fetchSettingsAs(t, "security_officer", items)
	if v, ok := got["judge_api_key"]; ok && v != maskedSecretValue {
		t.Fatalf("judge_api_key 只能脱敏占位，不得回传明文: %v", v)
	}
	raw, _ := json.Marshal(got)
	for _, secret := range []string{"sk-very-secret", "pw@proxy", "LICENSE-BLOB"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("响应不得包含 %q: %s", secret, raw)
		}
	}
}

func TestAuditorAndOtherNonAdminRolesStillGetOnlyTheMinimalView(t *testing.T) {
	for _, role := range []string{"auditor", "developer", "viewer", "dept_manager"} {
		got := fetchSettingsAs(t, role, merged())
		for k := range systemOnlySettings {
			if _, leaked := got[k]; leaked {
				t.Fatalf("%s 不得看到 %s", role, k)
			}
		}
		for _, k := range []string{"semantic_enabled", "file_content_dlp_enabled", "judge_backend"} {
			if _, leaked := got[k]; leaked {
				t.Fatalf("%s 不属于安全员，不得拿到安全相关子集里的 %s", role, k)
			}
		}
		if effectiveMode(got) != "record" || got["gateway_public_base_url"] == nil {
			t.Fatalf("%s 仍应拿到精简视图（执行模式与网关入口）: %v", role, got)
		}
	}
}

func TestSystemAdministratorStillGetsTheFullSettings(t *testing.T) {
	for _, role := range []string{"platform_admin", "tenant_admin", "tenant_owner"} {
		got := fetchSettingsAs(t, role, merged())
		for k := range systemOnlySettings {
			if _, ok := got[k]; !ok && k != "enterprise_license" {
				t.Fatalf("%s 应看到完整配置，缺 %s", role, k)
			}
		}
	}
}

// effectiveMode 取 security_execution_mode 对象里的 effective_mode。
func effectiveMode(settings map[string]any) any {
	obj, _ := settings["security_execution_mode"].(map[string]any)
	return obj["effective_mode"]
}

// 安全员的页面（语义检测控制台、文件策略页、MCP 三页）读取的 settings 键必须都在白名单里，否则收窄会让这些页面静默变空。
// 键清单取自前端源码：SemanticConsole.tsx 的表单键与 judge_*，FilePolicySettings.tsx 的 file_content_dlp_enabled。
func TestSecurityOfficerWhitelistCoversTheKeysItsPagesRead(t *testing.T) {
	needed := []string{
		"semantic_enabled", "semantic_agent_enabled", "semantic_input_enabled", "semantic_total_timeout",
		"inspect_user_input", "inspect_model_output", "inspect_tool_results", "inspect_history", "inspect_builtin_context",
		"fp_suppression_enabled", "judge_backend", "judge_model", "judge_provider_id", "judge_url", "judge_allow_private_egress",
		"file_content_dlp_enabled", "gateway_public_base_url", "gateway_public_endpoints", "gateway_public_url_mode",
	}
	for _, k := range needed {
		if !securityOfficerSettingKeys[k] {
			t.Fatalf("安全员页面依赖的配置键 %s 不在白名单里", k)
		}
	}
	// 反向：白名单里不得出现登录、会话、代理、许可证、通知、计费类键
	for k := range securityOfficerSettingKeys {
		for _, banned := range []string{"console_", "outbound_proxy", "enterprise_license", "notify_", "billing_", "smtp", "password"} {
			if strings.Contains(k, banned) {
				t.Fatalf("白名单键 %s 属于系统类配置（%s），不得对安全员开放", k, banned)
			}
		}
	}
}

func (s settingsRepoStub) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, s.Get, keys)
}
