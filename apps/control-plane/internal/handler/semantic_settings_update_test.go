package handler

// 第 3 项：安全员保存语义检测配置。
//   - PUT /system/settings 归 SoDSystem、handler 仅 platform_admin：安全员调用必须仍被拒（问题的根因，也是不放开它的依据）；
//   - PUT /security/semantic/settings 是专用入口：安全员能保存语义/研判键，但不能借此改 console_admin_ip_allowlist 等系统键，
//     也不能把「研判走内网地址」打开；审计员与其他角色一律 403。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 这组用例覆盖「白名单 / 内网出口 / 其他角色 / 校验沿用」；调用者是平台级账号（语义配置是全平台共享的，租户级账号会先被拒，
// 见 semantic_settings_judge_guard_test.go），并带上读取到的 expected_version。
func semanticSettingsRequest(role string, body map[string]any) *http.Request {
	b2 := map[string]any{}
	for k, v := range body {
		b2[k] = v
	}
	if _, ok := b2["expected_version"]; !ok {
		b2["expected_version"] = semanticVersionOf(nil)
	}
	raw, _ := json.Marshal(b2)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/security/semantic/settings", strings.NewReader(string(raw)))
	user := &repository.User{ID: "u-" + role, TenantID: semanticConfigTenant, Role: role, Status: "active"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = permission.WithSoDAllowed(ctx)
	return req.WithContext(ctx)
}

func putSemanticSettingsAs(t *testing.T, role string, body map[string]any) (*httptest.ResponseRecorder, *versionedRepo) {
	t.Helper()
	repo := newVersionedRepo(nil)
	deps := &Dependencies{SystemRepo: repo}
	rec := httptest.NewRecorder()
	UpdateSemanticSettings(deps).ServeHTTP(rec, semanticSettingsRequest(role, body))
	return rec, repo
}

func TestSecurityOfficerCannotUseSystemSettingsToSaveSemanticConfig(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	rec := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(rec, semanticSettingsRequest("security_officer", map[string]any{"semantic_enabled": true}))
	if rec.Code != http.StatusForbidden || len(repo.settings) != 0 {
		t.Fatalf("PUT /system/settings 必须仍然拒绝安全员（系统类接口）：status=%d saved=%v", rec.Code, repo.settings)
	}
}

func TestSecurityOfficerCanSaveSemanticDetectionConfig(t *testing.T) {
	for _, role := range []string{"security_officer", "platform_admin"} {
		rec, repo := putSemanticSettingsAs(t, role, map[string]any{
			"semantic_enabled": true, "semantic_input_enabled": true, "semantic_total_timeout": 20,
			"inspect_user_input": true, "inspect_history": false, "fp_suppression_enabled": true,
			"judge_backend": "bundled", "judge_model": "qwen3-4b",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 保存语义检测配置应成功：status=%d body=%s", role, rec.Code, rec.Body.String())
		}
		if repo.settings["semantic_enabled"] != "true" || repo.settings["judge_model"] != "qwen3-4b" || repo.settings["semantic_total_timeout"] != "20" {
			t.Fatalf("%s 的配置没有落库：%v", role, repo.settings)
		}
	}
}

func TestSecurityOfficerCannotChangeSystemKeysThroughSemanticEndpoint(t *testing.T) {
	systemKeys := []string{
		"console_admin_ip_allowlist", "console_admin_totp_required", "login_lockout_threshold", "outbound_proxy_url",
		"log_retention_days", "gateway_public_base_url", "security_execution_mode", "security_audit_only",
		"tier1_url", "license_key", "unrelated_key",
	}
	for _, key := range systemKeys {
		// 单独夹带一个系统键，以及与合法语义键混在一起，都必须整体被拒且什么都不落库。
		for _, body := range []map[string]any{
			{key: "x"},
			{"semantic_enabled": true, key: "x"},
		} {
			rec, repo := putSemanticSettingsAs(t, "security_officer", body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "setting_not_allowed") {
				t.Fatalf("借语义入口改 %s 必须 400 setting_not_allowed：status=%d body=%s", key, rec.Code, rec.Body.String())
			}
			if len(repo.settings) != 0 {
				t.Fatalf("越界请求不得有任何键落库（含合法键）：%v", repo.settings)
			}
		}
	}
}

func TestSecurityOfficerCannotEnablePrivateJudgeEgress(t *testing.T) {
	for _, v := range []any{true, "true", "TRUE"} {
		rec, repo := putSemanticSettingsAs(t, "security_officer", map[string]any{"judge_allow_private_egress": v, "semantic_enabled": true})
		if rec.Code != http.StatusForbidden || len(repo.settings) != 0 {
			t.Fatalf("安全员不得打开研判内网出口（%v）：status=%d saved=%v", v, rec.Code, repo.settings)
		}
	}
	// 关闭（以及保持关闭）是允许的。
	rec, repo := putSemanticSettingsAs(t, "security_officer", map[string]any{"judge_allow_private_egress": false})
	if rec.Code != http.StatusOK || repo.settings["judge_allow_private_egress"] != "false" {
		t.Fatalf("安全员应可关闭研判内网出口：status=%d saved=%v body=%s", rec.Code, repo.settings, rec.Body.String())
	}
	// 系统管理员保持原有权限（见 TestUpdateSystemSettingsAllowsPrivateEgress...）：这里只看角色闸门，不走真实 DNS。
	rec, _ = putSemanticSettingsAs(t, "platform_admin", map[string]any{"judge_allow_private_egress": true})
	if rec.Code == http.StatusForbidden {
		t.Fatalf("系统管理员不应被角色闸门拒绝：%s", rec.Body.String())
	}
}

func TestSemanticSettingsEndpointRejectsOtherRoles(t *testing.T) {
	for _, role := range []string{"auditor", "tenant_admin", "tenant_owner", "dept_manager", "developer", "viewer", "platform_connector"} {
		rec, repo := putSemanticSettingsAs(t, role, map[string]any{"semantic_enabled": true})
		if rec.Code != http.StatusForbidden || len(repo.settings) != 0 {
			t.Fatalf("%s 不应能写语义检测配置：status=%d saved=%v", role, rec.Code, repo.settings)
		}
	}
}

func TestSemanticSettingsEndpointKeepsValidationAndSecretHandling(t *testing.T) {
	rec, repo := putSemanticSettingsAs(t, "security_officer", map[string]any{"semantic_total_timeout": 600})
	if rec.Code != http.StatusBadRequest || len(repo.settings) != 0 {
		t.Fatalf("格式校验必须沿用：status=%d saved=%v", rec.Code, repo.settings)
	}
	rec, repo = putSemanticSettingsAs(t, "security_officer", map[string]any{"semantic_output_enabled": true})
	if rec.Code != http.StatusBadRequest || len(repo.settings) != 0 {
		t.Fatalf("语义输出检测不得打开：status=%d saved=%v", rec.Code, repo.settings)
	}
	t.Setenv("PROVIDER_SECRET_KEY", strings.Repeat("a", 32))
	rec, repo = putSemanticSettingsAs(t, "security_officer", map[string]any{"judge_api_key": "sk-plain-secret"})
	if rec.Code == http.StatusOK && repo.settings["judge_api_key"] == "sk-plain-secret" {
		t.Fatalf("judge_api_key 不得明文落库")
	}
}
