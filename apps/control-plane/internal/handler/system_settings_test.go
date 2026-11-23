package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func adminCtxRequest(method, target string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	})
	return req.WithContext(ctx)
}

// I1: judge_api_key 必须加密落库（custom 模式新填的明文 key）。
func TestUpdateSystemSettingsEncryptsJudgeApiKey(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "unit-test-secret-key")
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]interface{}{
		"judge_backend": "custom",
		"judge_api_key": "sk-plaintext-secret",
	})
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	stored := repo.settings["judge_api_key"]
	if !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("judge_api_key 应加密落库(enc:v1: 前缀), got %q", stored)
	}
	if stored == "sk-plaintext-secret" {
		t.Fatalf("judge_api_key 明文落库了: %q", stored)
	}
}

// I1: 已加密的 judge_api_key 不得重复加密（占位/未变场景的幂等保护）。
func TestUpdateSystemSettingsDoesNotReEncryptJudgeApiKey(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "unit-test-secret-key")
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	already := "enc:v1:already-encrypted-blob"
	body, _ := json.Marshal(map[string]interface{}{
		"judge_api_key": already,
	})
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings["judge_api_key"] != already {
		t.Fatalf("已加密的 judge_api_key 被重复加密了: %q", repo.settings["judge_api_key"])
	}
}

// I1: 审计日志中 judge_api_key 必须脱敏，绝不留明文/密文。
func TestUpdateSystemSettingsAuditMasksJudgeApiKey(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "unit-test-secret-key")
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]interface{}{
		"judge_backend": "custom",
		"judge_api_key": "sk-plaintext-secret",
	})
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if len(repo.auditOps) != 1 {
		t.Fatalf("应记录 1 条审计, got %d", len(repo.auditOps))
	}
	detail := repo.auditOps[0].ActionDetail
	if got := detail["judge_api_key"]; got != "***" {
		t.Fatalf("审计 judge_api_key 应脱敏为 ***, got %v", got)
	}
	if detail["judge_backend"] != "custom" {
		t.Fatalf("审计应保留 judge_backend, got %v", detail["judge_backend"])
	}
}

// I1 红线：除 judge_api_key 外的普通键不得被加密/篡改（通用存取逻辑不受波及）。
func TestUpdateSystemSettingsDoesNotEncryptOtherKeys(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "unit-test-secret-key")
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]interface{}{
		"security_audit_only": true,
		"judge_url":           "https://8.8.8.8/v1/chat/completions",
	})
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings["security_audit_only"] != "true" {
		t.Fatalf("security_audit_only 被篡改: %q", repo.settings["security_audit_only"])
	}
	if repo.settings["judge_url"] != "https://8.8.8.8/v1/chat/completions" {
		t.Fatalf("judge_url 被篡改: %q", repo.settings["judge_url"])
	}
}

// I1: 面向 UI 的 GetSystemSettings 必须脱敏 judge_api_key，其它键原样返回。
func TestGetSystemSettingsMasksJudgeApiKey(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"judge_api_key":       "enc:v1:secret-blob",
		"security_audit_only": "true",
		"judge_model":         "gpt-5.5",
	}}
	deps := &Dependencies{SystemRepo: repo}
	w := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["judge_api_key"] != "***" {
		t.Fatalf("UI 端点 judge_api_key 应脱敏为 ***, got %#v", got["judge_api_key"])
	}
	if _, leaked := got["security_audit_only"]; leaked {
		t.Fatalf("UI 端点不得暴露工程字段: %#v", got)
	}
	mode, ok := got["security_execution_mode"].(map[string]any)
	if !ok || mode["configured_mode"] != "record" {
		t.Fatalf("客户语义模式缺失或错误: %#v", got)
	}
	if got["judge_model"] != "gpt-5.5" {
		t.Fatalf("judge_model 应原样返回, got %#v", got["judge_model"])
	}
}

func TestGetSystemSettingsShowsFileDLPEnvFallbackWhenDBSettingMissing(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{settings: map[string]string{}}}
	w := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["file_content_dlp_enabled"] != "true" {
		t.Fatalf("UI must display effective env fallback when DB key is missing, got %#v", got["file_content_dlp_enabled"])
	}
}

type capturingSystemRepo struct {
	settings map[string]string
	auditOps []*repository.AuditOperation
}

func (r *capturingSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	if v, ok := r.settings[key]; ok {
		return &repository.SystemSetting{Key: key, Value: v}, nil
	}
	return nil, nil
}

func (r *capturingSystemRepo) GetAll(ctx context.Context) ([]*repository.SystemSetting, error) {
	settings := make([]*repository.SystemSetting, 0, len(r.settings))
	for key, value := range r.settings {
		settings = append(settings, &repository.SystemSetting{Key: key, Value: value})
	}
	return settings, nil
}

func (r *capturingSystemRepo) Set(ctx context.Context, key, value string) error {
	if r.settings == nil {
		r.settings = map[string]string{}
	}
	r.settings[key] = value
	return nil
}

func TestGetInternalSystemSettingsReturnsRuntimeModeWithoutUserContext(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"security_audit_only":   "true",
		"content_audit_enabled": "true",
	}}
	deps := &Dependencies{SystemRepo: repo}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/system/settings", nil)
	w := httptest.NewRecorder()

	GetInternalSystemSettings(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]string
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["security_audit_only"] != "true" {
		t.Fatalf("security_audit_only = %q, want true", got["security_audit_only"])
	}
}

func (r *capturingSystemRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	for key, value := range settings {
		if err := r.Set(ctx, key, value); err != nil {
			return err
		}
	}
	return nil
}

func (r *capturingSystemRepo) CreateAuditOperation(ctx context.Context, op *repository.AuditOperation) error {
	r.auditOps = append(r.auditOps, op)
	return nil
}

func (r *capturingSystemRepo) ListAuditOperations(ctx context.Context, limit, offset int, userID string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}

func (r *capturingSystemRepo) GetBool(ctx context.Context, key string) (bool, error) {
	return r.settings[key] == "true", nil
}

func TestUpdateSystemSettingsAcceptsBooleanSwitchValues(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]interface{}{
		"content_audit_enabled": true,
		"tool_audit_enabled":    false,
		"log_retention_days":    "90",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/system/settings", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	UpdateSystemSettings(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings["content_audit_enabled"] != "true" {
		t.Fatalf("content_audit_enabled = %q, want true", repo.settings["content_audit_enabled"])
	}
	if repo.settings["tool_audit_enabled"] != "false" {
		t.Fatalf("tool_audit_enabled = %q, want false", repo.settings["tool_audit_enabled"])
	}
	if repo.settings["log_retention_days"] != "90" {
		t.Fatalf("log_retention_days = %q, want 90", repo.settings["log_retention_days"])
	}
}

func TestUpdateSystemSettingsRejectsInvalidLogRetentionDays(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]interface{}{
		"log_retention_days": "0",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/system/settings", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	UpdateSystemSettings(deps).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if _, ok := repo.settings["log_retention_days"]; ok {
		t.Fatalf("invalid log_retention_days should not be saved: %+v", repo.settings)
	}
}

func TestGetSystemSettingsUsesCustomerSecurityExecutionMode(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	repo := &capturingSystemRepo{settings: map[string]string{
		"security_audit_only": "false",
		"judge_model":         "gpt-5.5",
	}}
	deps := &Dependencies{SystemRepo: repo}
	w := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, leaked := got["security_audit_only"]; leaked {
		t.Fatalf("public settings leaked engineering key: %#v", got)
	}
	mode, ok := got["security_execution_mode"].(map[string]any)
	if !ok {
		t.Fatalf("missing customer mode object: %#v", got)
	}
	// 2.9.22（D7）：库里没有显式模式时部署变量作初值（record），不再显示锁定（原断言 locked=true）。
	if mode["configured_mode"] != "record" || mode["effective_mode"] != "record" || mode["locked"] != false || mode["source"] != "deployment" {
		t.Fatalf("unexpected security mode: %#v", mode)
	}
	if _, ok := mode["runtime_verified"].(bool); !ok || mode["runtime_status"] == nil {
		t.Fatalf("runtime receipt fields missing: %#v", mode)
	}
	if got["judge_model"] != "gpt-5.5" {
		t.Fatalf("unrelated setting changed: %#v", got)
	}
}

func TestGetSystemSettingsDatabaseRecordModeRemainsUnlockedWhenDeploymentCeilingIsFalse(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	w := httptest.NewRecorder()
	GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	mode, ok := got[securityExecutionModeSettingKey].(map[string]any)
	if !ok {
		t.Fatalf("missing security execution mode: %#v", got)
	}
	if mode["configured_mode"] != "record" || mode["effective_mode"] != "record" || mode["locked"] != false || mode["source"] != "system_setting" {
		t.Fatalf("database record mode must remain configurable when deployment ceiling is false: %#v", mode)
	}
}

func TestUpdateSystemSettingsAcceptsCustomerSecurityExecutionModeAndAuditsTransition(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]any{"security_execution_mode": "protect"})
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if repo.settings["security_audit_only"] != "false" {
		t.Fatalf("security mode not persisted compatibly: %#v", repo.settings)
	}
	if repo.settings["security_execution_mode"] != "protect" {
		t.Fatalf("customer field must map to canonical storage, got %#v", repo.settings)
	}
	if len(repo.auditOps) != 1 {
		t.Fatalf("audit count=%d", len(repo.auditOps))
	}
	detail := repo.auditOps[0].ActionDetail
	for key, want := range map[string]any{
		"old_configured_mode": "record", "new_configured_mode": "protect",
		"effective_mode": "protect", "source": "admin_settings", "last_modified_by": "user_admin",
	} {
		if detail[key] != want {
			t.Fatalf("audit %s=%#v want %#v; detail=%#v", key, detail[key], want, detail)
		}
	}
	if detail["last_modified_at"] == nil {
		t.Fatalf("audit missing modification time: %#v", detail)
	}
	get := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(get, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
	var response map[string]any
	if err := json.NewDecoder(get.Body).Decode(&response); err != nil {
		t.Fatalf("decode updated settings: %v", err)
	}
	mode := response[securityExecutionModeSettingKey].(map[string]any)
	if mode["last_modified_by"] != "user_admin" || mode["last_modified_at"] == "" {
		t.Fatalf("public mode metadata is not attributable: %#v", mode)
	}
	if _, leaked := response[securityExecutionModeModifiedBySettingKey]; leaked {
		t.Fatalf("internal metadata key leaked: %#v", response)
	}
}

func TestUpdateSystemSettingsRecordsModeChangeReasonOnlyInAudit(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	body, _ := json.Marshal(map[string]any{
		"security_execution_mode": "protect",
		"change_reason":           "  经变更窗口批准启用保护  ",
	})
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if _, persisted := repo.settings["change_reason"]; persisted {
		t.Fatalf("change reason must not become a system setting: %#v", repo.settings)
	}
	if len(repo.auditOps) != 1 || repo.auditOps[0].ActionDetail["change_reason"] != "经变更窗口批准启用保护" {
		t.Fatalf("change reason audit=%#v", repo.auditOps)
	}
}

func TestUpdateSystemSettingsRejectsMissingOrOversizedModeChangeReason(t *testing.T) {
	for name, value := range map[string]any{"blank": "  ", "oversized": strings.Repeat("变", 501), "wrong_type": true} {
		t.Run(name, func(t *testing.T) {
			repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
			body, _ := json.Marshal(map[string]any{"security_execution_mode": "record", "change_reason": value})
			w := httptest.NewRecorder()
			UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
			if w.Code != http.StatusBadRequest || repo.settings["security_audit_only"] != "true" || len(repo.auditOps) != 0 {
				t.Fatalf("status=%d settings=%#v audits=%d body=%s", w.Code, repo.settings, len(repo.auditOps), w.Body.String())
			}
		})
	}
}

// 未设部署锁的客户部署：控制台显式保存 protect/record 后双向生效并与投影一致。
// 部署锁（env=true）下 protect 被拒绝，见 TestDeploymentLockRejectsSwitchToProtect。
func TestUpdateSystemSettingsExplicitModeAppliesAfterSaveWithoutDeploymentLock(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	deps := &Dependencies{SystemRepo: repo}
	if !securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatal("upgrade must preserve record mode before explicit choice")
	}
	for _, mode := range []string{"protect", "record"} {
		body, _ := json.Marshal(map[string]any{"security_execution_mode": mode, "change_reason": "customer UI change"})
		w := httptest.NewRecorder()
		UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		wantOld := "record"
		if mode == "record" {
			wantOld = "protect"
		}
		if repo.auditOps[len(repo.auditOps)-1].ActionDetail["old_configured_mode"] != wantOld {
			t.Fatalf("audit does not match displayed previous mode: %#v", repo.auditOps[len(repo.auditOps)-1].ActionDetail)
		}
		if repo.settings["security_execution_mode"] != mode || securityAuditOnlyEnabled(context.Background(), deps) != (mode == "record") {
			t.Fatalf("mode not applied: %#v", repo.settings)
		}
		projection, err := buildSemanticEngineProjection(context.Background(), deps)
		if err != nil {
			t.Fatal(err)
		}
		if projection["security_execution_mode_managed"] != true || projection["security_audit_only"] != (mode == "record") {
			t.Fatalf("projection=%#v", projection)
		}
		internal := httptest.NewRecorder()
		GetInternalSystemSettings(deps).ServeHTTP(internal, httptest.NewRequest(http.MethodGet, "/", nil))
		var values map[string]string
		if err := json.Unmarshal(internal.Body.Bytes(), &values); err != nil {
			t.Fatal(err)
		}
		if values["security_audit_only"] != repo.settings["security_audit_only"] {
			t.Fatalf("internal settings disagree")
		}
	}
	if len(repo.auditOps) != 2 {
		t.Fatalf("audit count=%d", len(repo.auditOps))
	}
}

func TestUpdateSystemSettingsRejectsInvalidSecurityExecutionModeStrictly(t *testing.T) {
	for name, value := range map[string]any{"unknown": "audit", "boolean": true, "object": map[string]any{"mode": "record"}} {
		t.Run(name, func(t *testing.T) {
			repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
			body, _ := json.Marshal(map[string]any{"security_execution_mode": value})
			w := httptest.NewRecorder()
			UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if repo.settings["security_audit_only"] != "true" {
				t.Fatalf("invalid mode mutated DB: %#v", repo.settings)
			}
		})
	}
}

func systemSettingsRequestAsRole(role string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/settings", nil)
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_" + role, TenantID: "tenant_default", Role: role, Status: "active",
	}))
}

func TestGetSystemSettingsOrdinaryUserReceivesOnlySecurityExecutionMode(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"security_audit_only":   "false",
		"judge_model":           "private-model",
		"content_audit_enabled": "true",
	}}
	for _, role := range []string{"viewer", "security_admin", "dept_manager"} {
		t.Run(role, func(t *testing.T) {
			w := httptest.NewRecorder()
			GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, systemSettingsRequestAsRole(role))
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != 1 || got[securityExecutionModeSettingKey] == nil {
				t.Fatalf("ordinary user must receive only security mode: %#v", got)
			}
			if _, leaked := got["judge_model"]; leaked {
				t.Fatalf("ordinary user received unrelated settings: %#v", got)
			}
		})
	}
}

func TestGetSystemSettingsFullAdministratorsKeepFullResponse(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"security_audit_only": "true",
		"judge_model":         "visible-to-full-admin",
	}}
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		t.Run(role, func(t *testing.T) {
			w := httptest.NewRecorder()
			GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, systemSettingsRequestAsRole(role))
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got["judge_model"] != "visible-to-full-admin" || got[securityExecutionModeSettingKey] == nil {
				t.Fatalf("full administrator response regressed: %#v", got)
			}
		})
	}
}

func TestUpdateSystemSettingsModeRequestRejectsAdditionalFields(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"known general setting": {"content_audit_enabled": true},
		"unknown typo":          {"security_execution_mod": "protect"},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
			payload := map[string]any{"security_execution_mode": "protect"}
			for key, value := range extra {
				payload[key] = value
			}
			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if repo.settings["security_audit_only"] != "true" || len(repo.auditOps) != 0 {
				t.Fatalf("rejected dedicated request mutated state: settings=%#v audits=%d", repo.settings, len(repo.auditOps))
			}
		})
	}
}

type failedModeWriteRepo struct{ *capturingSystemRepo }

func (r failedModeWriteRepo) SetMultiple(context.Context, map[string]string) error {
	return errors.New("storage unavailable")
}

func TestExplicitSecurityModeWriteFailureKeepsStateAndAudit(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: failedModeWriteRepo{repo}}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/", []byte(`{"security_execution_mode":"protect"}`)))
	if w.Code == http.StatusOK || repo.settings["security_audit_only"] != "true" || repo.settings["security_execution_mode"] != "" || len(repo.auditOps) != 0 {
		t.Fatalf("failed save mutated state: %d %#v", w.Code, repo)
	}
}

func TestExplicitSecurityModeRejectsForgedMetadataAndLegacyConflict(t *testing.T) {
	for _, payload := range []string{
		`{"security_execution_mode_managed":true}`, `{"security_execution_mode_modified_by":"forged"}`,
		`{"security_execution_mode_modified_at":"2026-09-06T00:00:00Z"}`, `{"security_audit_only":true}`,
	} {
		repo := &capturingSystemRepo{settings: map[string]string{"security_execution_mode": "protect", "security_audit_only": "false"}}
		w := httptest.NewRecorder()
		UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/", []byte(payload)))
		if w.Code != http.StatusBadRequest || repo.settings["security_audit_only"] != "false" || len(repo.auditOps) != 0 {
			t.Fatalf("accepted conflicting update: %d", w.Code)
		}
	}
}

func TestExplicitSecurityModeSignedProjectionPreservesLegacyAndSignsManagedMarker(t *testing.T) {
	for _, locked := range []bool{false, true} {
		env := ""
		if locked {
			env = "true"
		}
		t.Setenv("SECURITY_AUDIT_ONLY", env)
		for _, mode := range []string{"", "invalid", "protect", "record"} {
			deps := semanticTestDeps(map[string]string{"security_execution_mode": mode, "security_audit_only": "false"})
			configs, err := buildSemanticComponentConfigs(context.Background(), deps)
			if err != nil {
				t.Fatal(err)
			}
			managed := mode == "protect" || mode == "record"
			// managed 按控制台模式；未 managed 时部署变量作初值（true=记录），否则按旧键（false=防护）。
			// 2.9.22（D7）前部署锁一律记录，原断言 locked || mode=="record" 随之改写。
			wantAudit := mode == "record" || (locked && !managed)
			for _, cfg := range []map[string]any{configs.Engine, configs.Gateway} {
				marker, exists := cfg["security_execution_mode_managed"]
				if exists != managed || (managed && marker != true) || cfg["security_audit_only"] != wantAudit {
					t.Fatalf("locked=%v mode=%q config=%#v", locked, mode, cfg)
				}
			}
		}
	}
}

func TestGetSystemSettingsPublicGatewayAddressWithoutPrivateSettings(t *testing.T) {
	for _, role := range []string{"viewer", "security_admin", "dept_manager"} {
		t.Run(role, func(t *testing.T) {
			repo := &capturingSystemRepo{settings: map[string]string{
				"gateway_public_base_url": "http://customer.example:8084/v1",
				"judge_api_key":           "private-test-key",
				"outbound_proxy_url":      "http://user:password@proxy.example:3128",
			}}
			w := httptest.NewRecorder()
			GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, systemSettingsRequestAsRole(role))
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d", w.Code)
			}
			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got["gateway_public_base_url"] != "http://customer.example:8084/v1" {
				t.Fatalf("public gateway address missing: %#v", got)
			}
			if len(got) != 2 || got[securityExecutionModeSettingKey] == nil {
				t.Fatalf("only public address and security mode may be returned: %#v", got)
			}
		})
	}
}

// 保留期最少 30 天：界面/接口提交 1~29 天返回中文错误，且不落库。
func TestUpdateSystemSettingsRejectsLogRetentionBelowFloor(t *testing.T) {
	for _, value := range []string{"1", "29"} {
		repo := &capturingSystemRepo{}
		deps := &Dependencies{SystemRepo: repo}
		body, _ := json.Marshal(map[string]interface{}{"log_retention_days": value})
		req := httptest.NewRequest(http.MethodPut, "/admin/v1/system/settings", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
			ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin", Status: "active",
		}))
		w := httptest.NewRecorder()
		UpdateSystemSettings(deps).ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "最少保留 30 天") {
			t.Fatalf("value=%s status=%d body=%s", value, w.Code, w.Body.String())
		}
		if _, ok := repo.settings["log_retention_days"]; ok {
			t.Fatalf("below-floor retention must not be saved: %+v", repo.settings)
		}
	}
}

func putSystemSettingsForTest(t *testing.T, repo *capturingSystemRepo, payload map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/system/settings", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin", Status: "active"})
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, req.WithContext(ctx))
	return w
}

func TestUpdateSystemSettingsAcceptsAlertTTLSettingsAndAudits(t *testing.T) {
	repo := &capturingSystemRepo{}
	w := putSystemSettingsForTest(t, repo, map[string]interface{}{"alert_ttl_enabled": true, "alert_group_ttl_days": 30})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.settings["alert_ttl_enabled"] != "true" || repo.settings["alert_group_ttl_days"] != "30" {
		t.Fatalf("settings=%+v", repo.settings)
	}
	if len(repo.auditOps) != 1 || repo.auditOps[0].ActionType != "update_system_settings" {
		t.Fatalf("audit=%+v", repo.auditOps)
	}
	d := repo.auditOps[0].ActionDetail
	if d["alert_ttl_enabled"] != "true" || d["alert_group_ttl_days"] != "30" {
		t.Fatalf("audit detail must include TTL keys: %#v", d)
	}
}

func TestUpdateSystemSettingsNormalizesAlertTTLStrings(t *testing.T) {
	repo := &capturingSystemRepo{}
	w := putSystemSettingsForTest(t, repo, map[string]interface{}{"alert_ttl_enabled": "FALSE", "alert_group_ttl_days": " 7 "})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.settings["alert_ttl_enabled"] != "false" || repo.settings["alert_group_ttl_days"] != "7" {
		t.Fatalf("settings=%+v", repo.settings)
	}
}

func TestUpdateSystemSettingsRejectsInvalidAlertTTLSettings(t *testing.T) {
	cases := []map[string]interface{}{
		{"alert_group_ttl_days": 0},
		{"alert_group_ttl_days": 366},
		{"alert_group_ttl_days": 7.5},
		{"alert_group_ttl_days": "abc"},
		{"alert_group_ttl_days": ""},
		{"alert_ttl_enabled": "yes"},
		{"alert_ttl_enabled": 1},
	}
	for _, payload := range cases {
		repo := &capturingSystemRepo{}
		w := putSystemSettingsForTest(t, repo, payload)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%v: status=%d body=%s", payload, w.Code, w.Body.String())
		}
		if len(repo.settings) != 0 || len(repo.auditOps) != 0 {
			t.Fatalf("%v: invalid value must not be saved/audited: %+v", payload, repo.settings)
		}
	}
}

// DB 无值时，系统设置页要看到当前实际生效的值（env 兜底），而不是误显示为关闭。
func TestGetSystemSettingsFillsEffectiveAlertTTLFallback(t *testing.T) {
	t.Setenv("ALERT_TTL_ENABLED", "true")
	t.Setenv("ALERT_GROUP_TTL_DAYS", "21")
	get := func(repo *capturingSystemRepo) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/settings", nil)
		ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin", Status: "active"})
		w := httptest.NewRecorder()
		GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, req.WithContext(ctx))
		var got map[string]any
		_ = json.NewDecoder(w.Body).Decode(&got)
		return got
	}
	got := get(&capturingSystemRepo{settings: map[string]string{}})
	if got["alert_ttl_enabled"] != "true" || got["alert_group_ttl_days"] != "21" {
		t.Fatalf("env fallback not exposed: %v %v", got["alert_ttl_enabled"], got["alert_group_ttl_days"])
	}
	got = get(&capturingSystemRepo{settings: map[string]string{"alert_ttl_enabled": "false", "alert_group_ttl_days": "30"}})
	if got["alert_ttl_enabled"] != "false" || got["alert_group_ttl_days"] != "30" {
		t.Fatalf("db values must win: %v %v", got["alert_ttl_enabled"], got["alert_group_ttl_days"])
	}
}

func (r *capturingSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
