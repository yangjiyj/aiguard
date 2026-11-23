package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 2.9.22（设计 D7）：部署变量 SECURITY_AUDIT_ONLY 不再锁定控制台，只在库里没有
// security_execution_mode 时作初值。原 P0 硬上限（2026-09-27）的三条断言随用户 11-17 决定改写：
// 库里已有显式 protect 时，控制台展示、下发投影与生效判定都按 protect，不显示锁定。
func TestDeploymentAuditOnlyDoesNotOverrideStoredProtect(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	deps := semanticTestDeps(map[string]string{
		"security_audit_only":     "false",
		"security_execution_mode": "protect",
	})
	if securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatal("stored managed protect must win over the deployment initial value")
	}
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if configs.Engine["security_audit_only"] != false || configs.Gateway["security_audit_only"] != false {
		t.Fatalf("every projection must follow the console: engine=%#v gateway=%#v", configs.Engine, configs.Gateway)
	}
	w := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	mode := got[securityExecutionModeSettingKey].(map[string]any)
	if mode["effective_mode"] != "protect" || mode["locked"] != false || mode["source"] != "admin_settings" {
		t.Fatalf("console must show the stored mode, unlocked: %#v", mode)
	}
}

// 库里没有显式执行模式时，部署变量作初值：仍是记录模式（与 2.9.21 一致，不变严），但不锁定。
func TestDeploymentAuditOnlyIsInitialRecordWhenModeMissing(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	deps := semanticTestDeps(map[string]string{"security_audit_only": "false"})
	if !securityAuditOnlyEnabled(context.Background(), deps) || !mcpAuditOnlyCeiling(context.Background(), deps) {
		t.Fatal("deployment initial value must apply while no explicit mode is stored")
	}
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if configs.Engine["security_audit_only"] != true || configs.Gateway["security_audit_only"] != true {
		t.Fatalf("initial value must be record: engine=%#v gateway=%#v", configs.Engine, configs.Gateway)
	}
	w := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	mode := got[securityExecutionModeSettingKey].(map[string]any)
	if mode["effective_mode"] != "record" || mode["locked"] != false || mode["source"] != "deployment" {
		t.Fatalf("console must show the deployment initial value, unlocked: %#v", mode)
	}
}

// 部署变量为 true 时，控制台仍能切换到 protect（原 409 拒绝随 D7 改写），写库并审计，各组件随之按防护执行。
func TestDeploymentAuditOnlyAllowsSwitchToProtect(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	body, _ := json.Marshal(map[string]any{"security_execution_mode": "protect", "change_reason": "switch to protect"})
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.settings["security_execution_mode"] != "protect" || repo.settings["security_audit_only"] != "false" || len(repo.auditOps) != 1 {
		t.Fatalf("switch must persist and audit: settings=%#v audits=%d", repo.settings, len(repo.auditOps))
	}
	deps := semanticTestDeps(repo.settings)
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if configs.Engine["security_audit_only"] != false || configs.Gateway["security_audit_only"] != false || securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatalf("components must enforce after the switch: engine=%#v gateway=%#v", configs.Engine, configs.Gateway)
	}
}

// 部署锁下仍允许显式保存 record（幂等、可审计）。
func TestDeploymentLockStillAcceptsRecord(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	body, _ := json.Marshal(map[string]any{"security_execution_mode": "record", "change_reason": "confirm record"})
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	if w.Code != http.StatusOK || repo.settings["security_execution_mode"] != "record" {
		t.Fatalf("status=%d settings=%#v body=%s", w.Code, repo.settings, w.Body.String())
	}
}

// MCP 工具契约告诉 LSE"期望 block 的样本是否会真拦"：与数据面一致，部署变量只作初值
// （2.9.22 D7），库里有显式 protect 时如实报告会拦（原断言“部署锁下只审计”随之改写）。
func TestMCPContractAuditCeilingTreatsDeploymentAsInitialValue(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{settings: map[string]string{
		"security_audit_only": "false", "security_execution_mode": "protect",
	}}}
	if mcpAuditOnlyCeiling(context.Background(), deps) {
		t.Fatal("stored console protect must apply even with the deployment variable set")
	}
	legacy := &Dependencies{SystemRepo: &capturingSystemRepo{settings: map[string]string{"security_audit_only": "false"}}}
	if !mcpAuditOnlyCeiling(context.Background(), legacy) {
		t.Fatal("without an explicit mode the deployment initial value is record")
	}
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	if mcpAuditOnlyCeiling(context.Background(), deps) {
		t.Fatal("without the lock the console protect mode must apply")
	}
}

// 看门狗基线由服务端维护：通过 API 改写它就能掩盖一次模式变更，必须拒绝。
func TestExecutionModeBaselineCannotBeWrittenThroughAPI(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	body := []byte(`{"security_execution_mode_watch_baseline":"protect|2026-09-27T00:00:00Z"}`)
	w := httptest.NewRecorder()
	UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	if w.Code != http.StatusBadRequest || repo.settings[executionModeBaselineKey] != "" {
		t.Fatalf("baseline must be server-managed: status=%d settings=%#v", w.Code, repo.settings)
	}
}

// 审查第 9 项：写旧键 security_audit_only 时同时写入显式执行模式，让它真正生效；
// 部署变量为 true、库里没有显式模式时写 false，原先返回 200 却仍按部署变量记录。
func TestLegacyAuditOnlyWriteBecomesExplicitMode(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	for _, tc := range []struct {
		legacy   bool
		wantMode string
		wantRec  bool
	}{{false, "protect", false}, {true, "record", true}} {
		repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
		body, _ := json.Marshal(map[string]any{"security_audit_only": tc.legacy})
		w := httptest.NewRecorder()
		UpdateSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
		if w.Code != http.StatusOK {
			t.Fatalf("legacy=%v status=%d body=%s", tc.legacy, w.Code, w.Body.String())
		}
		if repo.settings["security_execution_mode"] != tc.wantMode || repo.settings["security_execution_mode_modified_by"] == "" || len(repo.auditOps) != 1 {
			t.Fatalf("legacy=%v 必须写入显式模式并审计：settings=%#v audits=%d", tc.legacy, repo.settings, len(repo.auditOps))
		}
		deps := semanticTestDeps(repo.settings)
		configs, err := buildSemanticComponentConfigs(context.Background(), deps)
		if err != nil {
			t.Fatal(err)
		}
		if securityAuditOnlyEnabled(context.Background(), deps) != tc.wantRec || configs.Engine["security_audit_only"] != tc.wantRec || configs.Gateway["security_audit_only"] != tc.wantRec {
			t.Fatalf("legacy=%v 写入后必须生效：engine=%v gateway=%v", tc.legacy, configs.Engine["security_audit_only"], configs.Gateway["security_audit_only"])
		}
	}
}
