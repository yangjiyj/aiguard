package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// P0-3 fresh-install contract (2026-09-28): a fresh install ships
// SECURITY_AUDIT_ONLY=false (deployment lock off) and migration 139 seeds
// security_audit_only=true. The effective mode must therefore be record (no
// blocking) everywhere, shown as unlocked, and the console must be able to
// switch to protect. Setting SECURITY_AUDIT_ONLY=true instead is a hard lock
// the console cannot lift; see p0_audit_ceiling_test.go.

// freshInstallSettings mirrors the rows migration 139 writes on an empty
// database (verified on a real PostgreSQL run of all migrations).
func freshInstallSettings() map[string]string {
	return map[string]string{"security_audit_only": "true"}
}

func TestFreshInstallStartsInUnlockedRecordMode(t *testing.T) {
	for _, env := range []string{"false", ""} {
		t.Run("env="+env, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", env)
			deps := semanticTestDeps(freshInstallSettings())
			if !securityAuditOnlyEnabled(context.Background(), deps) {
				t.Fatal("fresh install must start in record mode")
			}
			configs, err := buildSemanticComponentConfigs(context.Background(), deps)
			if err != nil {
				t.Fatal(err)
			}
			if configs.Engine["security_audit_only"] != true || configs.Gateway["security_audit_only"] != true {
				t.Fatalf("fresh install projections must be record: engine=%#v gateway=%#v", configs.Engine, configs.Gateway)
			}
			w := httptest.NewRecorder()
			GetSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			mode := got[securityExecutionModeSettingKey].(map[string]any)
			if mode["configured_mode"] != "record" || mode["effective_mode"] != "record" || mode["locked"] != false {
				t.Fatalf("fresh install must show record and unlocked: %#v", mode)
			}
		})
	}
}

func TestFreshInstallConsoleCanSwitchToProtect(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	repo := &capturingSystemRepo{settings: freshInstallSettings()}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]any{"security_execution_mode": "protect", "change_reason": "enable protection"})
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(w, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	if w.Code != http.StatusOK {
		t.Fatalf("fresh install must allow switching to protect: status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.settings["security_execution_mode"] != "protect" || repo.settings["security_audit_only"] != "false" {
		t.Fatalf("protect not persisted: %#v", repo.settings)
	}
	if securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatal("after switching to protect the effective mode must be protect")
	}
}

// An empty settings table (for example a database restored without the
// migration 139 rows) must still fail safe to record, never to protect, and
// every control-plane reader must agree with the signed projections.
func TestMissingModeSettingsFailSafeToRecord(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	deps := semanticTestDeps(map[string]string{})
	if !securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatal("missing mode settings must resolve to record")
	}
	if !mcpAuditOnlyCeiling(context.Background(), deps) {
		t.Fatal("MCP contract must report audit-only when no mode is stored")
	}
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if configs.Engine["security_audit_only"] != true || configs.Gateway["security_audit_only"] != true {
		t.Fatalf("projections must be record: engine=%#v gateway=%#v", configs.Engine, configs.Gateway)
	}
	// nil deps and a missing repository are both "no stored mode".
	if !securityAuditOnlyEnabled(context.Background(), nil) || !securityAuditOnlyEnabled(context.Background(), &Dependencies{}) {
		t.Fatal("missing dependencies or repository must resolve to record")
	}
	if !mcpAuditOnlyCeiling(context.Background(), nil) {
		t.Fatal("MCP contract without dependencies must report audit-only")
	}
}

// Explicit legacy protect (security_audit_only=false, no managed mode) must still
// resolve to protect in every reader; the safe default only covers missing rows.
func TestLegacyProtectSettingStillResolvesToProtect(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	deps := semanticTestDeps(map[string]string{"security_audit_only": "false"})
	if securityAuditOnlyEnabled(context.Background(), deps) {
		t.Fatal("explicit legacy protect must stay protect")
	}
	if mcpAuditOnlyCeiling(context.Background(), deps) {
		t.Fatal("MCP contract must report blocking for explicit legacy protect")
	}
}
