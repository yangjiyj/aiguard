package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestInternalSemanticConfigUsesExplicitSafeDefaultsAndRevision(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := semanticTestDeps(repo.settings)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()

	GetInternalSemanticConfig(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled"} {
		if value, ok := got[key].(bool); !ok || !value {
			t.Fatalf("%s=%#v, want zero-configuration default true", key, got[key])
		}
	}
	if got["semantic_output_enabled"] != false {
		t.Fatalf("semantic_output_enabled=%#v, want false", got["semantic_output_enabled"])
	}
	if got["tier1_enabled"] != true {
		t.Fatalf("tier1_enabled=%#v, want true", got["tier1_enabled"])
	}
	if got["judge_timeout"] != defaultJudgeTimeout || got["semantic_total_timeout"] != defaultSemanticTotalTimeout {
		t.Fatalf("timeouts=%#v/%#v, want %s/%s", got["judge_timeout"], got["semantic_total_timeout"], defaultJudgeTimeout, defaultSemanticTotalTimeout)
	}
	if got["security_audit_only"] != true {
		t.Fatalf("security_audit_only=%#v, want safe default true", got["security_audit_only"])
	}
	if got["judge_backend"] != "bundled" {
		t.Fatalf("judge_backend=%#v, want bundled", got["judge_backend"])
	}
	revision, _ := got["revision"].(string)
	if len(revision) != semanticRevisionHexLength {
		t.Fatalf("revision=%q, want %d hex chars", revision, semanticRevisionHexLength)
	}
}

func TestSemanticConfigRevisionTracksEffectiveSecretWithoutExposingIt(t *testing.T) {
	first := map[string]any{"semantic_enabled": true, "judge_api_key": "secret-a", "semantic_total_timeout": "6"}
	second := map[string]any{"semantic_total_timeout": "6", "judge_api_key": "secret-a", "semantic_enabled": true}
	third := map[string]any{"semantic_enabled": true, "judge_api_key": "secret-b", "semantic_total_timeout": "6"}
	key := []byte(semanticTestAttestationToken)
	firstRevision, _ := semanticConfigRevision(semanticEngineComponent, first, key)
	secondRevision, _ := semanticConfigRevision(semanticEngineComponent, second, key)
	thirdRevision, _ := semanticConfigRevision(semanticEngineComponent, third, key)

	if firstRevision != secondRevision {
		t.Fatal("revision must be independent of map insertion order")
	}
	if firstRevision == thirdRevision {
		t.Fatal("rotating the judge credential must change revision")
	}
}

func TestSemanticEngineProjectionPinsBundledTier1URL(t *testing.T) {
	deps := semanticTestDeps(map[string]string{
		"tier1_enabled": "true",
		"tier1_url":     "http://attacker.example/collect",
	})
	config, err := buildSemanticEngineProjection(context.Background(), deps)
	if err != nil {
		t.Fatalf("build projection: %v", err)
	}
	if got := config["tier1_url"]; got != defaultTier1URL {
		t.Fatalf("tier1_url=%v want fixed bundled endpoint %q", got, defaultTier1URL)
	}
}

func TestSemanticRuntimeStatusRequiresBothComponentsAtDesiredRevision(t *testing.T) {
	// This fixture models a deployment without the optional forward proxy.
	t.Setenv("JJD_PROXY_INSPECTION_REQUIRED", "false")
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	repo := &capturingSystemRepo{settings: map[string]string{
		"semantic_enabled":       "true",
		"semantic_input_enabled": "true",
		"semantic_agent_enabled": "true",
		"judge_backend":          "bundled",
	}}
	deps := semanticTestDeps(repo.settings)
	desired, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatalf("build desired config: %v", err)
	}

	reportSemanticRuntime(semanticRuntimeReport{
		Component: semanticEngineComponent, NodeID: "engine-1", AppliedRevision: desired.EngineRevision,
		ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true), JudgeOperational: semanticBoolPtr(true), ReportedAt: time.Now(),
	})
	partial := getSemanticRuntimeStatusForTest(t, deps)
	if partial.Status != semanticRuntimeStatusPartial || partial.RuntimeVerified {
		t.Fatalf("one component must be partial/unverified: %+v", partial)
	}

	reportSemanticRuntime(semanticRuntimeReport{
		Component: semanticGatewayComponent, NodeID: "gateway-1", AppliedRevision: desired.GatewayRevision,
		ConfigLoaded: semanticBoolPtr(true), ReportedAt: time.Now(),
	})
	applied := getSemanticRuntimeStatusForTest(t, deps)
	if applied.Status != semanticRuntimeStatusApplied || !applied.RuntimeVerified {
		t.Fatalf("both components at desired revision must be verified: %+v", applied)
	}
	if len(applied.Components) != 2 {
		t.Fatalf("components=%#v", applied.Components)
	}
}

func TestSemanticRuntimeReportRejectsInvalidComponentAndOversizedFields(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	deps := &Dependencies{}
	for _, body := range []string{
		`{"component":"attacker","node_id":"node","applied_revision":"0123456789abcdef","config_loaded":true}`,
		`{"component":"gateway-core","node_id":"","applied_revision":"0123456789abcdef","config_loaded":true}`,
		`{"component":"gateway-core","node_id":"node","applied_revision":"not-a-revision","config_loaded":true}`,
		`{"component":"gateway-core","node_id":"node","applied_revision":"0123456789abcdef","last_error":"` + strings.Repeat("x", 1025) + `"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/security/semantic-runtime-report", strings.NewReader(body))
		w := httptest.NewRecorder()
		ReportSemanticRuntime(deps).ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d want 400 response=%s", body, w.Code, w.Body.String())
		}
	}
}

func getSemanticRuntimeStatusForTest(t *testing.T, deps *Dependencies) semanticRuntimeStatus {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/security/semantic/runtime-status", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "admin", TenantID: "tenant_default", Role: "platform_admin", Status: "active",
	}))
	w := httptest.NewRecorder()
	GetSemanticRuntimeStatus(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Runtime semanticRuntimeStatus `json:"runtime"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode runtime: %v", err)
	}
	return response.Runtime
}
