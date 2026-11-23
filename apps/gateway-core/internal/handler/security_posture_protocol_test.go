package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestSecurityPostureGatewayRetainsDesiredRevisionUnderDeploymentLock(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	config, err := client.fetchSemanticRuntimeConfig(context.Background())
	if err != nil {
		t.Fatalf("fetch signed configuration: %v", err)
	}
	if !config.SecurityAuditOnly {
		t.Fatal("deployment recording lock was lifted")
	}
	report := semanticRuntimeReportPayload(config, "")
	if report["desired_revision"] != payload["revision"] {
		t.Fatalf("recording lock must retain original desired revision: report=%v desired=%v", report, payload["revision"])
	}
	if report["applied_revision"] == payload["revision"] {
		t.Fatal("effective hard-lock revision must remain distinct from protect intent")
	}
}

func TestSecurityPostureGatewayReportsActualModeAndSource(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		managed, configuredRecord, deploymentLock bool
		legacy                                    *bool
		wantRecord                                bool
		wantSource                                string
	}{
		{name: "unmanaged-refreshed-protect", wantSource: "signed"},
		{name: "unmanaged-refreshed-record", configuredRecord: true, wantRecord: true, wantSource: "signed"},
		{name: "unmanaged-legacy-record", legacy: postureTestBool(true), wantRecord: true, wantSource: "legacy"},
		{name: "unmanaged-legacy-protect", legacy: postureTestBool(false), wantSource: "legacy"},
		{name: "managed-protect", managed: true, wantSource: "signed"},
		{name: "managed-record", managed: true, configuredRecord: true, wantRecord: true, wantSource: "signed"},
		// 2.9.22（D7）：部署变量只作初值。托管模式优先（原期望 record/deployment 随之改写），
		// 没有显式模式时才取部署变量。
		{name: "deployment-env-managed-protect", managed: true, deploymentLock: true, wantSource: "signed"},
		{name: "deployment-initial-value", deploymentLock: true, wantRecord: true, wantSource: "deployment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			if tc.deploymentLock {
				t.Setenv("SECURITY_AUDIT_ONLY", "true")
			}
			t.Setenv("MCP_POLICY_FAIL_MODE", "closed")
			t.Setenv("SKILL_ADMISSION_FAIL_MODE", "closed")
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
			payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, tc.configuredRecord, false)
			payload["security_execution_mode_managed"] = tc.managed
			payload["guardrail_fail_closed_enabled"] = true
			revision, err := semanticGatewayConfigRevision(payload, gatewaySemanticTestKey)
			if err != nil {
				t.Fatal(err)
			}
			payload["revision"] = revision
			reported := make(chan map[string]any, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == semanticGatewayConfigPath {
					_ = json.NewEncoder(w).Encode(payload)
					return
				}
				if r.URL.Path == semanticGatewayReportPath {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					reported <- body
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
			mcp := NewMCPProxyHandler(nil, client, false)
			mcp.StartServerCacheInvalidator(context.Background())
			forward := NewForwardProxyHandler(nil, "tenant-test", "http://unused.invalid")
			forward.SetRuntimeConfigClient(client, false)
			if binder, ok := any(client).(interface {
				ConfigureSecurityPosture(*config.Config, *MCPProxyHandler, *ForwardProxyHandler)
			}); ok {
				binder.ConfigureSecurityPosture(&config.Config{MCPGatewayEnabled: true, MCPToolResultGuardEnabled: true}, mcp, forward)
			}
			runtime, err := client.fetchSemanticRuntimeConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client.runtimeCache.setSemanticConfig(runtime)
			if tc.legacy != nil {
				client.runtimeCache.setSecurityAuditOnly(*tc.legacy)
			}
			if err := client.reportSemanticRuntime(context.Background(), runtime, ""); err != nil {
				t.Fatal(err)
			}
			body := <-reported
			facts, ok := body["posture"].(map[string]any)
			if !ok {
				t.Fatalf("runtime receipt omitted actual consumer posture: %v", body)
			}
			if facts["security_audit_only"] != tc.wantRecord || facts["execution_mode_source"] != tc.wantSource {
				t.Fatalf("receipt disagrees with request mode: %v want record=%t source=%s", facts, tc.wantRecord, tc.wantSource)
			}
			if client.SecurityAuditOnly(context.Background(), false) != tc.wantRecord {
				t.Fatal("request and receipt mode differ")
			}
			if body["desired_revision"] != revision {
				t.Fatalf("desired revision lost: %v", body)
			}
			wantDifferent := tc.wantRecord != tc.configuredRecord
			if (body["applied_revision"] != revision) != wantDifferent {
				t.Fatalf("actual mode not reflected in revision: %v", body)
			}
			if facts["mcp_result_guard_enabled"] != true || facts["mcp_result_checker_wired"] != false || facts["mcp_cache_invalidator_wired"] != true || facts["mcp_cache_invalidator_running"] != false {
				t.Fatalf("receipt must expose enabled but unavailable consumers: %v", facts)
			}
			// 2.9.22 批次 2B：准入服务不可用不再有部署级 fail-closed（原期望 closed），处置按防护项 skill.admission_unavailable。
			if facts["guardrail_fail_closed"] != true || facts["capacity_fail_closed"] != true || facts["skill_admission_fail_mode"] != "open" {
				t.Fatalf("receipt omitted consumed failure controls: %v", facts)
			}
		})
	}
}

func postureTestBool(value bool) *bool { return &value }
