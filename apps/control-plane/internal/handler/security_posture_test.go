package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

func postureTestGateway(record bool, source string) *inspectionscope.GatewaySecurityPosture {
	b := inspectionscope.PostureBool
	return &inspectionscope.GatewaySecurityPosture{SchemaVersion: 1, SecurityAuditOnly: b(record), ExecutionModeSource: source, DeploymentAuditOnly: b(source == "deployment"),
		GuardrailFailClosed: b(true), CapacityFailClosed: b(false), MCPPolicyFailMode: "closed", SkillAdmissionFailMode: "closed", ForwardProxyMode: "deny_unlisted", WhitelistFailMode: "closed",
		MCPGatewayEnabled: b(true), MCPResultGuardEnabled: b(true), MCPResultCheckerWired: b(true), MCPCacheInvalidatorWired: b(true), MCPCacheInvalidatorRunning: b(true),
		SecurityActionHeaderEnabled: b(false), FileDLPEnabled: b(true), InspectUserInput: b(true), InspectModelOutput: b(true), InspectToolResults: b(true), AgentGuardWired: b(true), SkillAdmissionWired: b(true), ReverseStreamGuardWired: b(true)}
}

func postureTestProxy(now time.Time, revision string) inspectionscope.RuntimeStatus {
	b := inspectionscope.PostureBool
	return inspectionscope.RuntimeStatus{Component: "proxy-server", ConfigComponent: "gateway-core", NodeID: "proxy-1", Status: "applied", ConfigLoaded: true, Fresh: true, AppliedRevision: revision, LastSuccessAt: now.Format(time.RFC3339Nano),
		Posture: &inspectionscope.ProxySecurityPosture{SchemaVersion: 1, SecurityAuditOnly: b(false), DeploymentAuditOnly: b(false), CapacityFailClosed: b(false), DetectionFailMode: "open", WhitelistFailMode: "closed",
			InspectionQueueWired: b(true), InspectUserInput: b(true), InspectModelOutput: b(true), InspectToolResults: b(true), ModeSourceVerified: b(true), TLSInspectionCapable: b(true)}}
}

func postureTestReports(t *testing.T, now time.Time) (semanticComponentConfigs, []byte, map[string][]semanticRuntimeReport, inspectionscope.RuntimeStatus) {
	t.Helper()
	key := []byte("posture-test-attestation-key")
	configs := semanticComponentConfigs{Gateway: map[string]any{"security_audit_only": false, "security_execution_mode_managed": true},
		Engine: map[string]any{"semantic_enabled": false, "semantic_input_enabled": true, "judge_api_key": "must-never-leak", "judge_api_base": "https://secret.invalid"}, EngineRevision: strings.Repeat("e", 32)}
	var err error
	configs.GatewayRevision, err = semanticConfigRevision(semanticGatewayComponent, configs.Gateway, key)
	if err != nil {
		t.Fatal(err)
	}
	reports := map[string][]semanticRuntimeReport{
		semanticGatewayComponent: {{Component: semanticGatewayComponent, NodeID: "gateway-1", ConfigLoaded: inspectionscope.PostureBool(true), DesiredRevision: configs.GatewayRevision, AppliedRevision: configs.GatewayRevision, ReportedAt: now, Posture: postureTestGateway(false, "signed")}},
		semanticEngineComponent:  {{Component: semanticEngineComponent, NodeID: "engine-1", ConfigLoaded: inspectionscope.PostureBool(true), AppliedRevision: configs.EngineRevision, ReportedAt: now}},
	}
	return configs, key, reports, postureTestProxy(now, configs.GatewayRevision)
}

func TestSecurityPostureRequiresFreshMatchingReceiptsFromEveryConsumer(t *testing.T) {
	now := time.Now().UTC()
	for _, name := range []string{"valid", "gateway-missing", "gateway-old-schema", "gateway-stale", "gateway-future", "gateway-wrong-component", "gateway-desired-mismatch", "gateway-applied-mismatch", "gateway-fetch-failed", "gateway-one-bad-node", "proxy-missing", "proxy-stale", "proxy-mode-unverified", "proxy-wrong-revision", "proxy-probe-error", "engine-missing", "engine-stale"} {
		t.Run(name, func(t *testing.T) {
			configs, key, reports, proxy := postureTestReports(t, now)
			gateway := &reports[semanticGatewayComponent][0]
			var probeErr error
			switch name {
			case "gateway-missing":
				delete(reports, semanticGatewayComponent)
			case "gateway-old-schema":
				gateway.Posture = nil
			case "gateway-stale":
				gateway.ReportedAt = now.Add(-semanticRuntimeReportTTL - time.Second)
			case "gateway-future":
				gateway.ReportedAt = now.Add(time.Minute)
			case "gateway-wrong-component":
				gateway.Component = semanticEngineComponent
			case "gateway-desired-mismatch":
				gateway.DesiredRevision = strings.Repeat("a", 32)
			case "gateway-applied-mismatch":
				gateway.AppliedRevision = strings.Repeat("a", 32)
			case "gateway-fetch-failed":
				gateway.ErrorCode = "config_fetch_failed"
			case "gateway-one-bad-node":
				other := *gateway
				other.NodeID = "gateway-2"
				other.Posture = nil
				reports[semanticGatewayComponent] = append(reports[semanticGatewayComponent], other)
			case "proxy-missing":
				proxy.Posture = nil
			case "proxy-stale":
				proxy.LastSuccessAt = now.Add(-semanticRuntimeReportTTL - time.Second).Format(time.RFC3339Nano)
			case "proxy-mode-unverified":
				proxy.Posture.ModeSourceVerified = inspectionscope.PostureBool(false)
			case "proxy-wrong-revision":
				proxy.AppliedRevision = strings.Repeat("a", 32)
			case "proxy-probe-error":
				probeErr = errors.New("unavailable")
			case "engine-missing":
				delete(reports, semanticEngineComponent)
			case "engine-stale":
				reports[semanticEngineComponent][0].ReportedAt = now.Add(-semanticRuntimeReportTTL - time.Second)
			}
			out := buildSecurityPosture("tenant-a", configs, key, reports, proxy, probeErr, now)
			if out.RuntimeVerified != (name == "valid") {
				t.Fatalf("receipt verification wrong: %+v", out)
			}
			if strings.HasPrefix(name, "gateway-") && out.Channels[0].EffectiveMode != "unknown" {
				t.Fatalf("unverified gateway guessed mode: %+v", out.Channels)
			}
			if strings.HasPrefix(name, "proxy-") && out.Channels[3].EffectiveMode != "unknown" {
				t.Fatalf("unverified proxy guessed mode: %+v", out.Channels[3])
			}
			payload, _ := json.Marshal(out)
			if strings.Contains(string(payload), "must-never-leak") || strings.Contains(string(payload), "secret.invalid") || strings.Contains(string(payload), "judge_api") {
				t.Fatalf("secret escaped safe DTO: %s", payload)
			}
			if name == "valid" {
				if len(out.Channels) != 5 || len(out.MLLayers) != 10 || *out.MLLayers[1].RuntimeEnabled {
					t.Fatalf("ML master switch not consumed: %+v", out)
				}
				if out.Channels[3].FailModes[2].ID != "proxy_detection" || out.Channels[3].FailModes[2].Mode != "open" {
					t.Fatalf("proxy ordinary failure getter not reported: %+v", out.Channels[3])
				}
			}
		})
	}
}

func TestSecurityPostureExposesMixedNodesAndRecordingSource(t *testing.T) {
	now := time.Now().UTC()
	configs, key, reports, proxy := postureTestReports(t, now)
	configs.Gateway["security_execution_mode_managed"] = false
	configs.GatewayRevision, _ = semanticConfigRevision(semanticGatewayComponent, configs.Gateway, key)
	first := &reports[semanticGatewayComponent][0]
	first.DesiredRevision, first.AppliedRevision = configs.GatewayRevision, configs.GatewayRevision
	first.Posture = postureTestGateway(false, "legacy")
	second := *first
	second.NodeID = "gateway-2"
	second.Posture = postureTestGateway(true, "startup")
	actual := map[string]any{"security_audit_only": true, "security_execution_mode_managed": false}
	second.AppliedRevision, _ = semanticConfigRevision(semanticGatewayComponent, actual, key)
	reports[semanticGatewayComponent] = append(reports[semanticGatewayComponent], second)
	proxy.AppliedRevision = configs.GatewayRevision
	out := buildSecurityPosture("tenant-a", configs, key, reports, proxy, nil, now)
	if out.RuntimeVerified || out.Channels[0].EffectiveMode != "mixed" || out.Channels[0].RuntimeVerified {
		t.Fatalf("multi-node divergence hidden: %+v", out)
	}
	if strings.Join(out.Channels[0].ModeSources, ",") != "legacy,startup" {
		t.Fatalf("actual sources lost: %+v", out.Channels[0])
	}
	if !strings.Contains(strings.Join(out.Warnings, ","), "gateway_execution_mode_startup") {
		t.Fatalf("startup recording reason hidden: %+v", out.Warnings)
	}
}

func TestSecurityPostureDeploymentLockUsesActualRevision(t *testing.T) {
	now := time.Now().UTC()
	configs, key, reports, proxy := postureTestReports(t, now)
	report := &reports[semanticGatewayComponent][0]
	report.Posture = postureTestGateway(true, "deployment")
	actual := map[string]any{"security_audit_only": true, "security_execution_mode_managed": true}
	report.AppliedRevision, _ = semanticConfigRevision(semanticGatewayComponent, actual, key)
	out := buildSecurityPosture("tenant-a", configs, key, reports, proxy, nil, now)
	if out.Channels[0].ConfiguredMode != "protect" || out.Channels[0].EffectiveMode != "record" || !out.Channels[0].RuntimeVerified {
		t.Fatalf("deployment hard lock not visible: %+v", out.Channels[0])
	}
	if out.Channels[3].EffectiveMode != "mixed" {
		t.Fatalf("proxy mode disagreement hidden: %+v", out.Channels[3])
	}
	if strings.Join(out.Channels[0].ModeSources, ",") != "deployment" {
		t.Fatalf("deployment source lost: %+v", out.Channels[0])
	}
}

func TestSecurityPostureReadRouteRejectsUnauthorizedUsersAndWrites(t *testing.T) {
	for _, path := range []string{"/admin/v1/security/posture", "/api/security/posture"} {
		for _, tc := range []struct {
			method, role, tenant string
			want                 int
		}{
			{http.MethodGet, "", "", http.StatusUnauthorized}, {http.MethodGet, "developer", "tenant-a", http.StatusForbidden}, {http.MethodGet, "auditor", "tenant-a", http.StatusForbidden},
			{http.MethodGet, "platform_admin", "", http.StatusForbidden}, {http.MethodPost, "platform_admin", "tenant-a", http.StatusMethodNotAllowed},
		} {
			t.Run(path+tc.method+tc.role+tc.tenant, func(t *testing.T) {
				r := httptest.NewRequest(tc.method, path+"?tenant_id=forged", nil)
				r.Header.Set("X-Tenant-ID", "forged")
				if tc.role != "" {
					r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{Role: tc.role, TenantID: tc.tenant}))
				}
				w := httptest.NewRecorder()
				GetSecurityPosture(&Dependencies{})(w, r)
				if w.Code != tc.want {
					t.Fatalf("unauthorized or write route accepted: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestSecurityPostureReadUsesAuthenticatedTenantAndPreservesRecordingDefault(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	repo := &capturingSystemRepo{settings: map[string]string{"security_audit_only": "true"}}
	before, _ := json.Marshal(repo.settings)
	deps := &Dependencies{SystemRepo: repo, SecurityEngineInternalToken: "test-token", SemanticGatewayAttestationKey: "posture-gateway-test-key", RulePackAttestationTokens: map[string]string{semanticConfigTenant: "posture-engine-test-key"}}
	oldClient := proxyScopeHTTPClient
	t.Cleanup(func() { proxyScopeHTTPClient = oldClient })
	proxyScopeHTTPClient = &http.Client{Transport: inspectionRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"component":"proxy-server","config_component":"gateway-core"}`))}, nil
	})}
	for _, path := range []string{"/admin/v1/security/posture", "/api/security/posture"} {
		for _, role := range []string{"platform_admin", "security_officer"} {
			r := httptest.NewRequest(http.MethodGet, path+"?tenant_id=forged", nil)
			r.Header.Set("X-Tenant-ID", "forged")
			r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{Role: role, TenantID: "tenant-authenticated"}))
			w := httptest.NewRecorder()
			GetSecurityPosture(deps)(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("read failed: %d %s", w.Code, w.Body.String())
			}
			var out securityPosture
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.TenantID != "tenant-authenticated" || out.RuntimeVerified || len(out.Channels) != 5 {
				t.Fatalf("forged tenant accepted or absent runtime guessed: %+v", out)
			}
			for _, channel := range out.Channels {
				if channel.ConfiguredMode != "record" || channel.EffectiveMode != "unknown" || channel.RuntimeVerified {
					t.Fatalf("recording product default altered or inferred runtime: %+v", channel)
				}
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("tenant posture may be cached")
			}
		}
	}
	after, _ := json.Marshal(repo.settings)
	if string(before) != string(after) || len(repo.auditOps) != 0 {
		t.Fatal("read-only posture changed settings or wrote audit operations")
	}
}

func TestSecurityPostureGatewayReceiptRejectsInvalidOrEnginePosture(t *testing.T) {
	for _, name := range []string{"old-schema", "missing-control", "missing-desired-revision", "contradictory-lock", "unknown-control", "engine-receipt"} {
		t.Run(name, func(t *testing.T) {
			resetSemanticRuntimeReportsForTest()
			t.Cleanup(resetSemanticRuntimeReportsForTest)
			p := postureTestGateway(false, "signed")
			encoded, _ := json.Marshal(p)
			var facts map[string]any
			_ = json.Unmarshal(encoded, &facts)
			body := map[string]any{"component": semanticGatewayComponent, "node_id": "gateway-1", "applied_revision": strings.Repeat("a", 32), "desired_revision": strings.Repeat("b", 32), "config_loaded": true, "posture": facts}
			component := semanticGatewayComponent
			switch name {
			case "old-schema":
				facts["schema_version"] = 0
			case "missing-control":
				delete(facts, "inspect_user_input")
			case "missing-desired-revision":
				delete(body, "desired_revision")
			case "contradictory-lock":
				facts["deployment_audit_only"] = true
			case "unknown-control":
				facts["token"] = "must-not-leak"
			case "engine-receipt":
				component = semanticEngineComponent
				body["component"] = component
			}
			payload, _ := json.Marshal(body)
			r := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/security/semantic-runtime-report/gateway", strings.NewReader(string(payload)))
			deps := &Dependencies{RulePackAttestationTokens: map[string]string{semanticConfigTenant: "posture-report-test-token"}}
			if component == semanticEngineComponent {
				r.Header.Set("X-Tenant-ID", semanticConfigTenant)
				r.Header.Set(rulePackAttestationHeader, "posture-report-test-token")
			}
			w := httptest.NewRecorder()
			ReportSemanticRuntimeComponent(deps, component)(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid runtime facts accepted: %s %d %s", name, w.Code, w.Body.String())
			}
			if semanticRuntimeLedgerSizeForTest() != 0 {
				t.Fatal("invalid posture contaminated runtime ledger")
			}
		})
	}
}
