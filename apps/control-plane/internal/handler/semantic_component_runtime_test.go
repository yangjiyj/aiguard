package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

const semanticTestAttestationToken = "semantic-component-test-attestation"

func semanticTestDeps(settings map[string]string) *Dependencies {
	return &Dependencies{
		SystemRepo:                    &capturingSystemRepo{settings: settings},
		RulePackAttestationTokens:     map[string]string{semanticConfigTenant: semanticTestAttestationToken},
		SemanticGatewayAttestationKey: "semantic-gateway-test-attestation",
	}
}

func decodeSemanticPayload(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	return payload
}

func TestSemanticGatewayProjectionNeverContainsJudgeConfiguration(t *testing.T) {
	deps := semanticTestDeps(map[string]string{
		"semantic_enabled": "true", "semantic_input_enabled": "true",
		"semantic_agent_enabled": "false", "security_audit_only": "false",
		"judge_backend": "custom", "judge_url": "https://judge.example/v1/chat/completions",
		"judge_model": "secret-model", "judge_api_key": "secret-key",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config/gateway", nil)
	recorder := httptest.NewRecorder()
	GetInternalSemanticGatewayConfig(deps).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	payload := decodeSemanticPayload(t, recorder)
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// 2.9.22：正向代理防跳板出站的三个开关和两份名单也只下发给网关（未登记目标、白名单读取
	// 失败两项库里没存时不下发）。
	want := []string{"file_content_dlp_enabled", "forward_proxy_egress_allow_loopback", "forward_proxy_egress_allow_metadata", "forward_proxy_egress_allow_private", "forward_proxy_egress_allowed_cidrs", "forward_proxy_egress_allowed_hosts", "guardrail_fail_closed_enabled", "inspect_builtin_context", "inspect_history", "inspect_model_output", "inspect_tool_results", "inspect_user_input", "revision", "security_audit_only", "semantic_agent_enabled", "semantic_enabled", "semantic_input_enabled"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("gateway projection keys=%v want=%v", keys, want)
	}
	if len(payload["revision"].(string)) != semanticRevisionHexLength {
		t.Fatalf("revision=%q", payload["revision"])
	}
}

func TestInspectionScopeDefaultsAndSignedChanges(t *testing.T) {
	settings := map[string]string{"judge_backend": "bundled"}
	before, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(settings))
	if err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]bool{
		"inspect_user_input": true, "inspect_model_output": true,
		"inspect_builtin_context": false, "inspect_history": false, "inspect_tool_results": true,
	} {
		if before.Engine[key] != expected || before.Gateway[key] != expected {
			t.Fatalf("scope %s must be consistent in both signed projections", key)
		}
		settings[key] = fmt.Sprint(!expected)
		after, buildErr := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(settings))
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		if before.EngineRevision == after.EngineRevision || before.GatewayRevision == after.GatewayRevision {
			t.Fatalf("scope %s change must invalidate both revisions", key)
		}
		delete(settings, key)
	}
}

func TestSemanticEngineProjectionRequiresDedicatedAttestation(t *testing.T) {
	deps := semanticTestDeps(map[string]string{"judge_backend": "bundled"})
	handler := GetInternalSemanticEngineConfig(deps)
	for _, tc := range []struct {
		name, tenant, token string
		wantStatus          int
	}{
		{name: "missing attestation", tenant: semanticConfigTenant, wantStatus: http.StatusUnauthorized},
		{name: "wrong token", tenant: semanticConfigTenant, token: "wrong", wantStatus: http.StatusUnauthorized},
		{name: "wrong tenant", tenant: "tenant-other", token: semanticTestAttestationToken, wantStatus: http.StatusUnauthorized},
		{name: "valid engine", tenant: semanticConfigTenant, token: semanticTestAttestationToken, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config/engine", nil)
			req.Header.Set("X-Tenant-ID", tc.tenant)
			req.Header.Set(rulePackAttestationHeader, tc.token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				payload := decodeSemanticPayload(t, recorder)
				for _, key := range semanticEngineProjectionKeys {
					if _, ok := payload[key]; !ok {
						t.Fatalf("engine projection missing %q: %#v", key, payload)
					}
				}
			}
		})
	}
}

func TestSemanticComponentRevisionUsesKeyedIndependentProjection(t *testing.T) {
	base := map[string]string{
		"semantic_enabled": "true", "semantic_input_enabled": "true",
		"semantic_agent_enabled": "true", "judge_backend": "custom",
		"judge_url":   "https://judge.example/v1/chat/completions",
		"judge_model": "judge", "judge_api_key": "secret-a",
	}
	first, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(base))
	if err != nil {
		t.Fatalf("build first: %v", err)
	}
	rotated := make(map[string]string, len(base))
	for key, value := range base {
		rotated[key] = value
	}
	rotated["judge_api_key"] = "secret-b"
	second, err := buildSemanticComponentConfigs(context.Background(), semanticTestDeps(rotated))
	if err != nil {
		t.Fatalf("build second: %v", err)
	}
	if first.EngineRevision == second.EngineRevision {
		t.Fatal("judge credential rotation must change engine revision")
	}
	if first.GatewayRevision != second.GatewayRevision {
		t.Fatal("judge credential rotation must not change gateway revision")
	}
	otherKeyDeps := semanticTestDeps(base)
	otherKeyDeps.RulePackAttestationTokens[semanticConfigTenant] = "different-attestation-key"
	otherEngineKey, err := buildSemanticComponentConfigs(context.Background(), otherKeyDeps)
	if err != nil {
		t.Fatalf("build with other key: %v", err)
	}
	if first.EngineRevision == otherEngineKey.EngineRevision || first.GatewayRevision != otherEngineKey.GatewayRevision {
		t.Fatal("engine and gateway revisions must use independent component keys")
	}
	otherGatewayKeyDeps := semanticTestDeps(base)
	otherGatewayKeyDeps.SemanticGatewayAttestationKey = "different-gateway-attestation-key"
	otherGatewayKey, err := buildSemanticComponentConfigs(context.Background(), otherGatewayKeyDeps)
	if err != nil {
		t.Fatalf("build with other gateway key: %v", err)
	}
	if first.EngineRevision != otherGatewayKey.EngineRevision || first.GatewayRevision == otherGatewayKey.GatewayRevision {
		t.Fatal("gateway revision must use its own verification key")
	}
	canonical, _ := json.Marshal(first.Engine)
	unkeyed := sha256.Sum256(canonical)
	if first.EngineRevision == hex.EncodeToString(unkeyed[:semanticRevisionBytes]) {
		t.Fatal("revision must not be an unkeyed short hash of secret-bearing config")
	}
}

func TestLegacySemanticConfigEndpointIsGone(t *testing.T) {
	recorder := httptest.NewRecorder()
	LegacySemanticConfigGone().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil))
	if recorder.Code != http.StatusGone {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "judge_api_key") {
		t.Fatalf("legacy endpoint leaked: %s", recorder.Body.String())
	}
}

func TestSemanticRuntimeStatusRequiresEveryActiveNodeAtComponentRevision(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	now := time.Now().UTC()
	desired := semanticDesiredRevisions{
		Engine: strings.Repeat("a", semanticRevisionHexLength), Gateway: strings.Repeat("b", semanticRevisionHexLength),
		EngineJudgeRequired: true,
	}
	for _, report := range []semanticRuntimeReport{
		{Component: semanticEngineComponent, NodeID: "engine-1", AppliedRevision: desired.Engine, HeldRevision: desired.Engine, ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true), JudgeOperational: semanticBoolPtr(true), ReportedAt: now},
		{Component: semanticGatewayComponent, NodeID: "gateway-1", AppliedRevision: desired.Gateway, HeldRevision: desired.Gateway, ConfigLoaded: semanticBoolPtr(true), ReportedAt: now},
		{Component: semanticGatewayComponent, NodeID: "gateway-2", AppliedRevision: strings.Repeat("c", semanticRevisionHexLength), HeldRevision: strings.Repeat("c", semanticRevisionHexLength), ConfigLoaded: semanticBoolPtr(true), ReportedAt: now},
	} {
		if err := recordSemanticRuntime(report, now); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	status := buildSemanticRuntimeStatus(desired, now)
	if status.RuntimeVerified || status.Status != semanticRuntimeStatusPartial {
		t.Fatalf("lagging second gateway must prevent verification: %+v", status)
	}
	gateway := semanticComponentStatusByName(t, status, semanticGatewayComponent)
	if gateway.ActiveNodes != 2 || gateway.AppliedNodes != 1 || gateway.Status == semanticRuntimeStatusApplied {
		t.Fatalf("gateway status hid lagging node: %+v", gateway)
	}
	if err := recordSemanticRuntime(semanticRuntimeReport{
		Component: semanticGatewayComponent, NodeID: "gateway-2", AppliedRevision: desired.Gateway,
		HeldRevision: desired.Gateway, ConfigLoaded: semanticBoolPtr(true), ReportedAt: now.Add(time.Second),
	}, now.Add(time.Second)); err != nil {
		t.Fatalf("update: %v", err)
	}
	status = buildSemanticRuntimeStatus(desired, now.Add(time.Second))
	if !status.RuntimeVerified || status.Status != semanticRuntimeStatusApplied {
		t.Fatalf("all active nodes converged should verify: %+v", status)
	}
}

func TestSemanticRuntimeLedgerIsBoundedAndExpiredNodesArePruned(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	now := time.Now().UTC()
	for index := 0; index < semanticRuntimeMaxNodesPerComponent; index++ {
		report := semanticRuntimeReport{Component: semanticGatewayComponent, NodeID: fmt.Sprintf("node-%d", index),
			AppliedRevision: strings.Repeat("a", semanticRevisionHexLength), ConfigLoaded: semanticBoolPtr(true), ReportedAt: now}
		if err := recordSemanticRuntime(report, now); err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
	}
	if err := recordSemanticRuntime(semanticRuntimeReport{
		Component: semanticGatewayComponent, NodeID: "overflow",
		AppliedRevision: strings.Repeat("a", semanticRevisionHexLength), ConfigLoaded: semanticBoolPtr(true), ReportedAt: now,
	}, now); err != errSemanticRuntimeLedgerFull {
		t.Fatalf("overflow err=%v", err)
	}
	afterTTL := now.Add(semanticRuntimeReportTTL + time.Second)
	if err := recordSemanticRuntime(semanticRuntimeReport{
		Component: semanticGatewayComponent, NodeID: "replacement",
		AppliedRevision: strings.Repeat("a", semanticRevisionHexLength), ConfigLoaded: semanticBoolPtr(true), ReportedAt: afterTTL,
	}, afterTTL); err != nil {
		t.Fatalf("expired entries not pruned: %v", err)
	}
	if count := semanticRuntimeLedgerSizeForTest(); count != 1 {
		t.Fatalf("ledger size=%d want=1", count)
	}
}

func TestSemanticRuntimeReportComponentCredentialIsolationAndDegradedReceipt(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	deps := semanticTestDeps(nil)
	revision := strings.Repeat("d", semanticRevisionHexLength)
	body := fmt.Sprintf("{\"component\":\"security-engine\",\"node_id\":\"engine-1\",\"applied_revision\":\"%s\",\"held_revision\":\"%s\",\"config_loaded\":true,\"judge_required\":true,\"judge_operational\":false,\"error_code\":\"config_apply_failed\"}", revision, revision)
	wrongPath := httptest.NewRecorder()
	ReportSemanticRuntimeComponent(deps, semanticGatewayComponent).ServeHTTP(wrongPath,
		httptest.NewRequest(http.MethodPost, "/admin/v1/internal/security/semantic-runtime-report/gateway", strings.NewReader(body)))
	if wrongPath.Code != http.StatusBadRequest {
		t.Fatalf("gateway path accepted engine identity: %s", wrongPath.Body.String())
	}
	for _, token := range []string{"", "wrong", semanticTestAttestationToken} {
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/security/semantic-runtime-report/engine", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", semanticConfigTenant)
		req.Header.Set(rulePackAttestationHeader, token)
		recorder := httptest.NewRecorder()
		ReportSemanticRuntimeComponent(deps, semanticEngineComponent).ServeHTTP(recorder, req)
		want := http.StatusUnauthorized
		if token == semanticTestAttestationToken {
			want = http.StatusOK
		}
		if recorder.Code != want {
			t.Fatalf("token=%q status=%d want=%d body=%s", token, recorder.Code, want, recorder.Body.String())
		}
	}
	status := buildSemanticRuntimeStatus(semanticDesiredRevisions{
		Engine: revision, Gateway: strings.Repeat("e", semanticRevisionHexLength),
	}, time.Now().UTC())
	engine := semanticComponentStatusByName(t, status, semanticEngineComponent)
	if engine.Status != semanticRuntimeStatusDegraded || engine.LastError != "config_apply_failed" || engine.HeldRevision != revision {
		t.Fatalf("degraded receipt not reachable: %+v", engine)
	}
}

func TestSemanticRuntimeRequiresOperationalJudgeWhenEnabled(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	now := time.Now().UTC()
	desired := semanticDesiredRevisions{
		Engine: strings.Repeat("a", semanticRevisionHexLength), Gateway: strings.Repeat("b", semanticRevisionHexLength),
		EngineJudgeRequired: true,
	}
	for _, report := range []semanticRuntimeReport{
		{Component: semanticEngineComponent, NodeID: "engine-1", AppliedRevision: desired.Engine, HeldRevision: desired.Engine, ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true), JudgeOperational: semanticBoolPtr(false), JudgeConsecutiveFailures: 1, ErrorCode: "judge_unavailable", ReportedAt: now},
		{Component: semanticGatewayComponent, NodeID: "gateway-1", AppliedRevision: desired.Gateway, HeldRevision: desired.Gateway, ConfigLoaded: semanticBoolPtr(true), ReportedAt: now},
	} {
		if err := recordSemanticRuntime(report, now); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	degraded := buildSemanticRuntimeStatus(desired, now)
	if degraded.RuntimeVerified || degraded.Status != semanticRuntimeStatusDegraded {
		t.Fatalf("loaded config with unavailable judge must not verify: %+v", degraded)
	}
	engine := semanticComponentStatusByName(t, degraded, semanticEngineComponent)
	if !engine.ConfigLoaded || !engine.JudgeRequired || engine.JudgeOperational || engine.JudgeConsecutiveFailures != 1 {
		t.Fatalf("runtime axes were collapsed or lost: %+v", engine)
	}
	if err := recordSemanticRuntime(semanticRuntimeReport{
		Component: semanticEngineComponent, NodeID: "engine-1", AppliedRevision: desired.Engine, HeldRevision: desired.Engine,
		ConfigLoaded: semanticBoolPtr(true), JudgeRequired: semanticBoolPtr(true), JudgeOperational: semanticBoolPtr(true),
		JudgeConsecutiveFailures: 0, ReportedAt: now.Add(time.Second),
	}, now.Add(time.Second)); err != nil {
		t.Fatalf("record recovery: %v", err)
	}
	recovered := buildSemanticRuntimeStatus(desired, now.Add(time.Second))
	if !recovered.RuntimeVerified || recovered.Status != semanticRuntimeStatusApplied {
		t.Fatalf("healthy judge plus loaded config should verify: %+v", recovered)
	}
}

func semanticBoolPtr(value bool) *bool { return &value }

func semanticComponentStatusByName(t *testing.T, status semanticRuntimeStatus, name string) semanticRuntimeComponentStatus {
	t.Helper()
	for _, component := range status.Components {
		if component.Component == name {
			return component
		}
	}
	t.Fatalf("component %q missing: %+v", name, status)
	return semanticRuntimeComponentStatus{}
}
