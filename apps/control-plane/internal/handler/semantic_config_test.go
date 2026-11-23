package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestResolveJudgeBackendBundled(t *testing.T) {
	got := resolveJudgeBackend(map[string]string{"judge_backend": "bundled"}, nil, func(string) string { return "" })
	if got.URL != "http://llm-judge:8080/v1/chat/completions" || got.Model != "bundled-judge" || got.APIKey != "bundled-judge" {
		t.Fatalf("bundled 解析错: %#v", got)
	}
}

func TestResolveJudgeBackendCustomDecryptsKey(t *testing.T) {
	settings := map[string]string{
		"judge_backend":              "custom",
		"judge_url":                  "https://relay.example/v1/chat/completions",
		"judge_model":                "gpt-5.5",
		"judge_api_key":              "ENC(abc)",
		"judge_allow_private_egress": "true",
	}
	got := resolveJudgeBackend(settings, nil, func(enc string) string { return "plain-" + enc })
	if got.URL != "https://relay.example/v1/chat/completions" || got.Model != "gpt-5.5" ||
		got.APIKey != "plain-ENC(abc)" || !got.AllowPrivateEgress {
		t.Fatalf("custom 解析/解密错: %#v", got)
	}
}

func TestResolveJudgeBackendProviderLooksUp(t *testing.T) {
	prov := &resolvedProvider{BaseURL: "https://api.deepseek.com", Model: "deepseek-v4-flash", APIKey: "sk-x"}
	got := resolveJudgeBackend(map[string]string{"judge_backend": "provider", "judge_provider_id": "p1"},
		map[string]*resolvedProvider{"p1": prov}, func(string) string { return "" })
	if got.URL != "https://api.deepseek.com/v1/chat/completions" || got.Model != "deepseek-v4-flash" || got.APIKey != "sk-x" {
		t.Fatalf("provider 解析错: %#v", got)
	}
}

func TestTestJudgeRejectsNonHTTPURL(t *testing.T) {
	_, err := runJudgeProbe(judgeBackend{URL: "file:///etc/passwd", Model: "m", APIKey: "k"}, 3)
	if err == nil {
		t.Fatalf("file:// 应被拒，未发请求")
	}
}

func TestTestJudgeRejectsLoopbackByDefault(t *testing.T) {
	_, err := runJudgeProbe(judgeBackend{URL: "http://127.0.0.1:65535/v1/chat/completions", Model: "m", APIKey: "k"}, 3)
	if err == nil {
		t.Fatalf("loopback judge must be rejected before dialing")
	}
}

func TestTestJudgeParsesVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"malicious\"}"}}]}`))
	}))
	defer srv.Close()
	endpoint, network := semanticJudgeNetworkForTestServer(t, srv, "judge.example")
	res, err := runJudgeProbeWithNetwork(
		context.Background(),
		judgeBackend{URL: endpoint, Model: "m", APIKey: "k"},
		5,
		network,
	)
	if err != nil || res.Verdict != "malicious" {
		t.Fatalf("探测应返回 malicious, got %#v err=%v", res, err)
	}
}

// SFIX-1(a): 内部供给端点必须回显 Tier-1/FP 四键（tier1_enabled/fp_suppression_enabled 布尔，
// tier1_low_threshold/tier1_high_threshold 数值字符串），否则 UpdateSmartDetectionConfig 写进
// system_settings 的值到不了 security-engine loader（loader 的 _BOOL_KEYS/_NUM_KEYS 已认这四键，
// 但端点从不 emit → override 恒空 → DB 配置对引擎不生效）。遵循"有才放、缺则略"范式。
func TestGetInternalSemanticConfigEmitsTier1AndFpKeys(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"tier1_enabled":          "true",
		"fp_suppression_enabled": "false",
		"tier1_low_threshold":    "0.15",
		"tier1_high_threshold":   "0.85",
	}}
	deps := semanticTestDeps(repo.settings)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()

	GetInternalSemanticConfig(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	// 布尔开关：settings 有 → 以 JSON bool 回显。
	if v, ok := got["tier1_enabled"].(bool); !ok || v != true {
		t.Errorf("tier1_enabled = %#v, want bool true", got["tier1_enabled"])
	}
	if v, ok := got["fp_suppression_enabled"].(bool); !ok || v != false {
		t.Errorf("fp_suppression_enabled = %#v, want bool false", got["fp_suppression_enabled"])
	}
	// 数值参数：原样透传字符串（与既有 semantic_total_timeout 等口径一致，loader 侧再转）。
	if got["tier1_low_threshold"] != "0.15" {
		t.Errorf("tier1_low_threshold = %#v, want \"0.15\"", got["tier1_low_threshold"])
	}
	if got["tier1_high_threshold"] != "0.85" {
		t.Errorf("tier1_high_threshold = %#v, want \"0.85\"", got["tier1_high_threshold"])
	}
}

// 缺键也必须下发确定的安全默认，engine 不再回退环境变量后宣称 applied。
func TestGetInternalSemanticConfigEmitsSafeTier1Defaults(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{}}
	deps := semanticTestDeps(repo.settings)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()

	GetInternalSemanticConfig(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if got["tier1_enabled"] != true || got["fp_suppression_enabled"] != false {
		t.Fatalf("missing bool settings must use delivery defaults: %#v", got)
	}
	for _, key := range []string{"source_aware_enabled", "confidence_gating_enabled", "coding_traffic_downgrade_enabled"} {
		if got[key] != true {
			t.Fatalf("missing %s must enable the shipped noise-control default: %#v", key, got)
		}
	}
	if got["tier1_low_threshold"] != "0.30" || got["tier1_high_threshold"] != "0.70" {
		t.Fatalf("missing thresholds must use deterministic defaults: %#v", got)
	}
}

func TestBuildSemanticEngineProjectionForcesOutputAttackDetectionOff(t *testing.T) {
	deps := semanticTestDeps(map[string]string{
		"semantic_enabled":        "true",
		"semantic_input_enabled":  "true",
		"semantic_output_enabled": "true",
	})

	got, err := buildSemanticEngineProjection(context.Background(), deps)
	if err != nil {
		t.Fatalf("buildSemanticEngineProjection: %v", err)
	}
	if got["semantic_output_enabled"] != false {
		t.Fatalf("semantic_output_enabled=%#v want false", got["semantic_output_enabled"])
	}
	if got["semantic_input_enabled"] != true {
		t.Fatalf("input semantic detection must remain enabled: %#v", got)
	}
}

// P1-A 任务16: 内部供给端点必须回显 source_aware/置信度门控/编码降级三翻转开关，
// 否则 DB override 到不了 security-engine loader（loader 的 _BOOL_KEYS 已认这三键），
// 交付默认翻转对引擎不生效。遵循"有才放、缺则略"范式。
func TestGetInternalSemanticConfigEmitsFlipFlags(t *testing.T) {
	repo := &capturingSystemRepo{settings: map[string]string{
		"source_aware_enabled":             "true",
		"confidence_gating_enabled":        "true",
		"coding_traffic_downgrade_enabled": "false",
	}}
	deps := semanticTestDeps(repo.settings)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/security/semantic-config", nil)
	w := httptest.NewRecorder()
	GetInternalSemanticConfig(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["source_aware_enabled"] != true {
		t.Errorf("source_aware_enabled = %#v, want true", got["source_aware_enabled"])
	}
	if got["confidence_gating_enabled"] != true {
		t.Errorf("confidence_gating_enabled = %#v, want true", got["confidence_gating_enabled"])
	}
	if got["coding_traffic_downgrade_enabled"] != false {
		t.Errorf("coding_traffic_downgrade_enabled = %#v, want false", got["coding_traffic_downgrade_enabled"])
	}
}

func TestTestSemanticJudgeRejectsOversizedRequest(t *testing.T) {
	body := []byte(`{"judge_backend":"custom","judge_api_key":"` + strings.Repeat("x", semanticJudgeMaxRequestBytes) + `"}`)
	response := httptest.NewRecorder()

	TestSemanticJudge(&Dependencies{}).ServeHTTP(
		response,
		adminCtxRequest(http.MethodPost, "/admin/v1/system/semantic/test-judge", body),
	)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413 body=%s", response.Code, response.Body.String())
	}
}

func TestTestSemanticJudgePrivateProviderRequiresExplicitOptIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"benign\"}"}}]}`))
	}))
	defer server.Close()
	endpoint, network := semanticJudgeNetworkForTestServerAddress(t, server, "private-judge.example", "10.0.0.9")

	providerRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"p-private": {ID: "p-private", TenantID: semanticConfigTenant, BaseURL: endpoint},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"p-private": {ProviderID: "p-private", SecretCiphertext: "sk-plain"},
		},
	}
	deps := &Dependencies{ProviderRepo: providerRepo}

	for _, tc := range []struct {
		name         string
		allowPrivate bool
		wantOK       bool
	}{
		{name: "default deny", allowPrivate: false, wantOK: false},
		{name: "explicit opt in", allowPrivate: true, wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"judge_backend":              "provider",
				"judge_provider_id":          "p-private",
				"judge_model":                "judge-m",
				"judge_allow_private_egress": tc.allowPrivate,
			})
			response := httptest.NewRecorder()
			testSemanticJudgeWithNetwork(deps, network).ServeHTTP(
				response,
				adminCtxRequest(http.MethodPost, "/admin/v1/system/semantic/test-judge", body),
			)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var got map[string]any
			if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if ok, _ := got["ok"].(bool); ok != tc.wantOK {
				t.Fatalf("allow_private=%v ok=%v want %v response=%#v", tc.allowPrivate, ok, tc.wantOK, got)
			}
		})
	}
}

// I2: test-judge 的 provider 查表必须用 tenant_default（与内部端点/运行时一致），
// 而非调用者 user.TenantID。否则非默认租户的管理员测着通、跑起来空。
func TestTestSemanticJudgeProviderUsesTenantDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"malicious\"}"}}]}`))
	}))
	defer srv.Close()
	endpoint, network := semanticJudgeNetworkForTestServer(t, srv, "provider-judge.example")
	// provider 归属 tenant_default（与运行时口径一致）。
	provRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"p1": {ID: "p1", TenantID: semanticConfigTenant, BaseURL: endpoint},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"p1": {ProviderID: "p1", SecretCiphertext: "sk-plain"},
		},
	}
	deps := &Dependencies{ProviderRepo: provRepo}

	body, _ := json.Marshal(map[string]interface{}{
		"judge_backend":              "provider",
		"judge_provider_id":          "p1",
		"judge_model":                "judge-m",
		"judge_allow_private_egress": false,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/system/semantic/test-judge", bytes.NewReader(body))
	// 调用者属于非默认租户：若仍按 user.TenantID 查，provider 解析为空 → 探测失败。
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_other",
		Role:     "platform_admin",
		Status:   "active",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	testSemanticJudgeWithNetwork(deps, network).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := got["ok"].(bool); !ok {
		t.Fatalf("test-judge 应解析到 tenant_default 下的 provider 并探测成功, got %#v", got)
	}
}

func TestSemanticProjectionDeploymentRecordModeOverridesConfiguredProtect(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	deps := semanticTestDeps(map[string]string{"security_audit_only": "false"})
	configs, err := buildSemanticComponentConfigs(context.Background(), deps)
	if err != nil {
		t.Fatalf("build configs: %v", err)
	}
	if configs.Engine["security_audit_only"] != true || configs.Gateway["security_audit_only"] != true {
		t.Fatalf("deployment record mode must win in every projection: engine=%#v gateway=%#v", configs.Engine, configs.Gateway)
	}
}
