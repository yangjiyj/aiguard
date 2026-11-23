package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSemanticRuntimeConfigRequiresMasterSwitchForAgentAndInput(t *testing.T) {
	var reports int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case semanticGatewayConfigPath:
			_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(gatewaySemanticTestKey, false, true, true, true, false))
		case semanticGatewayReportPath:
			atomic.AddInt32(&reports, 1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if client.SemanticAgentEnabled(context.Background(), true) {
		t.Fatal("master=false must disable agent semantic even when agent=true")
	}
	if client.SemanticInputEnabled(context.Background(), true) {
		t.Fatal("master=false must disable input semantic even when input=true")
	}
	if atomic.LoadInt32(&reports) != 1 {
		t.Fatalf("successful config apply must report exactly once, got %d", reports)
	}
}

func TestSemanticRuntimeConfigReportsAppliedRevisionWithoutSecret(t *testing.T) {
	reported := make(chan map[string]any, 1)
	expectedRevision := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, false, true, true, false)["revision"].(string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case semanticGatewayConfigPath:
			if r.Header.Get("X-JJDGuard-Internal-Token") != gatewaySemanticInternalTestSecret {
				t.Fatal("missing internal authentication")
			}
			_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(gatewaySemanticTestKey, true, false, true, true, false))
		case semanticGatewayReportPath:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reported <- body
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	config, err := client.refreshSemanticRuntimeConfig(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !config.Enabled || !config.AgentEnabled || config.InputEnabled {
		t.Fatalf("unexpected config: %+v", config)
	}
	select {
	case body := <-reported:
		if body["component"] != semanticGatewayComponent || body["applied_revision"] != expectedRevision {
			t.Fatalf("unexpected report: %#v", body)
		}
		if _, leaked := body["judge_api_key"]; leaked {
			t.Fatalf("runtime report leaked judge secret: %#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("missing runtime report")
	}
}

func TestSemanticRuntimeConfigRejectsInvalidRevisionAndUsesFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"revision":               "bad",
			"semantic_enabled":       true,
			"semantic_input_enabled": true,
			"semantic_agent_enabled": true,
			"security_audit_only":    true,
		})
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err == nil {
		t.Fatal("invalid revision refresh must fail")
	}
	if client.SemanticAgentEnabled(context.Background(), false) {
		t.Fatal("invalid revision must not activate semantic config")
	}
}

func TestInputSemanticAsyncRequiresEffectiveInputSwitch(t *testing.T) {
	h := &ChatCompletionsHandler{
		toolRiskClient: &ToolRiskClient{runtimeCache: &runtimeSettingsCache{ttl: time.Minute}},
	}
	t.Setenv("SECURITY_SEMANTIC_INPUT_ASYNC", "true")
	t.Setenv("SECURITY_SEMANTIC_ENABLED", "true")
	t.Setenv("SECURITY_SEMANTIC_INPUT_ENABLED", "true")

	h.toolRiskClient.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, Enabled: true, InputEnabled: false,
	})
	if h.inputSemanticAsyncEnabled(context.Background()) {
		t.Fatal("async semantic must not bypass effective input=false")
	}
	h.toolRiskClient.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, Enabled: true, InputEnabled: true,
	})
	if h.inputSemanticAsyncEnabled(context.Background()) {
		t.Fatal("retired async bypass must stay off even when legacy env and runtime input are true")
	}
}

// 文件内容 DLP 全局开关：动态缓存值必须覆盖启动环境后备。
func TestFileContentDLPEnabledDynamicCacheOverridesEnvFallback(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true") // 启动后备开
	client := &ToolRiskClient{runtimeCache: &runtimeSettingsCache{ttl: time.Minute}}
	// 缓存声明动态值 false → 必须覆盖启动后备 true。
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision:              gatewaySemanticRevision,
		FileContentDLPEnabled: false,
	})
	if client.FileContentDLPEnabled(context.Background(), true) {
		t.Fatal("动态配置 false 必须覆盖启动环境后备 true")
	}
	// 缓存声明动态值 true → 必须为开。
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision:              gatewaySemanticRevision,
		FileContentDLPEnabled: true,
	})
	if !client.FileContentDLPEnabled(context.Background(), false) {
		t.Fatal("动态配置 true 必须开启文件 DLP")
	}
}

// 控制平面 gateway 投影现在 emit file_content_dlp_enabled（5键）；
// gateway 解析必须认该字段并纳入验签，否则 DisallowUnknownFields 拒绝整个响应。
func TestFileContentDLPEnabledFlowsFromGatewayProjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(
				gatewaySemanticTestKey, true, true, true, true, true,
			))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
		t.Fatalf("refresh with file_content_dlp_enabled must succeed: %v", err)
	}
	if !client.FileContentDLPEnabled(context.Background(), false) {
		t.Fatal("gateway 投影 file_content_dlp_enabled=true 必须流到运行态")
	}
}
