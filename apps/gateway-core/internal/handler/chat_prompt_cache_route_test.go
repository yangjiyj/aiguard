package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 客户现场：Claude 路由的 chat 请求只要带 cache_control 就 422
// 「configured route cannot preserve the request feature contract」。
func TestChatToMessagesConversionAdmitsCacheControl(t *testing.T) {
	routeRecord := route("p-claude", "anthropic", "https://claude.example", "claude-opus-4-8")
	routeRecord.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true, AnthropicMessages: true}
	body := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`)
	features := relay.DetectRequestFeatures("chat", body, false)
	if !features.CacheTokens {
		t.Fatalf("fixture must carry the cache_tokens feature")
	}
	protocol, decision := selectModelRouteProtocol(routeRecord, features)
	if !decision.Eligible || protocol != "messages" {
		t.Fatalf("cache_control chat request must route to messages: protocol=%q decision=%+v", protocol, decision)
	}

	// 路由显式声明不支持 cache_tokens 时仍然拒绝，保持能力声明的语义。
	routeRecord.ProtocolCapabilities.FeatureDeclared = map[string]bool{"cache_tokens": true}
	routeRecord.ProtocolCapabilities.CacheTokens = false
	if _, decision := selectModelRouteProtocol(routeRecord, features); decision.Eligible {
		t.Fatalf("route declaring no cache support must stay ineligible: %+v", decision)
	}
}

func TestChatToMessagesExecutionSendsCacheBreakpoints(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"cache_read_input_tokens":2000,"cache_creation_input_tokens":30,"output_tokens":2}}`))
	}))
	defer server.Close()

	routeRecord := route("p-claude", "custom", server.URL, "claude-opus-4-8")
	routeRecord.ProviderAuthMode = "bearer"
	routeRecord.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true, AnthropicMessages: true}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routeRecord, Decision: &modelrouter.RoutingDecision{}}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-chat-cache", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	adapter := &provider.AnthropicAdapter{BaseURL: server.URL, APIKey: "test-key", AuthMode: "bearer"}
	body := []byte(`{"model":"logical/model","messages":[{"role":"system","content":"long agent policy"},{"role":"user","content":"hi"},{"role":"assistant","content":"hello"},{"role":"user","content":"next"}]}`)

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-claude": "test-key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-claude": adapter}},
		Envelope: envelope, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	system, _ := gotBody["system"].([]any)
	if len(system) != 1 || system[0].(map[string]any)["cache_control"] == nil {
		t.Fatalf("system breakpoint missing upstream: %#v", gotBody["system"])
	}
	var response struct {
		Usage struct {
			PromptTokens        int `json:"prompt_tokens"`
			PromptTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	chatBody, err := adapter.TransformResponse(result.ResponseBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(chatBody, &response); err != nil {
		t.Fatalf("decode response %s: %v", chatBody, err)
	}
	if response.Usage.PromptTokens != 2040 || response.Usage.PromptTokensDetails.CachedTokens != 2000 {
		t.Fatalf("cache usage not mapped back to Chat: %s", chatBody)
	}
}
