package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 2.9.11 实测：同一模型同时勾 chat_completions 和 anthropic_messages、provider 类型
// custom/openai、鉴权方式为默认的 api_key 时，chat 请求桥接到原生 Messages，
// 适配器不认 "api_key" 直接报错，网关不到 1ms 返回 502 provider_unavailable。
func TestCreateAdapter_DualProtocolBridgeAcceptsLegacyAPIKeyAuthMode(t *testing.T) {
	for _, tc := range []struct {
		providerType, authMode, wantHeader, wantValue string
	}{
		{"custom", "api_key", "Authorization", "Bearer sk-test"},
		{"openai", "api_key", "Authorization", "Bearer sk-test"},
		{"custom", "x-api-key", "X-Api-Key", "sk-test"},
		{"openai", "bearer", "Authorization", "Bearer sk-test"},
	} {
		t.Run(tc.providerType+"/"+tc.authMode, func(t *testing.T) {
			var gotPath, gotHeader string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotHeader = r.Header.Get(tc.wantHeader)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
			}))
			defer upstream.Close()

			record := &modelrouter.ModelRecord{
				ID: "m", ProviderType: tc.providerType, ProviderBaseURL: upstream.URL + "/v1",
				ProviderAuthMode: tc.authMode, UpstreamModelID: "m",
				ProtocolCapabilities: modelrouter.ProtocolCapabilities{
					Explicit: true, ChatCompletions: true, AnthropicMessages: true,
				},
			}
			adapter := (&RealProviderAdapterFactory{}).CreateAdapter(record, "sk-test")
			envelope := &modelrouter.RequestEnvelope{RequestID: "r", EndpointType: "chat", Model: "m", UpstreamModelID: "m"}
			payload, err := adapter.TransformRequest(envelope, []byte(`{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`))
			if err != nil {
				t.Fatalf("TransformRequest: %v", err)
			}
			if _, err := adapter.Call(context.Background(), envelope, payload); err != nil {
				t.Fatalf("Call 不应在发出请求前失败: %v", err)
			}
			if gotPath != "/v1/messages" {
				t.Fatalf("应走原生 Messages, path=%q", gotPath)
			}
			if gotHeader != tc.wantValue {
				t.Fatalf("%s=%q, want %q", tc.wantHeader, gotHeader, tc.wantValue)
			}
			if strings.Contains(gotHeader, "api_key") {
				t.Fatalf("鉴权头异常: %q", gotHeader)
			}
		})
	}
}
