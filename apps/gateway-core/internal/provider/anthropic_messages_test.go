package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestMessagesTransformOnlyRewritesTopLevelModel(t *testing.T) {
	raw := []byte(`{"model":"logical","max_tokens":64,"metadata":{"model":"nested","large":9007199254740993123456789},"thinking":{"type":"enabled","budget_tokens":32},"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool-1","content":[{"type":"text","text":"done"}]}]}],"unknown":{"keep":[1,true,null]}}`)

	for _, adapter := range []ProviderAdapter{&OpenAIAdapter{}, &AnthropicAdapter{}} {
		t.Run(adapter.Name(), func(t *testing.T) {
			envelope := &modelrouter.RequestEnvelope{
				EndpointType:    "messages",
				Model:           "logical",
				UpstreamModelID: "kiro-native",
			}
			got, err := adapter.TransformRequest(envelope, raw)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(got, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["model"]) != `"kiro-native"` {
				t.Fatalf("top-level model=%s", fields["model"])
			}
			for _, key := range []string{"max_tokens", "metadata", "thinking", "messages", "unknown"} {
				var wantFields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &wantFields); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(fields[key], wantFields[key]) {
					t.Fatalf("%s changed\nwant=%s\n got=%s", key, wantFields[key], fields[key])
				}
			}
			if !bytes.Contains(got, []byte("9007199254740993123456789")) {
				t.Fatalf("large integer lexical form changed: %s", got)
			}
		})
	}
}

func TestMessagesNativeTransportPreservesMetadataAndCredentials(t *testing.T) {
	type adapterCase struct {
		name              string
		baseHasV1         bool
		adapter           func(string) ProviderAdapter
		wantAuthorization string
		wantAPIKey        string
	}
	cases := []adapterCase{
		{
			name: "openai-bearer-no-v1",
			adapter: func(base string) ProviderAdapter {
				return &OpenAIAdapter{BaseURL: base, APIKey: "provider-bearer"}
			},
			wantAuthorization: "Bearer provider-bearer",
		},
		{
			name:      "openai-bearer-with-v1",
			baseHasV1: true,
			adapter: func(base string) ProviderAdapter {
				return &OpenAIAdapter{BaseURL: base, APIKey: "provider-bearer"}
			},
			wantAuthorization: "Bearer provider-bearer",
		},
		{
			name: "anthropic-key-no-v1",
			adapter: func(base string) ProviderAdapter {
				return &AnthropicAdapter{BaseURL: base, APIKey: "provider-anthropic"}
			},
			wantAPIKey: "provider-anthropic",
		},
		{
			name:      "anthropic-key-with-v1",
			baseHasV1: true,
			adapter: func(base string) ProviderAdapter {
				return &AnthropicAdapter{BaseURL: base, APIKey: "provider-anthropic"}
			},
			wantAPIKey: "provider-anthropic",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotRawQuery string
			var gotHeader http.Header
			var gotBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotRawQuery = r.URL.RawQuery
				gotHeader = r.Header.Clone()
				gotBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Anthropic-Request-Id", "ant-upstream-1")
				w.Header().Set("X-RateLimit-Remaining", "42")
				w.Header().Set("Set-Cookie", "must-not-pass=1")
				w.Header().Set("Server", "must-not-pass")
				_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","content":[]}`)
			}))
			defer server.Close()

			baseURL := server.URL
			if tc.baseHasV1 {
				baseURL += "/v1"
			}
			metadata := &AnthropicTransportMetadata{
				RequestHeaders: http.Header{
					"Anthropic-Version":         []string{"2024-01-01"},
					"Anthropic-Beta":            []string{"feature-a", "feature-b"},
					"X-Claude-Code-Session-Id":  []string{"session-safe"},
					"X-Stainless-Lang":          []string{"js"},
					"Authorization":             []string{"Bearer inbound-jjdguard"},
					"X-Api-Key":                 []string{"inbound-api-key"},
					"Cookie":                    []string{"private=1"},
					"X-Jjdguard-Internal-Token": []string{"internal-secret"},
				},
				RawQuery: "beta=one&beta=two&encoded=%2Fkeep",
			}
			ctx := WithAnthropicTransportMetadata(context.Background(), metadata)
			envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", UpstreamModelID: "kiro-native"}
			payload := []byte(`{"model":"kiro-native","messages":[],"unknown":1}`)
			got, err := tc.adapter(baseURL).Call(ctx, envelope, payload)
			if err != nil {
				t.Fatal(err)
			}
			if gotPath != "/v1/messages" {
				t.Fatalf("path=%q", gotPath)
			}
			if gotRawQuery != metadata.RawQuery {
				t.Fatalf("query=%q", gotRawQuery)
			}
			if !bytes.Equal(gotBody, payload) {
				t.Fatalf("body changed\nwant=%s\n got=%s", payload, gotBody)
			}
			if gotHeader.Get("Authorization") != tc.wantAuthorization || gotHeader.Get("X-Api-Key") != tc.wantAPIKey {
				t.Fatalf("credentials authorization=%q api-key=%q", gotHeader.Get("Authorization"), gotHeader.Get("X-Api-Key"))
			}
			if gotHeader.Get("Authorization") == "Bearer inbound-jjdguard" || gotHeader.Get("X-Api-Key") == "inbound-api-key" {
				t.Fatal("inbound credential leaked upstream")
			}
			if gotHeader.Get("Cookie") != "" || gotHeader.Get("X-Jjdguard-Internal-Token") != "" {
				t.Fatalf("private headers leaked: %v", gotHeader)
			}
			if gotHeader.Get("Anthropic-Version") != "2024-01-01" {
				t.Fatalf("anthropic-version=%q", gotHeader.Get("Anthropic-Version"))
			}
			if values := gotHeader.Values("Anthropic-Beta"); !reflect.DeepEqual(values, []string{"feature-a", "feature-b"}) {
				t.Fatalf("anthropic-beta=%v", values)
			}
			if gotHeader.Get("X-Claude-Code-Session-Id") != "session-safe" || gotHeader.Get("X-Stainless-Lang") != "js" {
				t.Fatalf("safe metadata missing: %v", gotHeader)
			}
			if string(got) != `{"id":"msg_1","type":"message","role":"assistant","content":[]}` {
				t.Fatalf("response changed: %s", got)
			}
			if metadata.ResponseHeaders.Get("Anthropic-Request-Id") != "ant-upstream-1" || metadata.ResponseHeaders.Get("X-RateLimit-Remaining") != "42" {
				t.Fatalf("safe response headers=%v", metadata.ResponseHeaders)
			}
			if metadata.ResponseHeaders.Get("Set-Cookie") != "" || metadata.ResponseHeaders.Get("Server") != "" {
				t.Fatalf("unsafe response headers=%v", metadata.ResponseHeaders)
			}
		})
	}
}

func TestAnthropicChatBridgeUsesBearerWhenConfigured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer examplegw-provider-key" {
			t.Fatalf("authorization=%q", got)
		}
		if got := r.Header.Get("X-Api-Key"); got != "" {
			t.Fatalf("unexpected x-api-key=%q", got)
		}
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","content":[]}`)
	}))
	defer server.Close()

	adapter := &AnthropicAdapter{BaseURL: server.URL, APIKey: "examplegw-provider-key", AuthMode: "bearer"}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-opus-5"}
	if _, err := adapter.Call(context.Background(), envelope, []byte(`{"model":"claude-opus-5","messages":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestMessagesRejectsCredentialQueryBeforeUpstream(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metadata := &AnthropicTransportMetadata{RawQuery: "feature=ok&token=client-secret"}
	ctx := WithAnthropicTransportMetadata(context.Background(), metadata)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical"}
	_, err := (&OpenAIAdapter{BaseURL: server.URL, APIKey: "provider-key"}).Call(ctx, envelope, []byte(`{"model":"logical","messages":[]}`))
	if err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("error=%v", err)
	}
	if called.Load() {
		t.Fatal("credential query reached upstream")
	}
}

func TestMessagesUpstream400PreservesBodyAndHeaders(t *testing.T) {
	raw := []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"bad compact"},"request_id":"kiro-400"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	metadata := &AnthropicTransportMetadata{}
	ctx := WithAnthropicTransportMetadata(context.Background(), metadata)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical"}
	_, err := (&AnthropicAdapter{BaseURL: server.URL, APIKey: "provider-key"}).Call(ctx, envelope, []byte(`{"model":"logical","messages":[]}`))
	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil || upstreamErr.StatusCode != http.StatusBadRequest || !bytes.Equal(upstreamErr.Body, raw) {
		t.Fatalf("error=%T %v", err, err)
	}
	if upstreamErr.Headers.Get("Content-Type") != "application/json; charset=utf-8" || upstreamErr.Headers.Get("Retry-After") != "7" {
		t.Fatalf("error headers=%v", upstreamErr.Headers)
	}
	if metadata.ResponseHeaders.Get("Retry-After") != "7" {
		t.Fatalf("captured headers=%v", metadata.ResponseHeaders)
	}
}

func TestMessagesStreamingPreservesRawAnthropicSSE(t *testing.T) {
	raw := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n" +
		"event: extension.unknown\ndata: {\"type\":\"extension.unknown\",\"keep\":true}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	for _, tc := range []struct {
		name    string
		adapter func(string) ProviderAdapter
	}{
		{name: "openai-bearer", adapter: func(base string) ProviderAdapter { return &OpenAIAdapter{BaseURL: base, APIKey: "bearer"} }},
		{name: "anthropic-key", adapter: func(base string) ProviderAdapter { return &AnthropicAdapter{BaseURL: base, APIKey: "anthropic"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var received []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, raw)
			}))
			defer server.Close()

			envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", Streaming: true}
			payload := []byte(`{"model":"logical","messages":[],"stream":true,"unknown":9007199254740993123456789}`)
			got, err := tc.adapter(server.URL).CallStreaming(context.Background(), envelope, payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != raw {
				t.Fatalf("SSE changed\nwant=%q\n got=%q", raw, got)
			}
			if bytes.Contains(received, []byte("stream_options")) {
				t.Fatalf("OpenAI stream_options leaked into Messages: %s", received)
			}
			if !bytes.Contains(received, []byte("9007199254740993123456789")) {
				t.Fatalf("request number changed: %s", received)
			}
		})
	}
}

func TestAnthropicMessagesHTTPClientsAllowTenMinuteWindow(t *testing.T) {
	nonStreaming, err := anthropicMessagesHTTPClient("", false)
	if err != nil {
		t.Fatal(err)
	}
	if nonStreaming.Timeout < 10*time.Minute {
		t.Fatalf("non-streaming timeout=%s", nonStreaming.Timeout)
	}
	streaming, err := anthropicMessagesHTTPClient("", true)
	if err != nil {
		t.Fatal(err)
	}
	if streaming.Timeout != 0 {
		t.Fatalf("streaming total timeout=%s", streaming.Timeout)
	}
	transport, ok := streaming.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout < 10*time.Minute {
		t.Fatalf("streaming response header timeout=%v", transport)
	}
}
