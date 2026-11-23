package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestAuthorizationRawCallUsesCompleteURLAndRawHeader(t *testing.T) {
	const credential = "app-key-without-bearer"
	var gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.RequestURI(), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	completeURL := server.URL + "/private/api/llm/chat/completions/V2?tenant=demo"
	adapter := &OpenAIAdapter{BaseURL: completeURL, APIKey: credential, AuthMode: "authorization_raw"}
	_, err := adapter.Call(context.Background(), &modelrouter.RequestEnvelope{EndpointType: "chat"}, []byte(`{"model":"vendor-model","messages":[]}`))
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if gotPath != "/private/api/llm/chat/completions/V2?tenant=demo" {
		t.Fatalf("request URI = %q", gotPath)
	}
	if gotAuth != credential {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

func TestAuthorizationRawStreamingPathsUseCompleteURLAndRawHeader(t *testing.T) {
	const credential = "raw-app-key"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/only/chat/V2" || r.Header.Get("Authorization") != credential {
			t.Errorf("request path=%q authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"OK\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL + "/only/chat/V2", APIKey: credential, AuthMode: "authorization_raw"}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}
	payload := []byte(`{"model":"vendor-model","messages":[]}`)
	if _, err := adapter.CallStreaming(context.Background(), envelope, payload); err != nil {
		t.Fatalf("CallStreaming() error = %v", err)
	}
	reader, _, err := adapter.OpenStream(context.Background(), envelope, payload)
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer reader.Close()
	if _, err := reader.Next(context.Background()); err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestAuthorizationRawRejectsNonChatEndpoints(t *testing.T) {
	adapter := &OpenAIAdapter{BaseURL: "https://upstream.example.test/only/chat", APIKey: "raw-key", AuthMode: "authorization_raw"}
	for _, endpoint := range []string{"embeddings", "responses", "images", "messages", "files"} {
		t.Run(endpoint, func(t *testing.T) {
			if adapter.SupportsEndpoint(endpoint) {
				t.Fatalf("SupportsEndpoint(%q) = true", endpoint)
			}
			_, err := adapter.Call(context.Background(), &modelrouter.RequestEnvelope{EndpointType: endpoint}, []byte(`{}`))
			if err == nil || !IsEndpointNotSupported(err) || !strings.Contains(err.Error(), "authorization_raw") {
				t.Fatalf("Call() error = %v", err)
			}
		})
	}
}
