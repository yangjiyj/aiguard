package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestOpenAIAdapterSendsRequestsThroughConfiguredOutboundProxy(t *testing.T) {
	var gotRequestURI, gotAuthorization string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-proxy","choices":[]}`)
	}))
	defer proxy.Close()

	adapter := &OpenAIAdapter{
		BaseURL:  "http://upstream.example.test/v1",
		APIKey:   "provider-secret",
		ProxyURL: proxy.URL,
	}
	_, err := adapter.Call(context.Background(), &modelrouter.RequestEnvelope{EndpointType: "chat"}, []byte(`{"model":"test","messages":[]}`))
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if gotRequestURI != "http://upstream.example.test/v1/chat/completions" {
		t.Fatalf("proxy received request URI %q", gotRequestURI)
	}
	if gotAuthorization != "Bearer provider-secret" {
		t.Fatalf("proxy received authorization %q", gotAuthorization)
	}
}

func TestOpenAIAdapterRejectsInvalidConfiguredOutboundProxy(t *testing.T) {
	adapter := &OpenAIAdapter{
		BaseURL:  "http://upstream.example.test/v1",
		APIKey:   "provider-secret",
		ProxyURL: "socks5://127.0.0.1:1080",
	}
	_, err := adapter.Call(context.Background(), &modelrouter.RequestEnvelope{EndpointType: "chat"}, []byte(`{"model":"test","messages":[]}`))
	if err == nil {
		t.Fatal("Call() succeeded with an unsupported configured proxy scheme")
	}
}
