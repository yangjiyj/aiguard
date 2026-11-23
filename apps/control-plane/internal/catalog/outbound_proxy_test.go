package catalog

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIClientFetchModelsUsesConfiguredOutboundProxy(t *testing.T) {
	var gotRequestURI string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[{"id":"model-through-proxy"}]}`)
	}))
	defer proxy.Close()

	ctx := WithOutboundProxy(context.Background(), proxy.URL)
	models, err := NewOpenAIClient().FetchModels(ctx, "http://upstream.example.test", "provider-key")
	if err != nil {
		t.Fatalf("FetchModels() error = %v", err)
	}
	if len(models) != 1 || models[0].ID != "model-through-proxy" {
		t.Fatalf("models = %#v", models)
	}
	if gotRequestURI != "http://upstream.example.test/v1/models" {
		t.Fatalf("proxy request URI = %q", gotRequestURI)
	}
}
