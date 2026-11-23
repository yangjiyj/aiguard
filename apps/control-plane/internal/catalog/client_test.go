package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIClientFetchModelsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path
		if r.URL.Path != "/v1/models" {
			t.Errorf("Expected path /v1/models, got %s", r.URL.Path)
		}

		// Verify Authorization header
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", r.Header.Get("Authorization"))
		}

		// Return mock response
		resp := map[string]interface{}{
			"object": "list",
			"data": []interface{}{
				map[string]interface{}{"id": "gpt-4", "object": "model"},
				map[string]interface{}{"id": "gpt-3.5-turbo", "object": "model"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient()
	ctx := context.Background()

	models, err := client.FetchModels(ctx, server.URL, "test-api-key")
	if err != nil {
		t.Fatalf("FetchModels failed: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("Expected 2 models, got %d", len(models))
	}

	if models[0].ID != "gpt-4" {
		t.Errorf("Expected first model id='gpt-4', got '%s'", models[0].ID)
	}

	if models[1].ID != "gpt-3.5-turbo" {
		t.Errorf("Expected second model id='gpt-3.5-turbo', got '%s'", models[1].ID)
	}
}

func TestOpenAIClientFetchModelsEmptyBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should still hit /v1/models
		if r.URL.Path != "/v1/models" {
			t.Errorf("Expected path /v1/models, got %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"object": "list",
			"data":   []interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient()
	ctx := context.Background()

	// The test server URL overrides the default
	models, err := client.FetchModels(ctx, server.URL, "test-api-key")
	if err != nil {
		t.Fatalf("FetchModels failed: %v", err)
	}

	if len(models) != 0 {
		t.Errorf("Expected 0 models, got %d", len(models))
	}
}

func TestOpenAIClientFetchModelsBaseURLAlreadyContainsV1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("Expected path /v1/models, got %s", r.URL.Path)
		}

		resp := map[string]interface{}{
			"object": "list",
			"data": []interface{}{
				map[string]interface{}{"id": "kimi-k2.5", "object": "model"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient()
	ctx := context.Background()

	models, err := client.FetchModels(ctx, server.URL+"/v1", "test-api-key")
	if err != nil {
		t.Fatalf("FetchModels failed: %v", err)
	}

	if len(models) != 1 {
		t.Fatalf("Expected 1 model, got %d", len(models))
	}
	if models[0].ID != "kimi-k2.5" {
		t.Fatalf("Expected model kimi-k2.5, got %s", models[0].ID)
	}
}

func TestOpenAIClientFetchModelsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewOpenAIClient()
	ctx := context.Background()

	_, err := client.FetchModels(ctx, server.URL, "test-api-key")
	if err == nil {
		t.Error("Expected error for HTTP 500, got nil")
	}
}

func TestOpenAIClientFetchModelsNetworkError(t *testing.T) {
	client := NewOpenAIClient()
	ctx := context.Background()

	// Use invalid URL
	_, err := client.FetchModels(ctx, "http://invalid-host-that-does-not-exist", "test-api-key")
	if err == nil {
		t.Error("Expected error for invalid host, got nil")
	}
}

func TestAnthropicClientRejectsUnsafeTarget(t *testing.T) {
	_, err := NewAnthropicClient().FetchModels(context.Background(), "http://127.0.0.1", "secret")
	if err == nil || err.Error() != "anthropic_catalog_invalid_target" {
		t.Fatalf("expected safe Anthropic target validation, got %v", err)
	}
}

func TestFactoryGetClientOpenAI(t *testing.T) {
	factory := NewFactory()

	client, err := factory.GetClient("openai")
	if err != nil {
		t.Fatalf("GetClient failed for openai: %v", err)
	}

	if client == nil {
		t.Error("Expected non-nil client for openai")
	}

	// Verify it's an OpenAIClient
	_, ok := client.(*OpenAIClient)
	if !ok {
		t.Error("Expected OpenAIClient for provider type 'openai'")
	}
}

func TestFactoryGetClientAnthropic(t *testing.T) {
	factory := NewFactory()

	client, err := factory.GetClient("anthropic")
	if err != nil {
		t.Fatalf("GetClient failed for anthropic: %v", err)
	}

	if client == nil {
		t.Error("Expected non-nil client for anthropic")
	}

	// Verify it's an AnthropicClient
	_, ok := client.(*AnthropicClient)
	if !ok {
		t.Error("Expected AnthropicClient for provider type 'anthropic'")
	}
}

func TestFactoryGetClientOpenAICompatibleAliases(t *testing.T) {
	factory := NewFactory()

	for _, providerType := range []string{"deepseek", "moonshot", "doubao", "kimi", "newapi", "openrouter", "xinference"} {
		client, err := factory.GetClient(providerType)
		if err != nil {
			t.Fatalf("GetClient failed for %s: %v", providerType, err)
		}
		if client == nil {
			t.Fatalf("Expected non-nil client for %s", providerType)
		}
		if _, ok := client.(*OpenAIClient); !ok {
			t.Fatalf("Expected OpenAIClient for provider type %s", providerType)
		}
	}
}

func TestFactoryGetClientVertexUsesExplicitNonOpenAICatalogPath(t *testing.T) {
	client, err := NewFactory().GetClient("vertex")
	if err != nil {
		t.Fatalf("GetClient failed for vertex: %v", err)
	}
	unsupported, ok := client.(*UnsupportedCatalogClient)
	if !ok || unsupported.ProviderType != "vertex" {
		t.Fatalf("expected explicit unsupported-catalog client for vertex, got %T %#v", client, client)
	}
}

func TestFactoryGetClientUnsupportedProvider(t *testing.T) {
	factory := NewFactory()

	client, err := factory.GetClient("unknown_provider")
	if err == nil {
		t.Fatal("Expected unsupported provider error")
	}
	if !IsProviderUnsupported(err) {
		t.Fatalf("Expected ErrProviderUnsupported, got %v", err)
	}
	if client != nil {
		t.Fatal("Expected nil client for unsupported provider")
	}
}

func TestIsProviderUnsupported(t *testing.T) {
	if !IsProviderUnsupported(ErrProviderUnsupported) {
		t.Error("Expected IsProviderUnsupported to return true for ErrProviderUnsupported")
	}

	if IsProviderUnsupported(nil) {
		t.Error("Expected IsProviderUnsupported to return false for nil")
	}

	if IsProviderUnsupported(context.DeadlineExceeded) {
		t.Error("Expected IsProviderUnsupported to return false for other errors")
	}
}

func TestOpenAIClientFetchModelsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewOpenAIClient()
	ctx := context.Background()

	_, err := client.FetchModels(ctx, server.URL, "test-api-key")
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}
