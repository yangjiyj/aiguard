package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func TestProviderTypesSelectExplicitAdapters(t *testing.T) {
	config := ProviderConfig{BaseURL: "https://upstream.example", APIKey: "test-key"}
	for _, tc := range []struct {
		providerType string
		wantName     string
	}{
		{providerType: "custom", wantName: "custom"},
		{providerType: "newapi", wantName: "newapi"},
		{providerType: "openrouter", wantName: "openrouter"},
		{providerType: "xinference", wantName: "xinference"},
		{providerType: "azure", wantName: "azure"},
		{providerType: "vertex", wantName: "gemini"},
	} {
		t.Run(tc.providerType, func(t *testing.T) {
			adapter := GetAdapterWithConfig(tc.providerType, config)
			if adapter == nil {
				t.Fatalf("provider %q returned no adapter", tc.providerType)
			}
			if got := adapter.Name(); got != tc.wantName {
				t.Fatalf("provider %q selected %q; want %q", tc.providerType, got, tc.wantName)
			}
		})
	}
}

func TestAzureDeploymentMappingUsesUpstreamDeploymentAndSeparateResponsesPath(t *testing.T) {
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "customer-coding-prod", UpstreamModelID: "azure-deployment-42"}
	chatURL, err := azureEndpoint("https://resource.openai.azure.com", env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(chatURL, "/openai/deployments/azure-deployment-42/chat/completions") || !strings.Contains(chatURL, "api-version=") {
		t.Fatalf("Azure chat URL=%q", chatURL)
	}

	env.EndpointType = "responses"
	responsesURL, err := azureEndpoint("https://resource.openai.azure.com", env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(responsesURL, "/openai/v1/responses") || strings.Contains(responsesURL, "deployments/") {
		t.Fatalf("Azure Responses URL=%q", responsesURL)
	}
}

func TestAzureAdapterUsesApiKeyHeaderForNativeResponses(t *testing.T) {
	var gotPath string
	var gotAuth, gotAPIKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("api-key")
		_, _ = io.WriteString(w, `{"id":"resp_azure","object":"response","status":"completed","output":[]}`)
	}))
	defer server.Close()

	adapter := GetAdapterWithConfig("azure", ProviderConfig{BaseURL: server.URL, APIKey: "azure-test-key"})
	envelope := &modelrouter.RequestEnvelope{
		EndpointType: "responses", Model: "customer-coding-prod", UpstreamModelID: "azure-deployment-42",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true},
	}
	if _, err := adapter.Call(context.Background(), envelope, []byte(`{"model":"azure-deployment-42","input":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/responses" || gotAPIKey != "azure-test-key" || gotAuth != "" {
		t.Fatalf("Azure request path/auth mismatch: path=%q api-key=%q authorization=%q", gotPath, gotAPIKey, gotAuth)
	}
}

func TestAzureEndpointDoesNotDuplicateConfiguredOpenAIRoot(t *testing.T) {
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "public-chat", UpstreamModelID: "deployment-7"}
	for _, base := range []string{
		"https://resource.openai.azure.com/openai",
		"https://resource.openai.azure.com/openai/",
	} {
		endpoint, err := azureEndpoint(base, env)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(endpoint, "/openai/openai/") {
			t.Fatalf("duplicated Azure root for %q: %s", base, endpoint)
		}
	}

	env.EndpointType = "responses"
	endpoint, err := azureEndpoint("https://resource.openai.azure.com/openai/v1/", env)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://resource.openai.azure.com/openai/v1/responses" {
		t.Fatalf("v1 endpoint=%q", endpoint)
	}

	env.EndpointType = "chat"
	endpoint, err = azureEndpointWithVersion("https://resource.openai.azure.com/openai", env, "2025-04-01")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(endpoint, "api-version=2025-04-01") || strings.Contains(endpoint, "/openai/openai/") {
		t.Fatalf("deployment endpoint=%q", endpoint)
	}
}

func TestAzureBearerRequiresExplicitAuthMode(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://resource.openai.azure.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyAdapter := &OpenAIAdapter{Azure: true, APIKey: "secret"}
	if err := apiKeyAdapter.setAuthentication(req); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("api-key") != "secret" || req.Header.Get("Authorization") != "" {
		t.Fatalf("default Azure auth headers=%v", req.Header)
	}

	req = req.Clone(req.Context())
	bearerAdapter := &OpenAIAdapter{Azure: true, APIKey: "oauth-token", AuthMode: "entra"}
	if err := bearerAdapter.setAuthentication(req); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer oauth-token" || req.Header.Get("api-key") != "" {
		t.Fatalf("explicit bearer auth headers=%v", req.Header)
	}
}

func TestOpenStreamConvertsResponsesBridgeToChatEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("path=%s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\n")
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}
	envelope := &modelrouter.RequestEnvelope{
		EndpointType: "chat", Model: "public-chat", UpstreamModelID: "responses-model",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true, ChatResponsesBridge: true},
	}
	reader, _, err := adapter.OpenStream(context.Background(), envelope, []byte("{\"model\":\"public-chat\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	event, err := reader.Next(context.Background())
	if err != nil || event.Type != relay.EventTextDelta || event.Delta != "hello" {
		t.Fatalf("first event=%+v err=%v", event, err)
	}
	event, err = reader.Next(context.Background())
	if err != nil || event.Type != relay.EventMessageEnd || event.Usage == nil {
		t.Fatalf("terminal event=%+v err=%v", event, err)
	}
}
