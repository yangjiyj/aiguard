package handler

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type createModelProbeStub struct {
	results map[string]catalog.ModelProbeResult
	calls   []catalog.ModelProbeRequest
}

func (s *createModelProbeStub) Probe(_ context.Context, req catalog.ModelProbeRequest) catalog.ModelProbeResult {
	s.calls = append(s.calls, req)
	return s.results[req.Protocol]
}

func TestProbeOpenAIModelProtocolsDetectsChatAndResponses(t *testing.T) {
	prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{
		"chat_completions": {OK: true},
		"responses":        {OK: true},
	}}
	provider := &repository.Provider{ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", BaseURL: "https://api.example.test/v1", AuthMode: "api_key"}

	protocols, record, err := probeOpenAIModelProtocols(context.Background(), prober, provider, "secret", "gpt-5.5")
	if err != nil {
		t.Fatal(err)
	}
	if protocols["chat_completions"] != true || protocols["responses_native"] != true {
		t.Fatalf("detected protocols = %#v", protocols)
	}
	metadata, ok := protocols["metadata"].(map[string]interface{})
	if !ok || metadata["verified"] != true || metadata["source"] != "live_protocol_probe" {
		t.Fatalf("probe metadata = %#v", protocols["metadata"])
	}
	if len(record.Endpoints) != 2 || record.Endpoints[0].EndpointType != "chat" || record.Endpoints[0].State != "supported" || record.Endpoints[1].EndpointType != "responses" || record.Endpoints[1].State != "supported" {
		t.Fatalf("probe record = %#v", record)
	}
	if len(prober.calls) != 2 || prober.calls[0].DeploymentName != "gpt-5.5" || prober.calls[1].DeploymentName != "gpt-5.5" {
		t.Fatalf("probe calls = %#v", prober.calls)
	}
}

func TestProbeOpenAIModelProtocolsKeepsTransientFailureUnknown(t *testing.T) {
	prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{
		"chat_completions": {OK: true},
		"responses":        {ErrorKind: catalog.ModelProbeErrorTimeout},
	}}
	provider := &repository.Provider{ID: "provider-a", TenantID: "tenant-a", ProviderType: "openai", BaseURL: "https://api.example.test/v1", AuthMode: "bearer"}

	protocols, record, err := probeOpenAIModelProtocols(context.Background(), prober, provider, "secret", "chat-only")
	if err != nil {
		t.Fatal(err)
	}
	if protocols["chat_completions"] != true {
		t.Fatalf("chat capability missing: %#v", protocols)
	}
	if protocols["responses_native"] == true {
		t.Fatalf("transient Responses failure must not be promoted: %#v", protocols)
	}
	if record.Endpoints[1].State != "unknown" || record.Endpoints[1].ErrorKind != catalog.ModelProbeErrorTimeout {
		t.Fatalf("Responses fact = %#v", record.Endpoints[1])
	}
}

func TestProbeOpenAIModelProtocolsDetectsNativeMessagesForClaude(t *testing.T) {
	prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{
		"chat_completions": {ErrorKind: catalog.ModelProbeErrorUpstream},
		"responses":        {ErrorKind: catalog.ModelProbeErrorUpstream},
		"messages":         {OK: true},
	}}
	provider := &repository.Provider{ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", BaseURL: "https://api.example.test/v1", AuthMode: "bearer"}

	protocols, record, err := probeOpenAIModelProtocols(context.Background(), prober, provider, "secret", "claude-opus-4-8")
	if err != nil {
		t.Fatal(err)
	}
	if protocols["anthropic_messages"] != true || protocols["chat_completions"] == true || protocols["responses_native"] == true {
		t.Fatalf("detected protocols = %#v", protocols)
	}
	if len(record.Endpoints) != 3 || record.Endpoints[2].EndpointType != "messages" || record.Endpoints[2].State != "supported" {
		t.Fatalf("probe record = %#v", record)
	}
	if len(prober.calls) != 3 || prober.calls[2].Protocol != "messages" {
		t.Fatalf("probe calls = %#v", prober.calls)
	}
}

func TestProbeOpenAIModelProtocolsRejectsUnverifiedModel(t *testing.T) {
	prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{
		"chat_completions": {ErrorKind: catalog.ModelProbeErrorUpstream},
		"responses":        {ErrorKind: catalog.ModelProbeErrorUpstream},
	}}
	provider := &repository.Provider{ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", BaseURL: "https://api.example.test/v1", AuthMode: "api_key"}

	if _, _, err := probeOpenAIModelProtocols(context.Background(), prober, provider, "secret", "broken"); err == nil {
		t.Fatal("expected auto detection to reject a model with no verified endpoint")
	}
}

func TestProviderSupportsOpenAIProtocolProbe(t *testing.T) {
	for _, providerType := range []string{"openai", "custom", "azure", "deepseek", "moonshot", "qwen", "zhipu", "hunyuan", "minimax", "gemini", "vertex", "bedrock"} {
		if !providerSupportsOpenAIProtocolProbe(providerType) {
			t.Fatalf("%s should support OpenAI protocol probing", providerType)
		}
	}
	for _, providerType := range []string{"anthropic", "future-native"} {
		if providerSupportsOpenAIProtocolProbe(providerType) {
			t.Fatalf("%s must require an explicit protocol", providerType)
		}
	}
}

func TestProbeImageModelUsesOnlyImagesAndPersistsImageEvidence(t *testing.T) {
	for _, name := range []string{"gpt-image-2", "gpt-image-2.5-flare", "gpt-image-2.5-sunburst"} {
		prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{"images": {OK: true, PayloadValidated: true}}}
		provider := &repository.Provider{ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", BaseURL: "https://api.example.test", AuthMode: "bearer"}
		protocols, record, err := probeOpenAIModelProtocols(context.Background(), prober, provider, "secret", name)
		if err != nil {
			t.Fatal(err)
		}
		if len(prober.calls) != 1 || prober.calls[0].Protocol != "images" || prober.calls[0].Timeout < 60*time.Second {
			t.Fatalf("wrong image probe: %#v", prober.calls)
		}
		if protocols["images"] != true || protocols["chat_completions"] == true || protocols["responses_native"] == true {
			t.Fatalf("wrong image protocols: %#v", protocols)
		}
		if len(record.Endpoints) != 1 || record.Endpoints[0].EndpointType != "images" || record.Endpoints[0].State != "supported" {
			t.Fatalf("wrong image evidence: %#v", record)
		}
	}
}
