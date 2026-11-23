package modelrouter

import (
	"encoding/json"
	"testing"
	"time"
)

// 渠道配置变更会让旧探测作废（unknown）；探测过期只是建议，仍按上次验证结果路由。
func TestApplyEffectiveEndpointCapabilitiesDropsStaleDigestButKeepsExpiredProof(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	digest := ProviderConfigDigest("openai", "https://upstream.example", "bearer")
	raw, err := json.Marshal(map[string]EndpointCapability{
		"chat":      {State: "supported", Source: "probe", ProviderConfigDigest: digest, ExpiresAt: now.Add(time.Hour)},
		"responses": {State: "supported", Source: "probe", ProviderConfigDigest: "stale-digest", ExpiresAt: now.Add(time.Hour)},
		"messages":  {State: "supported", Source: "probe", ProviderConfigDigest: digest, ExpiresAt: now},
		"files":     {State: "supported", Source: "administrator_override", Override: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ApplyEffectiveEndpointCapabilities(ProtocolCapabilities{ChatResponsesBridge: true}, raw, digest, now)
	if !got.Explicit || !got.SupportsEndpoint("chat") || got.SupportsEndpoint("responses") || !got.SupportsEndpoint("messages") || !got.AnthropicMessages || !got.SupportsEndpoint("files") {
		t.Fatalf("effective capabilities=%+v states=%+v", got, got.EndpointStates)
	}
	if got.EndpointStates["responses"].State != "unknown" || got.EndpointStates["messages"].State != "expired" {
		t.Fatalf("stale states=%+v", got.EndpointStates)
	}
}

func TestMissingEffectiveFactsAreUnavailable(t *testing.T) {
	legacy := ParseProtocolCapabilities([]byte(`{"protocols":{"chat_completions":true}}`))
	got := ApplyEffectiveEndpointCapabilities(legacy, nil, "", time.Now())
	if got.SupportsEndpoint("chat") || got.Explicit {
		t.Fatalf("missing effective facts were treated as supported: %+v", got)
	}
}

func TestOperationalMigrationDigestExpiresOnProviderConfigChange(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	legacyDigest := LegacyProviderConfigDigest("custom", "https://upstream.example", "bearer")
	raw, err := json.Marshal(map[string]EndpointCapability{
		"chat": {State: "supported", Source: "observed_success_migration", ProviderConfigDigest: legacyDigest, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	current := ProviderConfigDigest("custom", "https://upstream.example", "bearer")
	got := ApplyEffectiveEndpointCapabilities(ProtocolCapabilities{}, raw, current, now, legacyDigest)
	if !got.SupportsEndpoint("chat") {
		t.Fatalf("matching migration digest was rejected: %+v", got.EndpointStates)
	}
	changedLegacy := LegacyProviderConfigDigest("custom", "https://changed.example", "bearer")
	got = ApplyEffectiveEndpointCapabilities(ProtocolCapabilities{}, raw, ProviderConfigDigest("custom", "https://changed.example", "bearer"), now, changedLegacy)
	if got.SupportsEndpoint("chat") || got.EndpointStates["chat"].State != "unknown" {
		t.Fatalf("changed provider config retained capability: %+v", got.EndpointStates)
	}
}

func TestResponsesCapabilityUsesExplicitConfigurationOnly(t *testing.T) {
	raw := []byte(`{"protocols":{"responses_native":true}}`)
	for _, tc := range []struct {
		name  string
		model string
		want  bool
	}{
		{name: "customer alias", model: "customer-coding-prod", want: true},
		{name: "gpt image alias does not override explicit capability", model: "gpt-image-2", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := responsesNativeCapability(raw); got != tc.want {
				t.Fatalf("responses capability for %q=%v want=%v", tc.model, got, tc.want)
			}
		})
	}
}

func TestConfiguredEndpointCapabilitiesAreIndependentFromModelNames(t *testing.T) {
	chatOnly := ModelRecord{
		ModelName:            "gpt-5.5",
		ProtocolCapabilities: ProtocolCapabilities{Explicit: true, ChatCompletions: true},
	}
	if !chatOnly.SupportsConfiguredEndpoint("chat") || chatOnly.SupportsConfiguredEndpoint("responses") {
		t.Fatalf("chat-only route capability mismatch: %#v", chatOnly.ProtocolCapabilities)
	}

	responsesOnly := ModelRecord{
		ModelName:            "customer-coding-prod",
		ProtocolCapabilities: ProtocolCapabilities{Explicit: true, ResponsesNative: true},
	}
	if !responsesOnly.SupportsConfiguredEndpoint("responses") || responsesOnly.SupportsConfiguredEndpoint("chat") {
		t.Fatalf("Responses-only route capability mismatch: %#v", responsesOnly.ProtocolCapabilities)
	}
	if responsesOnly.SupportsChatCompletionsBridge() {
		t.Fatal("Responses support alone must not enable a Chat protocol bridge")
	}

	explicitBridge := responsesOnly
	explicitBridge.ProtocolCapabilities.ChatResponsesBridge = true
	if !explicitBridge.SupportsChatCompletionsBridge() {
		t.Fatal("explicit Chat-to-Responses bridge capability was ignored")
	}

	gemini := ModelRecord{
		ModelName:            "customer-gemini-alias",
		ProtocolCapabilities: ProtocolCapabilities{Explicit: true, Gemini: true},
	}
	if !gemini.SupportsConfiguredEndpoint("chat") || gemini.SupportsConfiguredEndpoint("responses") {
		t.Fatalf("Gemini route capability mismatch: %#v", gemini.ProtocolCapabilities)
	}
}

func TestImageResponsesBridgeIsExplicit(t *testing.T) {
	parsed := ParseProtocolCapabilities([]byte(`{"protocols":{"images":true,"images_responses_bridge":true}}`))
	if !parsed.Images || !parsed.ImagesResponsesBridge {
		t.Fatalf("explicit image bridge capability was lost: %#v", parsed)
	}
	withoutBridge := ParseProtocolCapabilities([]byte(`{"protocols":{"images":true}}`))
	if withoutBridge.ImagesResponsesBridge {
		t.Fatalf("image bridge was inferred: %#v", withoutBridge)
	}
}

func TestChatResponsesBridgeIsExplicit(t *testing.T) {
	parsed := ParseProtocolCapabilities([]byte(`{"protocols":{"responses_native":true,"chat_responses_bridge":true}}`))
	if !parsed.ResponsesNative || !parsed.ChatResponsesBridge {
		t.Fatalf("explicit Chat bridge capability was lost: %#v", parsed)
	}
	withoutBridge := ParseProtocolCapabilities([]byte(`{"protocols":{"responses_native":true}}`))
	if withoutBridge.ChatResponsesBridge {
		t.Fatalf("Chat bridge was inferred from Responses support: %#v", withoutBridge)
	}
}

func TestFilesCapabilityRequiresExplicitConfiguration(t *testing.T) {
	files := ParseProtocolCapabilities([]byte(`{"protocols":{"files":true}}`))
	if !files.Files || !files.SupportsEndpoint("files") {
		t.Fatalf("explicit files capability was lost: %#v", files)
	}

	responsesOnly := ParseProtocolCapabilities([]byte(`{"protocols":{"responses_native":true}}`))
	if responsesOnly.SupportsEndpoint("files") {
		t.Fatalf("responses capability must not imply files: %#v", responsesOnly)
	}

	legacy := ModelRecord{ModelName: "legacy-model"}
	if legacy.SupportsConfiguredEndpoint("files") {
		t.Fatalf("legacy route must not infer files support: %#v", legacy)
	}
}

func TestAdvancedCapabilitiesAreExplicitAndVerified(t *testing.T) {
	raw := []byte("{\"protocols\":{\"chat_completions\":true,\"stream\":true,\"tools\":true,\"tool_results\":true,\"parallel_tools\":true,\"vision\":true,\"reasoning\":true,\"response_format\":true,\"json_schema\":true,\"cache_tokens\":true,\"idempotent\":true,\"retryable\":true,\"metadata\":{\"verified\":true,\"source\":\"probe\",\"version\":\"2026-08-23\"}}}")
	got := ParseProtocolCapabilities(raw)
	if !got.Explicit || !got.Stream || !got.Tools || !got.ToolResults || !got.ParallelTools ||
		!got.Vision || !got.Reasoning || !got.ResponseFormat || !got.JSONSchema ||
		!got.CacheTokens || !got.Idempotent || !got.Retryable || !got.Verified {
		t.Fatalf("advanced capabilities lost: %#v", got)
	}
	if got.Source != "probe" || got.Version != "2026-08-23" {
		t.Fatalf("capability provenance lost: %#v", got)
	}
}

func TestUnknownAdvancedCapabilitiesRemainFalse(t *testing.T) {
	got := ParseProtocolCapabilities([]byte("{\"protocols\":{\"chat_completions\":true}}"))
	if got.Tools || got.Reasoning || got.CacheTokens || got.Verified {
		t.Fatalf("unknown capabilities were inferred: %#v", got)
	}
}

func TestProtocolCapabilitiesDistinguishUnknownAndExplicitUnsupportedFeatures(t *testing.T) {
	unknown := ParseProtocolCapabilities([]byte(`{"protocols":{"chat_completions":true}}`))
	if !unknown.SupportsFeatureOrUnknown("vision") || !unknown.SupportsFeatureOrUnknown("tools") {
		t.Fatalf("unprobed native features must remain compatible: %#v", unknown)
	}
	explicit := ParseProtocolCapabilities([]byte(`{"protocols":{"chat_completions":true,"vision":false,"tools":true}}`))
	if explicit.SupportsFeatureOrUnknown("vision") || !explicit.SupportsFeatureOrUnknown("tools") {
		t.Fatalf("explicit feature capability was not enforced: %#v", explicit)
	}
}

func TestOnlyAdministratorOverrideBlocksAProbedEndpoint(t *testing.T) {
	digest := ProviderConfigDigest("openai", "https://upstream.example", "bearer")
	raw, err := json.Marshal(map[string]EndpointCapability{
		"chat":      {State: "unsupported", Source: "probe", ProviderConfigDigest: digest},
		"responses": {State: "unknown", Source: "none"},
		"messages":  {State: "unsupported", Source: "administrator_override", Override: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ApplyEffectiveEndpointCapabilities(ProtocolCapabilities{}, raw, digest, time.Now())
	if got.BlocksEndpoint("chat") || got.BlocksEndpoint("responses") || !got.BlocksEndpoint("messages") {
		t.Fatalf("only administrator override may block: %+v", got.EndpointStates)
	}
	declared := ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	if !declared.BlocksEndpoint("chat") || declared.BlocksEndpoint("responses") {
		t.Fatalf("administrator-declared protocols keep blocking undeclared endpoints")
	}
}
