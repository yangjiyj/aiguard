package providercompat

import "testing"

func TestBackendProviderRegistryKeepsRuntimeCatalogAndProbeAligned(t *testing.T) {
	for _, providerType := range []string{
		"openai", "custom", "newapi", "openrouter", "xinference",
		"deepseek", "moonshot", "doubao", "kimi", "qwen", "zhipu", "hunyuan", "minimax",
	} {
		if !RuntimeSupported(providerType) || !OpenAICompatible(providerType) ||
			!SupportsOpenAICatalog(providerType) || !SupportsOpenAIProtocolProbe(providerType) {
			t.Fatalf("OpenAI-compatible provider %q is not aligned across backend stages", providerType)
		}
	}

	for _, providerType := range []string{"anthropic", "bedrock", "gemini", "vertex"} {
		if !RuntimeSupported(providerType) {
			t.Fatalf("native provider %q is not runtime supported", providerType)
		}
		if SupportsOpenAICatalog(providerType) || SupportsOpenAIProtocolProbe(providerType) {
			t.Fatalf("native provider %q was incorrectly admitted to OpenAI discovery", providerType)
		}
	}
}
