// Package providercompat is the single backend registry for provider wire
// families.  Provider labels must never imply endpoint capability: model
// endpoint facts are still established independently by probes or overrides.
package providercompat

import "strings"

type Family string

const (
	FamilyOpenAICompatible Family = "openai_compatible"
	FamilyAnthropic        Family = "anthropic"
	FamilyBedrock          Family = "bedrock"
	FamilyGemini           Family = "gemini"
)

type Spec struct {
	Family              Family
	OpenAICatalog       bool
	OpenAIProtocolProbe bool
}

var specs = map[string]Spec{
	"openai":     {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"azure":      {Family: FamilyOpenAICompatible, OpenAIProtocolProbe: true},
	"custom":     {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"newapi":     {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"openrouter": {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"xinference": {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},

	// These named providers expose the OpenAI wire contract used by the
	// gateway.  Endpoint availability remains per-model and probe-gated.
	"deepseek": {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"moonshot": {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"doubao":   {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"kimi":     {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"qwen":     {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"zhipu":    {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"hunyuan":  {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},
	"minimax":  {Family: FamilyOpenAICompatible, OpenAICatalog: true, OpenAIProtocolProbe: true},

	"anthropic": {Family: FamilyAnthropic},
	"bedrock":   {Family: FamilyBedrock},
	"gemini":    {Family: FamilyGemini},
	"vertex":    {Family: FamilyGemini},
}

func Lookup(providerType string) (Spec, bool) {
	spec, ok := specs[strings.ToLower(strings.TrimSpace(providerType))]
	return spec, ok
}

func RuntimeSupported(providerType string) bool {
	_, ok := Lookup(providerType)
	return ok
}

func OpenAICompatible(providerType string) bool {
	spec, ok := Lookup(providerType)
	return ok && spec.Family == FamilyOpenAICompatible
}

func SupportsOpenAICatalog(providerType string) bool {
	spec, ok := Lookup(providerType)
	return ok && spec.OpenAICatalog
}

func SupportsOpenAIProtocolProbe(providerType string) bool {
	spec, ok := Lookup(providerType)
	return ok && spec.OpenAIProtocolProbe
}
