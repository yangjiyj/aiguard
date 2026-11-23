package modelrouter

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"strings"
	"time"
)

type EndpointCapability struct {
	State                string    `json:"state"`
	Source               string    `json:"source"`
	SourceVersion        string    `json:"source_version"`
	ProviderConfigDigest string    `json:"provider_config_digest"`
	VerifiedAt           time.Time `json:"verified_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	Override             bool      `json:"is_override"`
}

// ProtocolCapabilities is the protocol contract of one logical-model route.
// It is deliberately separate from the public model name and from provider
// selection. Explicit is true only when the record contains a protocols map.
type ProtocolCapabilities struct {
	Stream                bool
	Tools                 bool
	ToolResults           bool
	ParallelTools         bool
	Vision                bool
	Reasoning             bool
	ResponseFormat        bool
	JSONSchema            bool
	CacheTokens           bool
	Idempotent            bool
	Retryable             bool
	Verified              bool
	Source                string
	Version               string
	Explicit              bool                          `json:"-"`
	ChatCompletions       bool                          `json:"chat_completions"`
	ResponsesNative       bool                          `json:"responses_native"`
	ChatResponsesBridge   bool                          `json:"chat_responses_bridge"`
	AnthropicMessages     bool                          `json:"anthropic_messages"`
	Gemini                bool                          `json:"gemini"`
	Images                bool                          `json:"images"`
	Embeddings            bool                          `json:"embeddings"`
	Files                 bool                          `json:"files"`
	ImagesResponsesBridge bool                          `json:"images_responses_bridge"`
	EndpointStates        map[string]EndpointCapability `json:"-"`
	FeatureDeclared       map[string]bool               `json:"-"`
}

// SupportsFeatureOrUnknown preserves native compatibility for legacy routes
// while honoring an explicit false capability. This lets routing distinguish
// "not probed" from "probed/overridden unsupported" without model-name rules.
func (c ProtocolCapabilities) SupportsFeatureOrUnknown(feature string) bool {
	feature = strings.ToLower(strings.TrimSpace(feature))
	if c.FeatureDeclared == nil || !c.FeatureDeclared[feature] {
		return true
	}
	switch feature {
	case "stream":
		return c.Stream
	case "tools":
		return c.Tools
	case "tool_results":
		return c.ToolResults
	case "parallel_tools":
		return c.ParallelTools
	case "vision":
		return c.Vision
	case "reasoning":
		return c.Reasoning
	case "response_format":
		return c.ResponseFormat
	case "json_schema":
		return c.JSONSchema
	case "cache_tokens":
		return c.CacheTokens
	case "idempotent":
		return c.Idempotent
	case "retryable":
		return c.Retryable
	default:
		return true
	}
}

func (c ProtocolCapabilities) SupportsEndpoint(endpoint string) bool {
	endpoint = normalizeEndpointType(endpoint)
	if c.EndpointStates != nil {
		return routableEndpointState(c.EndpointStates[endpoint])
	}
	switch endpoint {
	case "chat":
		// The Gemini adapter exposes the gateway's Chat Completions contract
		// while translating it to generateContent upstream.
		return c.ChatCompletions || c.Gemini
	case "responses":
		return c.ResponsesNative
	case "messages":
		return c.AnthropicMessages
	case "gemini", "gemini_generate_content":
		return c.Gemini
	case "images":
		return c.Images
	case "embeddings":
		return c.Embeddings
	case "files":
		return c.Files
	default:
		return false
	}
}

func normalizeEndpointType(endpoint string) string {
	switch strings.ToLower(strings.TrimSpace(endpoint)) {
	case "chat_completions":
		return "chat"
	case "anthropic_messages":
		return "messages"
	default:
		return strings.ToLower(strings.TrimSpace(endpoint))
	}
}

func ProviderConfigDigest(providerType, baseURL, authMode string) string {
	return modelcatalog.ProviderConfigDigest(providerType, baseURL, authMode)
}
func LegacyProviderConfigDigest(providerType, baseURL, authMode string) string {
	return modelcatalog.LegacyProviderConfigDigest(providerType, baseURL, authMode)
}

func ApplyEffectiveEndpointCapabilities(base ProtocolCapabilities, raw []byte, currentProviderConfigDigest string, now time.Time, compatibleProviderConfigDigests ...string) ProtocolCapabilities {
	var states map[string]EndpointCapability
	if len(raw) == 0 || json.Unmarshal(raw, &states) != nil || len(states) == 0 {
		return ProtocolCapabilities{}
	}
	base.Explicit = true
	base.EndpointStates = make(map[string]EndpointCapability, len(states))
	base.Verified = false
	for endpoint, capability := range states {
		endpoint = normalizeEndpointType(endpoint)
		switch capability.State {
		case "supported", "unsupported", "unknown", "expired":
		default:
			capability.State = "unknown"
		}
		digestValid := capability.ProviderConfigDigest != "" && capability.ProviderConfigDigest == currentProviderConfigDigest
		for _, compatibleDigest := range compatibleProviderConfigDigests {
			digestValid = digestValid || capability.ProviderConfigDigest == compatibleDigest
		}
		if !capability.Override && !digestValid {
			capability.State = "unknown"
		}
		if !capability.Override && digestValid && !capability.ExpiresAt.IsZero() && !now.Before(capability.ExpiresAt) {
			capability.State = "expired"
		}
		base.EndpointStates[endpoint] = capability
		if capability.State == "supported" {
			base.Verified = true
		}
	}
	base.ChatCompletions = routableEndpointState(base.EndpointStates["chat"])
	base.ResponsesNative = routableEndpointState(base.EndpointStates["responses"])
	base.AnthropicMessages = routableEndpointState(base.EndpointStates["messages"])
	base.Images = routableEndpointState(base.EndpointStates["images"])
	base.Embeddings = routableEndpointState(base.EndpointStates["embeddings"])
	base.Files = routableEndpointState(base.EndpointStates["files"])
	return base
}

// 探测过期只是建议：仍按上次验证通过的结果路由。渠道配置变更导致的作废（unknown）不算。
func routableEndpointState(c EndpointCapability) bool {
	return c.State == "supported" || (c.State == "expired" && !c.Override)
}

// BlocksEndpoint 只在管理员明确不允许时为真：管理员手工声明的协议（没有探测状态）
// 未包含该入口，或管理员把该端点覆盖为 unsupported。探测得出的未验证、失败都不拦截。
func (c ProtocolCapabilities) BlocksEndpoint(endpoint string) bool {
	if !c.Explicit {
		return false
	}
	if c.EndpointStates == nil {
		return !c.SupportsEndpoint(endpoint)
	}
	state, ok := c.EndpointStates[normalizeEndpointType(endpoint)]
	return ok && state.Override && state.State == "unsupported"
}

// ParseProtocolCapabilities reads only the explicit protocol section. Legacy
// capability keys remain available to callers but never create Responses
// support from a model-name prefix.
func ParseProtocolCapabilities(raw []byte) ProtocolCapabilities {
	var document struct {
		Protocols    map[string]json.RawMessage `json:"protocols"`
		EndpointType string                     `json:"endpoint_type"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &document) != nil || document.Protocols == nil {
		return ProtocolCapabilities{}
	}
	result := ProtocolCapabilities{Explicit: true}
	_, hasChatCompletions := document.Protocols["chat_completions"]
	decodeBool := func(name string) bool {
		var value bool
		if err := json.Unmarshal(document.Protocols[name], &value); err != nil {
			return false
		}
		return value
	}
	result.ChatCompletions = decodeBool("chat_completions")
	result.ResponsesNative = decodeBool("responses_native")
	result.ChatResponsesBridge = decodeBool("chat_responses_bridge")
	result.AnthropicMessages = decodeBool("anthropic_messages")
	result.Gemini = decodeBool("gemini")
	result.Images = decodeBool("images")
	result.Embeddings = decodeBool("embeddings")
	result.Files = decodeBool("files")
	result.ImagesResponsesBridge = decodeBool("images_responses_bridge")
	result.FeatureDeclared = make(map[string]bool)
	decodeFeature := func(name string) bool {
		if _, ok := document.Protocols[name]; !ok {
			return false
		}
		result.FeatureDeclared[name] = true
		return decodeBool(name)
	}
	result.Stream = decodeFeature("stream")
	result.Tools = decodeFeature("tools")
	result.ToolResults = decodeFeature("tool_results")
	result.ParallelTools = decodeFeature("parallel_tools")
	result.Vision = decodeFeature("vision")
	result.Reasoning = decodeFeature("reasoning")
	result.ResponseFormat = decodeFeature("response_format")
	result.JSONSchema = decodeFeature("json_schema")
	result.CacheTokens = decodeFeature("cache_tokens")
	result.Idempotent = decodeFeature("idempotent")
	result.Retryable = decodeFeature("retryable")
	if rawMetadata, ok := document.Protocols["metadata"]; ok {
		var metadata map[string]any
		if json.Unmarshal(rawMetadata, &metadata) == nil {
			result.Verified, _ = metadata["verified"].(bool)
			result.Source, _ = metadata["source"].(string)
			result.Version, _ = metadata["version"].(string)
		}
	}
	// Older verified chat records wrote endpoint_type alongside a protocols
	// object. Preserve that independently recorded fact during the transition.
	if !hasChatCompletions && document.EndpointType == "chat" {
		result.ChatCompletions = true
	}
	return result
}

// SupportsConfiguredEndpoint applies only explicit route capability facts.
func (m ModelRecord) SupportsConfiguredEndpoint(endpoint string) bool {
	return m.ProtocolCapabilities.Explicit && m.ProtocolCapabilities.SupportsEndpoint(endpoint)
}

// SupportsChatCompletionsBridge reports whether the gateway is explicitly
// authorized to translate Chat Completions into native Responses. Native
// Responses support alone must never opt a route into protocol conversion.
func (m ModelRecord) SupportsChatCompletionsBridge() bool {
	c := m.ProtocolCapabilities
	return c.Explicit && c.ChatResponsesBridge && c.ResponsesNative && !c.ChatCompletions && !c.Gemini
}
