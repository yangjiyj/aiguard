package relay

import (
	"bytes"
	"encoding/json"
	"strings"
)

// RequestFeatures describes what a client request actually uses. It is
// intentionally independent from model names and provider types.
type RequestFeatures struct {
	ResponsesCompatibility bool
	IngressProtocol        string
	UpstreamProtocol       string
	BodyBytes              int
	MessageCount           int
	Stream                 bool
	Tools                  bool
	ToolResults            bool
	ParallelTools          bool
	Vision                 bool
	Audio                  bool
	Video                  bool
	Files                  bool
	Reasoning              bool
	ResponseFormat         bool
	JSONSchema             bool
	CacheTokens            bool
	Stateful               bool
	LongContext            bool
	Idempotent             bool
	Retryable              bool
	RequireVerified        bool
}

// ProtocolConversion is a declared, route-specific conversion. A conversion
// without Lossless=true cannot admit a request whose fields would be lost.
type ProtocolConversion struct {
	From     string
	To       string
	Lossless bool
}

// RouteCapabilities is the immutable capability declaration for one provider
// and model route. Empty protocol lists are deliberately not treated as
// wildcard support.
type RouteCapabilities struct {
	ProviderID        string
	ModelID           string
	Source            string
	Version           string
	Verified          bool
	IngressProtocols  []string
	UpstreamProtocols []string
	Conversions       []ProtocolConversion

	Stream         bool
	Tools          bool
	ToolResults    bool
	ParallelTools  bool
	Vision         bool
	Audio          bool
	Video          bool
	Files          bool
	Reasoning      bool
	ResponseFormat bool
	JSONSchema     bool
	CacheTokens    bool
	Stateful       bool
	LongContext    bool
	Idempotent     bool
	Retryable      bool
}

type CapabilityDecision struct {
	Eligible bool
	Reasons  []string
}

func MatchRoute(request RequestFeatures, route RouteCapabilities) CapabilityDecision {
	var reasons []string
	add := func(reason string) {
		for _, existing := range reasons {
			if existing == reason {
				return
			}
		}
		reasons = append(reasons, reason)
	}

	ingress := normalizeProtocol(request.IngressProtocol)
	if ingress == "" {
		add("ingress_protocol_missing")
	} else if !containsProtocol(route.IngressProtocols, ingress) && !hasLosslessConversion(route, ingress, request.UpstreamProtocol) {
		add("ingress_protocol")
	}
	if request.UpstreamProtocol != "" && !containsProtocol(route.UpstreamProtocols, request.UpstreamProtocol) {
		add("upstream_protocol")
	}
	if request.RequireVerified && !route.Verified {
		add("verified_required")
	}

	check := func(required bool, supported bool, name string) {
		if required && !supported {
			add(name)
		}
	}
	check(request.Stream, route.Stream, "stream")
	check(request.Tools, route.Tools, "tools")
	check(request.ToolResults, route.ToolResults, "tool_results")
	check(request.ParallelTools, route.ParallelTools, "parallel_tools")
	check(request.Vision, route.Vision, "vision")
	check(request.Audio, route.Audio, "audio")
	check(request.Video, route.Video, "video")
	check(request.Files, route.Files, "files")
	check(request.Reasoning, route.Reasoning, "reasoning")
	check(request.ResponseFormat, route.ResponseFormat, "response_format")
	check(request.JSONSchema, route.JSONSchema, "json_schema")
	check(request.CacheTokens, route.CacheTokens, "cache_tokens")
	check(request.Stateful, route.Stateful, "stateful")
	check(request.LongContext, route.LongContext, "long_context")
	check(request.Idempotent, route.Idempotent, "idempotent")
	check(request.Retryable, route.Retryable, "retryable")

	return CapabilityDecision{Eligible: len(reasons) == 0, Reasons: reasons}
}

// DetectRequestFeatures extracts the semantic shape used for route admission.
// It intentionally ignores model names and provider types. Unknown JSON fields
// remain in the secured body and are handled by the selected native adapter.
func DetectRequestFeatures(endpoint string, rawBody []byte, streaming bool) RequestFeatures {
	features := RequestFeatures{
		IngressProtocol: normalizeProtocol(endpoint),
		BodyBytes:       len(rawBody),
		Stream:          streaming,
		LongContext:     len(rawBody) >= 256*1024,
	}
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	var body map[string]any
	if decoder.Decode(&body) != nil {
		return features
	}
	if stream, ok := body["stream"].(bool); ok {
		features.Stream = features.Stream || stream
	}
	if tools, ok := body["tools"].([]any); ok && len(tools) > 0 {
		features.Tools = true
	}
	if value, ok := body["parallel_tool_calls"].(bool); ok && value {
		features.ParallelTools = true
	}
	if _, ok := body["reasoning_effort"]; ok {
		features.Reasoning = true
	}
	if _, ok := body["reasoning"]; ok {
		features.Reasoning = true
	}
	if _, ok := body["thinking"]; ok {
		features.Reasoning = true
	}
	if _, ok := body["enable_thinking"]; ok {
		features.Reasoning = true
	}
	if format, ok := body["response_format"].(map[string]any); ok {
		features.ResponseFormat = true
		features.JSONSchema = protocolStringValue(format["type"]) == "json_schema"
	}
	if text, ok := body["text"].(map[string]any); ok {
		if format, ok := text["format"].(map[string]any); ok {
			features.ResponseFormat = true
			features.JSONSchema = protocolStringValue(format["type"]) == "json_schema"
		}
	}
	if _, ok := body["prompt_cache_key"]; ok {
		features.CacheTokens = true
	}
	if _, ok := body["previous_response_id"]; ok {
		features.Stateful = true
	}
	if _, ok := body["conversation"]; ok {
		features.Stateful = true
	}
	if messages, ok := body["messages"].([]any); ok {
		features.MessageCount = len(messages)
	}
	if input, ok := body["input"].([]any); ok && len(input) > features.MessageCount {
		features.MessageCount = len(input)
	}
	if features.MessageCount >= 24 {
		features.LongContext = true
	}
	walkRequestValue(body, &features)
	return features
}

// PrefersResponsesBridge identifies Chat requests for which the typed
// Responses item model is materially safer than forwarding a Chat-shaped
// payload to an upstream that only proves simple Chat compatibility.
func PrefersResponsesBridge(features RequestFeatures) bool {
	return normalizeProtocol(features.IngressProtocol) == "chat" &&
		(features.ToolResults || features.ParallelTools || features.Vision || features.Audio ||
			features.Video || features.Files || features.Reasoning || features.ResponseFormat ||
			features.JSONSchema || features.CacheTokens || features.Stateful || features.LongContext)
}

// FeatureNames returns a stable, content-free fingerprint suitable for audit
// records and routing diagnostics.
func FeatureNames(features RequestFeatures) []string {
	result := make([]string, 0, 16)
	add := func(enabled bool, name string) {
		if enabled {
			result = append(result, name)
		}
	}
	add(features.Stream, "stream")
	add(features.Tools, "tools")
	add(features.ToolResults, "tool_results")
	add(features.ParallelTools, "parallel_tools")
	add(features.Vision, "vision")
	add(features.Audio, "audio")
	add(features.Video, "video")
	add(features.Files, "files")
	add(features.Reasoning, "reasoning")
	add(features.ResponseFormat, "response_format")
	add(features.JSONSchema, "json_schema")
	add(features.CacheTokens, "cache_tokens")
	add(features.Stateful, "stateful")
	add(features.LongContext, "long_context")
	return result
}

func walkRequestValue(value any, features *RequestFeatures) {
	switch current := value.(type) {
	case []any:
		for _, item := range current {
			walkRequestValue(item, features)
		}
	case map[string]any:
		role := protocolStringValue(current["role"])
		if role == "tool" || role == "function" {
			features.ToolResults = true
		}
		typ := protocolStringValue(current["type"])
		switch typ {
		case "function", "custom", "computer", "computer_use_preview", "web_search", "web_search_preview", "file_search", "mcp", "code_interpreter", "image_generation":
			features.Tools = true
		case "function_call", "custom_tool_call", "tool_use":
			features.Tools = true
		case "function_call_output", "custom_tool_call_output", "tool_result":
			features.Tools = true
			features.ToolResults = true
		case "image", "image_url", "input_image":
			features.Vision = true
		case "audio", "input_audio":
			features.Audio = true
		case "video", "video_url", "input_video":
			features.Video = true
		case "file", "input_file":
			features.Files = true
		case "reasoning", "thinking":
			features.Reasoning = true
		}
		if _, ok := current["image_url"]; ok {
			features.Vision = true
		}
		if _, ok := current["file_id"]; ok {
			features.Files = true
		}
		if _, ok := current["cache_control"]; ok {
			features.CacheTokens = true
		}
		if calls, ok := current["tool_calls"].([]any); ok {
			features.Tools = features.Tools || len(calls) > 0
			features.ParallelTools = features.ParallelTools || len(calls) > 1
		}
		for _, child := range current {
			walkRequestValue(child, features)
		}
	}
}

func protocolStringValue(value any) string {
	text, _ := value.(string)
	return normalizeProtocol(text)
}

func normalizeProtocol(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func containsProtocol(values []string, wanted string) bool {
	wanted = normalizeProtocol(wanted)
	for _, value := range values {
		if normalizeProtocol(value) == wanted {
			return true
		}
	}
	return false
}

func hasLosslessConversion(route RouteCapabilities, from, requestedUpstream string) bool {
	for _, conversion := range route.Conversions {
		if normalizeProtocol(conversion.From) != from || !conversion.Lossless {
			continue
		}
		if requestedUpstream == "" || normalizeProtocol(conversion.To) == normalizeProtocol(requestedUpstream) {
			return containsProtocol(route.UpstreamProtocols, conversion.To)
		}
	}
	return false
}
