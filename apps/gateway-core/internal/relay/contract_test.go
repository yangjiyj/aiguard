package relay

import (
	"strings"
	"testing"
)

func TestMatchRouteRejectsSilentFeatureLoss(t *testing.T) {
	request := RequestFeatures{
		IngressProtocol: "chat",
		Stream:          true,
		Tools:           true,
		ToolResults:     true,
		ParallelTools:   true,
		Vision:          true,
		Reasoning:       true,
		JSONSchema:      true,
		CacheTokens:     true,
		Idempotent:      true,
		Retryable:       true,
	}
	caps := RouteCapabilities{
		ProviderID:        "provider-1",
		ModelID:           "model-1",
		IngressProtocols:  []string{"chat"},
		UpstreamProtocols: []string{"responses"},
		Conversions:       []ProtocolConversion{{From: "chat", To: "responses", Lossless: true}},
		Stream:            true,
		Tools:             true,
		ToolResults:       true,
		ParallelTools:     true,
		Vision:            true,
		Reasoning:         true,
		JSONSchema:        true,
		Idempotent:        true,
		Retryable:         true,
		Verified:          true,
	}

	decision := MatchRoute(request, caps)
	if decision.Eligible {
		t.Fatal("route with undeclared cache token support must be ineligible")
	}
	if !strings.Contains(strings.Join(decision.Reasons, ","), "cache_tokens") {
		t.Fatalf("reasons=%v; want cache_tokens", decision.Reasons)
	}

	caps.CacheTokens = true
	if decision = MatchRoute(request, caps); !decision.Eligible {
		t.Fatalf("complete explicit capability set should match: %+v", decision)
	}
}

func TestMatchRouteDoesNotInferProtocolFromModelName(t *testing.T) {
	request := RequestFeatures{IngressProtocol: "chat"}
	caps := RouteCapabilities{ModelID: "gpt-4o", UpstreamProtocols: []string{"responses"}}
	decision := MatchRoute(request, caps)
	if decision.Eligible {
		t.Fatal("model name must not imply a chat or Responses capability")
	}
	if !strings.Contains(strings.Join(decision.Reasons, ","), "protocol") {
		t.Fatalf("reasons=%v; want protocol reason", decision.Reasons)
	}
}

func TestDetectRequestFeaturesCoversAgenticMultimodalHistory(t *testing.T) {
	raw := []byte(`{
		"stream":true,
		"reasoning_effort":"high",
		"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object"}}},
		"prompt_cache_key":"workspace-a",
		"tools":[{"type":"function","function":{"name":"shell"}},{"type":"mcp","server_label":"docs"}],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"inspect"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"}},{"type":"file","file":{"file_id":"file_1"}}]},
			{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"shell","arguments":"{}"}},{"id":"two","type":"function","function":{"name":"read","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"one","content":"ok"}
		]
	}`)
	got := DetectRequestFeatures("chat", raw, false)
	if !got.Stream || !got.Tools || !got.ToolResults || !got.ParallelTools || !got.Vision || !got.Files || !got.Reasoning || !got.ResponseFormat || !got.JSONSchema || !got.CacheTokens {
		t.Fatalf("incomplete request fingerprint: %+v", got)
	}
	if got.MessageCount != 3 || !PrefersResponsesBridge(got) {
		t.Fatalf("agentic request was not selected for typed bridge: %+v", got)
	}
}

func TestDetectRequestFeaturesCoversResponsesStateAndMedia(t *testing.T) {
	raw := []byte(`{"previous_response_id":"resp_1","input":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AA"}},{"type":"input_video","video_url":"https://example.invalid/v.mp4"}]}]}`)
	got := DetectRequestFeatures("responses", raw, false)
	if !got.Stateful || !got.Audio || !got.Video || got.IngressProtocol != "responses" {
		t.Fatalf("Responses fingerprint mismatch: %+v", got)
	}
}

func TestMatchRouteAllowsUnverifiedNativeButCanRequireVerification(t *testing.T) {
	request := RequestFeatures{IngressProtocol: "chat"}
	route := RouteCapabilities{IngressProtocols: []string{"chat"}, UpstreamProtocols: []string{"chat"}}
	if decision := MatchRoute(request, route); !decision.Eligible {
		t.Fatalf("native passthrough should not be disabled solely by missing probe metadata: %+v", decision)
	}
	request.RequireVerified = true
	if decision := MatchRoute(request, route); decision.Eligible || !strings.Contains(strings.Join(decision.Reasons, ","), "verified_required") {
		t.Fatalf("verified conversion contract was not enforced: %+v", decision)
	}
}
