package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func TestResponsesBridgeCompletesTerminalTextAndToolArguments(t *testing.T) {
	for _, done := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal-only-arguments", true: "arguments-done-before-terminal"}[done], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"fixture-\"}\n\n")
				io.WriteString(w, "data: {\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"id\":\"fc_internal\",\"call_id\":\"call_public\",\"type\":\"function_call\",\"name\":\"lookup\"}}\n\n")
				io.WriteString(w, "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"item_id\":\"fc_internal\",\"delta\":\"{\\\"q\\\":\"}\n\n")
				if done {
					io.WriteString(w, "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":1,\"item_id\":\"fc_internal\",\"arguments\":\"{\\\"q\\\":\\\"ok\\\"}\"}\n\n")
				}
				io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"id\":\"msg\",\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"fixture-ok\"}]},{\"id\":\"fc_internal\",\"call_id\":\"call_public\",\"type\":\"function_call\",\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\\\"ok\\\"}\"}],\"usage\":{\"input_tokens\":13,\"output_tokens\":7}}}\n\n")
			}))
			defer server.Close()
			adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "fixture"}
			envelope := chatResponsesBridgeEnvelope()
			reader, _, err := adapter.OpenStream(context.Background(), envelope, []byte(`{"input":"ping"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			var text, args strings.Builder
			starts := 0
			terminal := false
			for {
				event, err := reader.Next(context.Background())
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				switch event.Type {
				case relay.EventTextDelta:
					text.WriteString(event.Delta)
				case relay.EventToolCallStart:
					starts++
					if event.ToolCall.ID != "call_public" {
						t.Errorf("wrong public call id: %+v", event.ToolCall)
					}
				case relay.EventToolArgumentsDelta, relay.EventToolArgumentsDone:
					args.WriteString(event.Delta)
					if event.ToolCall.ID != "call_public" {
						t.Errorf("tool args identity changed: %+v", event.ToolCall)
					}
				case relay.EventMessageEnd:
					terminal = true
					if event.FinishReason != "tool_calls" || event.Usage == nil || event.Usage.OutputTokens != 7 {
						t.Errorf("bad terminal: %+v", event)
					}
				}
			}
			if text.String() != "fixture-ok" || args.String() != `{"q":"ok"}` || starts != 1 || !terminal {
				t.Fatalf("text=%q args=%q starts=%d terminal=%t", text.String(), args.String(), starts, terminal)
			}
		})
	}
}

func TestBedrockToolStreamRejectsPartialArgumentsAndExceptions(t *testing.T) {
	cases := map[string][][]byte{
		"invalid-arguments":  {bedrockTestEvent("contentBlockStart", []byte(`{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"call","name":"lookup"}}}`)), bedrockTestEvent("contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{"}}}`)), bedrockTestEvent("messageStop", []byte(`{"stopReason":"tool_use"}`))},
		"missing-tool-start": {bedrockTestEvent("contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{}"}}}`)), bedrockTestEvent("messageStop", []byte(`{"stopReason":"tool_use"}`))},
		"missing-stop":       {bedrockTestEvent("contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"text":"partial"}}`))},
	}
	for name, frames := range cases {
		t.Run(name, func(t *testing.T) {
			var body strings.Builder
			for _, frame := range frames {
				body.Write(frame)
			}
			if _, err := accumulateBedrockEventStream(strings.NewReader(body.String()), nil, time.Now()); err == nil {
				t.Fatal("partial tool stream was accepted")
			}
		})
	}
}

func TestGeminiAPIKeyTargetPreservesVersionAndHidesCredential(t *testing.T) {
	for _, base := range []string{"https://example.test", "https://example.test/v1", "https://example.test/v1beta"} {
		adapter := &GeminiAdapter{BaseURL: base, APIKey: "secret-fixture"}
		endpoint, key, apiKey, err := adapter.requestTarget(context.Background(), chatResponsesBridgeEnvelope(), true)
		if err != nil {
			t.Fatal(err)
		}
		if !apiKey || key != "secret-fixture" || strings.Contains(endpoint, "secret-fixture") || strings.Contains(endpoint, "key=") || !strings.HasSuffix(endpoint, ":streamGenerateContent?alt=sse") {
			t.Fatalf("invalid developer API target: %s", endpoint)
		}
	}
	adapter := &GeminiAdapter{BaseURL: "https://us-central1-aiplatform.googleapis.com", APIKey: "key"}
	if _, _, _, err := adapter.requestTarget(context.Background(), chatResponsesBridgeEnvelope(), false); err == nil {
		t.Fatal("Vertex accepted a developer API key")
	}
}

func TestBedrockToolsRetainStrictAndNamedChoice(t *testing.T) {
	config, err := bedrockTools(map[string]json.RawMessage{"tools": json.RawMessage(`[{"type":"function","function":{"name":"lookup","strict":true,"parameters":{"type":"object"}}}]`), "tool_choice": json.RawMessage(`{"type":"function","function":{"name":"lookup"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(config)
	if !strings.Contains(string(raw), `"strict":true`) || !strings.Contains(string(raw), `"tool":{"name":"lookup"}`) {
		t.Fatalf("tool semantics lost: %s", raw)
	}
}

func TestResponsesBridgeBoundsManySmallTextChunks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		event, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": strings.Repeat("x", 4096)})
		for i := 0; i < 1025; i++ {
			if _, err := io.WriteString(w, "data: "+string(event)+"\n\n"); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "fixture"}
	reader, _, err := adapter.OpenStream(context.Background(), chatResponsesBridgeEnvelope(), []byte(`{"input":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	count := 0
	for {
		_, err = reader.Next(context.Background())
		if err != nil {
			break
		}
		count++
	}
	if err == nil || !strings.Contains(err.Error(), "bounded buffer") || count > 1024 {
		t.Fatalf("stream accumulation did not stop at its bound: count=%d err=%v", count, err)
	}
}

func TestGeminiRejectsUnrepresentableToolSemantics(t *testing.T) {
	adapter := &GeminiAdapter{}
	envelope := chatResponsesBridgeEnvelope()
	for _, field := range []string{
		`"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"lookup"}]}`,
		`"tool_choice":{"type":"function","function":{"name":"lookup","extension":true}}`,
		`"tools":[{"type":"function","function":{"name":"lookup","strict":true,"parameters":{"type":"object"}}}]`,
		`"tools":[{"type":"custom","function":{"name":"lookup"}}]`,
	} {
		raw := []byte(`{"messages":[{"role":"user","content":"ping"}],` + field + `}`)
		if _, err := adapter.TransformRequest(envelope, raw); err == nil {
			t.Errorf("unsupported tool contract was silently accepted: %s", raw)
		}
	}
}

func TestAnthropicBridgePreservesStrictAndDisablesTools(t *testing.T) {
	adapter := &AnthropicAdapter{}
	raw := []byte(`{"model":"logical","messages":[{"role":"user","content":"ping"}],"tools":[{"type":"function","function":{"name":"lookup","strict":true,"parameters":{"type":"object","additionalProperties":false}}}],"tool_choice":"none","parallel_tool_calls":false}`)
	transformed, err := adapter.TransformRequest(chatResponsesBridgeEnvelope(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(transformed, &body); err != nil {
		t.Fatal(err)
	}
	choice, _ := body["tool_choice"].(map[string]any)
	tools, _ := body["tools"].([]any)
	if choice["type"] != "none" || choice["disable_parallel_tool_use"] != nil || len(tools) != 1 || tools[0].(map[string]any)["strict"] != true {
		t.Fatalf("Anthropic tool contract changed: %s", transformed)
	}
	_, err = adapter.TransformRequest(chatResponsesBridgeEnvelope(), []byte(`{"model":"logical","messages":[{"role":"user","content":"ping"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[]}}`))
	if err == nil {
		t.Fatal("unrepresentable tool_choice was silently accepted")
	}
}

func TestBedrockARNDeploymentRemainsOneEscapedPathSegmentOverHTTP(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		want := "/relay/model/arn:aws:bedrock:us-east-1:123:inference-profile%2Ffixture/converse"
		if r.URL.EscapedPath() != want {
			t.Errorf("ARN was split into extra route segments: got %s want %s", r.URL.EscapedPath(), want)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") {
			t.Error("ARN request lost SigV4")
		}
		io.WriteString(w, `{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn"}`)
	}))
	defer server.Close()
	adapter := &BedrockAdapter{BaseURL: server.URL + "/relay", APIKey: `{"access_key_id":"AKID","secret_access_key":"SECRET","region":"us-east-1"}`}
	envelope := chatResponsesBridgeEnvelope()
	envelope.UpstreamModelID = "arn:aws:bedrock:us-east-1:123:inference-profile/fixture"
	request, err := adapter.TransformRequest(envelope, []byte(`{"messages":[{"role":"user","content":"ping"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.Call(context.Background(), envelope, request); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("upstream calls=%d", calls)
	}
}
