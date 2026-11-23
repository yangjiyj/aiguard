package handler

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// Each case traverses the real public handler, capability admission, real
// adapter request transform, HTTP transport and response/security transform.
// Both request tool history and returned calls/usage cross the wire.
func TestProtocolInteroperabilityHTTPMatrix(t *testing.T) {
	for _, upstream := range []string{"anthropic", "openai", "responses", "gemini", "bedrock"} {
		for _, ingress := range []string{"chat", "messages", "responses"} {
			for _, stream := range []bool{false, true} {
				for _, v2 := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/stream=%t/v2=%t", upstream, ingress, stream, v2), func(t *testing.T) {
						calls := 0
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							calls++
							raw, _ := io.ReadAll(r.Body)
							var body map[string]any
							if err := json.Unmarshal(raw, &body); err != nil {
								t.Error(err)
							}
							if body["model"] == "logical" {
								t.Errorf("logical model leaked upstream: %s", raw)
							}
							if !bytes.Contains(raw, []byte("lookup")) || !bytes.Contains(raw, []byte("previous")) {
								t.Errorf("tool definitions/history lost: %s", raw)
							}
							if stream {
								w.Header().Set("Content-Type", "text/event-stream")
							}
							switch upstream {
							case "anthropic":
								if r.URL.Path != "/v1/messages" || body["max_tokens"] == nil {
									t.Errorf("Messages request path=%s body=%s", r.URL.Path, raw)
								}
								if stream {
									io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"vendor\",\"content\":[],\"usage\":{\"input_tokens\":13,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"fixture-ok\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_fixture\",\"name\":\"lookup\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\\\"ok\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":7}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
								} else {
									io.WriteString(w, `{"id":"msg_fixture","type":"message","role":"assistant","model":"vendor","content":[{"type":"text","text":"fixture-ok"},{"type":"tool_use","id":"call_fixture","name":"lookup","input":{"q":"ok"}}],"stop_reason":"tool_use","usage":{"input_tokens":13,"output_tokens":7}}`)
								}
							case "openai":
								if r.URL.Path != "/v1/chat/completions" || body["messages"] == nil {
									t.Errorf("Chat path=%s body=%s", r.URL.Path, raw)
								}
								if stream {
									io.WriteString(w, "data: {\"id\":\"chat_fixture\",\"model\":\"vendor\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"fixture-ok\",\"tool_calls\":[{\"index\":0,\"id\":\"call_fixture\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\\\"ok\\\"}\"}}]}}]}\n\ndata: {\"id\":\"chat_fixture\",\"model\":\"vendor\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":13,\"completion_tokens\":7,\"total_tokens\":20}}\n\ndata: [DONE]\n\n")
								} else {
									io.WriteString(w, `{"id":"chat_fixture","object":"chat.completion","model":"vendor","choices":[{"index":0,"message":{"role":"assistant","content":"fixture-ok","tool_calls":[{"id":"call_fixture","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"ok\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":13,"completion_tokens":7,"total_tokens":20}}`)
								}
							case "responses":
								if r.URL.Path != "/v1/responses" || body["input"] == nil || body["messages"] != nil {
									t.Errorf("Responses path=%s body=%s", r.URL.Path, raw)
								}
								result := `{"id":"resp_fixture","object":"response","status":"completed","model":"vendor","output":[{"id":"msg_fixture","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"fixture-ok"}]},{"id":"fc_fixture","type":"function_call","status":"completed","call_id":"call_fixture","name":"lookup","arguments":"{\"q\":\"ok\"}"}],"usage":{"input_tokens":13,"output_tokens":7,"total_tokens":20}}`
								if stream {
									fmt.Fprintf(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":%s}\n\n", result)
								} else {
									io.WriteString(w, result)
								}
							case "gemini":
								if contents, ok := body["contents"].([]any); !ok || len(contents) != 2 {
									t.Errorf("parallel tool turns split: %s", raw)
								}
								if body["contents"] == nil || r.Header.Get("X-Goog-Api-Key") != "fixture-key" {
									t.Errorf("Gemini request path=%s body=%s", r.URL.Path, raw)
								}
								if !bytes.Contains(raw, []byte(`"functionResponse":{"id":"previous","name":"lookup"`)) {
									t.Errorf("Gemini result lost original function name/id: %s", raw)
								}
								result := `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"fixture-ok"},{"functionCall":{"id":"call_fixture","name":"lookup","args":{"q":"ok"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":13,"candidatesTokenCount":7,"totalTokenCount":20}}`
								if stream {
									fmt.Fprintf(w, "data: %s\n\n", result)
								} else {
									io.WriteString(w, result)
								}
							case "bedrock":
								if messages, ok := body["messages"].([]any); !ok || len(messages) != 2 {
									t.Errorf("parallel tool turns split: %s", raw)
								}
								if body["toolConfig"] == nil || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
									t.Errorf("Bedrock request path=%s body=%s", r.URL.Path, raw)
								}
								if stream {
									w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
									for _, event := range []struct{ name, body string }{
										{"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"fixture-ok"}}`},
										{"contentBlockStart", `{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call_fixture","name":"lookup"}}}`},
										{"contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"q\":"}}}`},
										{"contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"\"ok\"}"}}}`},
										{"messageStop", `{"stopReason":"tool_use"}`},
										{"metadata", `{"usage":{"inputTokens":13,"outputTokens":7,"totalTokens":20}}`},
									} {
										w.Write(interopBedrockEvent(event.name, event.body))
									}
								} else {
									io.WriteString(w, `{"output":{"message":{"role":"assistant","content":[{"text":"fixture-ok"},{"toolUse":{"toolUseId":"call_fixture","name":"lookup","input":{"q":"ok"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":13,"outputTokens":7,"totalTokens":20}}`)
								}
							}
						}))
						defer server.Close()
						providerType := upstream
						caps := modelrouter.ProtocolCapabilities{Explicit: true, Verified: true}
						credential := "fixture-key"
						switch upstream {
						case "anthropic":
							caps.AnthropicMessages = true
						case "openai":
							caps.ChatCompletions = true
						case "responses":
							providerType = "openai"
							caps.ResponsesNative = true
							caps.ChatResponsesBridge = true
						case "gemini":
							caps.ChatCompletions = true
						case "bedrock":
							caps.ChatCompletions = true
							credential = `{"access_key_id":"AKID","secret_access_key":"SECRET","region":"us-east-1"}`
						}
						record := &modelrouter.ModelRecord{ID: "m", ProviderID: "p", ProviderType: providerType, ProviderBaseURL: server.URL, UpstreamModelID: "vendor", ModelName: "logical", Status: "active", ProtocolCapabilities: caps, ResponsesNative: caps.ResponsesNative}
						resolver := &MockModelResolver{ModelRecord: record, ProviderAPIKey: credential}
						cfg := &config.Config{UpstreamStreaming: stream}
						audit := &MockAuditWriter{}
						factory := &RealProviderAdapterFactory{}
						var h http.HandlerFunc
						engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: *record}}
						switch ingress {
						case "chat":
							handler := NewChatCompletionsHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil)
							if v2 {
								handler.SetRouting(nil, nil, nil, engine)
							}
							h = handler.Handler()
						case "messages":
							handler := NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil)
							if v2 {
								handler.SetModelRoutingEngine(engine)
							}
							h = handler.Handler()
						case "responses":
							handler := NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, factory, nil, nil)
							if v2 {
								handler.SetModelRoutingEngine(engine)
							}
							h = handler.Handler()
						}
						raw := interopParallelRequest(t, ingress, interopRequest(ingress, stream))
						req := httptest.NewRequest(http.MethodPost, "/v1/"+ingress, strings.NewReader(raw))
						req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a"))
						w := httptest.NewRecorder()
						h.ServeHTTP(w, req)
						result := w.Body.String()
						if w.Code != http.StatusOK || calls != 1 {
							t.Fatalf("status=%d upstream_calls=%d body=%s", w.Code, calls, result)
						}
						for _, value := range []string{"fixture-ok", "lookup", "call_fixture"} {
							if !strings.Contains(result, value) {
								t.Errorf("missing %q in %s", value, result)
							}
						}
						if !strings.Contains(result, `13`) || !strings.Contains(result, `7`) {
							t.Errorf("usage lost: %s", result)
						}
						if stream {
							terminal := map[string]string{"chat": "[DONE]", "messages": "message_stop", "responses": "response.completed"}[ingress]
							if !strings.Contains(result, terminal) {
								t.Errorf("terminal event lost: %s", result)
							}
						}
					})
				}
			}
		}
	}
}

func interopRequest(ingress string, stream bool) string {
	switch ingress {
	case "messages":
		return fmt.Sprintf(`{"model":"logical","max_tokens":128,"stream":%t,"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"previous","name":"lookup","input":{"q":"previous"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"previous","content":"previous result"},{"type":"text","text":"continue"}]}],"tools":[{"name":"lookup","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}]}`, stream)
	case "responses":
		return fmt.Sprintf(`{"model":"logical","stream":%t,"input":[{"type":"function_call","call_id":"previous","name":"lookup","arguments":"{\"q\":\"previous\"}"},{"type":"function_call_output","call_id":"previous","output":"previous result"},{"role":"user","content":"continue"}],"tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}]}`, stream)
	default:
		return fmt.Sprintf(`{"model":"logical","stream":%t,"messages":[{"role":"assistant","tool_calls":[{"id":"previous","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"previous\"}"}}]},{"role":"tool","tool_call_id":"previous","content":"previous result"},{"role":"user","content":"continue"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"q":{"type":"string"}}}}}]}`, stream)
	}
}

func interopBedrockEvent(name, payload string) []byte {
	key := []byte(":event-type")
	header := append([]byte{byte(len(key))}, key...)
	header = append(header, 7, byte(len(name)>>8), byte(len(name)))
	header = append(header, []byte(name)...)
	total := 12 + len(header) + len(payload) + 4
	frame := make([]byte, 12)
	binary.BigEndian.PutUint32(frame[:4], uint32(total))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(header)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[:8]))
	frame = append(frame, header...)
	frame = append(frame, []byte(payload)...)
	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.ChecksumIEEE(frame))
	return append(frame, sum...)
}

func TestResponsesCompatibilityRejectsUnmappedExtensions(t *testing.T) {
	for _, raw := range []string{
		`{"model":"logical","input":"hello","unknown_extension":{"keep":true}}`,
		`{"model":"logical","input":"hello","store":true}`,
		`{"model":"logical","input":"hello","tools":[{"name":"lookup","parameters":{"type":"object"}}]}`,
		`{"model":"logical","input":"hello","tool_choice":{"type":"function","name":"one","function":{"name":"two"}}}`,
		`{"model":"logical","input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AA","text":"ignored"}]}]}`,
		`{"model":"logical","input":"hello","tool_choice":{"type":"allowed_tools","mode":"required","tools":[]}}`,
		`{"model":"logical","input":[{"role":"user","content":[{"type":"input_text","text":"hello","annotations":[{"signed":true}]}]}]}`,
		`{"model":"logical","input":[{"role":"user","content":"hello","item_extension":true}]}`,
		`{"model":"logical","input":[{"type":"reasoning","summary":[{"text":"signed"}]}]}`,
		`{"model":"logical","input":"hello","tools":[{"type":"function","name":"lookup","namespace":"private"}]}`,
	} {
		if !requiresNativeResponses([]byte(raw)) {
			t.Errorf("unmapped Responses fields were admitted: %s", raw)
		}
	}
	if requiresNativeResponses([]byte(`{"model":"logical","input":"hello","store":false,"top_p":0.8,"metadata":{"trace":"fixture"},"parallel_tool_calls":true}`)) {
		t.Fatal("portable stateless controls were rejected")
	}
}

func TestResponsesCompatibilityPreservesIncompleteStatus(t *testing.T) {
	handler := &ResponsesHandler{}
	response := handler.transformChatToResponsesResponse([]byte(`{"id":"chat","model":"logical","choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":"length"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), "fixture")
	if response.Status != "incomplete" || response.IncompleteDetails == nil || response.IncompleteDetails.Reason != "max_output_tokens" || len(response.Output) != 1 || response.Output[0].Status != "incomplete" {
		t.Fatalf("truncation was reported as completed: %+v", response)
	}
}

func interopParallelRequest(t *testing.T, ingress, raw string) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	switch ingress {
	case "responses":
		input := body["input"].([]any)
		body["input"] = []any{input[0], map[string]any{"type": "function_call", "call_id": "previous_two", "name": "lookup", "arguments": "{}"}, input[1], map[string]any{"type": "function_call_output", "call_id": "previous_two", "output": "second result"}, input[2]}
	case "messages":
		messages := body["messages"].([]any)
		assistant := messages[0].(map[string]any)
		assistant["content"] = append(assistant["content"].([]any), map[string]any{"type": "tool_use", "id": "previous_two", "name": "lookup", "input": map[string]any{}})
		user := messages[1].(map[string]any)
		content := user["content"].([]any)
		user["content"] = []any{content[0], map[string]any{"type": "tool_result", "tool_use_id": "previous_two", "content": "second result"}, content[1]}
	default:
		messages := body["messages"].([]any)
		assistant := messages[0].(map[string]any)
		assistant["tool_calls"] = append(assistant["tool_calls"].([]any), map[string]any{"id": "previous_two", "type": "function", "function": map[string]any{"name": "lookup", "arguments": "{}"}})
		body["messages"] = []any{messages[0], messages[1], map[string]any{"role": "tool", "tool_call_id": "previous_two", "content": "second result"}, messages[2]}
	}
	result, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(result)
}

func TestResponsesCompatibilityPreservesPortableControlsOverHTTP(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		metadata, _ := body["metadata"].(map[string]any)
		if value, exists := body["temperature"]; !exists || value != float64(0) || body["top_p"] != float64(0.7) || body["store"] != false || body["parallel_tool_calls"] != true || metadata["trace"] != "fixture" {
			t.Errorf("portable controls changed: %+v", body)
		}
		io.WriteString(w, `{"id":"chat","model":"vendor","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer server.Close()
	record := &modelrouter.ModelRecord{ID: "m", ProviderID: "p", ProviderType: "openai", ProviderBaseURL: server.URL, UpstreamModelID: "vendor", ModelName: "logical", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}}
	resolver := &MockModelResolver{ModelRecord: record, ProviderAPIKey: "fixture"}
	handler := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil)
	raw := `{"model":"logical","input":"ping","temperature":0,"top_p":0.7,"store":false,"parallel_tool_calls":true,"metadata":{"trace":"fixture"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(raw))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a"))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, req)
	if w.Code != 200 || calls != 1 {
		t.Fatalf("status=%d calls=%d response=%s", w.Code, calls, w.Body.String())
	}
}

func TestResponsesNativeMixedPlanCannotOptIntoBridgeFromRawMessages(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native-fallback=%t", native), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/v1/responses" {
					t.Errorf("uninspected extension entered a Chat bridge: path=%s", r.URL.Path)
				}
				io.WriteString(w, `{"id":"resp_fixture","object":"response","status":"completed","model":"vendor","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"safe result"}]}],"usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}`)
			}))
			defer server.Close()
			primary := modelrouter.ModelRecord{ID: "chat", ProviderID: "chat-provider", ProviderType: "openai", ProviderBaseURL: server.URL, UpstreamModelID: "vendor", ModelName: "logical", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true}}
			plan := modelrouter.RoutePlan{Primary: primary}
			if native {
				fallback := primary
				fallback.ID = "native"
				fallback.ProviderID = "native-provider"
				fallback.ResponsesNative = true
				fallback.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ResponsesNative: true}
				plan.Fallbacks = []modelrouter.ModelRecord{fallback}
			}
			resolver := &MockModelResolver{ModelRecord: &primary, ProviderAPIKey: "fixture"}
			security := &MockSecurityChecker{}
			handler := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, security, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil)
			handler.SetModelRoutingEngine(&executionTestEngine{applied: true, hasPolicy: true, plan: plan})
			raw := `{"model":"logical","input":"SAFE_CHECKED_INPUT","messages":[{"role":"user","content":"UNINSPECTED_EXTENSION"}],"ResponsesCompatibility":true,"responses_compatibility":true}`
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(raw))
			req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a"))
			w := httptest.NewRecorder()
			handler.Handler().ServeHTTP(w, req)
			var inspected strings.Builder
			for _, call := range security.InputCheckCalls {
				inspected.WriteString(call.Content)
			}
			if !strings.Contains(inspected.String(), "SAFE_CHECKED_INPUT") || strings.Contains(inspected.String(), "UNINSPECTED_EXTENSION") {
				t.Fatalf("test must isolate inspected input from unknown extension: %q", inspected.String())
			}
			if native {
				if w.Code != 200 || calls != 1 {
					t.Fatalf("native fallback status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
				}
			} else if calls != 0 || w.Code == 200 {
				t.Fatalf("raw client opt-in bypassed native-only admission: status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
			}
		})
	}
}
