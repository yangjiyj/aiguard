package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const googleToolRequest = `{"systemInstruction":{"parts":[{"text":"be brief"}]},"contents":[{"role":"model","parts":[{"functionCall":{"id":"previous_a","name":"lookup","args":{"q":"a"}}},{"functionCall":{"id":"previous_b","name":"lookup","args":{"q":"b"}}}]},{"role":"user","parts":[{"functionResponse":{"id":"previous_a","name":"lookup","response":{"answer":"a"}}},{"functionResponse":{"id":"previous_b","name":"lookup","response":{"answer":"b"}}},{"text":"continue"}]}],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{"type":"OBJECT","properties":{"q":{"type":"STRING"}},"required":["q"]}}]}],"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["lookup"]}},"generationConfig":{"maxOutputTokens":128}}`

func TestGeminiIngressRealHTTPAnthropicAndOpenAI(t *testing.T) {
	for _, upstream := range []string{"anthropic", "openai"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", upstream, stream), func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					raw, _ := io.ReadAll(r.Body)
					for _, needle := range []string{"previous_a", "previous_b", "lookup", "be brief", "continue"} {
						if !strings.Contains(string(raw), needle) {
							t.Errorf("lost %s in %s", needle, raw)
						}
					}
					w.Header().Set("Content-Type", "application/json")
					if upstream == "anthropic" {
						if r.URL.Path != "/v1/messages" {
							t.Errorf("path=%s", r.URL.Path)
						}
						io.WriteString(w, `{"id":"msg","type":"message","role":"assistant","model":"vendor","content":[{"type":"text","text":"done"},{"type":"tool_use","id":"call_a","name":"lookup","input":{"q":"a"}},{"type":"tool_use","id":"call_b","name":"lookup","input":{"q":"b"}}],"stop_reason":"tool_use","usage":{"input_tokens":13,"output_tokens":7}}`)
					} else {
						if r.URL.Path != "/v1/chat/completions" {
							t.Errorf("path=%s", r.URL.Path)
						}
						io.WriteString(w, `{"id":"chat","object":"chat.completion","model":"vendor","choices":[{"index":0,"message":{"role":"assistant","content":"done","tool_calls":[{"id":"call_a","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"a\"}"}},{"id":"call_b","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"b\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":13,"completion_tokens":7,"total_tokens":20}}`)
					}
				}))
				defer server.Close()
				caps := modelrouter.ProtocolCapabilities{Explicit: true, Verified: true}
				if upstream == "anthropic" {
					caps.AnthropicMessages = true
				} else {
					caps.ChatCompletions = true
				}
				record := &modelrouter.ModelRecord{ID: "m", ProviderID: "p", ModelName: "logical", ProviderType: upstream, ProviderBaseURL: server.URL, UpstreamModelID: "vendor", Status: "active", ProtocolCapabilities: caps}
				security := &MockSecurityChecker{}
				audit := &MockAuditWriter{}
				chat := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{ModelRecord: record, ProviderAPIKey: "fixture"}, &MockRateLimitChecker{}, security, audit, &RealProviderAdapterFactory{}, nil, nil)
				authenticated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer personal-fixture" || r.URL.Path != "/v1/chat/completions" {
						t.Error("Google request bypassed normalized shared auth path")
					}
					chat.Handler().ServeHTTP(w, r)
				})
				bridge := NewGeminiIngressHandler(&config.Config{}, authenticated)
				action := "generateContent"
				if stream {
					action = "streamGenerateContent?alt=sse"
				}
				req := httptest.NewRequest("POST", "/v1beta/models/logical:"+action, strings.NewReader(googleToolRequest))
				req.Header.Set("X-Goog-Api-Key", "personal-fixture")
				req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a"))
				w := httptest.NewRecorder()
				bridge.Handler().ServeHTTP(w, req)
				raw := w.Body.String()
				if w.Code != 200 || calls != 1 {
					t.Fatalf("status %d calls %d body=%s", w.Code, calls, raw)
				}
				if stream {
					if !strings.HasPrefix(raw, "data: ") || !strings.HasSuffix(raw, "\n\n") {
						t.Fatal("invalid Google SSE event")
					}
					raw = strings.TrimSpace(strings.TrimPrefix(raw, "data: "))
				}
				var result struct {
					Candidates []struct {
						Content struct {
							Parts []map[string]json.RawMessage `json:"parts"`
						} `json:"content"`
						Finish string `json:"finishReason"`
					} `json:"candidates"`
					Usage map[string]int `json:"usageMetadata"`
				}
				if json.Unmarshal([]byte(raw), &result) != nil || len(result.Candidates) != 1 || result.Candidates[0].Finish != "STOP" {
					t.Fatalf("invalid native result %s", raw)
				}
				if len(result.Candidates[0].Content.Parts) != 3 || result.Usage["promptTokenCount"] != 13 || result.Usage["candidatesTokenCount"] != 7 || result.Usage["totalTokenCount"] != 20 {
					t.Fatalf("tool loop/usage lost: %s", raw)
				}
				for _, part := range result.Candidates[0].Content.Parts {
					if value, exists := part["functionCall"]; exists {
						var call struct {
							ID   string            `json:"id"`
							Name string            `json:"name"`
							Args map[string]string `json:"args"`
						}
						if json.Unmarshal(value, &call) != nil || call.ID == "" || call.Name != "lookup" || call.Args["q"] == "" {
							t.Fatal("incomplete tool arguments")
						}
					}
				}
				if len(security.InputCheckCalls) == 0 || len(security.OutputCheckCalls) == 0 {
					t.Fatal("Google path bypassed existing security checks")
				}
			})
		}
	}
}

func TestGeminiIngressRejectsUnmappedSemanticsBeforeBackend(t *testing.T) {
	for _, raw := range []string{
		`{"contents":[{"parts":[{"text":"x"}]}],"cachedContent":"secret"}`,
		`{"contents":[{"role":"model","parts":[{"functionCall":{"id":"a","name":"lookup","args":{}}},{"text":"after call"}]},{"parts":[{"functionResponse":{"id":"a","name":"lookup","response":{}}}]}]}`,
		`{"contents":[{"parts":[{"inlineData":{"data":"a"}}]}]}`,
		`{"contents":[{"parts":[{"text":"x","thought":true}]}]}`,
		// thinkingConfig 已映射为 reasoning_effort（见 gemini_cli_config_test.go），不再是未映射语义
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"candidateCount":2}}`,
		`{"contents":[{"parts":[{"functionResponse":{"name":"missing","response":{}}}]}]}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"toolConfig":{"functionCallingConfig":{"mode":"VALIDATED"}}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"messages":[{"role":"system","content":"uninspected"}]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			calls := 0
			bridge := NewGeminiIngressHandler(nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			w := httptest.NewRecorder()
			bridge.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1beta/models/x:generateContent", strings.NewReader(raw)))
			if w.Code != 400 || calls != 0 || !strings.Contains(w.Body.String(), "INVALID_ARGUMENT") {
				t.Fatalf("unmapped payload entered backend: %d %d %s", w.Code, calls, w.Body.String())
			}
		})
	}
}

func TestGeminiIngressCredentialConflictAndURLSanitization(t *testing.T) {
	for _, same := range []bool{true, false} {
		calls := 0
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"invalid api key"}}`)
		})
		bridge := NewGeminiIngressHandler(nil, backend)
		r := httptest.NewRequest("POST", "/v1beta/models/x:generateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"x"}]}]}`))
		r.Header.Set("X-Goog-Api-Key", "a")
		token := "a"
		if !same {
			token = "b"
		}
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		bridge.Handler().ServeHTTP(w, r)
		if same && (calls != 1 || w.Code != 401 || !strings.Contains(w.Body.String(), "UNAUTHENTICATED")) {
			t.Fatal("same header credentials rejected or auth error not converted")
		}
		if !same && (calls != 0 || w.Code != 400) {
			t.Fatal("conflicting credentials were accepted")
		}
	}
	observed := false
	guard := GeminiURLCredentialGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { observed = true }))
	r := httptest.NewRequest("POST", "/v1beta/models/x:streamGenerateContent?key=do-not-log&alt=sse", nil)
	w := httptest.NewRecorder()
	guard.ServeHTTP(w, r)
	if observed || w.Code != 400 || strings.Contains(r.RequestURI, "do-not-log") || strings.Contains(r.URL.RawQuery, "do-not-log") || strings.Contains(w.Body.String(), "do-not-log") {
		t.Fatal("query credential reached an observer or response")
	}
}

func TestGeminiIngressOutputBufferOverflowIsExplicitError(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("x", 8192)
		for i := 0; i < geminiBridgeLimit/len(chunk)+1; i++ {
			if _, err := io.WriteString(w, chunk); err != nil {
				break
			}
		}
	})
	bridge := NewGeminiIngressHandler(nil, backend)
	w := httptest.NewRecorder()
	bridge.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1beta/models/x:streamGenerateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"x"}]}]}`)))
	if w.Code != 502 || !strings.Contains(w.Body.String(), "32 MiB") || strings.Contains(w.Header().Get("Content-Type"), "event-stream") {
		t.Fatalf("overflow emitted success: %d %s", w.Code, w.Body.String())
	}
}

func TestGeminiIngressSchemaDataAndToolAssociation(t *testing.T) {
	raw := `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"ok":true}}}]}],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{"type":"OBJECT","properties":{"type":{"type":"STRING","const":"UPPER"}},"default":{"type":"UPPER"}}}]}]}`
	chat, err := geminiRequestToChat([]byte(raw), "logical")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(chat)
	if !strings.Contains(string(encoded), `"default":{"type":"UPPER"}`) || !strings.Contains(string(encoded), `"const":"UPPER"`) {
		t.Fatal("schema data was rewritten")
	}
	messages := chat["messages"].([]any)
	call := messages[0].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	result := messages[1].(map[string]any)
	if call["id"] != result["tool_call_id"] {
		t.Fatal("implicit function result association lost")
	}
}

func TestGeminiIngressGuardSanitizesUnknownMethodsAndCatalog(t *testing.T) {
	for _, path := range []string{"/v1beta", "/v1/models", "/v1beta/models/x:countTokens", "/v1beta/models/x:generateConten", "/v1beta/models", "/v1beta/files", "/v1/models/x:countTokens"} {
		r := httptest.NewRequest("POST", path+"?key=never-log", nil)
		w := httptest.NewRecorder()
		GeminiURLCredentialGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("observer reached") })).ServeHTTP(w, r)
		if w.Code != 400 || strings.Contains(r.RequestURI, "never-log") || strings.Contains(r.URL.RawQuery, "never-log") {
			t.Fatalf("query key survived for %s", path)
		}
	}
}

func TestGeminiModelsAuthorizedProjectionAndPagination(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Fatal("catalog auth path not canonical")
		}
		io.WriteString(w, `{"object":"list","data":[{"id":"chat-model"},{"id":"image-model"}]}`)
	})
	bridge := NewGeminiIngressHandler(nil, nil, backend)
	r := httptest.NewRequest("GET", "/v1beta/models?pageSize=1", nil)
	r.Header.Set("X-Goog-Api-Key", "fixture")
	w := httptest.NewRecorder()
	bridge.ModelsHandler().ServeHTTP(w, r)
	var page struct {
		Models []map[string]any `json:"models"`
		Next   string           `json:"nextPageToken"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Models) != 1 || page.Next == "" {
		t.Fatalf("invalid page %s", w.Body.String())
	}
	if _, exists := page.Models[0]["supportedGenerationMethods"]; exists {
		t.Fatal("invented model capability")
	}
	second := httptest.NewRequest("GET", "/v1beta/models?pageToken="+page.Next+"&pageSize=1", nil)
	second.Header.Set("Authorization", "Bearer fixture")
	next := httptest.NewRecorder()
	bridge.ModelsHandler().ServeHTTP(next, second)
	if !strings.Contains(next.Body.String(), "image-model") || strings.Contains(next.Body.String(), "supportedGenerationMethods") || strings.Contains(next.Body.String(), "nextPageToken") {
		t.Fatalf("catalog changed authorization/capability semantics %s", next.Body.String())
	}
}

func TestGeminiIngressInputLimitAndStreamErrorAreVisible(t *testing.T) {
	called := false
	bridge := NewGeminiIngressHandler(&config.Config{APIRequestBodyLimitBytes: 8}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	w := httptest.NewRecorder()
	bridge.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1beta/models/x:streamGenerateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"too long"}]}]}`)))
	if w.Code != 413 || called {
		t.Fatal("Google request limit bypassed")
	}
	bridge = NewGeminiIngressHandler(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		io.WriteString(w, `{"error":{"message":"budget exceeded"}}`)
	}))
	w = httptest.NewRecorder()
	bridge.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1beta/models/x:streamGenerateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"hi"}]}]}`)))
	if w.Code != 429 || !strings.Contains(w.Body.String(), "RESOURCE_EXHAUSTED") || strings.Contains(w.Body.String(), "data:") {
		t.Fatal("stream error was hidden by success framing")
	}
}
