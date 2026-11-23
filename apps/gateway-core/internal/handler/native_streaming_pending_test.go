package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func nativePendingHTTP(t *testing.T, protocol string, cfg *config.Config, upstreamBody string, security SecurityChecker) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer upstream.Close()
	record := &modelrouter.ModelRecord{ID: "model", ProviderID: "provider", ModelName: "test", UpstreamModelID: "test", ProviderType: "openai", ProviderBaseURL: upstream.URL, Status: "active", ResponsesNative: true}
	reqBody := `{"model":"test","input":"inspect","stream":true}`
	if protocol == "messages" {
		record.ProviderType = "anthropic"
		reqBody = `{"model":"test","max_tokens":100,"messages":[{"role":"user","content":"inspect"}],"stream":true}`
	}
	resolver := &MockModelResolver{ProviderAPIKey: "fixture-key", ModelRecord: record}
	var handler http.HandlerFunc
	if protocol == "messages" {
		handler = NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, security, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil).Handler()
	} else {
		handler = NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, security, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil).Handler()
	}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(setAuthInfo(r.Context(), "tenant", "project", "user", "key", "session"))
		handler.ServeHTTP(w, r)
	}))
	defer gateway.Close()
	resp, err := http.Post(gateway.URL+"/v1/"+protocol, "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

const nativePendingMessagesSecret = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg\",\"model\":\"test\",\"content\":[],\"usage\":{\"input_tokens\":1}}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"key=sk-live-\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"secret-123\"}}\n\n" +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
const nativePendingResponsesSecret = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp\",\"output\":[]}}\n\n" +
	"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg\",\"output_index\":3,\"content_index\":1,\"sequence_number\":5,\"delta\":\"key=sk-live-\"}\n\n" +
	"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg\",\"output_index\":3,\"content_index\":1,\"sequence_number\":6,\"delta\":\"secret-123\"}\n\n" +
	"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"test\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"

func TestHTTPNativePendingPreventsSplitSecretPrefix(t *testing.T) {
	for _, protocol := range []string{"messages", "responses"} {
		t.Run(protocol, func(t *testing.T) {
			fixture := nativePendingMessagesSecret
			if protocol == "responses" {
				fixture = nativePendingResponsesSecret
			}
			checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
				if strings.Contains(s, "key=sk-live-secret-123") {
					return "block", []SecurityFinding{{Type: "secret"}}
				}
				return "allow", nil
			}}
			body := nativePendingHTTP(t, protocol, &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, fixture, checker)
			if strings.Contains(body, "sk-live-") {
				t.Fatalf("native secret prefix leaked: %s", body)
			}
			if !strings.Contains(body, "security_blocked") {
				t.Fatalf("missing native security failure: %s", body)
			}
		})
	}
}

func TestHTTPNativePendingFlushPreservesIdentityAndStrictBlocksPrefixes(t *testing.T) {
	for _, protocol := range []string{"messages", "responses"} {
		for _, mode := range []string{"stream_enforce", "strict_buffered"} {
			t.Run(protocol+"_"+mode, func(t *testing.T) {
				fixture := nativePendingMessagesSecret
				if protocol == "responses" {
					fixture = nativePendingResponsesSecret
				}
				safe := strings.ReplaceAll(strings.ReplaceAll(fixture, "key=sk-live-", "hello-"), "secret-123", "世界")
				body := nativePendingHTTP(t, protocol, &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode}, safe, &streamRegressionSecurity{})
				content := ""
				lastSequence := -1
				for _, line := range strings.Split(body, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var frame map[string]interface{}
					if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &frame); err != nil {
						t.Fatal(err)
					}
					if seq, ok := frame["sequence_number"].(float64); ok {
						if int(seq) <= lastSequence {
							t.Fatalf("sequence regressed: %s", body)
						}
						lastSequence = int(seq)
					}
					if protocol == "messages" && frame["type"] == "content_block_delta" {
						delta, _ := frame["delta"].(map[string]interface{})
						if delta["type"] == "text_delta" {
							if frame["index"] != float64(2) {
								t.Fatalf("block identity changed: %s", line)
							}
							content += delta["text"].(string)
						}
					} else if protocol == "responses" && frame["type"] == "response.output_text.delta" {
						if frame["item_id"] != "msg" || frame["output_index"] != float64(3) || frame["content_index"] != float64(1) {
							t.Fatalf("item identity changed: %s", line)
						}
						content += frame["delta"].(string)
					}
				}
				if content != "hello-世界" {
					t.Fatalf("native final tail lost/duplicated: %q body=%s", content, body)
				}
				terminal := "event: message_stop"
				if protocol == "responses" {
					terminal = "event: response.completed"
				}
				if strings.Count(body, terminal) != 1 {
					t.Fatalf("missing/duplicate terminal: %s", body)
				}
				checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
					if strings.Contains(s, "key=sk-live-secret-123") {
						return "block", nil
					}
					return "allow", nil
				}}
				blocked := nativePendingHTTP(t, protocol, &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode}, fixture, checker)
				if strings.Contains(blocked, "sk-live-") || !strings.Contains(blocked, "security_blocked") {
					t.Fatalf("native %s released secret: %s", mode, blocked)
				}
			})
		}
	}
}
func TestHTTPNativeTerminalOnlySensitiveFieldCannotEscape(t *testing.T) {
	for _, mode := range []string{"stream_enforce", "strict_buffered"} {
		t.Run(mode, func(t *testing.T) {
			fixture := strings.ReplaceAll(strings.ReplaceAll(nativePendingResponsesSecret, "key=sk-live-", "hello-"), "secret-123", "world")
			fixture = strings.Replace(fixture, `"object":"response"`, `"object":"response","metadata":{"note":"terminal-only-secret"}`, 1)
			checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
				if strings.Contains(s, "terminal-only-secret") {
					return "block", nil
				}
				return "allow", nil
			}}
			body := nativePendingHTTP(t, "responses", &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode}, fixture, checker)
			if strings.Contains(body, "terminal-only-secret") || !strings.Contains(body, "security_blocked") {
				t.Fatalf("terminal snapshot bypassed check: %s", body)
			}
		})
	}
}
func TestHTTPNativeNonemptyStartSnapshotIsExplicitlyIncomplete(t *testing.T) {
	fixture := strings.Replace(nativePendingMessagesSecret, `"text":""`, `"text":"start-only-secret"`, 1)
	// A snapshot the live scanner cannot inspect is an inspection gap: it is
	// recorded (output_scan_incomplete) and never turns into a block.
	body := nativePendingHTTP(t, "messages", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, fixture, &streamRegressionSecurity{})
	if strings.Contains(body, "security_blocked") || !strings.Contains(body, "start-only-secret") {
		t.Fatalf("inspection gap must be forwarded, not blocked: %s", body)
	}
}
func TestNativePendingCancellationDoesNotFlushHeldBytes(t *testing.T) {
	for _, protocol := range []string{"messages", "responses"} {
		for _, mode := range []string{"stream_enforce", "strict_buffered"} {
			t.Run(protocol+"_"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				reader := &cancelAwareStreamReader{firstSent: make(chan struct{}), closed: make(chan struct{})}
				go func() { <-reader.firstSent; cancel() }()
				cfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode}
				rec := httptest.NewRecorder()
				tracker := &relay.CommitTracker{}
				env := &modelrouter.RequestEnvelope{RequestID: "native-cancel", Model: "test"}
				caller := &liveRelayCaller{reader: reader}
				var err error
				if protocol == "messages" {
					h := NewMessagesHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &streamRegressionSecurity{}, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil)
					_, err = h.tryLiveNativeMessagesStream(ctx, rec, env, caller, []byte("{}"), time.Now(), "", tracker, nil)
				} else {
					h := NewResponsesHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &streamRegressionSecurity{}, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil)
					_, err = h.tryLiveNativeResponsesStream(ctx, rec, env, caller, []byte("{}"), time.Now(), "", tracker, nil)
				}
				if !errors.Is(err, context.Canceled) || rec.Body.Len() != 0 || tracker.State() != relay.CommitNotStarted {
					t.Fatalf("cancel flushed native buffer: err=%v state=%s body=%s", err, tracker.State(), rec.Body.String())
				}
				select {
				case <-reader.closed:
				default:
					t.Fatal("native upstream not closed after cancellation")
				}
			})
		}
	}
}
func TestLiveOutputFindingEvidenceIsBounded(t *testing.T) {
	acc := newLiveStreamAccumulator()
	for i := 0; i < maxLiveOutputFindings+20; i++ {
		acc.rememberOutputFindings(0, []SecurityFinding{{Type: "audit", RuleID: fmt.Sprint(i)}})
	}
	if len(acc.outputFindings) > maxLiveOutputFindings || len(acc.outputFindingKeys) > maxLiveOutputFindings || acc.outputFindingBytes > maxLiveOutputFindingBytes {
		t.Fatal("unbounded finding evidence")
	}
	audit := acc.auditResult("allow")
	if audit.ResponseMetadata["output_findings_truncated"] != true || acc.outputFindingsDropped == 0 {
		t.Fatalf("missing evidence truncation state: %+v", audit)
	}
}

func TestHTTPNativeRetainedExtensionFieldsAreInspected(t *testing.T) {
	for _, tc := range []struct{ name, protocol, needle, replacement string }{
		{"responses delta logprobs", "responses", `"delta":"hello-"`, `"delta":"hello-","logprobs":[{"token":"frame-only-secret"}]`},
		{"messages delta extension", "messages", `"type":"content_block_delta"`, `"type":"content_block_delta","extra":"frame-only-secret"`},
		{"messages start extension", "messages", `"type":"message_start"`, `"type":"message_start","metadata":{"foo":"frame-only-secret"}`},
		{"responses created extension", "responses", `"type":"response.created"`, `"type":"response.created","metadata":{"foo":"frame-only-secret"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := nativePendingMessagesSecret
			if tc.protocol == "responses" {
				fixture = nativePendingResponsesSecret
			}
			fixture = strings.ReplaceAll(strings.ReplaceAll(fixture, "key=sk-live-", "hello-"), "secret-123", "world")
			fixture = strings.Replace(fixture, tc.needle, tc.replacement, 1)
			checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
				if strings.Contains(s, "frame-only-secret") {
					return "block", nil
				}
				return "allow", nil
			}}
			body := nativePendingHTTP(t, tc.protocol, &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, fixture, checker)
			if strings.Contains(body, "frame-only-secret") || !strings.Contains(body, "security_blocked") {
				t.Fatalf("retained native metadata bypass: %s", body)
			}
		})
	}
}
func TestNativeMaskCannotMoveTextAcrossItemIdentities(t *testing.T) {
	p := newLivePendingOutput(&ChatCompletionsHandler{cfg: &config.Config{OutputSecurityMode: "strict_buffered"}}, relay.OutputSecurityStrictBuffered)
	p.preserveRaw = true
	acc := newLiveStreamAccumulator()
	events := []relay.StreamEvent{
		{Type: relay.EventTextDelta, Delta: "first", Raw: []byte(`{"type":"response.output_text.delta","item_id":"one","output_index":0,"content_index":0,"delta":"first","sequence_number":1}`)},
		{Type: relay.EventTextDelta, Delta: "second", Raw: []byte(`{"type":"response.output_text.delta","item_id":"two","output_index":1,"content_index":0,"delta":"second","sequence_number":2}`)},
	}
	for _, event := range events {
		acc.observeEvent(event)
		if err := p.add(context.Background(), event, func(string, int) (bool, error) { return false, nil }, func(relay.StreamEvent) error { return nil }, func(string) error { return errLivePendingLimit }); err != nil {
			t.Fatal(err)
		}
	}
	err := p.reconcile(acc, ChatCompletionResponse{Choices: []Choice{{Index: 0, Message: ChoiceMessage{Content: "[masked]"}}}})
	if err == nil {
		t.Fatal("ambiguous mask was assigned to a different native item")
	}
}

func TestHTTPNativeTerminalEnvelopeCannotCarryUninspectedData(t *testing.T) {
	for _, mode := range []string{"stream_enforce", "strict_buffered"} {
		for _, tc := range []struct{ name, extra, secret string }{
			{"value", `,"extra":"envelope-only-secret"`, "envelope-only-secret"},
			{"property", `,"envelope-only-secret":true`, "envelope-only-secret"},
			{"number", `,"account":13800138000`, "13800138000"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				fixture := strings.ReplaceAll(strings.ReplaceAll(nativePendingResponsesSecret, "key=sk-live-", "hello-"), "secret-123", "world")
				fixture = strings.Replace(fixture, `"type":"response.completed"`, `"type":"response.completed"`+tc.extra, 1)
				checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
					if strings.Contains(s, tc.secret) {
						return "block", nil
					}
					return "allow", nil
				}}
				body := nativePendingHTTP(t, "responses", &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode}, fixture, checker)
				if strings.Contains(body, tc.secret) || !strings.Contains(body, "security_blocked") {
					t.Fatalf("unchecked terminal envelope leaked: %s", body)
				}
			})
		}
	}
}
