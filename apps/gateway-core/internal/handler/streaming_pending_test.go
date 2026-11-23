package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// Exercise the registered HTTP handler and capture actual client bytes, rather
// than only asserting what the incremental checker was called with.
func TestHTTPStreamPendingTailPreventsSplitSecretPrefix(t *testing.T) {
	for _, tc := range []struct {
		name           string
		fragments      []map[string]any
		secret, prefix string
	}{
		{"key", []map[string]any{{"content": "key=sk-live-"}, {"content": "secret-123"}}, "key=sk-live-secret-123", "sk-live-"},
		{"phone", []map[string]any{{"content": "phone=138"}, {"content": "00138000"}}, "phone=13800138000", "phone=138"},
		{"reasoning interleave", []map[string]any{{"reasoning_content": "key=sk-live-"}, {"content": "normal answer"}, {"reasoning_content": "secret-123"}}, "key=sk-live-secret-123", "sk-live-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				for _, delta := range tc.fragments {
					raw, _ := json.Marshal(map[string]any{"id": "pending", "model": "test", "choices": []any{map[string]any{"index": 0, "delta": delta}}})
					_, _ = io.WriteString(w, "data: "+string(raw)+"\n\n")
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
			}))
			defer upstream.Close()
			security := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
				if strings.Contains(s, tc.secret) {
					return "block", []SecurityFinding{{Type: "secret", RuleID: "split"}}
				}
				return "allow", nil
			}}
			handler := newPendingHTTPHandler(upstream.URL, &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, security)
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(setAuthInfo(r.Context(), "tenant", "project", "user", "key", "session"))
				handler.Handler().ServeHTTP(w, r)
			}))
			defer gateway.Close()
			resp, err := http.Post(gateway.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"inspect"}],"stream":true}`))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte(tc.prefix)) {
				t.Fatalf("unapproved prefix reached real HTTP client: %s", body)
			}
			if !bytes.Contains(body, []byte("security_blocked")) {
				t.Fatalf("missing security failure: %s", body)
			}
		})
	}
}

func newPendingHTTPHandler(url string, cfg *config.Config, security SecurityChecker) *ChatCompletionsHandler {
	return NewChatCompletionsHandler(cfg, &MockModelResolver{ProviderAPIKey: "fixture-key", ModelRecord: &modelrouter.ModelRecord{
		ID: "model-test", ProviderID: "provider-test", ModelName: "test", UpstreamModelID: "test", ProviderType: "openai", ProviderBaseURL: url, Status: "active",
	}}, &MockRateLimitChecker{}, security, &MockAuditWriter{}, nil, nil, nil)
}

func TestLiveTailAlwaysPreservesUTF8(t *testing.T) {
	if got := appendLiveTail("你好世界", 4); !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8 tail %q", got)
	}
}

type pendingMaskSecurity struct{ streamRegressionSecurity }

func (s *pendingMaskSecurity) CheckOutput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	if strings.Contains(content, "secret-123") {
		return "mask", strings.ReplaceAll(content, "secret-123", "[redacted]"), nil, nil
	}
	return "allow", content, nil, nil
}

func TestHTTPStreamFinalFlushAndStrictBudget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      *config.Config
		content  string
		security SecurityChecker
		want     string
		blocked  bool
	}{
		{"utf8 oversized delta", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, strings.Repeat("你好世界", 6000), &streamRegressionSecurity{}, "", false},
		{"final mask", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, "secret-123", &pendingMaskSecurity{}, "[redacted]", false},
		{"strict over budget", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "strict_buffered", OutputStrictMaxBytes: 1024}, strings.Repeat("confidential", 200), &streamRegressionSecurity{}, "", true},
		{"strict block", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "strict_buffered"}, "secret-123", &streamRegressionSecurity{action: func(string) (string, []SecurityFinding) { return "block", nil }}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				frame, _ := json.Marshal(map[string]any{"id": "final", "model": "test", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": tc.content}}}})
				_, _ = io.WriteString(w, "data: "+string(frame)+"\n\n")
				_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":11,\"total_tokens\":18}}\n\ndata: [DONE]\n\n")
			}))
			defer upstream.Close()
			h := newPendingHTTPHandler(upstream.URL, tc.cfg, tc.security)
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(setAuthInfo(r.Context(), "tenant", "project", "user", "key", "session"))
				h.Handler().ServeHTTP(w, r)
			}))
			defer gateway.Close()
			resp, err := http.Post(gateway.URL, "application/json", strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"inspect"}],"stream":true}`))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if tc.blocked {
				if bytes.Contains(body, []byte(tc.content[:10])) {
					t.Fatalf("strict output leaked: %.300s", body)
				}
				if !bytes.Contains(body, []byte("security_blocked")) {
					t.Fatalf("missing strict failure: %s", body)
				}
				return
			}
			got := ""
			for _, line := range strings.Split(string(body), "\n") {
				if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
					continue
				}
				var frame struct {
					Choices []struct {
						Delta struct {
							Content string `json:"content"`
						} `json:"delta"`
					} `json:"choices"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &frame); err != nil {
					t.Fatal(err)
				}
				for _, choice := range frame.Choices {
					if !utf8.ValidString(choice.Delta.Content) {
						t.Fatal("invalid client UTF-8")
					}
					got += choice.Delta.Content
				}
			}
			want := tc.want
			if want == "" {
				want = tc.content
			}
			if got != want {
				t.Fatalf("client content differs: got %d bytes, want %d", len(got), len(want))
			}
			if strings.Count(string(body), "data: [DONE]") != 1 || !bytes.Contains(body, []byte(`"completion_tokens":11`)) {
				t.Fatalf("missing terminal or usage: %.300s", body)
			}
		})
	}
}

func TestStreamToolArgumentsDLPBeforeClientFlush(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		security := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
			if strings.Contains(s, "secret-123") {
				return "block", []SecurityFinding{{Type: "secret", RuleID: "tool-secret"}}
			}
			return "allow", nil
		}}
		h := &ChatCompletionsHandler{cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", SecurityAuditOnly: auditOnly}, securityClient: security, auditWriter: &MockAuditWriter{}}
		rec := httptest.NewRecorder()
		_, err := h.tryLiveChatStream(context.Background(), rec, &modelrouter.RequestEnvelope{RequestID: "tool-dlp", Model: "test"},
			&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
				{Type: relay.EventToolCallStart, ToolCall: &relay.ToolCall{ID: "call", Name: "lookup", Index: 0, Arguments: `{"key":"`}},
				{Type: relay.EventToolArgumentsDelta, ToolCall: &relay.ToolCall{ID: "call", Index: 0}, Delta: `secret-123"}`},
				{Type: relay.EventMessageEnd, FinishReason: "tool_calls"},
			}}}, []byte("{}"), time.Now(), "", &relay.CommitTracker{})
		if auditOnly {
			if err != nil || strings.Count(rec.Body.String(), "secret-123") != 1 {
				t.Fatalf("audit tool output: err=%v body=%s", err, rec.Body.String())
			}
		} else if err == nil || strings.Contains(rec.Body.String(), "secret-123") {
			t.Fatalf("tool DLP failed: err=%v body=%s", err, rec.Body.String())
		}
	}
}

func TestPendingChannelSwitchKeepsSecretPrefixAndOrder(t *testing.T) {
	h := &ChatCompletionsHandler{cfg: &config.Config{OutputStreamHoldbackBytes: 8, OutputStreamScanBatchBytes: 8}}
	p := newLivePendingOutput(h, effectiveOutputSecurityMode(h.toolRiskClient, h.cfg))
	var emitted []relay.StreamEvent
	check := func(s string, _ int) (bool, error) {
		if strings.Contains(s, "secret123") {
			return false, errors.New("detected")
		}
		return false, nil
	}
	write := func(e relay.StreamEvent) error { emitted = append(emitted, e); return nil }
	incomplete := func(string) error { return errLivePendingLimit }
	events := []relay.StreamEvent{
		{Type: relay.EventTextDelta, Index: 0, Delta: "secret"},
		{Type: relay.EventTextDelta, Index: 1, Delta: strings.Repeat("other", 10)},
		{Type: relay.EventReasoningDelta, Index: 0, Delta: "reason"},
		{Type: relay.EventTextDelta, Index: 0, Delta: "123xxxx"},
	}
	var gotErr error
	for _, event := range events {
		if gotErr = p.add(context.Background(), event, check, write, incomplete); gotErr != nil {
			break
		}
	}
	if gotErr == nil {
		t.Fatal("cross-choice secret not detected")
	}
	for _, event := range emitted {
		if strings.Contains(event.Delta, "secret") {
			t.Fatalf("channel switch released secret prefix: %v", emitted)
		}
	}
}

func TestPendingOutputBudgetAndCancellationNeverFlushUnapprovedTail(t *testing.T) {
	h := &ChatCompletionsHandler{cfg: &config.Config{OutputStreamHoldbackBytes: 8, OutputStreamScanBatchBytes: 8, OutputStreamPendingBytes: 16}}
	p := newLivePendingOutput(h, effectiveOutputSecurityMode(h.toolRiskClient, h.cfg))
	written := 0
	write := func(e relay.StreamEvent) error { written += len(e.Delta); return nil }
	check := func(string, int) (bool, error) { return false, nil }
	incomplete := func(string) error { return errLivePendingLimit }
	if err := p.add(context.Background(), relay.StreamEvent{Type: relay.EventReasoningDelta, Delta: "held"}, check, write, incomplete); err != nil {
		t.Fatal(err)
	}
	err := p.add(context.Background(), relay.StreamEvent{Type: relay.EventTextDelta, Delta: strings.Repeat("x", 24)}, check, write, incomplete)
	if !errors.Is(err, errLivePendingLimit) || written != 0 {
		t.Fatalf("budget err=%v written=%d", err, written)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.drain(ctx, true, write); !errors.Is(err, context.Canceled) || written != 0 {
		t.Fatalf("canceled flush err=%v written=%d", err, written)
	}
}

type pendingGateSecurity struct {
	streamRegressionSecurity
	started chan struct{}
	release chan struct{}
}

func (s *pendingGateSecurity) CheckOutput(ctx context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	close(s.started)
	select {
	case <-s.release:
		return "allow", content, nil, nil
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	}
}
func TestHTTPStrictWritesNothingUntilCompleteOutputCheck(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"gate\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"held answer\"}}]}\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	security := &pendingGateSecurity{started: make(chan struct{}), release: make(chan struct{})}
	h := newPendingHTTPHandler(upstream.URL, &config.Config{UpstreamStreaming: true, OutputSecurityMode: "strict_buffered"}, security)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(setAuthInfo(r.Context(), "tenant", "project", "user", "key", "session"))
		h.Handler().ServeHTTP(w, r)
	}))
	defer gateway.Close()
	released := false
	defer func() {
		if !released {
			close(security.release)
		}
	}()
	type result struct {
		body []byte
		err  error
	}
	resultCh := make(chan result, 1)
	headersCh := make(chan struct{}, 1)
	go func() {
		resp, err := http.Post(gateway.URL, "application/json", strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"inspect"}],"stream":true}`))
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		headersCh <- struct{}{}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		resultCh <- result{body: body, err: err}
	}()
	select {
	case <-security.started:
	case <-time.After(2 * time.Second):
		t.Fatal("complete output check not reached")
	}
	select {
	case <-headersCh:
		t.Fatal("strict mode committed even headers before complete check")
	case <-time.After(25 * time.Millisecond):
	}
	close(security.release)
	released = true
	select {
	case got := <-resultCh:
		if got.err != nil || !bytes.Contains(got.body, []byte("held answer")) || !bytes.Contains(got.body, []byte("[DONE]")) {
			t.Fatalf("strict completion err=%v body=%s", got.err, got.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("strict response did not finish")
	}
}

func TestPendingDrainHonorsBackpressure(t *testing.T) {
	p := newLivePendingOutput(&ChatCompletionsHandler{cfg: &config.Config{OutputStreamHoldbackBytes: 4, OutputStreamScanBatchBytes: 8}}, relay.OutputSecurityStreamEnforce)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	writes := 0
	go func() {
		done <- p.add(context.Background(), relay.StreamEvent{Type: relay.EventTextDelta, Delta: strings.Repeat("a", 64)},
			func(string, int) (bool, error) { return false, nil },
			func(relay.StreamEvent) error {
				writes++
				if writes == 1 {
					close(started)
					<-release
				}
				return nil
			},
			func(string) error { return errLivePendingLimit })
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("buffer advanced past blocked client write: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type pendingTextFailureSecurity struct {
	streamRegressionSecurity
	audit bool
}

func (s *pendingTextFailureSecurity) CheckOutput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	s.outputCalls = append(s.outputCalls, content)
	if content == "ordinary text" && !s.audit {
		return "", "", nil, errors.New("text checker timeout")
	}
	return "block", content, []SecurityFinding{{Type: "secret", RuleID: "tool-dlp"}}, nil
}
func TestOutputTextFailureOrAuditDoesNotSkipToolDLP(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		checker := &pendingTextFailureSecurity{audit: auditOnly}
		h := &ChatCompletionsHandler{cfg: &config.Config{OutputSecurityMode: "stream_enforce", GuardrailFailureMode: "open", SecurityAuditOnly: auditOnly}, securityClient: checker, auditWriter: &MockAuditWriter{}}
		body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"ordinary text","tool_calls":[{"id":"call","type":"function","function":{"name":"lookup","arguments":"{\"key\":\"secret-123\"}"}}]},"finish_reason":"tool_calls"}]}`)
		_, audit, err := h.applyOutputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "text-error-tool"}, nil, body)
		if len(checker.outputCalls) != 2 {
			t.Fatalf("tool DLP skipped after text result: calls=%v", checker.outputCalls)
		}
		if auditOnly {
			if err != nil || audit.OutputAction != "audit" {
				t.Fatalf("audit-only changed: err=%v audit=%+v", err, audit)
			}
		} else if err == nil || audit.OutputAction != "block" {
			t.Fatalf("tool secret allowed after text fail-open: err=%v audit=%+v", err, audit)
		}
	}
}

// A mask that overflows the pending budget cannot be applied. The configured
// action is "mask", not "block": the original is released and flagged so the
// stream owner raises an alert.
func TestPendingOverflowReleasesUnresolvedMaskWithAlertFlag(t *testing.T) {
	p := newLivePendingOutput(&ChatCompletionsHandler{cfg: &config.Config{OutputStreamHoldbackBytes: 4, OutputStreamScanBatchBytes: 8, OutputStreamPendingBytes: 16}}, relay.OutputSecurityStreamEnforce)
	output := ""
	write := func(e relay.StreamEvent) error { output += e.Delta; return nil }
	check := func(s string, _ int) (bool, error) { return strings.Contains(s, "secret"), nil }
	incomplete := func(string) error { return nil }
	err := p.add(context.Background(), relay.StreamEvent{Type: relay.EventTextDelta, Delta: "secret12" + strings.Repeat("x", 32)}, check, write, incomplete)
	if err != nil || !strings.Contains(output, "secret") || !p.maskUnavailable {
		t.Fatalf("unresolved mask must be released and flagged: err=%v output=%q flagged=%t", err, output, p.maskUnavailable)
	}
}

type pendingFinalFailureSecurity struct{ streamRegressionSecurity }

func (s *pendingFinalFailureSecurity) CheckOutput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	if len(content) > 20 {
		return "", "", nil, errors.New("final checker unavailable")
	}
	return "mask", strings.ReplaceAll(content, "secret", "[mask]"), nil, nil
}
func TestPendingFinalFailureReleasesUnresolvedMaskWithAlert(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", GuardrailFailureMode: "open", OutputStreamScanBatchBytes: 8}, securityClient: &pendingFinalFailureSecurity{}, auditWriter: audit}
	rec := httptest.NewRecorder()
	_, err := h.tryLiveChatStream(context.Background(), rec, &modelrouter.RequestEnvelope{RequestID: "mask-final", Model: "test"},
		&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{{Type: relay.EventTextDelta, Delta: "secret12" + strings.Repeat("x", 32)}, {Type: relay.EventMessageEnd, FinishReason: "stop"}}}},
		[]byte("{}"), time.Now(), "", &relay.CommitTracker{})
	if err != nil || !strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("unresolved mask must be released, not blocked: err=%v output=%q", err, rec.Body.String())
	}
	alerted := false
	for _, event := range audit.SecurityEventWrites {
		alerted = alerted || (event.ActionTaken == "security_audit" && event.MaskUnavailable)
	}
	if !alerted {
		t.Fatalf("mask-unavailable alert missing: %+v", audit.SecurityEventWrites)
	}
}
