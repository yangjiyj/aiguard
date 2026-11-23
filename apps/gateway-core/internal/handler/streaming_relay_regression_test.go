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
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

type streamRegressionSecurity struct {
	mu          sync.Mutex
	outputCalls []string
	action      func(string) (string, []SecurityFinding)
}

func (s *streamRegressionSecurity) CheckInput(context.Context, *modelrouter.RequestEnvelope, string, int, string, string) (string, string, []SecurityFinding, error) {
	return "allow", "", nil, nil
}

func (s *streamRegressionSecurity) CheckOutput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	s.mu.Lock()
	s.outputCalls = append(s.outputCalls, content)
	s.mu.Unlock()
	if s.action == nil {
		return "allow", content, nil, nil
	}
	action, findings := s.action(content)
	return action, content, findings, nil
}

func (s *streamRegressionSecurity) CheckSemanticOnly(context.Context, *modelrouter.RequestEnvelope, string) ([]SecurityFinding, error) {
	return nil, nil
}

func (s *streamRegressionSecurity) CheckTriage(_ context.Context, _ *modelrouter.RequestEnvelope, _ string, findings []SecurityFinding) ([]SecurityFinding, error) {
	return findings, nil
}

func (s *streamRegressionSecurity) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.outputCalls...)
}

func TestTryLiveChatStreamRed_CrossDeltaOutputIsBlockedBeforeDangerousDeltaFlush(t *testing.T) {
	security := &streamRegressionSecurity{action: func(content string) (string, []SecurityFinding) {
		if strings.Contains(content, "api_key: sk-live-secret") {
			return "block", []SecurityFinding{{Type: "secret", Severity: "critical", RuleID: "secret-1"}}
		}
		return "allow", nil
	}}
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: security,
		auditWriter:    audit,
	}
	reader := &liveRelayReader{events: []relay.StreamEvent{
		{Type: relay.EventTextDelta, Index: 0, Delta: "api_key: "},
		{Type: relay.EventTextDelta, Index: 0, Delta: "sk-live-secret"},
		{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
	}}
	recorder := httptest.NewRecorder()
	tracker := &relay.CommitTracker{}
	attempted, err := h.tryLiveChatStream(context.Background(), recorder,
		&modelrouter.RequestEnvelope{RequestID: "req-cross-delta", Model: "model"},
		&liveRelayCaller{reader: reader}, []byte("{\"stream\":false}"), time.Now(), "", tracker)
	if !attempted || err == nil {
		t.Fatalf("attempted=%v err=%v; cross-delta secret must stop an enforce stream", attempted, err)
	}
	if strings.Contains(recorder.Body.String(), "sk-live-secret") {
		t.Fatalf("dangerous delta reached client: %q", recorder.Body.String())
	}
	calls := security.calls()
	if len(calls) != 1 || !strings.Contains(calls[0], "api_key: sk-live-secret") {
		t.Fatalf("output scanner did not receive coalesced complete output: %#v", calls)
	}
	if tracker.State() != relay.CommitAborted {
		t.Fatalf("tracker=%s, want aborted", tracker.State())
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].AuditResult == nil ||
		len(audit.RequestLogFinalizes[0].AuditResult.OutputFindings) != 1 {
		t.Fatalf("blocked output evidence missing from request finalization: %#v", audit.RequestLogFinalizes)
	}
}

func TestTryLiveChatStreamRed_AuditOnlyForwardsRiskAndRecordsEffectiveAudit(t *testing.T) {
	security := &streamRegressionSecurity{action: func(content string) (string, []SecurityFinding) {
		if strings.Contains(content, "token=secret") {
			return "block", []SecurityFinding{{Type: "secret", Severity: "high", RuleID: "secret-1"}}
		}
		return "allow", nil
	}}
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", SecurityAuditOnly: true},
		securityClient: security,
		auditWriter:    audit,
	}
	recorder := httptest.NewRecorder()
	tracker := &relay.CommitTracker{}
	attempted, err := h.tryLiveChatStream(context.Background(), recorder,
		&modelrouter.RequestEnvelope{RequestID: "req-audit-only", Model: "model"},
		&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
			{Type: relay.EventTextDelta, Index: 0, Delta: "token=secret"},
			{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
		}}}, []byte("{\"stream\":false}"), time.Now(), "", tracker)
	if !attempted || err != nil {
		t.Fatalf("audit-only stream must complete: attempted=%v err=%v", attempted, err)
	}
	if !strings.Contains(recorder.Body.String(), "token=secret") {
		t.Fatalf("audit-only stream did not forward raw content: %q", recorder.Body.String())
	}
	for _, event := range audit.SecurityEventWrites {
		if event.ActionTaken == "stream_blocked" || event.ActionTaken == "security_blocked" {
			t.Fatalf("audit-only risk was falsely marked blocked: %#v", audit.SecurityEventWrites)
		}
	}
	if !hasSecurityEvent(audit, "security_audit_only") {
		t.Fatalf("audit-only risk must produce an effective audit event: %#v", audit.SecurityEventWrites)
	}
}

func TestTryLiveChatStreamRed_FinalizesResponseEvidenceAndUsage(t *testing.T) {
	security := &streamRegressionSecurity{}
	audit := &MockAuditWriter{}
	metrics := relay.NewMetrics()
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: security,
		auditWriter:    audit,
		relayMetrics:   metrics,
	}
	usage := &relay.Usage{InputTokens: 11, OutputTokens: 22, CacheReadInputTokens: 7, CacheCreationInputTokens: 3}
	recorder := httptest.NewRecorder()
	tracker := &relay.CommitTracker{}
	attempted, err := h.tryLiveChatStream(context.Background(), recorder,
		&modelrouter.RequestEnvelope{RequestID: "req-finalize", Model: "model"},
		&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
			{Type: relay.EventTextDelta, Index: 0, Delta: "hello"},
			{Type: relay.EventUsageFinal, Usage: usage},
			{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop", Usage: usage},
		}}}, []byte("{\"stream\":false}"), time.Now(), "", tracker)
	if !attempted || err != nil {
		t.Fatalf("stream failed: attempted=%v err=%v", attempted, err)
	}
	if len(audit.ContentLogWrites) != 1 || audit.ContentLogWrites[0].Content != "hello" {
		t.Fatalf("response content evidence=%#v", audit.ContentLogWrites)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("request finalization=%#v", audit.RequestLogFinalizes)
	}
	var response map[string]any
	if err := json.Unmarshal(audit.RequestLogFinalizes[0].RespBody, &response); err != nil {
		t.Fatalf("final response body is not JSON: %v", err)
	}
	if response["usage"] == nil || !strings.Contains(string(audit.RequestLogFinalizes[0].RespBody), "prompt_tokens") {
		t.Fatalf("final usage missing from request log: %s", audit.RequestLogFinalizes[0].RespBody)
	}
	snapshot := metrics.Snapshot()
	if snapshot["prompt_cache_hit"] != 1 || snapshot["prompt_cache_write"] != 1 {
		t.Fatalf("cache usage metrics=%v", snapshot)
	}
}

type cancelAwareStreamReader struct {
	firstSent chan struct{}
	closed    chan struct{}
	once      sync.Once
}

func (r *cancelAwareStreamReader) Next(ctx context.Context) (relay.StreamEvent, error) {
	select {
	case <-r.firstSent:
		select {
		case <-ctx.Done():
			return relay.StreamEvent{}, ctx.Err()
		case <-time.After(time.Second):
			return relay.StreamEvent{}, errors.New("reader was not canceled")
		}
	default:
		r.once.Do(func() { close(r.firstSent) })
		return relay.StreamEvent{Type: relay.EventTextDelta, Index: 0, Delta: "first"}, nil
	}
}

func (r *cancelAwareStreamReader) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func TestTryLiveChatStreamRed_ClientCancelClosesUpstreamAndFinalizesCanceled(t *testing.T) {
	security := &streamRegressionSecurity{}
	audit := &cancelContextRecordingAuditWriter{MockAuditWriter: &MockAuditWriter{}}
	reader := &cancelAwareStreamReader{firstSent: make(chan struct{}), closed: make(chan struct{})}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: security,
		auditWriter:    audit,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-reader.firstSent
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	tracker := &relay.CommitTracker{}
	attempted, err := h.tryLiveChatStream(ctx, httptest.NewRecorder(),
		&modelrouter.RequestEnvelope{RequestID: "req-cancel", Model: "model"},
		&liveRelayCaller{reader: reader}, []byte("{\"stream\":false}"), time.Now(), "", tracker)
	if !attempted || !errors.Is(err, context.Canceled) {
		t.Fatalf("attempted=%v err=%v, want context cancellation", attempted, err)
	}
	if tracker.State() != relay.CommitNotStarted || !isLiveStreamTerminalError(err) {
		t.Fatalf("pending cancellation state=%s error=%v; no output should commit or retry", tracker.State(), err)
	}
	select {
	case <-reader.closed:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not close upstream reader")
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "client_canceled" {
		t.Fatalf("canceled request finalization=%#v", audit.RequestLogFinalizes)
	}
	if audit.securityEventContextErr != nil || !hasSecurityEvent(audit.MockAuditWriter, "stream_aborted") {
		t.Fatalf("canceled stream audit event used a canceled context or was missing: err=%v events=%#v", audit.securityEventContextErr, audit.SecurityEventWrites)
	}
}

type cancelContextRecordingAuditWriter struct {
	*MockAuditWriter
	securityEventContextErr error
}

func (w *cancelContextRecordingAuditWriter) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	w.securityEventContextErr = ctx.Err()
	w.MockAuditWriter.WriteSecurityEvent(ctx, envelope, findings, actionTaken, summary)
}

func TestTryLiveChatStreamRed_SplitToolArgumentsAreGuardedBeforeFlush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{\"data\":{\"id\":\"policy-1\",\"name\":\"strict\",\"policy_version\":\"v1\",\"mode\":\"strict\",\"default_action\":\"allow\",\"fail_policy\":\"fail_closed\",\"confirm_channel_enabled\":true,\"rules\":[],\"exceptions\":[],\"destructive\":{\"mode\":\"strict\",\"action\":\"block\",\"scope_type\":\"tenant\",\"scope_ref\":\"\",\"protocol\":\"\"},\"config_source\":\"tenant_policy\"}}")
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	toolRisk := NewToolRiskClient(server.URL, "internal-secret")
	toolRisk.runtimeCache.setSecurityAuditOnly(false)
	toolRisk.runtimeCache.setSemanticAgentEnabled(false)
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: &streamRegressionSecurity{},
		auditWriter:    audit,
		toolRiskClient: toolRisk,
	}
	recorder := httptest.NewRecorder()
	tracker := &relay.CommitTracker{}
	attempted, err := h.tryLiveChatStream(context.Background(), recorder,
		&modelrouter.RequestEnvelope{RequestID: "req-tool-fragments", TenantID: "tenant-1", UserID: "user-1", Model: "model"},
		&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
			{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: "call-1", Name: "shell_command", Index: 0}},
			{Type: relay.EventToolArgumentsDelta, Index: 0, Delta: "{\"command\":\"rm ", ToolCall: &relay.ToolCall{ID: "call-1", Index: 0}},
			{Type: relay.EventToolArgumentsDelta, Index: 0, Delta: "-rf /tmp/jjdguard-live-victim\"}", ToolCall: &relay.ToolCall{ID: "call-1", Index: 0}},
			{Type: relay.EventMessageEnd, Index: 0, FinishReason: "tool_calls"},
		}}}, []byte("{\"stream\":false}"), time.Now(), "", tracker)
	if !attempted || err != nil {
		t.Fatalf("tool stream failed: attempted=%v err=%v", attempted, err)
	}
	if strings.Contains(recorder.Body.String(), "rm -rf") || strings.Contains(recorder.Body.String(), "jdguard-live-victim") {
		t.Fatalf("dangerous tool arguments reached client before AgentGuard decision: %q", recorder.Body.String())
	}
	// action_taken 现记录真实处置动作（block/confirm/audit/alert），不再承载事件类型字符串。
	if !hasSecurityEvent(audit, "block") && !hasSecurityEvent(audit, "audit") && !hasSecurityEvent(audit, "alert") {
		t.Fatalf("missing AgentGuard evidence for split tool call: %#v", audit.SecurityEventWrites)
	}
}

func TestTryLiveChatStreamProviderWithoutStreamAdapterFallsBackToBuffered(t *testing.T) {
	h := &ChatCompletionsHandler{cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}}
	attempted, err := h.tryLiveChatStream(context.Background(), httptest.NewRecorder(),
		&modelrouter.RequestEnvelope{RequestID: "req-no-adapter", Model: "model"},
		&MockProviderCaller{}, []byte("{}"), time.Now(), "", &relay.CommitTracker{})
	if err != nil || attempted {
		t.Fatalf("provider without StreamAdapter must use buffered fallback: attempted=%v err=%v", attempted, err)
	}
	if _, ok := interface{}(&MockProviderCaller{}).(provider.StreamAdapter); ok {
		t.Fatal("test provider unexpectedly implements StreamAdapter")
	}
}

func TestTryLiveChatStreamOutputScanBoundaryIsExplicitAndAudited(t *testing.T) {
	largeDelta := strings.Repeat("x", maxLiveOutputAuditBytes+1)
	for _, test := range []struct {
		name       string
		mode       string
		failure    string
		wantError  bool
		wantStatus string
	}{
		// An output larger than the live audit budget is an inspection gap: it is
		// recorded and the stream continues even when fail-close is configured.
		{name: "enforce records and continues", mode: "stream_enforce", failure: "close", wantError: false, wantStatus: "success"},
		{name: "audit continues", mode: "stream_audit", failure: "close", wantError: false, wantStatus: "success"},
	} {
		t.Run(test.name, func(t *testing.T) {
			audit := &MockAuditWriter{}
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: test.mode, GuardrailFailureMode: test.failure},
				securityClient: &streamRegressionSecurity{},
				auditWriter:    audit,
			}
			tracker := &relay.CommitTracker{}
			_, err := h.tryLiveChatStream(context.Background(), httptest.NewRecorder(),
				&modelrouter.RequestEnvelope{RequestID: "req-boundary-" + test.name, Model: "model"},
				&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
					{Type: relay.EventTextDelta, Index: 0, Delta: largeDelta},
					{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
				}}}, []byte("{}"), time.Now(), "", tracker)
			if (err != nil) != test.wantError {
				t.Fatalf("err=%v, wantError=%v", err, test.wantError)
			}
			if !hasSecurityEvent(audit, "output_scan_incomplete") {
				t.Fatalf("missing output_scan_incomplete event: %#v", audit.SecurityEventWrites)
			}
			if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != test.wantStatus {
				t.Fatalf("final status=%#v, want %q", audit.RequestLogFinalizes, test.wantStatus)
			}
		})
	}
}

type observedStreamResponseWriter struct {
	header    http.Header
	status    int
	body      bytes.Buffer
	helloSeen chan struct{}
	once      sync.Once
}

func (w *observedStreamResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *observedStreamResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *observedStreamResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if bytes.Contains(body, []byte("\"content\":\"hello\"")) {
		w.once.Do(func() { close(w.helloSeen) })
	}
	return w.body.Write(body)
}

func (w *observedStreamResponseWriter) Flush() {}

func TestChatHandlerLiveTTFTWritesDeltaBeforeUpstreamTerminal(t *testing.T) {
	contentForwarded := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		if request["prompt_cache_key"] != "client-cache" {
			t.Fatalf("prompt_cache_key was dropped before upstream: %v", request["prompt_cache_key"])
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"chat-live\",\"model\":\"gpt-live\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"id\":\"chat-live\",\"model\":\"gpt-live\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"}}]}\n\n")
		flusher.Flush()
		select {
		case <-contentForwarded:
		case <-time.After(time.Second):
			return
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"chat-live\",\"model\":\"gpt-live\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	resolver := &MockModelResolver{
		ProviderAPIKey: "provider-key",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-live", ProviderID: "provider-live", ModelName: "gpt-live",
			UpstreamModelID: "gpt-live", ProviderType: "openai",
			ProviderBaseURL: upstream.URL, Status: "active",
		},
	}
	audit := &MockAuditWriter{}
	handler := NewChatCompletionsHandler(
		&config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"},
		resolver, &MockRateLimitChecker{}, &streamRegressionSecurity{}, audit, nil, nil, nil,
	)
	writer := &observedStreamResponseWriter{helloSeen: contentForwarded}
	requestBody := []byte("{\"model\":\"gpt-live\",\"messages\":[{\"role\":\"user\",\"content\":\"inspect\"}],\"stream\":true,\"prompt_cache_key\":\"client-cache\"}")
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(requestBody))
	request = request.WithContext(setAuthInfo(request.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123"))
	done := make(chan struct{})
	go func() {
		handler.Handler().ServeHTTP(writer, request)
		close(done)
	}()
	select {
	case <-contentForwarded:
	case <-time.After(2 * time.Second):
		t.Fatal("first text SSE delta was not forwarded before upstream terminal")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("live handler did not finish after terminal upstream event")
	}
	if writer.status != http.StatusOK || !bytes.Contains(writer.body.Bytes(), []byte("\"content\":\"hello\"")) {
		t.Fatalf("status=%d body=%s", writer.status, writer.body.Bytes())
	}
}
