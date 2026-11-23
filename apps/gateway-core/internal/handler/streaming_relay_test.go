package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

type liveRelayCaller struct {
	reader relay.StreamReader
}

func (c *liveRelayCaller) TransformRequest(_ *modelrouter.RequestEnvelope, raw []byte) ([]byte, error) {
	return raw, nil
}

func (c *liveRelayCaller) Call(context.Context, *modelrouter.RequestEnvelope, []byte) ([]byte, error) {
	return nil, io.EOF
}

func (c *liveRelayCaller) CallStreaming(context.Context, *modelrouter.RequestEnvelope, []byte) ([]byte, error) {
	return nil, io.EOF
}

func (c *liveRelayCaller) TransformResponse(body []byte) ([]byte, error) {
	return body, nil
}

func (c *liveRelayCaller) OpenStream(context.Context, *modelrouter.RequestEnvelope, []byte) (relay.StreamReader, provider.StreamResponseMeta, error) {
	return c.reader, provider.StreamResponseMeta{StatusCode: 200}, nil
}

type liveRelayReader struct {
	events []relay.StreamEvent
	index  int
	err    error
}

func (r *liveRelayReader) Next(ctx context.Context) (relay.StreamEvent, error) {
	select {
	case <-ctx.Done():
		return relay.StreamEvent{}, ctx.Err()
	default:
	}
	if r.index >= len(r.events) {
		if r.err != nil {
			return relay.StreamEvent{}, r.err
		}
		return relay.StreamEvent{}, io.EOF
	}
	event := r.events[r.index]
	r.index++
	return event, nil
}

func (r *liveRelayReader) Close() error { return nil }

func TestTryLiveChatStreamCoalescesSmallDeltasUntilFinalCheck(t *testing.T) {
	security := &MockSecurityChecker{}
	audit := &MockAuditWriter{}
	metrics := relay.NewMetrics()
	caller := &liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
		{Type: relay.EventTextDelta, Delta: "first"},
		{Type: relay.EventTextDelta, Delta: "second"},
		{Type: relay.EventMessageEnd, FinishReason: "stop"},
	}}}
	handler := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: security,
		auditWriter:    audit,
		relayMetrics:   metrics,
	}
	recorder := httptest.NewRecorder()
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", Model: "public-model", RequestStartedAt: time.Now()}
	tracker := &relay.CommitTracker{}
	attempted, err := handler.tryLiveChatStream(context.Background(), recorder, envelope, caller, []byte("{}"), time.Now(), "", tracker)
	if err != nil || !attempted || tracker.State() != relay.CommitCompleted {
		t.Fatalf("attempted=%v state=%s err=%v", attempted, tracker.State(), err)
	}
	body := recorder.Body.String()
	if strings.Count(body, "data:") != 3 {
		t.Fatalf("body=%q; want merged delta, finish and DONE", body)
	}
	if !strings.Contains(body, "first") || !strings.Contains(body, "second") {
		t.Fatalf("body=%q; deltas were not forwarded", body)
	}
	if len(security.OutputCheckCalls) != 1 {
		t.Fatalf("small response final security calls=%d; want 1", len(security.OutputCheckCalls))
	}
	assertRequestTimingPersisted(t, envelope, audit.RequestLogFinalizes[0].AuditResult, "output_security_ms", "pre_upstream_ms")
	snapshot := metrics.Snapshot()
	if snapshot["stream_events"] != 3 || snapshot["active_streams"] != 0 {
		t.Fatalf("stream metrics=%v", snapshot)
	}
}

func TestTryLiveChatStreamReconcilesResponsesToolArgumentSnapshot(t *testing.T) {
	const arguments = `{"skill":"deploy-jjdguard-upgrade-run"}`
	tests := []struct {
		name   string
		events []relay.StreamEvent
	}{
		{
			name: "streamed deltas suppress final snapshot",
			events: []relay.StreamEvent{
				{Type: relay.EventToolArgumentsDelta, Index: 0, Delta: `{"skill":"`, ToolCall: &relay.ToolCall{ID: "call-1", Index: 0}},
				{Type: relay.EventToolArgumentsDelta, Index: 0, Delta: `deploy-jjdguard-upgrade-run"}`, ToolCall: &relay.ToolCall{ID: "call-1", Index: 0}},
				{Type: relay.EventToolArgumentsDone, Index: 0, Delta: arguments, ToolCall: &relay.ToolCall{ID: "call-1", Index: 0}},
			},
		},
		{
			name: "done only supplies the compatibility snapshot",
			events: []relay.StreamEvent{
				{Type: relay.EventToolArgumentsDone, Index: 0, Delta: arguments, ToolCall: &relay.ToolCall{ID: "call-1", Index: 0}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			audit := &MockAuditWriter{}
			events := []relay.StreamEvent{
				{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: "call-1", Name: "Skill", Index: 0}},
			}
			events = append(events, tc.events...)
			events = append(events, relay.StreamEvent{Type: relay.EventMessageEnd, Index: 0, FinishReason: "tool_calls"})
			handler := &ChatCompletionsHandler{
				cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", SecurityAuditOnly: true},
				securityClient: &MockSecurityChecker{},
				auditWriter:    audit,
			}
			recorder := httptest.NewRecorder()
			tracker := &relay.CommitTracker{}
			attempted, err := handler.tryLiveChatStream(
				context.Background(), recorder,
				&modelrouter.RequestEnvelope{RequestID: "req-tool-snapshot", Model: "public-model"},
				&liveRelayCaller{reader: &liveRelayReader{events: events}}, []byte("{}"), time.Now(), "", tracker,
			)
			if err != nil || !attempted || tracker.State() != relay.CommitCompleted {
				t.Fatalf("attempted=%v state=%s err=%v", attempted, tracker.State(), err)
			}

			body := recorder.Body.String()
			if got := strings.Count(body, "deploy-jjdguard-upgrade-run"); got != 1 {
				t.Fatalf("tool arguments appeared %d times; want once: %q", got, body)
			}
			nameAt := strings.Index(body, `"name":"Skill"`)
			argumentsAt := strings.Index(body, "deploy-jjdguard-upgrade-run")
			if nameAt < 0 || argumentsAt < nameAt {
				t.Fatalf("tool arguments were emitted before the tool start: %q", body)
			}
			if len(audit.RequestLogFinalizes) != 1 {
				t.Fatalf("audit finalizations=%d, want 1", len(audit.RequestLogFinalizes))
			}
			var final ChatCompletionResponse
			if err := json.Unmarshal(audit.RequestLogFinalizes[0].RespBody, &final); err != nil {
				t.Fatal(err)
			}
			if len(final.Choices) != 1 || len(final.Choices[0].Message.ToolCalls) != 1 ||
				final.Choices[0].Message.ToolCalls[0].Function.Arguments != arguments {
				t.Fatalf("final audit response lost tool arguments: %s", audit.RequestLogFinalizes[0].RespBody)
			}
		})
	}
}

func TestTryLiveChatStreamTracksDoneAsFirstWrite(t *testing.T) {
	handler := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: &MockSecurityChecker{},
		auditWriter:    &MockAuditWriter{},
	}
	tracker := &relay.CommitTracker{}
	recorder := httptest.NewRecorder()
	attempted, err := handler.tryLiveChatStream(
		context.Background(), recorder,
		&modelrouter.RequestEnvelope{RequestID: "req-done", Model: "public-model"},
		&liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
			{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
		}}}, []byte("{}"), time.Now(), "", tracker,
	)
	if err != nil || !attempted || tracker.State() != relay.CommitCompleted {
		t.Fatalf("attempted=%v state=%s err=%v", attempted, tracker.State(), err)
	}
	if !strings.Contains(recorder.Body.String(), "finish_reason") || !strings.Contains(recorder.Body.String(), "data: [DONE]\n\n") {
		t.Fatalf("body=%q", recorder.Body.String())
	}
}

func TestTryLiveChatStreamAbortsAfterFirstEvent(t *testing.T) {
	handler := &ChatCompletionsHandler{
		cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
		securityClient: &MockSecurityChecker{},
		auditWriter:    &MockAuditWriter{},
	}
	tracker := &relay.CommitTracker{}
	recorder := httptest.NewRecorder()
	attempted, err := handler.tryLiveChatStream(
		context.Background(), recorder,
		&modelrouter.RequestEnvelope{RequestID: "req-abort", Model: "public-model"},
		&liveRelayCaller{reader: &liveRelayReader{
			events: []relay.StreamEvent{{Type: relay.EventTextDelta, Delta: "partial" + strings.Repeat("x", defaultLiveScanBatchBytes)}},
			err:    io.ErrUnexpectedEOF,
		}}, []byte("{}"), time.Now(), "", tracker,
	)
	if !attempted || !errors.Is(err, io.ErrUnexpectedEOF) || tracker.State() != relay.CommitAborted {
		t.Fatalf("attempted=%v state=%s err=%v", attempted, tracker.State(), err)
	}
	if !strings.Contains(recorder.Body.String(), "partial") || !strings.Contains(recorder.Body.String(), "stream_aborted") {
		t.Fatalf("body=%q", recorder.Body.String())
	}
}

func TestTryLiveChatStreamExecutionMatrix(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		caller    ProviderCaller
		attempted bool
	}{
		{name: "upstream streaming disabled", cfg: &config.Config{OutputSecurityMode: "stream_enforce"}, caller: &liveRelayCaller{reader: &liveRelayReader{}}},
		{name: "strict buffered", cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "strict_buffered"}, caller: &liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{{Type: relay.EventMessageEnd, FinishReason: "stop"}}}}, attempted: true},
		{name: "stream enforce", cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, caller: &liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"}}}}, attempted: true},
		{name: "stream audit", cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"}, caller: &liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"}}}}, attempted: true},
		{name: "caller without stream adapter", cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, caller: &MockProviderCaller{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &ChatCompletionsHandler{cfg: tt.cfg, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{}}
			tracker := &relay.CommitTracker{}
			recorder := httptest.NewRecorder()
			attempted, err := handler.tryLiveChatStream(context.Background(), recorder,
				&modelrouter.RequestEnvelope{RequestID: "req-matrix", Model: "public-model"},
				tt.caller, []byte("{}"), time.Now(), "", tracker)
			if err != nil || attempted != tt.attempted {
				t.Fatalf("attempted=%v want=%v err=%v", attempted, tt.attempted, err)
			}
			if tt.attempted && tracker.State() != relay.CommitCompleted {
				t.Fatalf("live state=%s", tracker.State())
			}
			if !tt.attempted && tracker.State() != relay.CommitNotStarted {
				t.Fatalf("buffered state=%s", tracker.State())
			}
		})
	}
}

func TestDefaultProviderFactoryConsumesConfiguredStreamIdleTimeout(t *testing.T) {
	timeout := 73 * time.Second
	handler := NewChatCompletionsHandler(
		&config.Config{UpstreamStreamIdleTimeout: timeout},
		&MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, nil, nil, nil,
	)
	factory, ok := handler.providerAdapterFactory.(*RealProviderAdapterFactory)
	if !ok || factory.StreamIdleTimeout != timeout {
		t.Fatalf("factory=%T timeout=%v", handler.providerAdapterFactory, factory.StreamIdleTimeout)
	}
	caller := factory.CreateAdapter(&modelrouter.ModelRecord{ProviderType: "openai"}, "synthetic-key")
	adapter, ok := caller.(*provider.OpenAIAdapter)
	if !ok || adapter.StreamIdleTimeout != timeout {
		t.Fatalf("adapter=%T timeout=%v", caller, adapter.StreamIdleTimeout)
	}
}
