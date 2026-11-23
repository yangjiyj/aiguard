package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

type streamBudgetControlPlane struct {
	mu          sync.Mutex
	cap         *int64
	measurement map[string]any
}

func (s *streamBudgetControlPlane) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/v1/billing/quotes":
			response := map[string]any{"billable_amount_micros": 100, "price_id": "price-1", "admitted_at": time.Now().UTC()}
			if s.cap != nil {
				response["stream_output_token_cap"] = *s.cap
			}
			_ = json.NewEncoder(w).Encode(response)
		case "/internal/v1/billing/measurements":
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			s.mu.Lock()
			s.measurement = payload
			s.mu.Unlock()
			_, _ = w.Write([]byte(`{"recorded":true,"billable_amount_micros":7}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *streamBudgetControlPlane) settled() (map[string]any, any, any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	usage, _ := s.measurement["usage"].(map[string]any)
	raw, _ := s.measurement["raw_usage"].(map[string]any)
	var source any
	if raw != nil {
		source = raw["usage_source"]
	}
	return usage, s.measurement["request_status"], source
}

// longStreamEvents 模拟不遵守输出上限的上游：持续产出，最后给出权威 usage。
func longStreamEvents(n int) []relay.StreamEvent {
	events := make([]relay.StreamEvent, 0, n+1)
	for i := 0; i < n; i++ {
		events = append(events, relay.StreamEvent{Type: relay.EventTextDelta, Delta: "hello world "})
	}
	return append(events, relay.StreamEvent{Type: relay.EventMessageEnd, FinishReason: "stop",
		Usage: &relay.Usage{InputTokens: 9, OutputTokens: int64(n * 3)}})
}

func runBudgetStream(t *testing.T, mode string, cap *int64, reader relay.StreamReader) (string, *streamBudgetControlPlane, *MockAuditWriter) {
	t.Helper()
	cp := &streamBudgetControlPlane{cap: cap}
	server := cp.server(t)
	client := NewBillingClientWithMode(server.URL, "internal-secret", "", "metering")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-budget", TenantID: "t", UserID: "u", Model: "m"}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 9, OutputTokens: 4096}); err != nil {
		t.Fatal(err)
	}
	inner := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{
		cfg:              &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode},
		securityClient:   &MockSecurityChecker{},
		auditWriter:      NewBillingAuditWriter(inner, client),
		billingPreflight: client,
	}
	recorder := httptest.NewRecorder()
	tracker := &relay.CommitTracker{}
	attempted, err := handler.tryLiveChatStream(context.Background(), recorder, envelope, &liveRelayCaller{reader: reader}, []byte("{}"), time.Now(), "", tracker)
	if err != nil || !attempted || tracker.State() != relay.CommitCompleted {
		t.Fatalf("attempted=%v state=%s err=%v", attempted, tracker.State(), err)
	}
	return recorder.Body.String(), cp, inner
}

// 兜底：上游不遵守输出上限时网关停止转发（finish_reason=length + 中文说明 + [DONE]），
// 但继续读上游到结束事件，按上游权威 usage 结算，不用本地估算。
func TestLiveChatStreamFallbackTruncatesAndSettlesUpstreamUsage(t *testing.T) {
	for _, mode := range []string{"stream_audit", "stream_enforce"} {
		t.Run(mode, func(t *testing.T) {
			limit := int64(5)
			body, cp, inner := runBudgetStream(t, mode, &limit, &liveRelayReader{events: longStreamEvents(200)})
			if !strings.Contains(body, `"finish_reason":"length"`) || !strings.Contains(body, "预算额度已用尽") || !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
				t.Fatalf("truncated stream must end with a legal length finish: %q", body)
			}
			if got := strings.Count(body, "hello world"); got >= 200 || got < 1 {
				t.Fatalf("forwarded %d deltas; stream was not truncated", got)
			}
			usage, status, source := cp.settled()
			if usage["output_tokens"] != float64(600) || usage["prompt_tokens"] != float64(9) || status != "incomplete" || source != "upstream" {
				t.Fatalf("settlement must use the upstream authoritative usage: status=%v source=%v usage=%v", status, source, usage)
			}
			if len(inner.RequestLogFinalizes) != 1 || inner.RequestLogFinalizes[0].Status != "incomplete" ||
				inner.RequestLogFinalizes[0].AuditResult.ResponseMetadata["stream_budget_truncated"] != true ||
				inner.RequestLogFinalizes[0].AuditResult.ResponseMetadata["stream_budget_usage_unavailable"] != nil {
				t.Fatalf("request log=%#v", inner.RequestLogFinalizes)
			}
		})
	}
}

// 兜底拿不到上游权威 usage（上游在结束前断开）时不做本地估算：用量来源标为待核对，结算不入账。
func TestLiveChatStreamFallbackWithoutUpstreamUsageSettlesEstimate(t *testing.T) {
	events := longStreamEvents(200)
	reader := &liveRelayReader{events: events[:len(events)-1], err: errors.New("upstream reset")}
	limit := int64(5)
	body, cp, inner := runBudgetStream(t, "stream_audit", &limit, reader)
	if !strings.Contains(body, `"finish_reason":"length"`) || !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Fatalf("client still gets a legal end: %q", body[max(0, len(body)-300):])
	}
	cp.mu.Lock()
	measured := cp.measurement
	cp.mu.Unlock()
	if measured == nil || measured["estimated"] != true || measured["usage"].(map[string]any)["output_tokens"] != float64(5) {
		t.Fatalf("missing usage must settle a capped estimate: %v", measured)
	}
	final := inner.RequestLogFinalizes[0]
	if final.Status != "incomplete" || final.Envelope.BillingUsageSource != "estimated_incomplete" ||
		final.Envelope.BillingOutcome != "recorded" || final.AuditResult.ResponseMetadata["stream_budget_usage_unavailable"] != true {
		t.Fatalf("request must be held as pending for review: status=%s source=%s outcome=%s meta=%v",
			final.Status, final.Envelope.BillingUsageSource, final.Envelope.BillingOutcome, final.AuditResult.ResponseMetadata)
	}
}

// 开关关闭（控制面不下发上限）：输出、结束事件与结算和改造前完全一致。
func TestLiveChatStreamWithoutBudgetCapIsUnchanged(t *testing.T) {
	body, cp, inner := runBudgetStream(t, "stream_audit", nil, &liveRelayReader{events: longStreamEvents(200)})
	if strings.Count(body, "hello world") != 200 || strings.Contains(body, `"finish_reason":"length"`) || strings.Contains(body, "预算额度已用尽") {
		t.Fatalf("stream without cap must be untouched: %q", body[len(body)-300:])
	}
	usage, _, _ := cp.settled()
	if usage["output_tokens"] != float64(600) || inner.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("usage=%v status=%s", usage, inner.RequestLogFinalizes[0].Status)
	}
	// 与完全不接计费时的输出逐字节一致（除去每次生成的 created 时间戳）。
	plain := &ChatCompletionsHandler{cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"}, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{}}
	recorder := httptest.NewRecorder()
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-budget", Model: "m"}
	if _, err := plain.tryLiveChatStream(context.Background(), recorder, envelope, &liveRelayCaller{reader: &liveRelayReader{events: longStreamEvents(200)}}, []byte("{}"), time.Now(), "", &relay.CommitTracker{}); err != nil {
		t.Fatal(err)
	}
	if stripCreated(recorder.Body.String()) != stripCreated(body) {
		t.Fatal("billing without a stream cap changed the forwarded bytes")
	}
}

func stripCreated(body string) string {
	out := make([]string, 0)
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, `"created":`); i >= 0 {
			j := strings.IndexAny(line[i+10:], ",}")
			line = line[:i] + line[i+10+j:]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestStreamBudgetGuardChecksEveryNEventsOrSecondWithSlack(t *testing.T) {
	clock := time.Unix(0, 0)
	newGuard := func(cap int64) *streamBudgetGuard {
		return &streamBudgetGuard{outputCap: cap, threshold: streamBudgetThreshold(cap), now: func() time.Time { return clock }, lastCheck: clock}
	}
	event := relay.StreamEvent{Type: relay.EventTextDelta, Delta: "hello world "}
	// 上限 5 时阈值为 5*3/2+32=39：8 个 delta（本地估 32）还在余量内，16 个（64）才触发。
	guard := newGuard(5)
	for i := 1; i < streamBudgetCheckEveryEvents; i++ {
		if guard.observe(event, 0) {
			t.Fatalf("checked before N events at %d", i)
		}
	}
	if guard.observe(event, 0) {
		t.Fatal("8 small deltas stay inside the estimation slack")
	}
	for i := 1; i < streamBudgetCheckEveryEvents; i++ {
		guard.observe(event, 0)
	}
	if !guard.observe(event, 0) {
		t.Fatal("16 deltas are clearly above the cap")
	}
	// 上游自己停在上限时，本地估算即使略超上限也不能误截断。
	guard = newGuard(100)
	if guard.observe(event, 120) {
		t.Fatal("output within the slack above the cap must not trigger the fallback")
	}
	clock = clock.Add(streamBudgetCheckInterval)
	if !guard.observe(event, 200) {
		t.Fatal("output clearly above the cap must trigger once the interval elapsed")
	}
	var nilGuard *streamBudgetGuard
	if nilGuard.observe(event, 0) {
		t.Fatal("nil guard never truncates")
	}
}
