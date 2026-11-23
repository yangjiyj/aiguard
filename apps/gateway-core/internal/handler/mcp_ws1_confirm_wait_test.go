package handler

// W1 1.9：审批等待超时返回标准 JSON-RPC 错误 + 明确文案；可选"挂起直到批准"模式。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func confirmPolicy(string, string) MCPEffectivePolicy {
	return MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm"}
}

type ws1RPCError struct {
	ID    json.RawMessage `json:"id"`
	Error struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}

func TestWS1ConfirmPendingTimeoutTellsClientHowToResume(t *testing.T) {
	env := newWS1Env(t, false, confirmPolicy)
	w := env.post(t, ws1ToolCallRequest)
	var resp ws1RPCError
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("应为 JSON-RPC 错误: %s", w.Body.String())
	}
	if string(resp.ID) != "9" || resp.Error.Code != -32000 {
		t.Fatalf("id/code: %s", w.Body.String())
	}
	for _, want := range []string{"已创建确认单", "待审批", "相同请求"} {
		if !strings.Contains(resp.Error.Message, want) {
			t.Fatalf("文案缺少 %q: %s", want, resp.Error.Message)
		}
	}
	if resp.Error.Data["reason"] != "confirmation_pending" || resp.Error.Data["retryable"] != true || resp.Error.Data["confirmation_id"] != "agcf-test" {
		t.Fatalf("data 应带可续接信息: %v", resp.Error.Data)
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatal("待审批期间不得触达上游")
	}
}

func TestWS1ConfirmRejectedEndsWaitImmediately(t *testing.T) {
	replay, record, secret := mcpResultFixture(t)
	record.ConfirmationState = "rejected"
	record.ExecutionStatus = "pending"
	handler := newMCPResultTestProxy(record, secret)
	started := time.Now()
	result := handler.waitMCPConfirmationResult(context.Background(), MCPConfirmationTicket{ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID}, replay, 3*time.Second)
	if !result.Terminal || result.ErrorCode != "confirmation_rejected" || time.Since(started) > time.Second {
		t.Fatalf("拒绝应立即终结: %+v elapsed=%s", result, time.Since(started))
	}
	code, msg, data := mcpConfirmationOutcomeError(result, agentguard.Decision{}, "mcppol_confirm")
	if code != -32000 || !strings.Contains(msg, "拒绝") || data["retryable"] != false {
		t.Fatalf("拒绝文案: %d %s %v", code, msg, data)
	}
}

func TestWS1ConfirmExpiredEndsWaitImmediately(t *testing.T) {
	replay, record, secret := mcpResultFixture(t)
	record.ConfirmationState = "pending"
	record.ExecutionStatus = "pending"
	record.ExpiresAt = time.Now().Add(-time.Second)
	handler := newMCPResultTestProxy(record, secret)
	started := time.Now()
	result := handler.waitMCPConfirmationResult(context.Background(), MCPConfirmationTicket{ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID}, replay, 3*time.Second)
	if !result.Terminal || result.ErrorCode != "confirmation_expired" || time.Since(started) > time.Second {
		t.Fatalf("过期应立即终结: %+v", result)
	}
	_, msg, _ := mcpConfirmationOutcomeError(result, agentguard.Decision{}, "")
	if !strings.Contains(msg, "过期") {
		t.Fatalf("过期文案: %s", msg)
	}
}

// ws1FlippingStore 在 delay 后把确认单切为已批准+已执行（模拟审批人通过）。
type ws1FlippingStore struct {
	mu     sync.Mutex
	record *mcpConfirmationExecutionRecord
	final  mcpConfirmationExecutionRecord
	at     time.Time
}

func (s *ws1FlippingStore) current() *mcpConfirmationExecutionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().After(s.at) {
		copy := s.final
		return &copy
	}
	copy := *s.record
	return &copy
}

func (s *ws1FlippingStore) ClaimGatewayExecution(context.Context, string, string, string) (*mcpConfirmationExecutionRecord, bool, error) {
	return s.current(), false, nil
}
func (s *ws1FlippingStore) GetGatewayExecution(context.Context, string, string) (*mcpConfirmationExecutionRecord, error) {
	return s.current(), nil
}
func (s *ws1FlippingStore) BeginGatewayEvidence(context.Context, string, string, string, string) error {
	return nil
}
func (s *ws1FlippingStore) CompleteGatewayExecution(context.Context, string, string, string, mcpExecutionCompletion) (*mcpConfirmationExecutionRecord, error) {
	return s.current(), nil
}

func ws1FlipFixture(t *testing.T, delay time.Duration) (*MCPProxyHandler, MCPConfirmationTicket, []byte, func() mcpConfirmationPollResult) {
	t.Helper()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "ws1-hold-key")
	replay, record, secret := mcpResultFixture(t)
	final := *record
	want := attachEncryptedMCPResult(t, secret, replay, &final, time.Now().Add(time.Minute))
	pending := *record
	pending.ConfirmationState = "pending"
	pending.ExecutionStatus = "pending"
	handler := newMCPResultTestProxy(record, secret)
	handler.confirmationExecutionStore = &ws1FlippingStore{record: &pending, final: final, at: time.Now().Add(delay)}
	ticket := MCPConfirmationTicket{ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID, ExpiresAt: record.ExpiresAt}
	budget := mcpConfirmationWaitBudget(mcpConfirmWaitModeHold, ticket, time.Now())
	wait := func() mcpConfirmationPollResult {
		return handler.waitMCPConfirmationResult(context.Background(), ticket, replay, budget)
	}
	return handler, ticket, want, wait
}

func TestWS1ConfirmHoldModeWaitsUntilApproved(t *testing.T) {
	t.Setenv("MCP_CONFIRM_WAIT_TIMEOUT", "0")
	_, _, want, wait := ws1FlipFixture(t, 300*time.Millisecond)
	result := wait()
	if string(result.Body) != string(want) {
		t.Fatalf("挂起模式应等到审批通过并返回执行结果: %+v", result)
	}
}

func TestWS1ConfirmHoldSSEKeepaliveThenResult(t *testing.T) {
	_, _, want, wait := ws1FlipFixture(t, 120*time.Millisecond)
	w := httptest.NewRecorder()
	writeHeldMCPConfirmationSSE(w, json.RawMessage("9"), agentguard.Decision{}, "mcppol_confirm", wait, 20*time.Millisecond)
	body := w.Body.String()
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("挂起+SSE 应返回事件流: %v", w.Header())
	}
	if !strings.Contains(body, ": awaiting-confirmation") {
		t.Fatalf("等待期间应发保活注释: %q", body)
	}
	payloads := parseMCPSSEDataPayloads(w.Body.Bytes())
	if len(payloads) != 1 || string(payloads[0]) != string(want) {
		t.Fatalf("最终事件应为执行结果: %q", body)
	}
}

func TestWS1ConfirmHoldSSERejectedEndsWithError(t *testing.T) {
	w := httptest.NewRecorder()
	wait := func() mcpConfirmationPollResult {
		return mcpConfirmationPollResult{Terminal: true, ErrorCode: "confirmation_rejected", Ticket: MCPConfirmationTicket{ConfirmationID: "cf"}}
	}
	writeHeldMCPConfirmationSSE(w, json.RawMessage(`"a"`), agentguard.Decision{}, "", wait, time.Second)
	payloads := parseMCPSSEDataPayloads(w.Body.Bytes())
	var resp ws1RPCError
	if len(payloads) != 1 || json.Unmarshal(payloads[0], &resp) != nil || string(resp.ID) != `"a"` || !strings.Contains(resp.Error.Message, "拒绝") {
		t.Fatalf("拒绝应以 JSON-RPC 错误事件结束: %q", w.Body.String())
	}
}

func TestWS1ConfirmWaitModeAndBudget(t *testing.T) {
	now := time.Now()
	ticket := MCPConfirmationTicket{ExpiresAt: now.Add(3 * time.Minute)}
	cases := []struct {
		mode, hold, wait string
		want             time.Duration
	}{
		{"", "", "", 2 * time.Second},
		{"timeout", "", "5s", 5 * time.Second},
		{"hold", "", "", 3 * time.Minute},
		{"hold", "1m", "", time.Minute},
		{"hold", "bogus", "", 3 * time.Minute},
		{"HOLD", "", "", 3 * time.Minute},
	}
	for _, c := range cases {
		t.Setenv("MCP_CONFIRM_WAIT_MODE", c.mode)
		t.Setenv("MCP_CONFIRM_HOLD_MAX", c.hold)
		t.Setenv("MCP_CONFIRM_WAIT_TIMEOUT", c.wait)
		got := mcpConfirmationWaitBudget(mcpConfirmationWaitMode(), ticket, now)
		if got < c.want-time.Second || got > c.want {
			t.Fatalf("%+v: got %s", c, got)
		}
	}
	if b := mcpConfirmationWaitBudget(mcpConfirmWaitModeHold, MCPConfirmationTicket{ExpiresAt: now.Add(-time.Minute)}, now); b != 0 {
		t.Fatalf("已过期的确认单不应挂起: %s", b)
	}
}

func TestWS1ConfirmAcceptsSSE(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Accept", "application/json, text/event-stream")
	if !mcpAcceptsSSE(r) {
		t.Fatal("应识别 text/event-stream")
	}
	r.Header.Set("Accept", "application/json")
	if mcpAcceptsSSE(r) {
		t.Fatal("仅 JSON 时不应走 SSE")
	}
}
