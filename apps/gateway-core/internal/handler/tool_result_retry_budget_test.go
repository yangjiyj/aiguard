package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 客户现场：控制面对某批客户端带回的工具结果持续拒绝（约束违约），而客户端每轮都重发整段历史、
// 网关上报失败又 forget 标记，于是每个会话轮次整批重投，PostgreSQL 日志里每分钟一批 200 条。
// 重投必须有终点：确定性拒绝立即放弃；暂时性失败有次数上限。

func newToolLogStub(t *testing.T, status func(call int32) int) (*httptest.Server, *int32) {
	t.Helper()
	var logs int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/tools/logs" {
			w.WriteHeader(http.StatusNotFound) // LinkSkillResult 等：与本用例无关
			return
		}
		n := atomic.AddInt32(&logs, 1)
		code := status(n)
		w.WriteHeader(code)
		if code < 300 {
			_, _ = w.Write([]byte(`{"id":"log-1"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &logs
}

func replayHistory(h *ChatCompletionsHandler, rounds int, ids ...string) {
	var msgs []Message
	for _, id := range ids {
		msgs = append(msgs, Message{Role: "tool", ToolCallID: id})
	}
	for i := 0; i < rounds; i++ {
		h.logToolResultObservations(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant-retry", RequestID: "r"}, msgs)
	}
}

func TestToolResultRejectedByControlPlaneIsDroppedNotRetried(t *testing.T) {
	srv, logs := newToolLogStub(t, func(int32) int { return http.StatusUnprocessableEntity })
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(srv.URL, "secret"), auditWriter: &MockAuditWriter{}}

	// 一个会话 20 轮、每轮重发同样 3 条历史工具结果：422 确定性拒绝只应各上报 1 次。
	replayHistory(h, 20, "call_a", "call_b", "call_c")
	if got := atomic.LoadInt32(logs); got != 3 {
		t.Fatalf("确定性拒绝应各只上报 1 次共 3 次，实际 %d 次（旧实现会随轮次放大到 60 次）", got)
	}
}

func TestToolResultTransientFailureRetriesWithinBudgetThenGivesUp(t *testing.T) {
	srv, logs := newToolLogStub(t, func(int32) int { return http.StatusBadRequest }) // 老控制面的 400 internal_error
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(srv.URL, "secret"), auditWriter: &MockAuditWriter{}}

	replayHistory(h, 50, "call_a")
	if got := atomic.LoadInt32(logs); got != toolResultMaxReportAttempts {
		t.Fatalf("持续失败应在 %d 次后放弃，实际上报 %d 次", toolResultMaxReportAttempts, got)
	}
}

func TestToolResultTransientFailureStillRecoversWithinBudget(t *testing.T) {
	// 前 2 次控制面抖动（500），之后恢复：不能漏记。
	srv, logs := newToolLogStub(t, func(n int32) int {
		if n <= 2 {
			return http.StatusInternalServerError
		}
		return http.StatusCreated
	})
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(srv.URL, "secret"), auditWriter: &MockAuditWriter{}}

	replayHistory(h, 10, "call_a")
	if got := atomic.LoadInt32(logs); got != 3 {
		t.Fatalf("2 次失败 + 1 次成功后应停止上报，共 3 次，实际 %d 次", got)
	}
}

func TestToolLogStatusErrorClassification(t *testing.T) {
	if !errors.Is(&toolLogStatusError{status: http.StatusUnprocessableEntity}, errToolLogRejected) {
		t.Fatal("422 必须被识别为确定性拒绝")
	}
	for _, status := range []int{400, 401, 429, 500, 502, 503} {
		if errors.Is(&toolLogStatusError{status: status}, errToolLogRejected) {
			t.Fatalf("%d 不是确定性拒绝，必须保持可重试", status)
		}
	}
	if got := (&toolLogStatusError{status: 400}).Error(); got != "control-plane logging returned status 400" {
		t.Fatalf("错误文案必须与改造前一致，实际 %q", got)
	}
}
