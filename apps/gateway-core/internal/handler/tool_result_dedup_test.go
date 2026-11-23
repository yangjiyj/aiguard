package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 客户现场回归：客户端每个请求都带着整段历史里的工具结果，网关对每条历史工具结果都
// 重复上报一次 result_observed（控制面按 tool_call_id 幂等合并，入库结果不变），
// 现场每小时约 3.8 万次 /internal/tools/logs。同一租户同一 tool_call_id 只上报一次。
func TestLogToolResultObservationsReportsEachToolCallOnce(t *testing.T) {
	var logs, links int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/internal/tools/logs"):
			atomic.AddInt32(&logs, 1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"log-1"}`))
		default:
			atomic.AddInt32(&links, 1)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(srv.URL, "secret"), auditWriter: &MockAuditWriter{}}
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", RequestID: "r1"}
	history := []Message{{Role: "tool", ToolCallID: "call_1"}, {Role: "tool", ToolCallID: "call_2"}}
	// 同一会话连续 5 轮请求，每轮都带着这两条历史工具结果，第 3 轮新增 call_3。
	for i := 0; i < 5; i++ {
		msgs := append([]Message{}, history...)
		if i >= 2 {
			msgs = append(msgs, Message{Role: "tool", ToolCallID: "call_3"})
		}
		env.RequestID = "r" + string(rune('1'+i))
		h.logToolResultObservations(context.Background(), env, msgs)
	}
	if got := atomic.LoadInt32(&logs); got != 3 {
		t.Fatalf("3 个不同的 tool_call_id 应各上报 1 次，共 3 次；实际 %d 次", got)
	}
	// 另一个租户的同名 tool_call_id 不能被误判为已上报。
	h.logToolResultObservations(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant-b", RequestID: "x"}, []Message{{Role: "tool", ToolCallID: "call_1"}})
	if got := atomic.LoadInt32(&logs); got != 4 {
		t.Fatalf("不同租户应各自上报，期望 4 次，实际 %d 次", got)
	}
}

func TestToolResultReportedSetIsBounded(t *testing.T) {
	s := newToolResultReportedSet(100)
	for i := 0; i < 1000; i++ {
		s.markIfNew("t", "call-"+itoaCaptchaTestGW(i))
	}
	if n := s.size(); n > 100 {
		t.Fatalf("已上报集合必须有上限，当前 %d", n)
	}
}

func itoaCaptchaTestGW(i int) string {
	if i == 0 {
		return "0"
	}
	b := []byte{}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
