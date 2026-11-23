package main

// 复审第四轮：日志留存不可用、按设置放行时记运行告警不能拖住请求——数据库卡住时请求照常返回。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type stuckRuntimeFaultWriter struct{ release chan struct{} }

func (stuckRuntimeFaultWriter) EnsureRequestLog(context.Context, *modelrouter.RequestEnvelope) {}
func (stuckRuntimeFaultWriter) FinalizeRequestLog(context.Context, *modelrouter.RequestEnvelope, []byte, string, int, int, *handler.AuditResult) {
}
func (stuckRuntimeFaultWriter) WriteSecurityEvent(context.Context, *modelrouter.RequestEnvelope, []handler.SecurityFinding, string, string) {
}
func (stuckRuntimeFaultWriter) WriteContentLog(context.Context, *modelrouter.RequestEnvelope, string, string, int) {
}
func (stuckRuntimeFaultWriter) UpsertAgentSession(context.Context, *modelrouter.RequestEnvelope) {}
func (stuckRuntimeFaultWriter) AnnotateTriage(context.Context, *modelrouter.RequestEnvelope, []handler.SecurityFinding) {
}
func (w stuckRuntimeFaultWriter) RecordRuntimeFault(context.Context, *modelrouter.RequestEnvelope, string) error {
	<-w.release
	return nil
}

func TestRetentionRuntimeGuardDoesNotWaitForStuckFaultWrite(t *testing.T) {
	sink := stuckRuntimeFaultWriter{release: make(chan struct{})}
	t.Cleanup(func() { close(sink.release) })
	faults := handler.NewRuntimeFaultEventWriter(sink)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guard := retentionRuntimeGuard("error", func() string { return "open" }, func(ctx context.Context) {
		faults.Record(ctx, "retention_unavailable", "x")
	})(next)
	started := time.Now()
	recorder := httptest.NewRecorder()
	guard.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if elapsed := time.Since(started); recorder.Code != http.StatusNoContent || elapsed > 200*time.Millisecond {
		t.Fatalf("数据库卡住时请求应照常放行：status=%d elapsed=%s", recorder.Code, elapsed)
	}
}
