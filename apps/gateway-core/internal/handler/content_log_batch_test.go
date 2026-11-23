package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 客户现场回归：一个 Claude Code 请求带上百条历史消息，原实现每条一个 SQL 语句（一次往返、
// 一次提交、一次 WAL 刷盘），现场 content_logs 一天 46 万行，磁盘慢时成为主要写入压力之一。
// 一个请求的全部消息改为一条语句写入；失败则逐条回退，保证不丢。
func TestWriteContentLogsBatchUsesOneStatement(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 3}}
	w := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	env := &modelrouter.RequestEnvelope{RequestID: "req-b", TenantID: "t", SessionID: "s", EndpointType: "chat"}
	w.WriteContentLogsBatch(context.Background(), env, []ContentLogEntry{
		{Role: "system", Content: "sys", MessageIndex: 0},
		{Role: "user", Content: "hi", MessageIndex: 1},
		{Role: "assistant", Content: "ok", MessageIndex: 3},
	})
	if mockDB.execCalls != 1 {
		t.Fatalf("一个请求的消息应一条语句写完，实际 %d 次 Exec", mockDB.execCalls)
	}
	q := mockDB.queries[0]
	for _, want := range []string{"INSERT INTO content_logs", "unnest(", "WITH ORDINALITY", "ON CONFLICT (request_id) DO NOTHING", "SELECT rl.id FROM request_logs rl"} {
		if !strings.Contains(q, want) {
			t.Fatalf("批量语句缺少 %q：%s", want, q)
		}
	}
	if strings.Contains(q, "ON CONFLICT (request_id) DO UPDATE") {
		t.Fatal("批量写入不得重写已存在的父请求行")
	}
}

func TestWriteContentLogsBatchFallsBackToPerMessageOnError(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}, failFirstExec: errors.New("batch failed")}
	w := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	env := &modelrouter.RequestEnvelope{RequestID: "req-f", TenantID: "t", EndpointType: "chat"}
	entries := make([]ContentLogEntry, 0, 4)
	for i := 0; i < 4; i++ {
		entries = append(entries, ContentLogEntry{Role: "user", Content: fmt.Sprintf("m%d", i), MessageIndex: i})
	}
	w.WriteContentLogsBatch(context.Background(), env, entries)
	if mockDB.execCalls != 1+len(entries) {
		t.Fatalf("批量失败应逐条回退：期望 %d 次 Exec，实际 %d", 1+len(entries), mockDB.execCalls)
	}
}

// 父请求行由并发事务在语句开始后才提交时，ON CONFLICT DO NOTHING 与兜底查询都看不到它，语句写入 0 行；
// 必须换新语句（新快照）重试一次，否则这条消息就丢了。
func TestWriteContentLogRetriesOnceWhenZeroRowsWritten(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 0}}
	w := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	env := &modelrouter.RequestEnvelope{RequestID: "req-r", TenantID: "t", EndpointType: "chat"}
	w.WriteContentLog(context.Background(), env, "user", "hello", 3)
	if mockDB.execCalls != 2 {
		t.Fatalf("写入 0 行应重试且只重试一次：期望 2 次 Exec，实际 %d", mockDB.execCalls)
	}
	if mockDB.queries[0] != mockDB.queries[1] || fmt.Sprint(mockDB.args[0]) != fmt.Sprint(mockDB.args[1]) {
		t.Fatal("重试必须使用同一语句与同一参数")
	}
}

func TestWriteContentLogsBatchRetriesOnceWhenZeroRowsWritten(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 0}}
	w := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	env := &modelrouter.RequestEnvelope{RequestID: "req-z", TenantID: "t", EndpointType: "chat"}
	w.WriteContentLogsBatch(context.Background(), env, []ContentLogEntry{
		{Role: "system", Content: "sys", MessageIndex: 0},
		{Role: "user", Content: "hi", MessageIndex: 1},
	})
	if mockDB.execCalls != 2 {
		t.Fatalf("批量写入 0 行应整批重试一次（不逐条回退）：期望 2 次 Exec，实际 %d", mockDB.execCalls)
	}
	if mockDB.queries[0] != mockDB.queries[1] || fmt.Sprint(mockDB.args[0]) != fmt.Sprint(mockDB.args[1]) {
		t.Fatal("重试必须使用同一语句与同一参数（含同一个父请求 id）")
	}
}

func TestWriteRequestContentLogsUsesBatchWriterWhenAvailable(t *testing.T) {
	rec := &recordingBatchWriter{MockAuditWriter: &MockAuditWriter{}}
	h := &ChatCompletionsHandler{auditWriter: rec}
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}
	h.writeRequestContentLogs(context.Background(), env, []Message{
		{Role: "system", Content: json.RawMessage(`"sys"`)},
		{Role: "user", Content: json.RawMessage(`""`)},
		{Role: "user", Content: json.RawMessage(`"q"`)},
	})
	if rec.batches != 1 {
		t.Fatalf("应整批写一次，实际 %d", rec.batches)
	}
	if len(rec.entries) != 2 || rec.entries[0].MessageIndex != 0 || rec.entries[1].MessageIndex != 2 {
		t.Fatalf("空消息跳过、message_index 保持原数组下标：%+v", rec.entries)
	}
}

type recordingBatchWriter struct {
	*MockAuditWriter
	batches int
	entries []ContentLogEntry
}

func (r *recordingBatchWriter) WriteContentLogsBatch(_ context.Context, _ *modelrouter.RequestEnvelope, entries []ContentLogEntry) {
	r.batches++
	r.entries = append(r.entries, entries...)
}
