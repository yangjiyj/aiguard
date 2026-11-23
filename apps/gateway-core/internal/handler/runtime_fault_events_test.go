package handler

// 2.9.22 规格审查第 3 项：故障按设置放行时记一条运行告警（security_check_failed），按键限频。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type faultEventCapture struct {
	*MockAuditWriter
	reasons []string
	tenants []string
	ensured int
}

func (c *faultEventCapture) EnsureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	c.ensured++
	c.MockAuditWriter.EnsureRequestLog(ctx, envelope)
}

func (c *faultEventCapture) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	status, _ := semanticStatusFromContext(ctx)
	c.reasons = append(c.reasons, status.Status+"/"+status.Reason)
	c.tenants = append(c.tenants, envelope.TenantID)
	c.MockAuditWriter.WriteSecurityEvent(ctx, envelope, findings, actionTaken, summary)
}

// 复审第四轮改动：Record 改为后台写，用例在每次 Record 后等后台写完再断言（writer.wait），断言不变。
func TestRuntimeFaultEventWriterRecordsRetentionReleaseWithRateLimit(t *testing.T) {
	capture := &faultEventCapture{MockAuditWriter: &MockAuditWriter{}}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	writer := NewRuntimeFaultEventWriter(capture)
	writer.limiter.now = func() time.Time { return now }
	if !writer.Record(context.Background(), "retention_unavailable", "日志留存不可用，按设置放行") {
		t.Fatal("首次放行必须记一条运行告警")
	}
	writer.wait()
	if writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("10 分钟内不重复记")
	}
	now = now.Add(10*time.Minute + time.Second)
	if !writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("过了限频窗口再记一条")
	}
	writer.wait()
	if len(capture.reasons) != 2 || capture.reasons[0] != "incomplete/retention_unavailable" || capture.tenants[0] != "tenant_default" || capture.ensured != 2 {
		t.Fatalf("事件应记平台租户、检测未完成、原因 retention_unavailable：%+v %+v ensured=%d", capture.reasons, capture.tenants, capture.ensured)
	}
	if capture.SecurityEventWrites[0].ActionTaken != "audit" {
		t.Fatalf("放行记 audit：%+v", capture.SecurityEventWrites[0])
	}
}

func TestMCPPolicyUnavailableReleaseWritesRateLimitedFaultEvent(t *testing.T) {
	open := &ToolRiskClient{mcpPolicyFailMode: "open"}
	released := applyMCPPolicyFailureDecision(open.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy()),
		agentguard.Decision{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow}, agentguard.ModeStrict)
	if !mcpPolicyGapReleased(released) {
		t.Fatalf("有缺口但未拦必须打标记：%+v", released)
	}
	closed := &ToolRiskClient{mcpPolicyFailMode: "closed"}
	blocked := applyMCPPolicyFailureDecision(closed.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy()),
		agentguard.Decision{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow}, agentguard.ModeStrict)
	if mcpPolicyGapReleased(blocked) {
		t.Fatalf("已按 closed 拦截的不算放行：%+v", blocked)
	}

	db := newFakeAuditDB()
	rec := &mcpProxyAuditRecorder{db: db}
	write := func(requestID, server string, decision agentguard.Decision) {
		record := mcpProxyAuditRecord{TenantID: "tenant-a", ProjectID: "project-a", RequestID: requestID, ServerID: server, ServerName: server}
		if err := rec.writeMCPProxyAuditTx(context.Background(), record, []mcpToolCallDecision{{Qualified: "demo__echo", Decision: decision}}, false); err != nil {
			t.Fatal(err)
		}
	}
	write("req-1", "server-a", released)
	write("req-2", "server-a", released) // 同租户同服务限频
	write("req-3", "server-b", released) // 另一个服务照记
	write("req-4", "server-c", blocked)  // 拦截的不记运行告警
	var faults []map[string]any
	for i, sql := range db.tx.execedSQL {
		if !strings.Contains(sql, "INSERT INTO security_events") {
			continue
		}
		args := db.tx.execedArgs[i]
		if args[4] != "security_check_failed" {
			continue
		}
		var summary map[string]any
		_ = json.Unmarshal(args[8].([]byte), &summary)
		faults = append(faults, summary)
	}
	if len(faults) != 2 {
		t.Fatalf("应按租户加服务限频记 2 条运行告警，实际 %d：%+v", len(faults), faults)
	}
	if faults[0]["semantic_reason"] != "mcp_policy_unavailable" || faults[0]["server_id"] != "server-a" || faults[1]["server_id"] != "server-b" {
		t.Fatalf("运行告警内容不对：%+v", faults)
	}
}

// 复审补充第 2 项：运行故障自建的请求日志 proxy_mode 记 runtime_fault，不再写死 chat_completion；
// 普通请求照旧记 chat_completion。
func TestEnsureRequestLogProxyModeMarksRuntimeFault(t *testing.T) {
	for endpoint, want := range map[string]string{"runtime_fault": "runtime_fault", "chat": "chat_completion", "": "chat_completion"} {
		mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
		writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
		writer.EnsureRequestLog(context.Background(), &modelrouter.RequestEnvelope{RequestID: "req-" + endpoint, TenantID: "tenant_default", EndpointType: endpoint})
		if mockDB.execCalls != 1 {
			t.Fatalf("expected 1 exec, got %d", mockDB.execCalls)
		}
		if strings.Contains(mockDB.queries[0], "'chat_completion'") {
			t.Fatalf("proxy_mode 不应再写死在 SQL 里：%s", mockDB.queries[0])
		}
		if !argsContainString(mockDB.args[0], want) {
			t.Fatalf("endpoint=%q 的 proxy_mode 应为 %s，参数 %#v", endpoint, want, mockDB.args[0])
		}
	}
}

// 能报告写入结果的写入器：前 failures 次失败，之后成功；block 非空时每次写入先等它关闭。
type faultResultWriter struct {
	*MockAuditWriter
	mu       sync.Mutex
	failures int
	writes   int
	tenants  []string
	block    chan struct{}
}

func (w *faultResultWriter) RecordRuntimeFault(_ context.Context, envelope *modelrouter.RequestEnvelope, _ string) error {
	if w.block != nil {
		<-w.block
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	w.tenants = append(w.tenants, envelope.TenantID+"/"+envelope.ProjectID)
	if w.writes <= w.failures {
		return errors.New("db down")
	}
	return nil
}

// 复审第四轮：写失败后退避 1 分钟，1 分钟内不重试；写成功后进 10 分钟限频窗口；告警固定挂平台租户。
// （替换第三轮的“写失败下一次照样记”用例，审查意见改为失败退避。）
func TestRuntimeFaultEventWriterBacksOffOneMinuteAfterFailedWrite(t *testing.T) {
	sink := &faultResultWriter{MockAuditWriter: &MockAuditWriter{}, failures: 1}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	writer := NewRuntimeFaultEventWriter(sink)
	writer.limiter.now = func() time.Time { return now }
	if !writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("首次应安排写入")
	}
	writer.wait()
	now = now.Add(59 * time.Second)
	if writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("写失败后 1 分钟内不重试")
	}
	now = now.Add(2 * time.Second)
	if !writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("退避 1 分钟后应重试")
	}
	writer.wait()
	if writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("写成功后进入限频窗口")
	}
	if sink.writes != 2 || sink.tenants[0] != "tenant_default/project_default" {
		t.Fatalf("writes=%d tenants=%v", sink.writes, sink.tenants)
	}
}

// 数据库卡住时，记运行告警不能拖住请求：Record 立刻返回，写入在后台等。
func TestRuntimeFaultEventWriterDoesNotBlockWhenDatabaseIsStuck(t *testing.T) {
	sink := &faultResultWriter{MockAuditWriter: &MockAuditWriter{}, block: make(chan struct{})}
	writer := NewRuntimeFaultEventWriter(sink)
	t.Cleanup(func() { close(sink.block); writer.wait() })
	started := time.Now()
	if !writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("应安排写入")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("Record 被卡住的写入拖了 %s", elapsed)
	}
	if writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("同一原因写入在途时不再安排")
	}
}

// 同一原因并发触发时只写一次。
func TestRuntimeFaultEventWriterConcurrentRecordsWriteOnce(t *testing.T) {
	sink := &faultResultWriter{MockAuditWriter: &MockAuditWriter{}, block: make(chan struct{})}
	writer := NewRuntimeFaultEventWriter(sink)
	var wg sync.WaitGroup
	var recorded atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if writer.Record(context.Background(), "retention_unavailable", "x") {
				recorded.Add(1)
			}
		}()
	}
	wg.Wait()
	close(sink.block)
	writer.wait()
	if sink.writes != 1 || recorded.Load() != 1 {
		t.Fatalf("并发只写一次：writes=%d recorded=%d", sink.writes, recorded.Load())
	}
}

type panickingFaultWriter struct{ *MockAuditWriter }

func (panickingFaultWriter) RecordRuntimeFault(context.Context, *modelrouter.RequestEnvelope, string) error {
	panic("audit driver bug")
}

// 合流前次要项：后台写入 panic 时日志带调用栈，并按失败退避。
func TestRuntimeFaultEventWriterPanicLogsStackAndBacksOff(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	writer := NewRuntimeFaultEventWriter(panickingFaultWriter{&MockAuditWriter{}})
	if !writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("应安排写入")
	}
	writer.wait()
	if !strings.Contains(buf.String(), "audit driver bug") || !strings.Contains(buf.String(), "goroutine ") {
		t.Fatalf("panic 日志应带调用栈：%s", buf.String())
	}
	if writer.Record(context.Background(), "retention_unavailable", "x") {
		t.Fatal("panic 按写失败退避")
	}
}
