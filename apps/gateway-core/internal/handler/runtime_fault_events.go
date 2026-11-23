package handler

// 故障按设置放行时记一条运行告警（2.9.22 规格审查第 3 项）。事件类型沿用检测故障
// security_check_failed，原因写进 semantic_reason，由控制面告警按原因分组；同一个键
// 10 分钟内只记一条，不按请求刷屏。

import (
	"context"
	"errors"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const runtimeFaultEventWindow = 10 * time.Minute

// runtimeFaultRetryBackoff 是写失败后再试的间隔：数据库出问题时不按请求反复重试。
const runtimeFaultRetryBackoff = time.Minute

// 平台级运行告警挂靠的租户与项目：与平台出站事件一致固定为默认租户，不随
// PROXY_DEFAULT_TENANT_ID 等部署变量漂移。
const (
	runtimeFaultTenantID  = "tenant_default"
	runtimeFaultProjectID = "project_default"
)

type runtimeFaultLimiter struct {
	mu       sync.Mutex
	last     map[string]time.Time
	retryAt  map[string]time.Time
	inflight map[string]bool
	window   time.Duration
	backoff  time.Duration
	now      func() time.Time
}

func newRuntimeFaultLimiter(window time.Duration) *runtimeFaultLimiter {
	return &runtimeFaultLimiter{last: map[string]time.Time{}, retryAt: map[string]time.Time{}, inflight: map[string]bool{},
		window: window, backoff: runtimeFaultRetryBackoff, now: time.Now}
}

// due 只判断该键是否到了可以再记的时候，不登记（事务提交成功后再 mark）。
func (l *runtimeFaultLimiter) due(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	last, ok := l.last[key]
	return !ok || l.now().Sub(last) >= l.window
}

func (l *runtimeFaultLimiter) mark(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.last[key] = l.now()
}

// begin 判断该键是否到了可以再记的时候并占位（同一键同时只有一个写入在途）。
// 写完必须调用 finish：写成功登记限频窗口，写失败退避 backoff 后才再试。
func (l *runtimeFaultLimiter) begin(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inflight[key] {
		return false
	}
	now := l.now()
	if last, ok := l.last[key]; ok && now.Sub(last) < l.window {
		return false
	}
	if retry, ok := l.retryAt[key]; ok && now.Before(retry) {
		return false
	}
	l.inflight[key] = true
	return true
}

func (l *runtimeFaultLimiter) finish(key string, written bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.inflight, key)
	if written {
		l.last[key] = l.now()
		delete(l.retryAt, key)
		return
	}
	l.retryAt[key] = l.now().Add(l.backoff)
}

// runtimeFaultRecorder 是能报告写入结果的审计写入器（RealAuditWriter、AsyncAuditWriter）。
type runtimeFaultRecorder interface {
	RecordRuntimeFault(ctx context.Context, envelope *modelrouter.RequestEnvelope, summary string) error
}

// recordRuntimeFault 写一条运行告警：请求日志 + security_check_failed 事件 + 收尾。
// 写入器不报告结果时（测试桩等）照原样写，按成功处理。
func recordRuntimeFault(ctx context.Context, writer AuditWriter, envelope *modelrouter.RequestEnvelope, summary string) error {
	if writer == nil {
		return errors.New("audit writer is unavailable")
	}
	if recorder, ok := writer.(runtimeFaultRecorder); ok {
		return recorder.RecordRuntimeFault(ctx, envelope, summary)
	}
	writer.EnsureRequestLog(ctx, envelope)
	writer.WriteSecurityEvent(ctx, envelope, nil, "audit", summary)
	writer.FinalizeRequestLog(ctx, envelope, nil, "security_check_failed", 0, 0, nil)
	return nil
}

// RuntimeFaultEventWriter 记没有业务请求可挂靠的平台级运行告警（如日志留存不可用）。
// 事件挂在一条自建的请求日志上（安全事件的 request_id 有外键），记在平台租户下。
// 写入在后台进行，不占请求路径；数据库卡住时同一原因最多一个写入在途。
type RuntimeFaultEventWriter struct {
	writer  AuditWriter
	limiter *runtimeFaultLimiter
	pending sync.WaitGroup
}

func NewRuntimeFaultEventWriter(writer AuditWriter) *RuntimeFaultEventWriter {
	return &RuntimeFaultEventWriter{writer: writer, limiter: newRuntimeFaultLimiter(runtimeFaultEventWindow)}
}

// Record 按原因限频，在后台记一条 security_check_failed，立刻返回；返回值表示这次是否安排了写入。
// 写成功后 10 分钟内同一原因不再记；写失败（含 panic）退避 1 分钟再试。
func (w *RuntimeFaultEventWriter) Record(ctx context.Context, reason, summary string) bool {
	if w == nil || w.writer == nil || !w.limiter.begin(reason) {
		return false
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: newAuditID("rtf_"), TenantID: runtimeFaultTenantID, ProjectID: runtimeFaultProjectID,
		EndpointType: "runtime_fault", RequestStartedAt: time.Now(),
	}
	ctx = withSemanticStatus(context.WithoutCancel(ctx), "incomplete", reason)
	w.pending.Add(1)
	go func() {
		defer w.pending.Done()
		written := false
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[runtime-fault] record %s panicked: %v\n%s", reason, recovered, debug.Stack())
			}
			w.limiter.finish(reason, written)
		}()
		if err := recordRuntimeFault(ctx, w.writer, envelope, summary); err != nil {
			log.Printf("[runtime-fault] record %s failed, retry after %s: %v", reason, runtimeFaultRetryBackoff, err)
			return
		}
		written = true
	}()
	return true
}

// wait 等已安排的后台写入结束。目前只有测试调用它；进程退出不等后台写入，未写完的告警随进程丢弃
// （它只是运行告警，同一原因下次故障时会再记）。
func (w *RuntimeFaultEventWriter) wait() {
	if w != nil {
		w.pending.Wait()
	}
}
