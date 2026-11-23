package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 缺省、非法或查询失败时 DB 读取器必须默认关闭。
func TestDBFileDLPSettingReaderDefaultsOffWhenMissing(t *testing.T) {
	r := NewDBFileDLPSettingReader(stubQueryFn(errNoRows, ""))
	if r.Enabled(context.Background()) {
		t.Fatal("system_settings 缺失键时必须默认关闭")
	}
}

// 数据库存 true 时返回开。
func TestDBFileDLPSettingReaderOnWhenTrue(t *testing.T) {
	r := NewDBFileDLPSettingReader(stubQueryFn(nil, "true"))
	if !r.Enabled(context.Background()) {
		t.Fatal("system_settings=true 时应开启")
	}
}

func TestDBSecurityAuditOnlySettingReaderUsesAuditSetting(t *testing.T) {
	var queriedKey string
	r := NewDBSecurityAuditOnlySettingReader(func(_ context.Context, _ string, args ...any) rowScanner {
		queriedKey, _ = args[0].(string)
		return stubScanner{value: "true"}
	})
	if !r.Enabled(context.Background()) {
		t.Fatal("security_audit_only=true 时应开启审计模式")
	}
	if queriedKey != securityAuditOnlySettingKey {
		t.Fatalf("queried setting key=%q want %q", queriedKey, securityAuditOnlySettingKey)
	}
}

// 非法值（非 "true"）按关闭处理。
func TestDBFileDLPSettingReaderOffForNonTrue(t *testing.T) {
	r := NewDBFileDLPSettingReader(stubQueryFn(nil, "yes"))
	if r.Enabled(context.Background()) {
		t.Fatal("system_settings 非 true 必须按关闭处理")
	}
}

// 查询失败（控制平面库不可达）默认关闭，不抛错。
func TestDBFileDLPSettingReaderOffWhenQueryFails(t *testing.T) {
	r := NewDBFileDLPSettingReader(stubQueryFn(errDBUnavailable, ""))
	if r.Enabled(context.Background()) {
		t.Fatal("查询失败时必须默认关闭")
	}
}

func TestDBFileDLPSettingReaderFallsBackToEnvBeforeFirstGoodValue(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	r := NewDBFileDLPSettingReader(stubQueryFn(errDBUnavailable, ""))
	if !r.Enabled(context.Background()) {
		t.Fatal("首次数据库查询失败时必须使用环境变量后备")
	}
}

func TestDBFileDLPSettingReaderKeepsLastGoodValueOnQueryFailure(t *testing.T) {
	var calls int32
	r := NewDBFileDLPSettingReader(func(_ context.Context, _ string, _ ...any) rowScanner {
		if atomic.AddInt32(&calls, 1) == 1 {
			return stubScanner{value: "true"}
		}
		return stubScanner{err: errDBUnavailable}
	}).(*DBFileDLPSettingReader)
	r.ttl = time.Millisecond

	if !r.Enabled(context.Background()) {
		t.Fatal("首次数据库 true 应开启")
	}
	time.Sleep(2 * time.Millisecond)
	if !r.Enabled(context.Background()) {
		t.Fatal("数据库短暂失败时必须保留最后有效 true，不能静默关闭")
	}
}

type countingFileDLPSettingReader struct {
	calls int32
	value bool
}

func (r *countingFileDLPSettingReader) Enabled(context.Context) bool {
	atomic.AddInt32(&r.calls, 1)
	return r.value
}

func TestCheckInputReadsFileDLPSettingOncePerRequest(t *testing.T) {
	reader := &countingFileDLPSettingReader{value: true}
	client := NewSecurityClient("http://127.0.0.1:1").WithFileDLPSettingReader(reader)
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))

	client.CheckInput(req.Context(), "tenant-a", "request-snapshot", req)
	if got := atomic.LoadInt32(&reader.calls); got != 1 {
		t.Fatalf("单次请求必须只读取一次文件 DLP 开关, got %d", got)
	}
}

func TestSecurityAuditOnlyEnvironmentCannotBeDisabledByDynamicReader(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	reader := &countingFileDLPSettingReader{value: false}
	client := NewSecurityClient("http://127.0.0.1:1").WithSecurityAuditOnlySettingReader(reader)

	if !client.securityAuditOnly(context.Background()) {
		t.Fatal("SECURITY_AUDIT_ONLY=true must remain audit-only when database reader returns false")
	}
	if got := atomic.LoadInt32(&reader.calls); got != 0 {
		t.Fatalf("forced audit mode must not query a reader that could weaken it, got %d call(s)", got)
	}
}

// 10 秒 TTL：TTL 内复用缓存，不重复查库；TTL 过期后重新查询拿新值。
func TestDBFileDLPSettingReaderCachesWithinTTL(t *testing.T) {
	var calls int32
	var cur atomic.Value
	cur.Store("")
	r := NewDBFileDLPSettingReader(func(_ context.Context, _ string, _ ...any) rowScanner {
		atomic.AddInt32(&calls, 1)
		v, _ := cur.Load().(string)
		return stubScanner{value: v}
	}).(*DBFileDLPSettingReader)
	r.ttl = 50 * time.Millisecond

	ctx := context.Background()
	_ = r.Enabled(ctx)
	_ = r.Enabled(ctx)
	_ = r.Enabled(ctx)
	if calls != 1 {
		t.Fatalf("TTL 内应只查一次库, got %d", calls)
	}
	// 切换仓储值，TTL 内仍读旧缓存（空 → false）。
	cur.Store("true")
	if r.Enabled(ctx) {
		t.Fatal("TTL 内不得刷新，应保持旧值 false")
	}
	// TTL 过期后读到新值 true。
	time.Sleep(60 * time.Millisecond)
	if !r.Enabled(ctx) {
		t.Fatal("TTL 过期后应读到新值 true")
	}
}

// ---- 测试桩 ----

// stubQueryFn 返回一个 querierFunc，按 err/value 模拟 system_settings 查询。
func stubQueryFn(err error, value string) querierFunc {
	return func(_ context.Context, _ string, _ ...any) rowScanner {
		return stubScanner{value: value, err: err}
	}
}

type stubScanner struct {
	value string
	err   error
}

func (s stubScanner) Scan(dest ...any) error {
	if s.err != nil {
		return s.err
	}
	if p, ok := dest[0].(*string); ok {
		*p = s.value
	}
	if len(dest) > 2 {
		*(dest[2].(*bool)) = true
	}
	return nil
}

// errNoRows / errDBUnavailable 在 file_dlp_setting.go 中定义。
var _ = sync.Mutex{}

func TestDBSecurityAuditOnlySettingReaderFirstFailureDefaultsToRecord(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	r := NewDBSecurityAuditOnlySettingReader(stubQueryFn(errDBUnavailable, ""))
	if !r.Enabled(context.Background()) {
		t.Fatal("security mode first read failure must default to record")
	}
}

func TestDBSecurityAuditOnlySettingReaderEnvironmentTrueOverridesDBFalse(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	r := NewDBSecurityAuditOnlySettingReader(stubQueryFn(nil, "false"))
	if !r.Enabled(context.Background()) {
		t.Fatal("deployment record mode must override dynamic protect")
	}
}

// 代码质量审查第三轮改动：原用例锁的是“旧键变成非法值时保留上次的防护”。控制面、引擎、网关
// 对非法旧键一律按安全默认记录模式（resolveSecurityExecutionMode），代理保留防护会对同一请求作出
// 相反的中断决定，所以改为断言非法值按记录，与控制面一致。
func TestDBSecurityAuditOnlySettingReaderInvalidValueFollowsControlPlaneSafeDefault(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	var calls int32
	r := NewDBSecurityAuditOnlySettingReader(func(_ context.Context, _ string, _ ...any) rowScanner {
		if atomic.AddInt32(&calls, 1) == 1 {
			return stubScanner{value: "false"}
		}
		return stubScanner{value: "invalid"}
	}).(*DBFileDLPSettingReader)
	r.ttl = time.Millisecond
	if r.Enabled(context.Background()) {
		t.Fatal("first valid false should enable protect")
	}
	time.Sleep(2 * time.Millisecond)
	if !r.Enabled(context.Background()) {
		t.Fatal("invalid legacy value must resolve to record like the control plane")
	}
}
