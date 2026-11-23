package handler

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// 明文 HTTP 转发（handleHTTP）：安全检测期间客户端断开（r.Context() 被取消）。
// 断开不是检测失败：记 cancelled/408，不写 security_check_failed / 拦截事件，不转发上游，
// 不走 fail-closed 的 503。对照组（引擎真的失败、请求 ctx 仍然存活）行为保持原样，
// 文件引用判决（allow-only 闸门）请求活着时照旧 fail-closed。
// 命名约定：helper 与类型统一用 pfg 前缀。

type pfgExec struct {
	sql    string
	args   []any
	ctxErr error
}

// pfgDB 是假的审计库：记录每次 Exec 的 SQL、参数和写入时 ctx 是否已取消。
type pfgDB struct {
	mu    sync.Mutex
	execs []pfgExec
}

func (d *pfgDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.execs = append(d.execs, pfgExec{sql: sql, args: args, ctxErr: ctx.Err()})
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (d *pfgDB) QueryRow(context.Context, string, ...any) pgx.Row { return pfgRow{} }

type pfgRow struct{}

func (pfgRow) Scan(...any) error { return errors.New("pfg: no rows") }

var _ retentionartifact.RepositoryDB = (*pfgDB)(nil)

func (d *pfgDB) snapshot() []pfgExec {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]pfgExec(nil), d.execs...)
}

// lastRequestLog 返回最后一次 request_logs 写入的 (status, status_code)。
func (d *pfgDB) lastRequestLog(t *testing.T) (string, int) {
	t.Helper()
	execs := d.snapshot()
	for i := len(execs) - 1; i >= 0; i-- {
		if strings.Contains(execs[i].sql, "request_logs") && len(execs[i].args) > 4 {
			code, _ := execs[i].args[4].(int)
			return fmt.Sprint(execs[i].args[3]), code
		}
	}
	t.Fatalf("没有写入任何 request_logs")
	return "", 0
}

// securityEvents 返回写入的 security_events 事件类型。
func (d *pfgDB) securityEvents() []string {
	var out []string
	for _, e := range d.snapshot() {
		if strings.Contains(e.sql, "security_events") && len(e.args) > 4 {
			out = append(out, fmt.Sprint(e.args[4]))
		}
	}
	return out
}

func (d *pfgDB) requireDetachedWrites(t *testing.T) {
	t.Helper()
	for _, e := range d.snapshot() {
		if e.ctxErr != nil && (strings.Contains(e.sql, "security_events") || strings.Contains(e.sql, "request_logs")) {
			t.Errorf("审计写入用了已取消的 ctx（%v）: %.60s", e.ctxErr, e.sql)
		}
	}
}

type pfgEnv struct {
	h             *ProxyHandler
	db            *pfgDB
	upstreamCalls *atomic.Int64
	ctx           context.Context
	cancel        context.CancelFunc
}

// newPFGEnv 搭一个明文转发 handler + 假审计库 + 假上游；engine 是安全引擎的 handler。
func newPFGEnv(t *testing.T, auditOnly bool, failMode string, engine http.HandlerFunc) *pfgEnv {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", strconv.FormatBool(auditOnly))
	t.Setenv("PROXY_DETECTION_FAIL_MODE", failMode)
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	db := &pfgDB{}
	writer := NewAuditWriter(nil)
	writer.db = db
	calls := &atomic.Int64{}
	// 目标主机显式在白名单内：否则白名单审计会先写一条同 request_id 的覆盖缺口事件，干扰事件断言。
	checker := newCheckerWithRules([]WhitelistRule{
		{HostPattern: "files.example.test", Port: 80, TenantID: "tenant_default", AuditEnabled: true},
		{HostPattern: "api.openai.com", Port: 80, TenantID: "tenant_default", AuditEnabled: true},
	})
	h := NewProxyHandler(checker, nil, NewSecurityClient(srv.URL), writer, nil)
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("forwarded")), Request: r}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &pfgEnv{h: h, db: db, upstreamCalls: calls, ctx: ctx, cancel: cancel}
}

// blockUntilGone 返回一个引擎 handler：命中 match 的调用先取消请求 ctx（模拟客户端断开），
// 再阻塞到网关侧放弃；其余调用走 other。
func (e *pfgEnv) blockUntilGone(match func(*http.Request) bool, other http.HandlerFunc) http.HandlerFunc {
	var once sync.Once
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if !match(r) {
			other(w, r)
			return
		}
		once.Do(e.cancel)
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}
}

func pfgPDFRequest(ctx context.Context) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", strings.NewReader("%PDF-1.4\nsafe text")).WithContext(ctx)
	r.Header.Set("Content-Type", "application/pdf")
	return r
}

func pfgFileIDRequest(ctx context.Context) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://api.openai.com/v1/responses",
		strings.NewReader(`{"model":"gpt-test","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-pfg","filename":"report.pdf"}]}]}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func pfgAllow(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"action":"allow","findings":[]}`)
}

func pfgEngineDown(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "detector unavailable", http.StatusServiceUnavailable)
}

type pfgConfig struct {
	auditOnly bool
	failMode  string
}

func (c pfgConfig) name() string {
	return "record=" + strconv.FormatBool(c.auditOnly) + "/mode=" + c.failMode
}

var pfgConfigs = []pfgConfig{{false, "closed"}, {false, "open"}, {true, "closed"}, {true, "open"}}

func (e *pfgEnv) requireCleanGone(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := e.upstreamCalls.Load(); got != 0 {
		t.Errorf("断开后不应转发上游, upstream calls=%d", got)
	}
	if w.Code != http.StatusRequestTimeout {
		t.Errorf("http=%d, want 408 (body=%q)", w.Code, w.Body.String())
	}
	if status, code := e.db.lastRequestLog(t); status != "cancelled" || code != http.StatusRequestTimeout {
		t.Errorf("审计状态=%s/%d, want cancelled/408", status, code)
	}
	if events := e.db.securityEvents(); len(events) != 0 {
		t.Errorf("断开不应写安全事件: %v", events)
	}
	e.db.requireDetachedWrites(t)
}

// 安全引擎检测调用期间断开。
func TestPlainForwardClientGoneDuringInputCheck(t *testing.T) {
	for _, cfg := range pfgConfigs {
		t.Run("client_gone/"+cfg.name(), func(t *testing.T) {
			var e *pfgEnv
			e = newPFGEnv(t, cfg.auditOnly, cfg.failMode, func(w http.ResponseWriter, r *http.Request) {
				e.blockUntilGone(func(*http.Request) bool { return true }, pfgAllow)(w, r)
			})
			w := httptest.NewRecorder()
			e.h.handleHTTP(w, pfgPDFRequest(e.ctx))
			e.requireCleanGone(t, w)
		})
		t.Run("engine_down/"+cfg.name(), func(t *testing.T) {
			e := newPFGEnv(t, cfg.auditOnly, cfg.failMode, pfgEngineDown)
			w := httptest.NewRecorder()
			e.h.handleHTTP(w, pfgPDFRequest(e.ctx))
			events := e.db.securityEvents()
			if len(events) != 1 || events[0] != "security_check_failed" {
				t.Errorf("对照组应写 1 条 security_check_failed, got %v", events)
			}
			if !cfg.auditOnly && cfg.failMode == "closed" {
				if w.Code != http.StatusServiceUnavailable || e.upstreamCalls.Load() != 0 {
					t.Errorf("fail-closed 对照组应 503 且不转发: http=%d upstream=%d", w.Code, e.upstreamCalls.Load())
				}
				if status, _ := e.db.lastRequestLog(t); status != "blocked" {
					t.Errorf("fail-closed 对照组审计状态=%s, want blocked", status)
				}
				return
			}
			if w.Code != http.StatusOK || e.upstreamCalls.Load() != 1 {
				t.Errorf("非 fail-closed 对照组应放行: http=%d upstream=%d", w.Code, e.upstreamCalls.Load())
			}
		})
	}
}

// 文件引用判决（allow-only 闸门）查询期间断开；对照组请求活着时查询失败照旧 fail-closed。
func TestPlainForwardClientGoneDuringFileVerdictGate(t *testing.T) {
	isVerdict := func(r *http.Request) bool { return r.URL.Path == "/scan-objects/verdict" }
	for _, cfg := range pfgConfigs {
		t.Run("client_gone/"+cfg.name(), func(t *testing.T) {
			var e *pfgEnv
			e = newPFGEnv(t, cfg.auditOnly, cfg.failMode, func(w http.ResponseWriter, r *http.Request) {
				e.blockUntilGone(isVerdict, pfgAllow)(w, r)
			})
			w := httptest.NewRecorder()
			e.h.handleHTTP(w, pfgFileIDRequest(e.ctx))
			e.requireCleanGone(t, w)
		})
		t.Run("lookup_failed/"+cfg.name(), func(t *testing.T) {
			e := newPFGEnv(t, cfg.auditOnly, cfg.failMode, func(w http.ResponseWriter, r *http.Request) {
				if isVerdict(r) {
					pfgEngineDown(w, r)
					return
				}
				pfgAllow(w, r)
			})
			w := httptest.NewRecorder()
			e.h.handleHTTP(w, pfgFileIDRequest(e.ctx))
			events := e.db.securityEvents()
			if len(events) != 1 {
				t.Errorf("判决查询失败应写 1 条事件, got %v", events)
			}
			if cfg.auditOnly {
				if w.Code != http.StatusOK || e.upstreamCalls.Load() != 1 {
					t.Errorf("只审计模式绝不拦截: http=%d upstream=%d", w.Code, e.upstreamCalls.Load())
				}
				return
			}
			// 2.9.22（任务 4.2）：查询失败按 file_reference_lookup_failure_action 处置，缺省告警放行
			// （原断言“请求活着时查询失败必须 fail-closed”随用户 11-17 决定改写；配成禁止见下一组）。
			if w.Code != http.StatusOK || e.upstreamCalls.Load() != 1 {
				t.Errorf("缺省告警放行: http=%d upstream=%d body=%q", w.Code, e.upstreamCalls.Load(), w.Body.String())
			}
		})
		t.Run("lookup_failed_block_configured/"+cfg.name(), func(t *testing.T) {
			e := newPFGEnv(t, cfg.auditOnly, cfg.failMode, func(w http.ResponseWriter, r *http.Request) {
				if isVerdict(r) {
					pfgEngineDown(w, r)
					return
				}
				pfgAllow(w, r)
			})
			e.h.securityClient.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.AlertAllow, LookupFailure: filereference.Block})
			w := httptest.NewRecorder()
			e.h.handleHTTP(w, pfgFileIDRequest(e.ctx))
			if cfg.auditOnly {
				if w.Code != http.StatusOK || e.upstreamCalls.Load() != 1 {
					t.Errorf("只审计模式绝不拦截: http=%d upstream=%d", w.Code, e.upstreamCalls.Load())
				}
				return
			}
			// 配成禁止时与普通检测失败模式无关：open 也照样拒绝。
			if w.Code != http.StatusForbidden || e.upstreamCalls.Load() != 0 {
				t.Errorf("配成禁止时判决查询失败必须拦: http=%d upstream=%d body=%q", w.Code, e.upstreamCalls.Load(), w.Body.String())
			}
			if status, _ := e.db.lastRequestLog(t); status != "blocked" {
				t.Errorf("审计状态=%s, want blocked", status)
			}
		})
	}
}

// cancelAfterResponse 先完整读回引擎响应再取消请求 ctx：检测本身成功，客户端在检测返回之后、
// 写安全事件之前断开。
type cancelAfterResponse struct {
	base   http.RoundTripper
	cancel context.CancelFunc
}

func (c cancelAfterResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	c.cancel()
	return resp, nil
}

// 检测返回真实命中（不拦截）后客户端断开：命中照常落安全事件，且写库不能用已取消的 ctx。
func TestPlainForwardSecurityEventWriteDetachedFromClientCancel(t *testing.T) {
	e := newPFGEnv(t, true, "open", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"audit","findings":[{"type":"secret","category":"api_key","severity":"high","rule_id":"pfg-1","action":"audit"}]}`)
	})
	e.h.securityClient.client = &http.Client{Transport: cancelAfterResponse{base: http.DefaultTransport, cancel: e.cancel}}
	e.h.handleHTTP(httptest.NewRecorder(), pfgPDFRequest(e.ctx))
	if events := e.db.securityEvents(); len(events) != 1 {
		t.Fatalf("真实命中应写 1 条安全事件, got %v", events)
	}
	e.db.requireDetachedWrites(t)
}

// 对照（钉住现状）：MITM 路径的检测 ctx 派生自 context.Background()，CONNECT 请求 ctx 取消
// 不会传到检测调用，检测失败照旧按 fail-closed 拒绝（503 inspection_unavailable），不会被判成断开。
func TestMITMInspectionCtxIgnoresConnectCancel(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "closed")
	cert := genTestCert(t)
	var upstreamHits int64
	ln, pool := fakeUpstream(t, cert, &upstreamHits)
	engine := httptest.NewServer(http.HandlerFunc(pfgEngineDown))
	t.Cleanup(engine.Close)
	h := &ProxyHandler{securityClient: NewSecurityClient(engine.URL), auditWriter: NewAuditWriter(nil), egressGuard: redirectGuard(ln.Addr().String())}

	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	connectCtx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil).WithContext(connectCtx)
		h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), r, "api.deepseek.com:443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = cliRaw.Close()
	<-done
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "inspection") {
		t.Fatalf("MITM 检测失败应照旧 503 fail-closed: status=%d body=%q", resp.StatusCode, body)
	}
	if atomic.LoadInt64(&upstreamHits) != 0 {
		t.Fatalf("fail-closed 不应转发上游, hits=%d", upstreamHits)
	}
}

// durable 检测路径：排队等待检测名额期间客户端断开（父 ctx 取消，等待返回 Canceled）不是容量不足。
// 名额通道无缓冲，admit 会一直等到请求 ctx 被取消。
func TestPlainForwardClientGoneDuringDurableAdmission(t *testing.T) {
	for _, cfg := range pfgConfigs {
		t.Run(cfg.name(), func(t *testing.T) {
			e := newPFGEnv(t, cfg.auditOnly, cfg.failMode, pfgAllow)
			e.h.securityClient.inspectionQueue = &InspectionQueue{slots: make(chan struct{})}
			r := httptest.NewRequest(http.MethodPost, "http://api.openai.com/v1/chat/completions",
				strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`)).WithContext(e.ctx)
			r.Header.Set("Content-Type", "application/json")
			time.AfterFunc(50*time.Millisecond, e.cancel)
			w := httptest.NewRecorder()
			e.h.handleHTTP(w, r)
			e.requireCleanGone(t, w)
		})
	}
}

// 判定函数的反向用例：检测超时（DeadlineExceeded）、请求 ctx 仍存活时的 Canceled 都不算断开。
func TestProxyClientGoneClassification(t *testing.T) {
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithTimeout(context.Background(), time.Nanosecond)
	defer stop()
	<-expired.Done()
	alive := context.Background()
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"canceled_ctx_canceled_err", gone, fmt.Errorf("post: %w", context.Canceled), true},
		{"canceled_ctx_other_err", gone, errors.New("connection refused"), false},
		{"deadline", expired, context.DeadlineExceeded, false},
		{"alive_ctx_canceled_err", alive, context.Canceled, false},
		{"nil_err", gone, nil, false},
	}
	for _, tc := range cases {
		if got := proxyClientGone(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: proxyClientGone=%v, want %v", tc.name, got, tc.want)
		}
	}
}
