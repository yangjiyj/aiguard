package handler

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// lockedBuffer 是并发安全的日志缓冲：后台协程写、测试读，裸 bytes.Buffer 在 -race 下会报数据竞争。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureGatewayLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	previous := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return buf
}

// 对端返回 5xx 且正文带敏感内容：日志要有状态码类别，不能带正文或请求 URL（含查询串里的用户/会话）。
func TestAgentGuardPolicyRefreshFailureLogCarriesClassNotBodyOrURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "db password=hunter2 host=db.internal", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	buf := captureGatewayLog(t)
	client := NewToolRiskClient(server.URL, "test-value")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-secret-77", SessionID: "sess-secret-88"}
	if _, err := client.GetAgentGuardPolicy(context.Background(), envelope); err == nil {
		t.Fatal("expected refresh failure")
	}
	out := buf.String()
	for _, want := range []string{"AgentGuard policy refresh failed", "tenant=tenant-1", "stale_available=false", "class=http_status", "http_status=503"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %q", out, want)
		}
	}
	for _, leaked := range []string{"hunter2", "db.internal", "user-secret-77", "sess-secret-88", server.URL} {
		if strings.Contains(out, leaked) {
			t.Fatalf("log leaks %q: %q", leaked, out)
		}
	}
}

// 连接被拒绝（*url.Error 包着 dial 错误）：旧日志只有 error_type=*url.Error，现在要能区分是连接失败。
func TestAgentGuardPolicyRefreshFailureLogClassifiesDialFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // 端口立即无人监听
	buf := captureGatewayLog(t)
	client := NewToolRiskClient(url, "test-value")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "project-1"}
	_, _ = client.GetAgentGuardPolicy(context.Background(), envelope)
	out := buf.String()
	if !strings.Contains(out, "class=connect_failed") || strings.Contains(out, "error_type=*url.Error") {
		t.Fatalf("log=%q", out)
	}
	if strings.Contains(out, url) {
		t.Fatalf("log leaks url: %q", out)
	}
}

// 超时：客户端 10s 超时会返回带 Timeout() 的 *url.Error。
func TestAgentGuardPolicyRefreshFailureLogClassifiesTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	buf := captureGatewayLog(t)
	client := NewToolRiskClient(server.URL, "test-value")
	client.httpClient.Timeout = 50 * time.Millisecond
	_, _ = client.GetAgentGuardPolicy(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "p"})
	if out := buf.String(); !strings.Contains(out, "class=timeout") {
		t.Fatalf("log=%q", out)
	}
}

// 现有行为不变：刷新失败时仍回退到上一份策略，并在日志里标明 stale_available=true。
func TestAgentGuardPolicyRefreshFailureStillServesStalePolicyAndSaysSo(t *testing.T) {
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"p","policy_version":"v1","mode":"strict","default_action":"allow","rules":[],"exceptions":[],"config_source":"tenant_policy"}}`))
	}))
	defer server.Close()
	buf := captureGatewayLog(t)
	client := NewToolRiskClient(server.URL, "test-value")
	client.agentGuardPolicyCache.ttl = 5 * time.Millisecond
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", ProjectID: "project-1"}
	if _, err := client.GetAgentGuardPolicy(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	fail = true
	policy, err := client.GetAgentGuardPolicy(context.Background(), envelope)
	if err != nil || policy == nil || policy.PolicyVersion != "v1" {
		t.Fatalf("stale policy not served: %#v err=%v", policy, err)
	}
	if out := buf.String(); !strings.Contains(out, "stale_available=true") || !strings.Contains(out, "class=http_status") {
		t.Fatalf("log=%q", out)
	}
}

// 语义运行时刷新失败：旧日志只有 %T（*errors.errorString）。
func TestSemanticRuntimeRefreshFailureLogCarriesClass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal detail tenant-secret", http.StatusBadGateway)
	}))
	defer server.Close()
	buf := captureGatewayLog(t)
	client := NewToolRiskClient(server.URL, "test-value")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := client.startSemanticRuntimeRefresh(ctx, time.Hour)
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "semantic runtime refresh failed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select { // 等协程退出后再断言，保证之后没有任何写入
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("semantic refresh goroutine did not stop after cancel")
	}
	out := buf.String()
	if !strings.Contains(out, "semantic runtime refresh failed") || !strings.Contains(out, "class=http_status") || !strings.Contains(out, "http_status=502") {
		t.Fatalf("log=%q", out)
	}
	if strings.Contains(out, "tenant-secret") || strings.Contains(out, "*errors.errorString") {
		t.Fatalf("log=%q", out)
	}
}

// 持续失败时语义刷新日志降噪（30 秒一次的周期下，一夜就是上千行）。
func TestSemanticRuntimeRefreshFailureLogIsThrottled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	buf := captureGatewayLog(t)
	client := NewToolRiskClient(server.URL, "test-value")
	for i := 0; i < 25; i++ {
		client.logSemanticRefreshFailure(context.DeadlineExceeded)
	}
	if lines := strings.Count(buf.String(), "semantic runtime refresh failed"); lines != 3 {
		t.Fatalf("lines=%d want 3", lines)
	}
}
