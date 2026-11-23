package handler

// D1（网关侧）：拉取红线配置失败且无缓存时，红线保持“仅告警”的降级行为不变（原设计），
// 但运维必须看得见：日志带 [WARN]/[ERROR] 级别标识、同一租户限频（避免每个请求刷一条）、
// 并暴露失败计数供健康/状态接口展示。

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

func redlineHandlerWithBrokenControlPlane(t *testing.T) (*MCPProxyHandler, *int32) {
	t.Helper()
	var hits int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r) // 模拟路由缺失（本次验收缺陷）
	}))
	t.Cleanup(cp.Close)
	h := NewMCPProxyHandler(nil, NewToolRiskClient(cp.URL, "s"), false)
	t.Cleanup(h.sseBridge.Close)
	return h, &hits
}

func TestRedlineFetchFailureStaysAlertOnlyButIsLoudlyLogged(t *testing.T) {
	buf := captureLog(t)
	h, _ := redlineHandlerWithBrokenControlPlane(t)
	actions := h.mcpRedlineActions(context.Background(), "tenant_x")
	if len(actions) != 0 {
		t.Fatalf("原设计：拉取失败且无缓存时红线只告警（空表），不得改变: %v", actions)
	}
	out := buf.String()
	if !strings.Contains(out, "[WARN]") && !strings.Contains(out, "[ERROR]") {
		t.Fatalf("降级日志必须带级别标识以便运维按级别过滤告警: %q", out)
	}
	if !strings.Contains(out, "tenant_x") || !strings.Contains(out, "alert-only") {
		t.Fatalf("日志要写明租户与降级后果: %q", out)
	}
}

func TestRedlineFetchFailureLogIsRateLimitedPerTenant(t *testing.T) {
	buf := captureLog(t)
	h, hits := redlineHandlerWithBrokenControlPlane(t)
	for i := 0; i < 50; i++ {
		_ = h.mcpRedlineActions(context.Background(), "tenant_x")
	}
	if n := strings.Count(buf.String(), "tenant_x"); n > 3 {
		t.Fatalf("同一租户的重复失败必须限频，50 次请求只应记 1 条左右，实际 %d 条", n)
	}
	// 失败不能被缓存成“成功”：每次请求仍会重拉（带上退避的另说），保证控制面修复后能立即恢复。
	if atomic.LoadInt32(hits) < 2 {
		t.Fatalf("失败后应继续尝试重拉，hits=%d", atomic.LoadInt32(hits))
	}
	// 另一个租户有自己的限频窗口，不能被前一个租户吞掉。
	_ = h.mcpRedlineActions(context.Background(), "tenant_y")
	if !strings.Contains(buf.String(), "tenant_y") {
		t.Fatal("每个租户的首次失败都必须有日志")
	}
}

func TestRedlineFetchFailureCounterIsExposed(t *testing.T) {
	_ = captureLog(t)
	h, _ := redlineHandlerWithBrokenControlPlane(t)
	if f, _ := h.RedlineFetchStatus(); f != 0 {
		t.Fatalf("初始失败计数应为 0: %d", f)
	}
	for i := 0; i < 5; i++ {
		_ = h.mcpRedlineActions(context.Background(), "tenant_x")
	}
	failures, lastErr := h.RedlineFetchStatus() // 第二个返回值现在是失败类别，不是错误原文
	if failures < 5 || lastErr == "" {
		t.Fatalf("失败计数与最近错误必须可读（供 /health 展示）: failures=%d lastErr=%q", failures, lastErr)
	}
	if strings.Contains(lastErr, "tenant_x") && strings.Contains(lastErr, "secret") {
		t.Fatalf("状态里不得带敏感信息: %q", lastErr)
	}
}

func TestRedlineFetchRecoveryClearsDegradedState(t *testing.T) {
	_ = captureLog(t)
	var ok atomic.Bool
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok.Load() {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"actions":{"cloud_metadata":"block"}}`))
	}))
	defer cp.Close()
	h := NewMCPProxyHandler(nil, NewToolRiskClient(cp.URL, "s"), false)
	defer h.sseBridge.Close()
	h.redlineSettings.ttl = time.Millisecond
	_ = h.mcpRedlineActions(context.Background(), "t1")
	ok.Store(true)
	time.Sleep(5 * time.Millisecond)
	if got := h.mcpRedlineActions(context.Background(), "t1"); got["cloud_metadata"] != "block" {
		t.Fatalf("控制面恢复后必须立刻拿到 block 配置: %v", got)
	}
	if _, lastErr := h.RedlineFetchStatus(); lastErr != "" {
		t.Fatalf("恢复后应清掉降级状态，lastErr=%q", lastErr)
	}
}
