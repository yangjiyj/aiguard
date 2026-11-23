package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// 客户现场回归：工具没有专门配置时控制面返回空列表，原实现不缓存这个「未配置」答复，
// Claude Code 每个请求带几十个工具定义，就向控制面发几十次 /internal/tools/config，
// 现场每小时约 2 万次，配合磁盘抖动把数据库连接打满。「未配置」也要缓存（时间更短）。
func TestCheckToolRiskCachesUnconfiguredToolAnswer(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	c := NewToolRiskClient(srv.URL, "secret")
	for i := 0; i < 20; i++ {
		res, err := c.CheckToolRisk(context.Background(), "tenant-a", "Read")
		if err != nil || res == nil || res.Action != "audit" || res.Blocked {
			t.Fatalf("未配置工具应按默认审计放行：%+v err=%v", res, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("同一未配置工具 20 次检查应只问控制面 1 次，实际 %d 次", got)
	}
	// 未配置答复的缓存比已配置的短，新加的配置能较快生效。
	if unconfiguredToolCacheTTL >= 5*time.Minute || unconfiguredToolCacheTTL <= 0 {
		t.Fatalf("未配置答复缓存时长不合理：%v", unconfiguredToolCacheTTL)
	}
	c.InvalidateCache()
	if _, err := c.CheckToolRisk(context.Background(), "tenant-a", "Read"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("InvalidateCache 后应重新询问控制面，实际 %d 次", got)
	}
}

// 控制面出错（非 404/200）时不缓存，下一次仍重试，避免把一次故障固化成「未配置」。
func TestCheckToolRiskDoesNotCacheControlPlaneErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := NewToolRiskClient(srv.URL, "secret")
	for i := 0; i < 3; i++ {
		_, _ = c.CheckToolRisk(context.Background(), "tenant-a", "Bash")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("控制面出错不应被缓存，期望 3 次，实际 %d 次", got)
	}
}
