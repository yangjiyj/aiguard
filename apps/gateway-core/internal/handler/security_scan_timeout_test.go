package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestIsSecurityScanTimeoutClassification 锁定「超时」与「引擎不可达」的判定边界。
//
// 这个区分是附件硬门的依据：超时说明引擎已收到请求并在检测，只是没跑完；
// 不可达说明内容从未被检测过，带附件时必须固定 fail-closed。
// 判错方向的后果不对称——把不可达误判成超时会让未扫描的文件被放行。
func TestIsSecurityScanTimeoutClassification(t *testing.T) {
	timeoutCases := []struct {
		name string
		err  error
	}{
		{"context.DeadlineExceeded 直接返回", context.DeadlineExceeded},
		{"被 fmt.Errorf 包装（真实调用链形态）", fmt.Errorf("failed to call security engine: %w", context.DeadlineExceeded)},
		{"多层包装", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", context.DeadlineExceeded))},
		{"net.Error 且 Timeout() 为真", &net.DNSError{IsTimeout: true}},
	}
	for _, tc := range timeoutCases {
		t.Run("timeout/"+tc.name, func(t *testing.T) {
			if !isSecurityScanTimeout(tc.err) {
				t.Fatalf("应判定为超时: %v", tc.err)
			}
		})
	}

	notTimeoutCases := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"鉴权失败", errors.New("security engine returned status 401: unauthorized")},
		{"服务端错误", errors.New("security engine returned status 503: unavailable")},
		{"连接被拒", &net.OpError{Op: "dial", Err: errors.New("connection refused")}},
		{"响应解码失败", errors.New("failed to decode response: unexpected EOF")},
		{"context 被取消（客户端主动断开，非引擎慢）", context.Canceled},
		{"DNS 失败但非超时", &net.DNSError{IsNotFound: true}},
	}
	for _, tc := range notTimeoutCases {
		t.Run("not-timeout/"+tc.name, func(t *testing.T) {
			if isSecurityScanTimeout(tc.err) {
				t.Fatalf("不应判定为超时: %v", tc.err)
			}
		})
	}
}

// TestIsSecurityScanTimeoutMatchesRealClientError 用真实 HTTP 往返产生的错误做端到端校验，
// 避免判定逻辑只对手工构造的 error 生效、对真实调用链失效。
func TestIsSecurityScanTimeoutMatchesRealClientError(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer slow.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", slow.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, doErr := http.DefaultClient.Do(req)
	if doErr == nil {
		t.Fatal("预期超时错误")
	}
	wrapped := fmt.Errorf("failed to call security engine: %w", doErr)
	if !isSecurityScanTimeout(wrapped) {
		t.Fatalf("真实超时错误应被识别: %v", wrapped)
	}

	// 对照：401 走的是同一条包装路径，但不能被认成超时
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer deny.Close()
	authErr := fmt.Errorf("security engine returned status %d: %s", http.StatusUnauthorized, "unauthorized")
	if isSecurityScanTimeout(authErr) {
		t.Fatalf("鉴权失败不应被识别为超时: %v", authErr)
	}
}
