package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAllOutboundRequestsHaveTimeout 锁定「每个出向请求都有超时预算」这一不变量。
//
// 背景：http.Client.Timeout 已置 0（它是含读体的全局墙钟，无法按请求区分预算），
// 因此每条出向路径都必须自己拿到 context deadline。漏掉任何一处，引擎挂住时
// 该调用会无限等待并拖住整个请求链。这个测试覆盖不走 check() 的那几条路径。
func TestAllOutboundRequestsHaveTimeout(t *testing.T) {
	// 服务端睡够长时间来模拟「引擎挂住」，但必须能自行返回：
	// 若 handler 阻塞在 <-r.Context().Done() 上，客户端超时并不会取消服务端 ctx，
	// httptest.Server.Close() 会一直等这些 handler 退出，把测试自己挂死。
	stop := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stop:
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	// 先放掉所有 handler，再 Close，避免 Close 卡在 WaitGroup 上。
	defer func() {
		close(stop)
		hang.Close()
	}()

	t.Setenv("SECURITY_ENGINE_TIMEOUT", "120ms")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "120ms")

	cases := []struct {
		name string
		call func(*Client) error
	}{
		{"CheckInput", func(c *Client) error {
			_, err := c.CheckInput(context.Background(), &CheckInputRequest{RequestID: "t", Content: "x"})
			return err
		}},
		{"CheckTriage", func(c *Client) error {
			_, err := c.CheckTriage(context.Background(), &CheckTriageRequest{RequestID: "t"})
			return err
		}},
		{"LookupFileVerdict", func(c *Client) error {
			_, err := c.LookupFileVerdict(context.Background(), "tenant", "subject", "provider", "file")
			return err
		}},
		{"ApplyContext", func(c *Client) error {
			_, err := c.ApplyContext(context.Background(), &ApplyContextRequest{TenantID: "t"})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(hang.URL)
			done := make(chan error, 1)
			start := time.Now()
			go func() { done <- tc.call(c) }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("%s 对挂死的引擎应返回错误", tc.name)
				}
				if elapsed := time.Since(start); elapsed > 2*time.Second {
					t.Fatalf("%s 超时预算未生效，等了 %v", tc.name, elapsed)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s 未在预算内返回——该出向请求缺少超时预算", tc.name)
			}
		})
	}
}
