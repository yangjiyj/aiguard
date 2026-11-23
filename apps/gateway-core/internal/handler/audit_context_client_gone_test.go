package handler

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// timeoutNetError 模拟 net.Error 的网络超时（isSecurityScanTimeout 认作超时），它不是 context.Canceled。
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

// clientGoneDuring 只在「错误是 context.Canceled，且原始请求 ctx 已被取消」时为 true：
// 其余一律仍算检测失败，保持原有行为。
func TestClientGoneDuring(t *testing.T) {
	canceled := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	alive := func() context.Context { return context.Background() }
	expired := func() context.Context {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		cancel()
		return ctx
	}

	cases := []struct {
		name string
		ctx  func() context.Context
		err  error
		want bool
	}{
		{"Canceled 且请求 ctx 已取消", canceled, context.Canceled, true},
		{"Canceled 但请求 ctx 未取消（引擎内部自己 cancel）", alive, context.Canceled, false},
		{"DeadlineExceeded 且请求 ctx 已取消", canceled, context.DeadlineExceeded, false},
		{"DeadlineExceeded 且请求 ctx 未取消", alive, context.DeadlineExceeded, false},
		{"包装的 Canceled 且请求 ctx 已取消", canceled, fmt.Errorf("x: %w", context.Canceled), true},
		{"包装的 Canceled 但请求 ctx 未取消", alive, fmt.Errorf("x: %w", context.Canceled), false},
		{"nil 错误且请求 ctx 已取消", canceled, nil, false},
		{"nil 错误且请求 ctx 未取消", alive, nil, false},
		{"普通错误且请求 ctx 已取消", canceled, errors.New("engine down"), false},
		{"网络超时错误且请求 ctx 已取消", canceled, timeoutNetError{}, false},
		{"哨兵错误且请求 ctx 已取消", canceled, errClientGoneDuringSecurity, true},
		{"再包一层的哨兵错误且请求 ctx 已取消", canceled, fmt.Errorf("%w: input message 3", errClientGoneDuringSecurity), true},
		{"哨兵错误但请求 ctx 未取消", alive, errClientGoneDuringSecurity, false},
		{"Canceled 且请求 ctx 因超时结束", expired, context.Canceled, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientGoneDuring(tc.ctx(), tc.err); got != tc.want {
				t.Fatalf("clientGoneDuring(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// 派生的带超时 ctx 不能拿来判定：它到期后 Err() 也非 nil，但那是检测超时，不是客户端断开。
// 正确用法是传原始请求 ctx；这条用例钉住「用原始 ctx 时超时场景判为 false」。
func TestClientGoneDuringIgnoresDerivedTimeoutCtx(t *testing.T) {
	request := context.Background()
	derived, cancel := context.WithTimeout(request, time.Nanosecond)
	defer cancel()
	<-derived.Done()
	if clientGoneDuring(request, derived.Err()) {
		t.Fatalf("派生 ctx 超时（%v）被误判为客户端断开", derived.Err())
	}
}

// 哨兵错误必须能被 errors.Is 认成 context.Canceled（调用方的 client_canceled 分支依赖它），
// 同时不能被当成 fail-closed 的「检测不可用」拒绝。
func TestClientGoneSentinelShape(t *testing.T) {
	err := fmt.Errorf("%w: output choice 0", errClientGoneDuringSecurity)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("哨兵错误必须包装 context.Canceled")
	}
	if isGuardrailDetectionUnavailable(err) {
		t.Fatal("哨兵错误不能被当成 fail-closed 拒绝")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("哨兵错误不能被当成超时")
	}
}
