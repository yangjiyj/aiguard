package handler

// 2.9.22 复审补充第 1 项：system_settings 读取器查库加 2 秒超时，查库期间不持锁；
// 超时或失败按现有规则回落（从未读到时取回落值，读到过时保留上次值）。

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSettingReaderQueryTimeoutIsTwoSeconds(t *testing.T) {
	if settingQueryTimeout != 2*time.Second {
		t.Fatalf("查库超时应为 2 秒，实际 %s", settingQueryTimeout)
	}
}

func TestSettingReaderQueryTimesOutAndFallsBack(t *testing.T) {
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "closed")
	reader := NewDBDetectionFailClosedSettingReader(func(ctx context.Context, _ string, _ ...any) rowScanner {
		<-ctx.Done() // 数据库卡住：只有超时能让它返回
		return stubScanner{err: ctx.Err()}
	}).(*DBFileDLPSettingReader)
	reader.queryTimeout = 50 * time.Millisecond
	done := make(chan bool, 1)
	go func() { done <- reader.Enabled(context.Background()) }()
	select {
	case got := <-done:
		if !got {
			t.Fatal("超时后应按回落规则取 PROXY_DETECTION_FAIL_MODE=closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("查库没有超时，调用被卡住")
	}
}

func TestSettingReaderDoesNotHoldLockWhileQuerying(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var block atomic.Bool
	reader := NewDBDetectionFailClosedSettingReader(func(ctx context.Context, _ string, _ ...any) rowScanner {
		if block.Load() {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return stubScanner{value: "true"}
	}).(*DBFileDLPSettingReader)
	if !reader.Enabled(context.Background()) {
		t.Fatal("初次读取应得到 true")
	}
	block.Store(true)
	reader.mu.Lock()
	reader.expireAt = time.Time{}
	reader.mu.Unlock()
	go reader.Enabled(context.Background())
	<-entered // 第一个调用已进入查库

	done := make(chan bool, 1)
	go func() {
		verified := reader.runtimeValueVerified()
		_ = verified
		done <- reader.Enabled(context.Background())
	}()
	select {
	case got := <-done:
		if !got {
			t.Fatal("刷新进行中应返回上次的值")
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("查库期间持有锁，其他调用被阻塞")
	}
	close(release)
}

// 代码质量审查第三轮：首次读取在途时，并发调用等它读完，不再各自查库。
func TestSettingReaderMergesConcurrentFirstReads(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	reader := NewDBDetectionFailClosedSettingReader(func(ctx context.Context, _ string, _ ...any) rowScanner {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return stubScanner{value: "true"}
	}).(*DBFileDLPSettingReader)
	const n = 8
	results := make(chan bool, n)
	var wg sync.WaitGroup
	start := func() {
		wg.Add(1)
		go func() { defer wg.Done(); results <- reader.Enabled(context.Background()) }()
	}
	start()
	<-entered
	for i := 1; i < n; i++ {
		start()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	for got := range results {
		if !got {
			t.Fatal("等待首次读取的调用应拿到读到的值")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("首次读取应只查一次库：calls=%d", calls.Load())
	}
}

// 查库与调用方的取消脱钩：客户端断开不让读取失败，只受读取器自己的超时约束。
func TestSettingReaderIgnoresCallerCancellation(t *testing.T) {
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "open")
	reader := NewDBDetectionFailClosedSettingReader(func(ctx context.Context, _ string, _ ...any) rowScanner {
		if err := ctx.Err(); err != nil {
			return stubScanner{err: err}
		}
		return stubScanner{value: "true"}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !reader.Enabled(ctx) {
		t.Fatal("调用方已取消时仍应读到库里的 true")
	}
}

// 与控制面同一解析：只认 true/false（不分大小写、可带空白），空值当没存；其他取值在执行模式
// 旧键上按记录（控制面 resolveSecurityExecutionMode 的安全默认），在其他开关上按关闭（同签名投影）。
func TestSettingReaderParsesLikeControlPlane(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("PROXY_DETECTION_FAIL_MODE", "closed")
	for _, tc := range []struct {
		name   string
		reader func(querierFunc) FileDLPSettingReader
		raw    string
		want   bool
	}{
		{"执行模式旧键非法按记录", NewDBSecurityAuditOnlySettingReader, "maybe", true},
		{"执行模式旧键大写空白", NewDBSecurityAuditOnlySettingReader, " FALSE ", false},
		{"检测即拦非法按关闭", NewDBDetectionFailClosedSettingReader, "1", false},
		{"检测即拦大写", NewDBDetectionFailClosedSettingReader, "TRUE", true},
		{"检测即拦空值当没存", NewDBDetectionFailClosedSettingReader, " ", true},
		{"文件检测非法按关闭", NewDBFileDLPSettingReader, "yes", false},
	} {
		if got := tc.reader(stubQueryFn(nil, tc.raw)).Enabled(context.Background()); got != tc.want {
			t.Errorf("%s：raw=%q got %v want %v", tc.name, tc.raw, got, tc.want)
		}
	}
}
