package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTimeoutForPayloadScalesWithSize 锁定「超时随 payload 体量线性放宽」。
//
// 背景：security-engine 检测耗时与文本长度成正比（home 实测约 16ms/KB），
// 此前写死 30s 导致约 2MB 的单条 message 必然超时，进而被 fail-close 判成 403。
func TestTimeoutForPayloadScalesWithSize(t *testing.T) {
	t.Setenv("SECURITY_ENGINE_TIMEOUT", "")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "")
	c := NewClient("http://se.invalid")

	small := c.timeoutForPayload(1024)
	if small < defaultSecurityBaseTimeout {
		t.Fatalf("小 payload 不应低于基准超时: got %v, base %v", small, defaultSecurityBaseTimeout)
	}

	// 2MB：此前写死 30s 会超时，现在必须给出明显更宽的预算。
	large := c.timeoutForPayload(2 * 1024 * 1024)
	if large <= small {
		t.Fatalf("大 payload 预算应更宽: small=%v large=%v", small, large)
	}
	if large <= 30*time.Second {
		t.Fatalf("2MB 预算必须超过旧的写死 30s，否则回归: got %v", large)
	}
}

// TestTimeoutForPayloadRespectsMaxCap 确认分级有硬顶，不会被超大 payload 拖成无限等待。
func TestTimeoutForPayloadRespectsMaxCap(t *testing.T) {
	t.Setenv("SECURITY_ENGINE_TIMEOUT", "")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "45s")
	c := NewClient("http://se.invalid")

	if got := c.timeoutForPayload(512 * 1024 * 1024); got != 45*time.Second {
		t.Fatalf("超大 payload 应被夹到上限 45s: got %v", got)
	}
}

// TestResolveBaseTimeoutFallsBackOnInvalidEnv 非法 env 必须回落默认值，不能变成 0（0 = 永不超时）。
func TestResolveBaseTimeoutFallsBackOnInvalidEnv(t *testing.T) {
	for _, raw := range []string{"", "abc", "-5s", "0s"} {
		t.Setenv("SECURITY_ENGINE_TIMEOUT", raw)
		if got := resolveBaseTimeout(); got != defaultSecurityBaseTimeout {
			t.Fatalf("env=%q 应回落默认值 %v: got %v", raw, defaultSecurityBaseTimeout, got)
		}
	}

	t.Setenv("SECURITY_ENGINE_TIMEOUT", "20s")
	if got := resolveBaseTimeout(); got != 20*time.Second {
		t.Fatalf("合法 env 应生效: got %v", got)
	}
}

// TestCheckInputTimesOutSlowEngine 确认慢引擎会以超时错误返回（而非无限挂住）。
func TestCheckInputTimesOutSlowEngine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(CheckInputResponse{Action: "allow"})
	}))
	defer srv.Close()

	t.Setenv("SECURITY_ENGINE_TIMEOUT", "150ms")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "150ms")
	c := NewClient(srv.URL)

	start := time.Now()
	_, err := c.CheckInput(context.Background(), &CheckInputRequest{
		RequestID: "t-slow", Content: "hello", ContentType: "text",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("慢引擎应返回超时错误")
	}
	if elapsed > time.Second {
		t.Fatalf("应在预算内放弃，实际等了 %v", elapsed)
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("错误应可被识别为超时，便于上层区分「不可达」与「超时」: %v", err)
	}
}

// TestCheckInputHonorsCallerDeadline 调用方更短的 deadline 不能被分级放宽覆盖。
func TestCheckInputHonorsCallerDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SECURITY_ENGINE_TIMEOUT", "60s")
	c := NewClient(srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := c.CheckInput(ctx, &CheckInputRequest{RequestID: "t-caller", Content: "x"}); err == nil {
		t.Fatal("应因调用方 deadline 而失败")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("调用方 deadline 应优先生效，实际等了 %v", elapsed)
	}
}

// TestCheckInputLargePayloadSucceedsWithinScaledBudget 大 payload 在分级预算内应成功，
// 这正是修复的目标场景：codex 长上下文不再被误判为引擎不可用。
func TestCheckInputLargePayloadSucceedsWithinScaledBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟按体量增长的检测耗时
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckInputResponse{Action: "allow", LatencyMs: 300})
	}))
	defer srv.Close()

	// 基准很小，靠体量分级把预算撑起来：2MB * 50ms/KB 远超 300ms
	t.Setenv("SECURITY_ENGINE_TIMEOUT", "50ms")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "180s")
	c := NewClient(srv.URL)

	resp, err := c.CheckInput(context.Background(), &CheckInputRequest{
		RequestID:   "t-large",
		Content:     strings.Repeat("x", 2*1024*1024),
		ContentType: "text",
	})
	if err != nil {
		t.Fatalf("大 payload 应在分级预算内成功: %v", err)
	}
	if resp.Action != "allow" {
		t.Fatalf("unexpected action: %s", resp.Action)
	}
}

// TestCheckInputUnreachableEngineIsNotTimeout 引擎不可达的错误不得看起来像超时，
// 否则上层的附件硬门会把「从未检测」误当成「检测超时」而放行。
func TestCheckInputUnreachableEngineIsNotTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unauthorized")
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.CheckInput(context.Background(), &CheckInputRequest{RequestID: "t-401", Content: "x"})
	if err == nil {
		t.Fatal("401 应返回错误")
	}
	if strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("鉴权失败不应被表述为超时: %v", err)
	}
}

func TestDefaultClientBudgetCoversManagedSemanticScan(t *testing.T) {
	t.Setenv("SECURITY_ENGINE_TIMEOUT", "")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "")
	c := NewClient("http://se.invalid")
	if c.timeoutForPayload(64) < 17*time.Second {
		t.Fatal("client cancels a 15s semantic scan before its transport margin")
	}
	parent, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	bounded, stop := c.withPayloadTimeout(parent, 64)
	defer stop()
	deadline, _ := bounded.Deadline()
	parentDeadline, _ := parent.Deadline()
	if deadline.After(parentDeadline) {
		t.Fatal("client must not extend a caller deadline")
	}
}
