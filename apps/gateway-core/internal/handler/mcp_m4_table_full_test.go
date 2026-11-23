package handler

// 复审 M-4：会话表全局写满时，淘汰「全局最旧」会让攻击者用多个 key 灌满表，挤掉受害者的合法会话。
// 新语义：满了先清理空闲超时的；仍满则拒绝新登记（503 + 日志），绝不淘汰其他主体的会话。每主体上限保持不变（淘汰自己最旧的）。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestM4_AttackerFillingTheTableCannotEvictVictimSession(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newMCPMemorySessionStore()
	s.now = func() time.Time { return now }
	s.maxTotal, s.maxPerPrincipal, s.idleTTL, s.maxLifetime = 6, 3, time.Hour, 24*time.Hour
	ctx := context.Background()
	victim := mcpSessionBinding{Principal: "victim", RouteHash: "h"}
	if err := s.Put(ctx, "t", "s", "victim-sess", victim); err != nil {
		t.Fatal(err)
	}
	// 攻击者用多个主体持续登记，试图把表灌满并挤掉最旧的受害者会话
	var rejected int
	for i := 0; i < 20; i++ {
		now = now.Add(time.Second)
		err := s.Put(ctx, "t", "s", fmt.Sprintf("atk-%d", i), mcpSessionBinding{Principal: fmt.Sprintf("attacker-%d", i/3), RouteHash: "h"})
		if errors.Is(err, errMCPSessionTableFull) {
			rejected++
		}
	}
	if rejected == 0 {
		t.Fatalf("表满后应拒绝新登记（errMCPSessionTableFull），实际全部被接受，说明在挤掉别人")
	}
	if _, ok, _ := s.Get(ctx, "t", "s", "victim-sess"); !ok {
		t.Fatalf("受害者的合法会话不得被攻击者挤掉")
	}
	if n := s.len(); n > 6 {
		t.Fatalf("总量必须有界: %d", n)
	}
}

func TestM4_FullTableFirstReclaimsIdleSessions(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newMCPMemorySessionStore()
	s.now = func() time.Time { return now }
	s.maxTotal, s.maxPerPrincipal, s.idleTTL, s.maxLifetime = 3, 3, time.Minute, 24*time.Hour
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.Put(ctx, "t", "s", fmt.Sprintf("old-%d", i), mcpSessionBinding{Principal: fmt.Sprintf("p%d", i), RouteHash: "h"}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Minute) // 全部空闲超时
	if err := s.Put(ctx, "t", "s", "fresh", mcpSessionBinding{Principal: "newcomer", RouteHash: "h"}); err != nil {
		t.Fatalf("空闲超时的会话应先被回收，新登记应成功: %v", err)
	}
	if _, ok, _ := s.Get(ctx, "t", "s", "fresh"); !ok {
		t.Fatal("新会话应已登记")
	}
}

func TestM4_PerPrincipalLimitStillEvictsOnlyThatPrincipalsOldest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newMCPMemorySessionStore()
	s.now = func() time.Time { return now }
	s.maxTotal, s.maxPerPrincipal, s.idleTTL, s.maxLifetime = 10, 2, time.Hour, 24*time.Hour
	ctx := context.Background()
	b := func(p string) mcpSessionBinding { return mcpSessionBinding{Principal: p, RouteHash: "h"} }
	_ = s.Put(ctx, "t", "s", "other", b("other"))
	_ = s.Put(ctx, "t", "s", "a1", b("a"))
	_ = s.Put(ctx, "t", "s", "a2", b("a"))
	if err := s.Put(ctx, "t", "s", "a3", b("a")); err != nil {
		t.Fatalf("每主体超限应淘汰自己最旧的而不是拒绝: %v", err)
	}
	if _, ok, _ := s.Get(ctx, "t", "s", "a1"); ok {
		t.Fatal("该主体最旧的 a1 应被淘汰")
	}
	if _, ok, _ := s.Get(ctx, "t", "s", "other"); !ok {
		t.Fatal("其他主体的会话不得受影响")
	}
}

// 端到端：表满时 initialize 登记失败要如实暴露为 503，而不是给客户端一个事后必 404 的会话 id。
func TestM4_InitializeWhenTableFullReturns503AndIssuesNoSession(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	env.handler.SetMCPSessionStore(fullStore{})
	w := doAsKey(env, "key-a", http.MethodPost, sessInit, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("会话表已满时 initialize 应 503，实际 %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("登记失败时不得把上游签发的会话 id 交给客户端: %q", w.Header().Get("Mcp-Session-Id"))
	}
}

type fullStore struct{}

func (fullStore) Put(context.Context, string, string, string, mcpSessionBinding) error {
	return errMCPSessionTableFull
}
func (fullStore) Get(context.Context, string, string, string) (mcpSessionBinding, bool, error) {
	return mcpSessionBinding{}, false, nil
}
func (fullStore) Delete(context.Context, string, string, string) error { return nil }
