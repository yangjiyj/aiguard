package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeIntegrationStore struct {
	mu            sync.Mutex
	instanceModes []string
	policyLoads   int
	receipts      []string
	policies      []ai.Policy
	instanceErr   error
	loadErr       error
	receiptErr    error
}

func (f *fakeIntegrationStore) UpsertInstance(_ context.Context, _, _, mode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.instanceErr != nil {
		return f.instanceErr
	}
	f.instanceModes = append(f.instanceModes, mode)
	return nil
}

func (f *fakeIntegrationStore) LoadPolicies(context.Context) ([]ai.Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policyLoads++
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return append([]ai.Policy{}, f.policies...), nil
}

func (f *fakeIntegrationStore) UpsertReceipt(_ context.Context, _, policyID, _, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.receiptErr != nil {
		return f.receiptErr
	}
	f.receipts = append(f.receipts, policyID+"@"+version)
	return nil
}

func (f *fakeIntegrationStore) counts() (instances, loads, receipts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.instanceModes), f.policyLoads, len(f.receipts)
}

type fakeIntegrationClock struct{ now time.Time }

func (c *fakeIntegrationClock) Now() time.Time          { return c.now }
func (c *fakeIntegrationClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestIntegrationRuntime(t *testing.T, auditOnly *bool) (*IntegrationPolicyRuntime, *fakeIntegrationStore, *fakeIntegrationClock) {
	t.Helper()
	record := true
	if auditOnly != nil {
		record = *auditOnly
	}
	g := NewIntegrationPolicyRuntime(nil, func(context.Context) bool { return record }, nil)
	store := &fakeIntegrationStore{}
	clock := &fakeIntegrationClock{now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	g.store, g.now = store, clock.Now
	return g, store, clock
}

func protectPolicy(id, version string) ai.Policy {
	return ai.Policy{ID: id, TenantID: "tenant1", AgentInstanceID: "agent1", Action: "block_model_egress", Enabled: true, Mode: "protect", Version: version}
}

// 心跳是每台网关每 3 秒一次写入的来源：策略读取可以保持 3 秒，但心跳写入必须降频。
func TestIntegrationHeartbeatIsThrottledWhilePoliciesStillPollEveryRound(t *testing.T) {
	g, store, clock := newTestIntegrationRuntime(t, nil)
	for i := 0; i < 10; i++ { // 30 秒内 10 轮（每轮 3 秒）
		if err := g.refresh(context.Background()); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		clock.Advance(PolicyRefreshInterval)
	}
	instances, loads, _ := store.counts()
	if loads != 10 {
		t.Fatalf("policy loads=%d, want 10 (策略读取必须保持及时)", loads)
	}
	if instances != 1 {
		t.Fatalf("heartbeat writes in first 30s=%d, want 1", instances)
	}
	// 越过心跳间隔后再写一次。
	clock.Advance(ai.HeartbeatInterval)
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if instances, _, _ = store.counts(); instances != 2 {
		t.Fatalf("heartbeat after interval=%d, want 2", instances)
	}
}

// 24 小时按 3 秒一轮：旧实现 28800 次心跳写；新实现必须压到 2880 次以内（≤ 1/10）。
func TestIntegrationHeartbeatWritesPerDayDropAtLeastTenfold(t *testing.T) {
	g, store, clock := newTestIntegrationRuntime(t, nil)
	rounds := int(24 * time.Hour / PolicyRefreshInterval)
	for i := 0; i < rounds; i++ {
		if err := g.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		clock.Advance(PolicyRefreshInterval)
	}
	instances, loads, _ := store.counts()
	if loads != rounds {
		t.Fatalf("loads=%d rounds=%d", loads, rounds)
	}
	if instances > rounds/10 {
		t.Fatalf("heartbeat writes per day=%d, want <= %d", instances, rounds/10)
	}
}

// 执行模式（record/protect）变化必须立即写心跳，否则状态页会用旧模式判 record_only。
func TestIntegrationModeChangeForcesImmediateHeartbeat(t *testing.T) {
	auditOnly := true
	g, store, clock := newTestIntegrationRuntime(t, &auditOnly)
	g.auditOnly = func(context.Context) bool { return auditOnly }
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(PolicyRefreshInterval)
	auditOnly = false
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.instanceModes) != 2 || store.instanceModes[0] != "record" || store.instanceModes[1] != "protect" {
		t.Fatalf("heartbeat modes=%v, want [record protect]", store.instanceModes)
	}
}

// 心跳写失败（磁盘卡顿）不能顺带让策略读取也停摆。
func TestIntegrationHeartbeatFailureDoesNotBlockPolicyLoad(t *testing.T) {
	g, store, _ := newTestIntegrationRuntime(t, nil)
	store.instanceErr = &pgconn.PgError{Code: "53300"}
	store.policies = []ai.Policy{protectPolicy("p1", "1")}
	err := g.refresh(context.Background())
	if err == nil {
		t.Fatal("heartbeat failure must be reported")
	}
	var refreshErr *integrationRefreshError
	if !errors.As(err, &refreshErr) || refreshErr.Step != "heartbeat" {
		t.Fatalf("error=%v, want step=heartbeat", err)
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.policies) != 1 || g.policies[0].ID != "p1" {
		t.Fatalf("policies not loaded after heartbeat failure: %+v", g.policies)
	}
}

// 实例没登记成功前不能写回执（回执表对实例表有外键，写了只会得到外键错误并加重负载）。
func TestIntegrationReceiptsWaitUntilInstanceRegistered(t *testing.T) {
	g, store, clock := newTestIntegrationRuntime(t, nil)
	store.instanceErr = errors.New("down")
	store.policies = []ai.Policy{protectPolicy("p1", "1")}
	_ = g.refresh(context.Background())
	if _, _, receipts := store.counts(); receipts != 0 {
		t.Fatalf("receipts written before instance registered: %d", receipts)
	}
	store.instanceErr = nil
	clock.Advance(PolicyRefreshInterval)
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, receipts := store.counts(); receipts != 1 {
		t.Fatalf("receipts after registration=%d, want 1", receipts)
	}
}

// 回执只在「版本变化」或「周期性校对」时写，而不是每 3 秒每条策略写一次。
func TestIntegrationReceiptsWrittenOnVersionChangeAndPeriodicSync(t *testing.T) {
	g, store, clock := newTestIntegrationRuntime(t, nil)
	store.policies = []ai.Policy{protectPolicy("p1", "1"), protectPolicy("p2", "1")}
	for i := 0; i < 5; i++ {
		if err := g.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		clock.Advance(PolicyRefreshInterval)
	}
	if _, _, receipts := store.counts(); receipts != 2 {
		t.Fatalf("receipts after 5 unchanged rounds=%d, want 2 (每条策略一次)", receipts)
	}
	// 策略 p1 升版：立即补写 p1 的新版本回执，p2 不重复写。
	store.policies = []ai.Policy{protectPolicy("p1", "2"), protectPolicy("p2", "1")}
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	got := strings.Join(store.receipts, ",")
	store.mu.Unlock()
	if got != "p1@1,p2@1,p1@2" {
		t.Fatalf("receipts=%q", got)
	}
	// 越过校对间隔后全量校对一次。
	clock.Advance(ai.HeartbeatInterval)
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, receipts := store.counts(); receipts != 5 {
		t.Fatalf("receipts after periodic sync=%d, want 5", receipts)
	}
}

// 回执写失败后要重试，不能把失败当成已写。
func TestIntegrationReceiptFailureIsRetriedNextRound(t *testing.T) {
	g, store, clock := newTestIntegrationRuntime(t, nil)
	store.policies = []ai.Policy{protectPolicy("p1", "1")}
	store.receiptErr = errors.New("disk stalled")
	err := g.refresh(context.Background())
	var refreshErr *integrationRefreshError
	if !errors.As(err, &refreshErr) || refreshErr.Step != "receipts" {
		t.Fatalf("error=%v, want step=receipts", err)
	}
	store.receiptErr = nil
	clock.Advance(PolicyRefreshInterval)
	if err = g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, receipts := store.counts(); receipts != 1 {
		t.Fatalf("receipt not retried: %d", receipts)
	}
}

// 红线：读失败要保持上一次已知的策略；不能清空（变成放行）。
func TestIntegrationPolicyReadFailureKeepsPreviousSnapshotAndStillBlocks(t *testing.T) {
	auditOnly := false
	g, store, clock := newTestIntegrationRuntime(t, &auditOnly)
	store.policies = []ai.Policy{protectPolicy("p1", "1")}
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.loadErr = context.DeadlineExceeded
	clock.Advance(PolicyRefreshInterval)
	err := g.refresh(context.Background())
	var refreshErr *integrationRefreshError
	if !errors.As(err, &refreshErr) || refreshErr.Step != "policies" {
		t.Fatalf("error=%v, want step=policies", err)
	}
	g.mu.RLock()
	kept := append([]ai.Policy{}, g.policies...)
	g.mu.RUnlock()
	if len(kept) != 1 || kept[0].ID != "p1" || kept[0].Version != "1" {
		t.Fatalf("snapshot replaced on read failure: %+v", kept)
	}
	// 读失败期间，保护模式的拦截仍然生效。
	request := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	ctx := context.WithValue(request.Context(), auth.TenantKey, "tenant1")
	ctx = context.WithValue(ctx, auth.AgentInstanceIDKey, "agent1")
	response := httptest.NewRecorder()
	called := false
	g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })).
		ServeHTTP(response, request.WithContext(ctx))
	if response.Code != 403 || called {
		t.Fatalf("read failure turned protect into pass-through: code=%d called=%v", response.Code, called)
	}
}

// 非法策略行同样不能让快照被部分替换或清空。
func TestIntegrationInvalidPolicyRowKeepsPreviousSnapshot(t *testing.T) {
	g, store, clock := newTestIntegrationRuntime(t, nil)
	store.policies = []ai.Policy{protectPolicy("p1", "1")}
	if err := g.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.loadErr = ai.ErrInvalid
	clock.Advance(PolicyRefreshInterval)
	if err := g.refresh(context.Background()); err == nil {
		t.Fatal("invalid policy must fail the refresh")
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.policies) != 1 {
		t.Fatalf("snapshot lost: %+v", g.policies)
	}
}

// 失败日志必须带「步骤 + 错误类别」，且不能带连接串/用户名/库名等敏感信息。
func TestIntegrationRefreshFailureLogCarriesClassNotSecrets(t *testing.T) {
	buf := captureGatewayLog(t)
	g, store, _ := newTestIntegrationRuntime(t, nil)
	store.loadErr = fmt.Errorf("failed to connect to `host=db.internal user=leaky_user password=leaky_pw database=leaky_db`: %w",
		&pgconn.PgError{Code: "53300", Message: "sorry, too many clients already"})
	g.refreshOnce(context.Background())
	out := buf.String()
	for _, want := range []string{"component=agent_integration", "error_code=integration_refresh_failed", "step=policies", "class=too_many_clients", "sqlstate=53300", "consecutive=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %q", out, want)
		}
	}
	for _, leaked := range []string{"leaky_user", "leaky_pw", "leaky_db", "db.internal", "sorry, too many"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("log %q leaks %q", out, leaked)
		}
	}
}

// 持续失败时日志降噪（首次 + 每 10 次），恢复时记一条。
func TestIntegrationRefreshFailureLogIsThrottledAndRecoveryLogged(t *testing.T) {
	buf := captureGatewayLog(t)
	g, store, clock := newTestIntegrationRuntime(t, nil)
	store.loadErr = context.DeadlineExceeded
	for i := 0; i < 25; i++ {
		g.refreshOnce(context.Background())
		clock.Advance(PolicyRefreshInterval)
	}
	failureLines := strings.Count(buf.String(), "integration_refresh_failed")
	if failureLines != 3 { // 第 1、10、20 次
		t.Fatalf("failure log lines=%d, want 3\n%s", failureLines, buf.String())
	}
	store.loadErr = nil
	g.refreshOnce(context.Background())
	if !strings.Contains(buf.String(), "integration_refresh_recovered") || !strings.Contains(buf.String(), "after=25") {
		t.Fatalf("recovery not logged:\n%s", buf.String())
	}
}

// 常驻失败时的重试间隔必须拉长（指数退避），而不是固定 3 秒打满。
func TestIntegrationRetryDelayBacksOffOnFailureAndResetsOnSuccess(t *testing.T) {
	g, store, _ := newTestIntegrationRuntime(t, nil)
	store.loadErr = errors.New("down")
	var maxDelay time.Duration
	for i := 0; i < 8; i++ {
		d := g.nextDelay(g.refreshOnce(context.Background()))
		if d > maxDelay {
			maxDelay = d
		}
		if d > integrationRetryMaxDelay {
			t.Fatalf("delay %s exceeds cap %s", d, integrationRetryMaxDelay)
		}
	}
	if maxDelay <= PolicyRefreshInterval {
		t.Fatalf("delay never grew beyond %s (max=%s)", PolicyRefreshInterval, maxDelay)
	}
	store.loadErr = nil
	if d := g.nextDelay(g.refreshOnce(context.Background())); d != PolicyRefreshInterval {
		t.Fatalf("delay after success=%s, want %s", d, PolicyRefreshInterval)
	}
}

// 没有数据库（db=nil）时 refresh 必须报错而不是 panic。
func TestIntegrationRefreshWithoutStoreReturnsError(t *testing.T) {
	g := NewIntegrationPolicyRuntime(nil, func(context.Context) bool { return true }, nil)
	if err := g.refresh(context.Background()); err == nil {
		t.Fatal("expected error without store")
	}
}
