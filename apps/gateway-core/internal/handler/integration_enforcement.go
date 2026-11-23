package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/yangjiyj/aiguard/packages/shared-go/backoff"
	"github.com/yangjiyj/aiguard/packages/shared-go/errclass"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// PolicyRefreshInterval 是策略读取周期（只读，开销小，保持及时）。
	PolicyRefreshInterval = 3 * time.Second
	// 刷新失败后的退避：6 秒起步、15 秒封顶，带抖动。连接被打满时不再固定 3 秒一次地争抢连接。
	integrationRetryBaseDelay = 2 * PolicyRefreshInterval
	integrationRetryMaxDelay  = 15 * time.Second
	// 持续失败时每 N 次打印一条，避免磁盘卡顿期间刷屏。
	integrationFailureLogEvery = 10
)

var errIntegrationNoStore = errors.New("integration store unavailable")

// integrationStore 隔离数据库访问，便于不依赖真实库测试刷新节奏与失败语义。
type integrationStore interface {
	UpsertInstance(ctx context.Context, instanceID, bootID, mode string) error
	LoadPolicies(ctx context.Context) ([]ai.Policy, error)
	UpsertReceipt(ctx context.Context, instanceID, policyID, bootID, version string) error
}

// integrationRefreshError 标明失败发生在刷新的哪一步。Error() 只含步骤与错误类别，
// 不含底层错误正文（连接串、用户名、库名、SQL 都可能出现在其中）。
type integrationRefreshError struct {
	Step string
	Err  error
}

func (e *integrationRefreshError) Error() string {
	return "integration refresh " + e.Step + ": " + errclass.Summary(e.Err)
}
func (e *integrationRefreshError) Unwrap() error { return e.Err }

type IntegrationPolicyRuntime struct {
	db                 *pgxpool.Pool
	store              integrationStore
	now                func() time.Time
	instanceID, bootID string
	auditOnly          func(context.Context) bool
	audit              AuditWriter
	mu                 sync.RWMutex
	policies           []ai.Policy

	// 以下字段只在刷新协程里读写，由 refreshMu 串行化。
	refreshMu           sync.Mutex
	registered          bool
	lastHeartbeat       time.Time
	lastHeartbeatMode   string
	lastReceiptSync     time.Time
	receiptVersions     map[string]string
	consecutiveFailures int
	retry               *backoff.Backoff
}

func NewIntegrationPolicyRuntime(db *pgxpool.Pool, auditOnly func(context.Context) bool, audit AuditWriter) *IntegrationPolicyRuntime {
	id := os.Getenv("GATEWAY_INSTANCE_ID")
	if !ai.ValidID(id) {
		id, _ = os.Hostname()
	}
	if !ai.ValidID(id) {
		id = "gateway-" + uuid.NewString()
	}
	g := &IntegrationPolicyRuntime{
		db: db, instanceID: id, bootID: uuid.NewString(), auditOnly: auditOnly, audit: audit,
		policies: []ai.Policy{}, now: time.Now, receiptVersions: map[string]string{},
		retry: backoff.New(integrationRetryBaseDelay, integrationRetryMaxDelay),
	}
	if db != nil { // 避免把 nil 指针装进接口后得到「非 nil 的空 store」
		g.store = &pgIntegrationStore{db: db}
	}
	return g
}

func (g *IntegrationPolicyRuntime) Start(ctx context.Context) {
	go func() {
		timer := time.NewTimer(g.nextDelay(g.refreshOnce(ctx)))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			timer.Reset(g.nextDelay(g.refreshOnce(ctx)))
		}
	}()
}

// nextDelay 成功时回到正常周期；失败时指数退避加抖动，封顶 integrationRetryMaxDelay。
func (g *IntegrationPolicyRuntime) nextDelay(err error) time.Duration {
	if err == nil {
		g.retry.Reset()
		return PolicyRefreshInterval
	}
	return g.retry.Next()
}

// refreshOnce 执行一轮刷新并记录结果。失败日志只含步骤与错误类别，持续失败时降噪。
func (g *IntegrationPolicyRuntime) refreshOnce(ctx context.Context) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := g.refresh(c)
	if err == nil {
		if g.consecutiveFailures > 0 {
			log.Printf("component=agent_integration stage=refresh event=integration_refresh_recovered after=%d", g.consecutiveFailures)
		}
		g.consecutiveFailures = 0
		return nil
	}
	if ctx.Err() != nil { // 进程退出中，不算故障
		return err
	}
	g.consecutiveFailures++
	if g.consecutiveFailures == 1 || g.consecutiveFailures%integrationFailureLogEvery == 0 {
		step, inner := "refresh", error(err)
		var refreshErr *integrationRefreshError
		if errors.As(err, &refreshErr) {
			step, inner = refreshErr.Step, refreshErr.Err
		}
		log.Printf("component=agent_integration stage=refresh error_code=integration_refresh_failed step=%s %s consecutive=%d",
			step, errclass.Summary(inner), g.consecutiveFailures)
	}
	return err
}

func (g *IntegrationPolicyRuntime) heartbeatDue(now time.Time, mode string) bool {
	return g.lastHeartbeat.IsZero() || mode != g.lastHeartbeatMode ||
		now.Before(g.lastHeartbeat) || now.Sub(g.lastHeartbeat) >= ai.HeartbeatInterval
}

// refresh 完成一轮：按需写心跳 → 读策略并原子替换快照 → 按需写回执。
//
// 失败语义（红线）：策略读取失败或存在非法行时保持上一次已知的快照，绝不清空；
// 心跳写失败不阻止策略读取；回执写失败只影响状态页的证据，不影响已加载策略的执行。
func (g *IntegrationPolicyRuntime) refresh(ctx context.Context) error {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	if g.store == nil {
		return &integrationRefreshError{Step: "store", Err: errIntegrationNoStore}
	}
	now := g.now()
	mode := "record"
	if g.auditOnly != nil && !g.auditOnly(ctx) {
		mode = "protect"
	}
	var firstErr *integrationRefreshError
	fail := func(step string, err error) {
		if firstErr == nil {
			firstErr = &integrationRefreshError{Step: step, Err: err}
		}
	}

	// 独立登记实例，保证策略加载失败的网关也留在状态页分母里；重启会换新的 boot ID。
	// 心跳降频到 ai.HeartbeatInterval；执行模式变化、首次启动时立即写。
	if g.heartbeatDue(now, mode) {
		if err := g.store.UpsertInstance(ctx, g.instanceID, g.bootID, mode); err != nil {
			fail("heartbeat", err)
		} else {
			g.registered, g.lastHeartbeat, g.lastHeartbeatMode = true, now, mode
		}
	}

	policies, err := g.store.LoadPolicies(ctx)
	if err != nil {
		fail("policies", err)
		return firstErr // 保持上一次快照
	}
	g.mu.Lock()
	g.policies = policies
	g.mu.Unlock()

	// 回执只描述上面刚替换进去的活动快照。失败的写入留下 pending/不一致的证据，而不是伪造已收敛。
	// 回执在「版本变化」或「周期性校对」时才写，不再每轮每条策略写一次；实例未登记成功前不写（外键）。
	if g.registered {
		syncAll := g.lastReceiptSync.IsZero() || now.Before(g.lastReceiptSync) || now.Sub(g.lastReceiptSync) >= ai.HeartbeatInterval
		next := make(map[string]string, len(policies))
		receiptFailed := false
		for _, p := range policies {
			if !syncAll && g.receiptVersions[p.ID] == p.Version {
				next[p.ID] = p.Version
				continue
			}
			if receiptFailed {
				continue
			}
			if err := g.store.UpsertReceipt(ctx, g.instanceID, p.ID, g.bootID, p.Version); err != nil {
				fail("receipts", err)
				receiptFailed = true
				continue
			}
			next[p.ID] = p.Version
		}
		g.receiptVersions = next
		if syncAll && !receiptFailed {
			g.lastReceiptSync = now
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return nil
}

// pgIntegrationStore 是生产实现：SQL 与改造前逐字一致。
type pgIntegrationStore struct{ db *pgxpool.Pool }

func (s *pgIntegrationStore) UpsertInstance(ctx context.Context, instanceID, bootID, mode string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO integration_gateway_instances(instance_id,boot_id,mode,last_seen_at) VALUES($1,$2,$3,now()) ON CONFLICT(instance_id) DO UPDATE SET boot_id=excluded.boot_id,mode=excluded.mode,last_seen_at=now()`, instanceID, bootID, mode)
	return err
}

func (s *pgIntegrationStore) LoadPolicies(ctx context.Context) ([]ai.Policy, error) {
	rows, err := s.db.Query(ctx, `SELECT id,tenant_id,agent_instance_id,action,enabled,mode,mcp_server_id,version::text,updated_at FROM integration_agent_policies ORDER BY tenant_id,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := []ai.Policy{}
	for rows.Next() {
		var p ai.Policy
		if err = rows.Scan(&p.ID, &p.TenantID, &p.AgentInstanceID, &p.Action, &p.Enabled, &p.Mode, &p.MCPServerID, &p.Version, &p.UpdatedAt); err != nil {
			return nil, err
		}
		if err = ai.ValidatePolicy(p); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

func (s *pgIntegrationStore) UpsertReceipt(ctx context.Context, instanceID, policyID, bootID, version string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO integration_gateway_receipts(instance_id,policy_id,boot_id,loaded_version,loaded_at) VALUES($1,$2,$3,$4::bigint,now())
          ON CONFLICT(instance_id,policy_id) DO UPDATE SET boot_id=excluded.boot_id,loaded_version=excluded.loaded_version,
          loaded_at=CASE WHEN integration_gateway_receipts.boot_id=excluded.boot_id AND integration_gateway_receipts.loaded_version=excluded.loaded_version THEN integration_gateway_receipts.loaded_at ELSE now() END,
          hit_count=CASE WHEN integration_gateway_receipts.boot_id=excluded.boot_id AND integration_gateway_receipts.loaded_version=excluded.loaded_version THEN integration_gateway_receipts.hit_count ELSE 0 END,
          blocked_count=CASE WHEN integration_gateway_receipts.boot_id=excluded.boot_id AND integration_gateway_receipts.loaded_version=excluded.loaded_version THEN integration_gateway_receipts.blocked_count ELSE 0 END`, instanceID, policyID, bootID, version)
	return err
}

func integrationPolicyMatches(p ai.Policy, tenant, agent, path, serverID string) bool {
	if !p.Enabled || p.TenantID != tenant || p.AgentInstanceID != agent || agent == "" {
		return false
	}
	switch p.Action {
	case "block_model_egress":
		return strings.HasPrefix(path, "/v1/") && path != "/v1/models" && !strings.HasPrefix(path, "/v1/models/")
	case "disable_mcp":
		return (path == "/mcp" || strings.HasPrefix(path, "/mcp/")) && (p.MCPServerID == "" || p.MCPServerID == serverID)
	}
	return false
}

func (g *IntegrationPolicyRuntime) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := auth.GetAuthInfo(r)
		if info.AgentInstanceID == "" {
			next.ServeHTTP(w, r)
			return
		}
		g.mu.RLock()
		policies := append([]ai.Policy{}, g.policies...)
		g.mu.RUnlock()
		blocked := false
		for _, p := range policies {
			if !integrationPolicyMatches(p, info.TenantID, info.AgentInstanceID, r.URL.Path, chi.URLParam(r, "serverID")) {
				continue
			}
			mode := securityexit.Record
			if p.Mode == "protect" && g.auditOnly != nil && !g.auditOnly(r.Context()) {
				mode = securityexit.Protect
			}
			decision := securityexit.Decide(mode, "block", securityexit.ToolPolicy)
			category := "unapproved_model_egress"
			if p.Action == "disable_mcp" {
				category = "mcp_policy"
			}
			envelope := &modelrouter.RequestEnvelope{RequestID: info.RequestID, TenantID: info.TenantID, ProjectID: info.ProjectID, UserID: info.UserID, ClientID: info.KeyID, KeyPrefix: info.KeyPrefix, AgentInstanceID: info.AgentInstanceID, AgentType: info.AgentType, SessionID: info.SessionID, TraceID: info.TraceID, EnvironmentScope: info.EnvironmentScope, Principal: info.Principal, EndpointType: "agent_integration", SourceIP: info.ClientIP}
			if g.audit != nil {
				g.audit.EnsureRequestLog(r.Context(), envelope)
				g.audit.WriteSecurityEvent(r.Context(), envelope, []SecurityFinding{{Type: "agent_policy", Severity: "high", Category: category, Action: decision.Action, Confidence: 1, PolicyCode: p.ID, RuleName: p.Action, MatchedLocation: "request"}}, decision.Action, fmt.Sprintf("integration policy %s version %s", p.ID, p.Version))
			}
			if g.db != nil {
				countCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
				n := int64(0)
				if decision.Enforce {
					n = 1
				}
				_, err := g.db.Exec(countCtx, `UPDATE integration_gateway_receipts SET hit_count=hit_count+1,blocked_count=blocked_count+$5 WHERE instance_id=$1 AND policy_id=$2 AND boot_id=$3 AND loaded_version=$4::bigint`, g.instanceID, p.ID, g.bootID, p.Version, n)
				cancel()
				if err != nil {
					log.Print("component=agent_integration stage=hit error_code=integration_hit_write_failed")
				}
			}
			blocked = blocked || decision.Enforce
		}
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-Id", info.RequestID)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "agent_policy_blocked", "message": "agent gateway policy denied the request", "request_id": info.RequestID}})
			return
		}
		next.ServeHTTP(w, r)
	})
}
