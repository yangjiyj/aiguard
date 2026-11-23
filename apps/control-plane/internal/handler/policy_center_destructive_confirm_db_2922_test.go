package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 复审建议：策略中心“删除与破坏”卡片选“确认”时 protocol 一律为空（所有协议），不沿用旧行的 mcp；
// 否则旧行 protocol=mcp 时切成确认只对 MCP 生效，chat 仍落不到确认（真库）。
func TestPolicyCenterDestructiveConfirm2922ClearsLegacyMCPProtocolDB(t *testing.T) {
	databaseURL := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tenantID := fmt.Sprintf("pcdc%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM agent_destructive_policies WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	operationRepo := repository.NewAgentOperationRepository(pool)
	if _, err := operationRepo.SavePolicy(ctx, repository.AgentOperationPolicyMutation{
		TenantID: tenantID, ActorID: "user_admin", Source: "admin_api",
		ScopeType: "tenant", Mode: "strict", Action: "block", Protocol: "mcp", ExpectedVersion: 1,
	}); err != nil {
		t.Fatalf("seed legacy mcp block row: %v", err)
	}

	agentRepo := repository.NewAgentGuardPolicyRepository(pool)
	deps := &Dependencies{
		AgentGuardPolicyRepo:     agentRepo,
		AgentGuardBehaviorRepo:   agentRepo,
		PolicyCenterBehaviorRepo: repository.NewPolicyCenterAgentBehaviorRepository(pool),
		AgentOperationRepo:       operationRepo,
		MCPPolicyRepo:            repository.NewMCPPoliciesRepository(pool),
		SystemRepo:               &behaviorAuditRepo{},
	}
	user := &repository.User{ID: "user_admin", TenantID: tenantID, Role: "platform_admin"}
	version := ws5BehaviorVersion(t, deps, user, policyCenterAgentBehaviorDestructive)
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps)(rec, behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/x",
		fmt.Sprintf(`{"action":"confirm","version":%q}`, version), user), policyCenterAgentBehaviorDestructive))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT confirm: %d %s", rec.Code, rec.Body.String())
	}

	for _, protocol := range []string{"chat", "responses", "mcp"} {
		effective, err := operationRepo.ResolveEffectivePolicy(ctx, tenantID, repository.AgentOperationEffectivePolicyInput{Protocol: protocol})
		if err != nil {
			t.Fatal(err)
		}
		if effective.Action != "confirm" || effective.Protocol != "" {
			t.Fatalf("%s: the card's confirm applies to all protocols: %+v", protocol, effective)
		}
	}
}
