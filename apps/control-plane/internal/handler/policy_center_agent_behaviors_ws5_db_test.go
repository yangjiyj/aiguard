package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// W5 5.1: all four AgentGuard categories saved in the policy center must be
// delivered to the gateway at the same time (real database).
func TestWS5PolicyCenterFourCategoriesAllEffectiveDB(t *testing.T) {
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
	tenantID := fmt.Sprintf("ws5pc%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID) })

	agentRepo := repository.NewAgentGuardPolicyRepository(pool)
	deps := &Dependencies{
		AgentGuardPolicyRepo:     agentRepo,
		AgentGuardBehaviorRepo:   agentRepo,
		PolicyCenterBehaviorRepo: repository.NewPolicyCenterAgentBehaviorRepository(pool),
		AgentOperationRepo:       repository.NewAgentOperationRepository(pool),
		MCPPolicyRepo:            repository.NewMCPPoliciesRepository(pool),
		SystemRepo:               &behaviorAuditRepo{},
	}
	user := &repository.User{ID: "user_admin", TenantID: tenantID, Role: "platform_admin"}
	keys := []string{policyCenterAgentBehaviorSystem, policyCenterAgentBehaviorFile, policyCenterAgentBehaviorNetwork, policyCenterAgentBehaviorDatabase}
	for _, key := range keys {
		version := ws5BehaviorVersion(t, deps, user, key)
		body := fmt.Sprintf(`{"action":"block","version":%q}`, version)
		rec := httptest.NewRecorder()
		PutPolicyCenterAgentBehavior(deps)(rec, behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/x", body, user), key))
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", key, rec.Code, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/internal", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	rec := httptest.NewRecorder()
	GetInternalAgentGuardEffectivePolicy(deps)(rec, req)
	var resp struct {
		Data struct {
			Rules []map[string]any `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v %s", err, rec.Body.String())
	}
	got := map[string]string{}
	for _, rule := range resp.Data.Rules {
		got[fmt.Sprint(rule["id"])] = fmt.Sprint(rule["action"])
	}
	for _, key := range keys {
		if got["policy-center-"+key] != "block" {
			t.Errorf("category %s not effective at gateway; delivered rules=%v", key, got)
		}
	}
	var count int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM agentguard_policies WHERE tenant_id=$1`, tenantID).Scan(&count)
	if count != 1 {
		t.Errorf("policy center must keep one managed policy, got %d rows", count)
	}
}

func ws5BehaviorVersion(t *testing.T, deps *Dependencies, user *repository.User, key string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps)(rec, withBehaviorUser(http.MethodGet, "/x", "", user))
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list: %v %s", err, rec.Body.String())
	}
	for _, item := range list.Items {
		if item["key"] == key {
			return fmt.Sprint(item["version"])
		}
	}
	t.Fatalf("behavior %s missing", key)
	return ""
}
