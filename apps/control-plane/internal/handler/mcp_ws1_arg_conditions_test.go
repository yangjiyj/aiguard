package handler

// W1 1.12：部门档位 + 参数条件策略（真库）。只经 HTTP 入口驱动，基线上同样可编译。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type ws1ApprovedSupplyRepo struct{}

func (ws1ApprovedSupplyRepo) ResolveMCPSupplyChain(context.Context, string, string, string) (repository.MCPSupplyChainResolution, error) {
	return repository.MCPSupplyChainResolution{Status: "approved", ServerStatus: "approved", ToolStatus: "approved"}, nil
}
func (ws1ApprovedSupplyRepo) ApplySupplyChainSync(context.Context, repository.MCPSupplyChainSyncInput) (*repository.MCPSupplyChainSyncResult, error) {
	return nil, nil
}
func (ws1ApprovedSupplyRepo) SetMCPServerAdmission(context.Context, string, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error) {
	return nil, nil
}
func (ws1ApprovedSupplyRepo) SetMCPToolAdmission(context.Context, string, string, string, string, string, string) (*repository.MCPAdmissionMutation, error) {
	return nil, nil
}

func TestWS1DepartmentScopeAndArgConditionsOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sfx := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
	tenant, dept1, dept2, userA, userB := "ws1ac"+sfx, "ws1d1"+sfx, "ws1d2"+sfx, "ws1ua"+sfx, "ws1ub"+sfx
	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, []any{tenant}},
		{`INSERT INTO teams(id,tenant_id,name,path) VALUES ($1,$2,$3,$4)`, []any{dept1, tenant, dept1, "/" + dept1}},
		{`INSERT INTO teams(id,tenant_id,name,path) VALUES ($1,$2,$3,$4)`, []any{dept2, tenant, dept2, "/" + dept2}},
		{`INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES ($1,$2,$1,'developer','active',$3,'manual')`, []any{userA, tenant, dept1}},
		{`INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES ($1,$2,$1,'developer','active',$3,'manual')`, []any{userB, tenant, dept2}},
	}
	for _, s := range seed {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed %s: %v", s.sql, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM mcp_policies WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	deps := &Dependencies{
		MCPPolicyRepo:      repository.NewMCPPoliciesRepository(pool),
		MCPSupplyChainRepo: ws1ApprovedSupplyRepo{},
		UserRepo:           repository.NewUserRepository(pool),
	}
	create := func(body map[string]any) (int, string) {
		rec := httptest.NewRecorder()
		CreateMCPPolicy(deps)(rec, ws1RedlineRequest(http.MethodPost, "/admin/v1/mcp-policies", tenant, "tenant_admin", body))
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.ID
	}
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{"server_id": "srv1", "tool_pattern": "fs_write", "mode": "strict"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	codeT, pTenant := create(base(map[string]any{"scope_type": "tenant", "default_action": "block"}))
	codeD, pDept := create(base(map[string]any{"scope_type": "department", "scope_ref": dept1, "default_action": "allow"}))
	codeU, pUser := create(base(map[string]any{"scope_type": "user", "scope_ref": userA, "default_action": "block",
		"arg_conditions": []map[string]any{{"path": "$.path", "op": "prefix", "value": "/etc/"}}}))
	if codeT != http.StatusCreated || codeD != http.StatusCreated || codeU != http.StatusCreated {
		t.Fatalf("create: tenant=%d department=%d user=%d (department scope and arg_conditions must be accepted)", codeT, codeD, codeU)
	}

	if code, _ := create(base(map[string]any{"scope_type": "user", "scope_ref": userA, "default_action": "block",
		"arg_conditions": []map[string]any{{"path": "$.path", "op": "bogus", "value": "x"}}})); code != http.StatusBadRequest {
		t.Fatalf("invalid arg condition op must be 400, got %d", code)
	}
	if code, _ := create(map[string]any{"scope_type": "tenant", "target_kind": "resource", "tool_pattern": "file://*", "default_action": "block",
		"arg_conditions": []map[string]any{{"path": "$.uri", "op": "exists"}}}); code != http.StatusBadRequest {
		t.Fatalf("arg_conditions on non-tool target must be 400, got %d", code)
	}

	effective := func(userID string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/mcp/effective-policy?server_id=srv1&tool_name=fs_write&user_id="+userID, nil)
		req.Header.Set("X-Tenant-ID", tenant)
		rec := httptest.NewRecorder()
		GetInternalMCPEffectivePolicy(deps)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("effective %s: %d %s", userID, rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	a := effective(userA)
	if a["policy_id"] != pDept || a["action"] != "allow" {
		t.Fatalf("userA (dept1) winner must be department allow %s, got %v", pDept, a)
	}
	chain, _ := a["arg_chain"].([]any)
	if len(chain) != 1 || chain[0].(map[string]any)["policy_id"] != pUser {
		t.Fatalf("userA arg_chain must carry the conditional user policy %s, got %v", pUser, a["arg_chain"])
	}
	b := effective(userB)
	if b["policy_id"] != pTenant || b["action"] != "block" || b["arg_chain"] != nil {
		t.Fatalf("userB (dept2) must fall back to tenant block without chain, got %v", b)
	}

	simulate := func(args string) string {
		body := map[string]any{"server_id": "srv1", "tool_name": "fs_write", "user_id": userA, "arguments": json.RawMessage(args)}
		rec := httptest.NewRecorder()
		SimulateMCPPolicy(deps)(rec, ws1RedlineRequest(http.MethodPost, "/admin/v1/mcp-policies/simulate", tenant, "tenant_admin", body))
		var out struct {
			Winning *struct {
				ID string `json:"id"`
			} `json:"winning"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Winning == nil {
			return ""
		}
		return out.Winning.ID
	}
	if got := simulate(`{"path":"/etc/cron.d/x"}`); got != pUser {
		t.Fatalf("simulate /etc must pick conditional policy %s, got %s", pUser, got)
	}
	if got := simulate(`{"path":"/tmp/x"}`); got != pDept {
		t.Fatalf("simulate /tmp must pick department policy %s, got %s", pDept, got)
	}

	var stored string
	if err := pool.QueryRow(ctx, `SELECT arg_conditions::text FROM mcp_policies WHERE id=$1`, pUser).Scan(&stored); err != nil || !strings.Contains(stored, "/etc/") {
		t.Fatalf("arg_conditions must persist: %q %v", stored, err)
	}
	update := func(body map[string]any) int {
		req := ws1RedlineRequest(http.MethodPut, "/admin/v1/mcp-policies/"+pUser, tenant, "tenant_admin", body)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", pUser)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		UpdateMCPPolicy(deps)(rec, req)
		return rec.Code
	}
	// 请求体不带 arg_conditions（如启停开关）→ 保留原条件；显式空数组 → 清空。
	if code := update(base(map[string]any{"scope_type": "user", "scope_ref": userA, "default_action": "block", "enabled": false})); code != http.StatusOK {
		t.Fatalf("update without arg_conditions: %d", code)
	}
	if err := pool.QueryRow(ctx, `SELECT arg_conditions::text FROM mcp_policies WHERE id=$1`, pUser).Scan(&stored); err != nil || !strings.Contains(stored, "/etc/") {
		t.Fatalf("update without arg_conditions must keep them: %q %v", stored, err)
	}
	if code := update(base(map[string]any{"scope_type": "user", "scope_ref": userA, "default_action": "block", "arg_conditions": []any{}})); code != http.StatusOK {
		t.Fatalf("update with empty arg_conditions: %d", code)
	}
	if err := pool.QueryRow(ctx, `SELECT arg_conditions::text FROM mcp_policies WHERE id=$1`, pUser).Scan(&stored); err != nil || stored != "[]" {
		t.Fatalf("explicit empty arg_conditions must clear: %q %v", stored, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE mcp_policies SET arg_conditions='{}'::jsonb WHERE id=$1`, pUser); err == nil {
		t.Fatalf("db must reject non-array arg_conditions")
	}
	if _, err := pool.Exec(ctx, `UPDATE mcp_policies SET scope_type='bogus' WHERE id=$1`, pUser); err == nil {
		t.Fatalf("db must reject unknown scope_type")
	}
}
