package handler

// W1 1.6（D2）：可选"只允许勾选的工具"模板。默认不变；套用后勾选放行、其余拦截。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func ws1ResolveAction(policies []*repository.MCPPolicy, tenant, server, tool string) string {
	p := repository.ResolveMCPPolicy(policies, repository.MCPPolicyScope{TenantID: tenant, ServerID: server, ToolName: tool})
	if p == nil {
		return "unmatched"
	}
	return p.Mode + "/" + p.DefaultAction
}

func TestWS1AllowlistTemplateDefaultUnchangedWithoutTemplate(t *testing.T) {
	if got := ws1ResolveAction(nil, "t", "s", "anything"); got != "unmatched" {
		t.Fatalf("未套用模板时必须保持默认（未命中→audit 放行），got %s", got)
	}
}

func TestWS1AllowlistTemplateAllowsCheckedBlocksRest(t *testing.T) {
	policies, err := repository.BuildMCPAllowlistTemplatePolicies("t", "s1", "admin", []string{" read ", "list", "read", ""}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 3 {
		t.Fatalf("1 条兜底 + 2 条去重后的放行，got %d", len(policies))
	}
	for _, p := range policies {
		p.CreatedAt = time.Now()
	}
	cases := map[string]string{"read": "strict/allow", "list": "strict/allow", "delete": "strict/block", "read2": "strict/block"}
	for tool, want := range cases {
		if got := ws1ResolveAction(policies, "t", "s1", tool); got != want {
			t.Fatalf("%s: want %s got %s", tool, want, got)
		}
	}
	if got := ws1ResolveAction(policies, "t", "other-server", "delete"); got != "unmatched" {
		t.Fatalf("模板只作用于所选 server，其他 server 行为不变，got %s", got)
	}
	if got := ws1ResolveAction(policies, "other-tenant", "s1", "delete"); got != "unmatched" {
		t.Fatalf("模板不得跨租户生效，got %s", got)
	}
}

func TestWS1AllowlistTemplateDisabledIsInert(t *testing.T) {
	policies, err := repository.BuildMCPAllowlistTemplatePolicies("t", "s1", "admin", []string{"read"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := ws1ResolveAction(policies, "t", "s1", "delete"); got != "unmatched" {
		t.Fatalf("以停用状态套用的模板不应生效，got %s", got)
	}
}

func TestWS1AllowlistTemplateAdminPolicyStillWins(t *testing.T) {
	policies, _ := repository.BuildMCPAllowlistTemplatePolicies("t", "s1", "admin", []string{"read"}, true)
	now := time.Now()
	for _, p := range policies {
		p.CreatedAt = now
	}
	manual := &repository.MCPPolicy{TenantID: "t", ScopeType: "key", ScopeRef: "sk-1", ServerID: "s1", ToolPattern: "read",
		Mode: "strict", DefaultAction: "block", Enabled: true, CreatedAt: now}
	all := append(policies, manual)
	p := repository.ResolveMCPPolicy(all, repository.MCPPolicyScope{TenantID: "t", KeyPrefix: "sk-1", ServerID: "s1", ToolName: "read"})
	if p == nil || p.DefaultAction != "block" {
		t.Fatalf("管理员写的更细作用域 block 仍应胜出: %+v", p)
	}
}

func TestWS1AllowlistTemplateRejectsInvalidSelection(t *testing.T) {
	for _, tools := range [][]string{nil, {"", "  "}, {"*"}, {"fs.*"}} {
		if _, err := repository.BuildMCPAllowlistTemplatePolicies("t", "s1", "admin", tools, true); err == nil {
			t.Fatalf("应拒绝 %v", tools)
		}
	}
	if _, err := repository.BuildMCPAllowlistTemplatePolicies("t", "", "admin", []string{"read"}, true); err == nil {
		t.Fatal("server_id 为空应拒绝")
	}
}

func ws1TemplateRequest(method, tenant, role, serverID string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/admin/v1/mcp-servers/"+serverID+"/allowlist-template", &buf)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", serverID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rc)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: "u-" + role, TenantID: tenant, Role: role})
	return req.WithContext(ctx)
}

func TestWS1AllowlistTemplateOnRealPostgres(t *testing.T) {
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
	tenant := fmt.Sprintf("ws1al%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM mcp_policies WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM mcp_servers WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	serverRepo := repository.NewMCPServersRepository(pool)
	serverID := tenant + "-s"
	if err := serverRepo.Create(ctx, &repository.MCPServer{ID: serverID, TenantID: tenant, Name: "s", ServerURL: "https://s.example/mcp", Status: "active", Transport: "streamable_http"}); err != nil {
		t.Fatalf("server: %v", err)
	}
	policyRepo := repository.NewMCPPoliciesRepository(pool)
	manual := &repository.MCPPolicy{TenantID: tenant, ServerID: serverID, ToolPattern: "danger", Mode: "strict", DefaultAction: "block", Enabled: true, Note: "manual"}
	if err := policyRepo.Create(ctx, manual); err != nil {
		t.Fatalf("manual: %v", err)
	}
	deps := &Dependencies{MCPServerRepo: serverRepo, MCPToolRepo: repository.NewMCPToolsRepository(pool), MCPPolicyRepo: policyRepo}

	count := func() (template, total int) {
		_ = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE note=$2), count(*) FROM mcp_policies WHERE tenant_id=$1`,
			tenant, repository.MCPAllowlistTemplateNote(serverID)).Scan(&template, &total)
		return
	}
	do := func(h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	if rec := do(ApplyMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodPost, tenant, "viewer", serverID, map[string]interface{}{"tools": []string{"read"}})); rec.Code != http.StatusForbidden {
		t.Fatalf("非管理员应 403，got %d", rec.Code)
	}
	if rec := do(ApplyMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodPost, "other-tenant", "tenant_admin", serverID, map[string]interface{}{"tools": []string{"read"}})); rec.Code != http.StatusNotFound {
		t.Fatalf("跨租户 server 应 404，got %d", rec.Code)
	}
	rec := do(ApplyMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodPost, tenant, "tenant_admin", serverID, map[string]interface{}{"tools": []string{"read"}, "dry_run": true}))
	if rec.Code != http.StatusOK {
		t.Fatalf("dry_run: %d %s", rec.Code, rec.Body.String())
	}
	if tpl, _ := count(); tpl != 0 {
		t.Fatalf("dry_run 不得落库，got %d", tpl)
	}

	rec = do(ApplyMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodPost, tenant, "tenant_admin", serverID, map[string]interface{}{"tools": []string{"read", "list"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	var view mcpAllowlistTemplateView
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if !view.Applied || !view.Enabled || len(view.AllowedTools) != 2 || len(view.UnknownTools) != 2 {
		t.Fatalf("apply view: %+v", view)
	}
	if tpl, total := count(); tpl != 3 || total != 4 {
		t.Fatalf("套用后应有 3 条模板 + 1 条手写，got tpl=%d total=%d", tpl, total)
	}

	rec = do(ApplyMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodPost, tenant, "tenant_admin", serverID, map[string]interface{}{"tools": []string{"read"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("reapply: %d", rec.Code)
	}
	if tpl, total := count(); tpl != 2 || total != 3 {
		t.Fatalf("重复套用应整组替换，got tpl=%d total=%d", tpl, total)
	}
	all, err := policyRepo.ListByTenant(ctx, tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	for tool, want := range map[string]string{"read": "strict/allow", "list": "strict/block", "danger": "strict/block"} {
		if got := ws1ResolveAction(all, tenant, serverID, tool); got != want {
			t.Fatalf("真库解析 %s: want %s got %s", tool, want, got)
		}
	}

	rec = do(GetMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodGet, tenant, "viewer", serverID, nil))
	view = mcpAllowlistTemplateView{}
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if rec.Code != http.StatusOK || !view.Applied || len(view.AllowedTools) != 1 || view.AllowedTools[0] != "read" {
		t.Fatalf("get: %d %+v", rec.Code, view)
	}

	rec = do(RemoveMCPAllowlistTemplate(deps), ws1TemplateRequest(http.MethodDelete, tenant, "tenant_admin", serverID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: %d", rec.Code)
	}
	if tpl, total := count(); tpl != 0 || total != 1 {
		t.Fatalf("撤销只删模板策略、手写策略保留，got tpl=%d total=%d", tpl, total)
	}
	all, _ = policyRepo.ListByTenant(ctx, tenant, "")
	if got := ws1ResolveAction(all, tenant, serverID, "list"); got != "unmatched" {
		t.Fatalf("撤销后恢复默认，got %s", got)
	}
}
