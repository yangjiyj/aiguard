package handler

// 跨租户核对（复审附加项）：permission.Middleware 对 SoD 放行三员的路由整体跳过 RBAC 矩阵，handler 自己的租户校验成了唯一一道关。
// 发现：agent-operation-protection 的 resolveAgentOperationTarget 用 roles.CanManageSecurityPolicy 判定「能否跨租户 / 配全局基线」。
// 该能力（308e08f55，2026-08-02）本是「平台管理员默认配置全局基线，也可切换具体租户；普通用户继续固定在当前租户」；
// W4（6da5a2770）把 platform_admin 机械替换成 CanManageSecurityPolicy，顺带把跨租户与全局基线权限给了 security_officer。
// 安全员属于某个租户，不是平台级角色（矩阵：Security policy, alert handling, evidence review）。修复：跨租户/全局只限系统管理员。

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func officerIn(tenant, role string) *repository.User {
	return &repository.User{ID: "officer", TenantID: tenant, Role: role, Status: "active"}
}

func TestSecurityOfficerCannotReadAnotherTenantsAgentOperationPolicy(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 2}}
	deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-a": true, "tenant-b": true}}}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=tenant&tenant_id=tenant-b", "", officerIn("tenant-a", "security_officer"))
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("A 租户安全员读 B 租户必须 403: %d %s", rec.Code, rec.Body.String())
	}
	if repo.gotTenantID == "tenant-b" {
		t.Fatalf("不得向仓库查询 B 租户的策略")
	}
}

func TestSecurityOfficerCannotUseTheAllTenantsScopeToReadOrWrite(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "agent", ScopeRef: "*", Mode: "light", Action: "alert_allow", Version: 1}}
	deps := &Dependencies{AgentOperationRepo: repo}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=all", "", officerIn("tenant-a", "security_officer"))
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("安全员读全局基线必须 403: %d %s", rec.Code, rec.Body.String())
	}
	body := `{"tenant_scope":"all","scope_type":"agent","scope_ref":"*","mode":"light","action":"alert_allow","version":1}`
	rec, req = agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, officerIn("tenant-a", "security_officer"))
	PutAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || repo.saved.TenantID != "" || repo.saved.ScopeType != "" {
		t.Fatalf("安全员写全局基线必须 403 且不落库: %d saved=%+v", rec.Code, repo.saved)
	}
}

func TestSecurityOfficerCannotWriteAnotherTenantsAgentOperationPolicy(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 1}}
	deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-a": true, "tenant-b": true}}}
	body := `{"tenant_scope":"tenant","tenant_id":"tenant-b","scope_type":"tenant","mode":"strict","action":"block","version":1}`
	rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, officerIn("tenant-a", "security_officer"))
	PutAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || repo.saved.TenantID == "tenant-b" {
		t.Fatalf("A 租户安全员改 B 租户必须 403 且不落库: %d saved=%+v", rec.Code, repo.saved)
	}
}

// 安全员在自己租户内的读写不受影响（含不带 tenant_id、带自己的 tenant_id 两种写法）。
func TestSecurityOfficerKeepsItsOwnTenantAgentOperationAccess(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 2}}
	deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-a": true}}}
	for _, path := range []string{
		"/admin/v1/agent-operation-protection",
		"/admin/v1/agent-operation-protection?tenant_scope=tenant",
		"/admin/v1/agent-operation-protection?tenant_scope=tenant&tenant_id=tenant-a",
	} {
		repo.gotTenantID = ""
		rec, req := agentOperationRequest(t, http.MethodGet, path, "", officerIn("tenant-a", "security_officer"))
		GetAgentOperationProtection(deps).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || repo.gotTenantID != "tenant-a" {
			t.Fatalf("%s：自己租户应可读: %d target=%q %s", path, rec.Code, repo.gotTenantID, rec.Body.String())
		}
	}
	body := `{"scope_type":"tenant","mode":"strict","action":"block","version":1}`
	rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, officerIn("tenant-a", "security_officer"))
	PutAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || repo.saved.TenantID != "tenant-a" {
		t.Fatalf("自己租户应可写: %d saved=%+v %s", rec.Code, repo.saved, rec.Body.String())
	}
}

// 系统管理员的跨租户与全局基线能力保持不变（原设计的受益者）。
func TestPlatformAdminKeepsCrossTenantAndGlobalAgentOperationScopes(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 2}}
	deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-b": true}}}
	admin := officerIn("tenant-a", "platform_admin")
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=tenant&tenant_id=tenant-b", "", admin)
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || repo.gotTenantID != "tenant-b" {
		t.Fatalf("系统管理员应能切到 B 租户: %d %s", rec.Code, rec.Body.String())
	}
	rec, req = agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=all", "", admin)
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"tenant_scope":"all"`) {
		t.Fatalf("系统管理员应能读全局基线: %d %s", rec.Code, rec.Body.String())
	}
}
