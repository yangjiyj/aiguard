package handler

// N2：platform_admin 读 tenant_scope=all（全局基线）在尚未保存任何策略时返回 404 "agent operation object not found"。
//
// 设计（docs/superpowers/specs/2026-08-02-agent-operation-protection-customer-ui-design.md §7）里 404 只留给
// 「目标租户不存在或为系统租户」「跨租户引用」；「所有租户」是合法的全局基线目标。某个范围还没保存过策略不是错误，
// 而是「未配置」：应返回与前端 defaultPolicy 一致的默认值（审计/记录，version=1，config_source=new_scope），
// 这样前端保存时带的 ExpectedVersion=1 也能对上。真正的存储错误仍然报错。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type notConfiguredAgentOperationRepo struct {
	fakeAgentOperationRepo
	err error
}

func (f *notConfiguredAgentOperationRepo) GetPolicy(_ context.Context, tenantID, _ string, _ string) (*repository.AgentOperationPolicy, error) {
	f.gotTenantID = tenantID
	return nil, f.err
}

func TestGetAgentOperationProtectionReturnsUnconfiguredDefaultInsteadOf404(t *testing.T) {
	cases := map[string]string{
		"全局基线 all（无参数默认值）":    "/admin/v1/agent-operation-protection",
		"全局基线 all（显式）":        "/admin/v1/agent-operation-protection?tenant_scope=all",
		"全局基线 all 的 agent 通配": "/admin/v1/agent-operation-protection?tenant_scope=all&scope_type=agent&scope_ref=*",
		"具体租户":                "/admin/v1/agent-operation-protection?tenant_scope=tenant&tenant_id=tenant-b",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &notConfiguredAgentOperationRepo{err: repository.ErrAgentOperationNotFound}
			deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-b": true}}}
			rec, req := agentOperationRequest(t, http.MethodGet, path, "", officerIn("tenant-a", "platform_admin"))
			GetAgentOperationProtection(deps).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("尚未保存策略应返回 200 的未配置默认值，实际 %d %s", rec.Code, rec.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["config_source"] != "new_scope" || got["mode"] != "audit" || got["action"] != "record" || got["version"] != float64(1) {
				t.Fatalf("默认值应为 audit/record/version=1/config_source=new_scope：%v", got)
			}
			if got["configured"] != false {
				t.Fatalf("响应要明确标出尚未配置（configured=false），而不是让调用方猜：%v", got)
			}
			if strings.Contains(rec.Body.String(), "not found") {
				t.Fatalf("响应不应再带误导性的 not found：%s", rec.Body.String())
			}
		})
	}
}

func TestGetAgentOperationProtectionMarksSavedPolicyAsConfigured(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 3}}
	deps := &Dependencies{AgentOperationRepo: repo}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=all", "", officerIn("tenant-a", "platform_admin"))
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["configured"] != true || got["version"] != float64(3) || got["mode"] != "strict" {
		t.Fatalf("已保存策略应原样返回且 configured=true：%d %v", rec.Code, got)
	}
}

// 「未配置」只是读不到行；目标租户不存在、存储故障等真正的错误必须保持原来的状态码，不能被一并吞成 200。
func TestGetAgentOperationProtectionStillReportsRealErrors(t *testing.T) {
	repo := &notConfiguredAgentOperationRepo{err: errors.New("database is down")}
	deps := &Dependencies{AgentOperationRepo: repo}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=all", "", officerIn("tenant-a", "platform_admin"))
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("存储故障应是 500，实际 %d %s", rec.Code, rec.Body.String())
	}
	deps = &Dependencies{AgentOperationRepo: &notConfiguredAgentOperationRepo{err: repository.ErrAgentOperationNotFound}, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{}}}
	rec, req = agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=tenant&tenant_id=no-such-tenant", "", officerIn("tenant-a", "platform_admin"))
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("目标租户不存在仍应是 404，实际 %d %s", rec.Code, rec.Body.String())
	}
}
