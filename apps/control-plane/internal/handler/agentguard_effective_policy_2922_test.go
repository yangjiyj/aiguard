package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 批次 2B：有效策略下发受限文件作用范围；没有 AgentGuard 策略时例外也照样下发（例外是租户级的，
// 指向受限文件、兜底项的例外要能生效）。网关与独立代理都从这个接口拉。
func TestInternalEffectivePolicyDeliversRestrictedScopesAndExceptionsWithoutPolicy(t *testing.T) {
	agentRepo := newFakeAgentGuardPolicyRepo()
	agentRepo.exceptions = append(agentRepo.exceptions, &repository.AgentGuardException{
		ID: "agex-plan", TenantID: "tenant-a", RuleID: "agent.restricted_file", TargetPattern: "/data/plan.docx",
		Decision: "allow", Enabled: true, ExpiresAt: time.Now().Add(time.Hour),
	}, &repository.AgentGuardException{
		ID: "agex-other", TenantID: "tenant-b", RuleID: "agent.restricted_file", Enabled: true, ExpiresAt: time.Now().Add(time.Hour),
	})
	operationRepo := &fakeEffectiveAgentOperationRepo{effective: &repository.AgentOperationEffectivePolicy{
		Mode: "audit", Action: "record", ScopeType: "tenant", ConfigSource: "tenant_policy",
		RestrictedFilePatterns: []string{"*.docx"}, RestrictedFileAction: "block", RestrictedFileScopes: []string{"proxy_output"},
	}}
	deps := &Dependencies{AgentGuardPolicyRepo: agentRepo, AgentOperationRepo: operationRepo}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/internal/agentguard/effective-policy?protocol=responses", nil))
	req.Header.Set("X-Tenant-ID", "tenant-a")
	rec := httptest.NewRecorder()
	GetInternalAgentGuardEffectivePolicy(deps)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data struct {
			Scopes     []string `json:"restricted_file_scopes"`
			Exceptions []struct {
				ID     string `json:"id"`
				RuleID string `json:"rule_id"`
			} `json:"exceptions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Scopes) != 1 || response.Data.Scopes[0] != "proxy_output" {
		t.Fatalf("restricted_file_scopes=%v", response.Data.Scopes)
	}
	if len(response.Data.Exceptions) != 1 || response.Data.Exceptions[0].ID != "agex-plan" {
		t.Fatalf("tenant exceptions must be delivered without an AgentGuard policy: %s", rec.Body.String())
	}
}
