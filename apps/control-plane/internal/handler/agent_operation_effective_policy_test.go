package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeEffectiveAgentOperationRepo struct {
	fakeAgentOperationRepo
	effective *repository.AgentOperationEffectivePolicy
}

func (f *fakeEffectiveAgentOperationRepo) ResolveEffectivePolicy(context.Context, string, repository.AgentOperationEffectivePolicyInput) (*repository.AgentOperationEffectivePolicy, error) {
	return f.effective, nil
}

func TestInternalAgentOperationEffectivePolicyExistsWithoutLegacyPolicy(t *testing.T) {
	operationRepo := &fakeEffectiveAgentOperationRepo{effective: &repository.AgentOperationEffectivePolicy{
		Mode: "light", Action: "block", ScopeType: "application", ScopeRef: "app-a",
		ConfigSource: "application_policy", Protocol: "mcp",
		DiscardablePaths: []string{"dist"}, NotifyChannelIDs: []string{"channel-a"},
	}}
	deps := &Dependencies{AgentGuardPolicyRepo: newFakeAgentGuardPolicyRepo(), AgentOperationRepo: operationRepo}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodGet,
		"/admin/v1/internal/agentguard/effective-policy?project_id=app-a&agent_id=codex&protocol=mcp", nil))
	req.Header.Set("X-Tenant-ID", "tenant-a")
	rec := httptest.NewRecorder()

	GetInternalAgentGuardEffectivePolicy(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data *struct {
			Mode                    string   `json:"mode"`
			ConfigSource            string   `json:"config_source"`
			Protocol                string   `json:"protocol"`
			DiscardablePaths        []string `json:"discardable_paths"`
			NotifyChannelSnapshotID []string `json:"notify_channel_ids"`
			Destructive             struct {
				Action    string `json:"action"`
				ScopeType string `json:"scope_type"`
				ScopeRef  string `json:"scope_ref"`
			} `json:"destructive"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data == nil || response.Data.Mode != "light" || response.Data.Destructive.Action != "block" ||
		response.Data.Destructive.ScopeType != "application" || response.Data.Destructive.ScopeRef != "app-a" ||
		response.Data.ConfigSource != "application_policy" || response.Data.Protocol != "mcp" ||
		len(response.Data.DiscardablePaths) != 1 || response.Data.DiscardablePaths[0] != "dist" ||
		len(response.Data.NotifyChannelSnapshotID) != 1 || response.Data.NotifyChannelSnapshotID[0] != "channel-a" {
		t.Fatalf("unexpected payload: %s", rec.Body.String())
	}
}
