package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func ws5BehaviorItem(t *testing.T, deps *Dependencies, user *repository.User, key string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	GetPolicyCenterAgentBehaviors(deps).ServeHTTP(rec, withBehaviorUser(http.MethodGet, "/admin/v1/policy-center/agent-behaviors", "", user))
	var snapshot struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, item := range snapshot.Items {
		if item["key"] == key {
			return item
		}
	}
	t.Fatalf("behavior %q missing", key)
	return nil
}

func ws5PutBehavior(deps *Dependencies, user *repository.User, key, body string) *httptest.ResponseRecorder {
	req := behaviorRouteRequest(withBehaviorUser(http.MethodPut, "/admin/v1/policy-center/agent-behaviors/"+key, body, user), key)
	rec := httptest.NewRecorder()
	PutPolicyCenterAgentBehavior(deps).ServeHTTP(rec, req)
	return rec
}

// W5 5.5: the network_egress category carries the sensitive-read -> egress
// switch; it is stored in behavior_json and delivered to the gateway.
func TestWS5PolicyCenterSequenceWindowSavedAndDelivered(t *testing.T) {
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	deps, _, agentRepo, _, _ := behaviorDeps("tenant-a", nil, nil, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}
	_ = now

	item := ws5BehaviorItem(t, deps, user, "network_egress")
	if item[agentGuardSequenceWindowKey] != float64(0) {
		t.Fatalf("sequence rule must default to off, got %#v", item[agentGuardSequenceWindowKey])
	}
	version, _ := item["version"].(string)
	rec := ws5PutBehavior(deps, user, "network_egress", `{"action":"alert_allow","version":"`+version+`","sensitive_read_egress_window_seconds":600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var stored *repository.AgentGuardPolicy
	for _, policy := range agentRepo.policies {
		if policy.TenantID == "tenant-a" {
			stored = policy
		}
	}
	if stored == nil || stored.BehaviorJSON[agentGuardSequenceWindowKey] != 600 {
		t.Fatalf("window not stored: %#v", stored)
	}
	delivered := agentGuardBehaviorFromJSON(stored.BehaviorJSON)
	if delivered[agentGuardSequenceWindowKey] != 600 {
		t.Fatalf("window not delivered to gateway: %#v", delivered)
	}
	if got := ws5BehaviorItem(t, deps, user, "network_egress")[agentGuardSequenceWindowKey]; got != float64(600) {
		t.Fatalf("window must read back, got %#v", got)
	}

	// Saving the action without the field keeps the window; 0 turns it off.
	version, _ = ws5BehaviorItem(t, deps, user, "network_egress")["version"].(string)
	if rec := ws5PutBehavior(deps, user, "network_egress", `{"action":"block","version":"`+version+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if policyCenterSequenceWindowSeconds(ws5StoredPolicy(agentRepo, "tenant-a")) != 600 {
		t.Fatalf("omitted field must keep the window: %#v", stored.BehaviorJSON)
	}
	version, _ = ws5BehaviorItem(t, deps, user, "network_egress")["version"].(string)
	if rec := ws5PutBehavior(deps, user, "network_egress", `{"action":"block","version":"`+version+`","sensitive_read_egress_window_seconds":0}`); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := ws5StoredPolicy(agentRepo, "tenant-a").BehaviorJSON[agentGuardSequenceWindowKey]; ok {
		t.Fatalf("0 must remove the window: %#v", stored.BehaviorJSON)
	}
}

func TestWS5PolicyCenterSequenceWindowValidation(t *testing.T) {
	deps, _, _, _, _ := behaviorDeps("tenant-a", nil, nil, nil)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a", Role: "platform_admin"}
	version, _ := ws5BehaviorItem(t, deps, user, "network_egress")["version"].(string)
	if rec := ws5PutBehavior(deps, user, "network_egress", `{"action":"block","version":"`+version+`","sensitive_read_egress_window_seconds":90000}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range window must be rejected, status=%d", rec.Code)
	}
	fileVersion, _ := ws5BehaviorItem(t, deps, user, "system_command")["version"].(string)
	if rec := ws5PutBehavior(deps, user, "system_command", `{"action":"block","version":"`+fileVersion+`","sensitive_read_egress_window_seconds":60}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("window on another category must be rejected, status=%d", rec.Code)
	}
}

func ws5StoredPolicy(repo *fakeAgentGuardPolicyRepo, tenantID string) *repository.AgentGuardPolicy {
	for _, policy := range repo.policies {
		if policy.TenantID == tenantID {
			return policy
		}
	}
	return &repository.AgentGuardPolicy{}
}
