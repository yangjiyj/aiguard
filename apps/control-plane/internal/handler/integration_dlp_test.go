package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"net/http/httptest"
	"testing"
)

func TestDLPReceiptActionRequiresAllBoundKeys(t *testing.T) {
	for _, gate := range []string{"record_only", "allow_block"} {
		t.Setenv("INTEGRATION_KEY_ENFORCEMENT", gate)
		p := repository.SecurityPolicy{Enabled: true, Action: "block", Authoring: &repository.SecurityPolicyAuthoring{Source: "agentshield"}, SubjectBinding: &repository.SecurityPolicySubjectBinding{KeyIDs: []string{"key1", "key2"}}}
		keys := []ai.Credential{{KeyID: "key1", AgentInstanceID: "a1", Status: "active", DLPEnforcement: "block"}, {KeyID: "key2", AgentInstanceID: "a2", Status: "active", DLPEnforcement: "block"}}
		want := "audit"
		if gate == "allow_block" {
			want = "block"
		}
		if got := integrationDLPEffectiveAction(p, keys, true); got != want {
			t.Fatalf("动作=%s，期望 %s", got, want)
		}
		keys[1].DLPEnforcement = "record"
		if got := integrationDLPEffectiveAction(p, keys, true); got != "audit" {
			t.Fatal("混合档位伪报拦截")
		}
		p.Authoring = nil
		if got := integrationDLPEffectiveAction(p, keys, true); got != "audit" {
			t.Fatal("非集成策略获得例外")
		}
	}
}

func TestDLPStatusUsesTenantAndVerifiedRuntimeReceipt(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "allow_block")
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	for _, state := range []string{"verified", "unavailable", "degraded", "skipped", "stale", "inactive"} {
		t.Run(state, func(t *testing.T) {
			keyStore := &credentialContractStore{key: ai.Credential{KeyID: "key1", AgentInstanceID: "agent1", Status: "active", DLPEnforcement: "block"}}
			store := &fakeSecurityPolicyStore{policies: []repository.SecurityPolicy{{ID: "policy1", Enabled: true, Action: "block", Authoring: &repository.SecurityPolicyAuthoring{Source: "agentshield"}, SubjectBinding: &repository.SecurityPolicySubjectBinding{KeyIDs: []string{"key1"}}, Capabilities: []repository.SecurityPolicyCapability{{Category: "phone_cn"}}}}}
			proof := func(_ context.Context, tenant string) (securityPolicyRuntimeProof, error) {
				if tenant != "tenant-a" {
					t.Fatal("回执使用了其他租户")
				}
				skipped := 0
				p := securityPolicyRuntimeProof{RulePackVersion: "fixture-version", RuntimeVerified: true, RuntimeStatus: runtimeStatusApplied, ActualSkippedCount: &skipped, ActivePolicyIDs: map[string]struct{}{"policy1": {}}}
				switch state {
				case "unavailable":
					return p, errors.New("fixture unavailable")
				case "degraded":
					p.Degraded = true
				case "skipped":
					skipped = 1
				case "stale":
					p.RuntimeStatus = runtimeStatusAppliedWithStaleNodes
				case "inactive":
					p.ActivePolicyIDs = nil
				}
				return p, nil
			}
			h := newSecurityPoliciesHandler(&Dependencies{IntegrationRepo: keyStore}, store, nil, proof)
			w := httptest.NewRecorder()
			user := &repository.User{TenantID: "tenant-a"}
			h.integrationDLPStatus(w, httptest.NewRequest("GET", "/admin/v1/integration/dlp-status?policy_id=policy1", nil), user)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var got struct {
				PolicyID  string `json:"policy_id"`
				Effective string `json:"effective_action"`
				Verified  bool   `json:"runtime_verified"`
				Active    bool   `json:"runtime_active"`
				Version   string `json:"rule_pack_version"`
				AuditOnly bool   `json:"audit_only"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			verified := state == "verified"
			if got.PolicyID != "policy1" || got.Effective != "block" || got.Verified != verified || got.Active != verified || !got.AuditOnly || keyStore.tenant != "tenant-a" {
				t.Fatalf("回执失真：%s", w.Body.String())
			}
			if state != "unavailable" && got.Version != "fixture-version" {
				t.Fatal("回执缺少真实规则包版本")
			}
		})
	}
}
