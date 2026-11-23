package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestAgentCredentialScopesCannotMintWildcardOrAdminAccess(t *testing.T) {
	for _, bad := range [][]string{nil, {"*"}, {"chat", "admin"}, {"CHAT"}} {
		if _, err := normalizeIntegrationScopes(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	scopes, err := normalizeIntegrationScopes([]string{"chat", "models", "chat"})
	if err != nil || len(scopes) != 2 {
		t.Fatalf("scopes=%v err=%v", scopes, err)
	}
}

func TestIntegrationRequestRejectsUnknownAndTrailingFields(t *testing.T) {
	for _, body := range []string{`{"agent_instance_id":"a","tenant_id":"foreign"}`, `{"agent_instance_id":"a"} {}`, `{"agent_instance_id":"a","password":"never-accepted"}`} {
		req := httptest.NewRequest("POST", "/admin/v1/integration/agent-credentials", strings.NewReader(body))
		w := httptest.NewRecorder()
		var value struct {
			AgentInstanceID string `json:"agent_instance_id"`
		}
		if integrationDecode(w, req, &value) || w.Code != 400 {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestConnectorRiskProjectionPreservesAgentAndExcludesContentAndSecrets(t *testing.T) {
	e := &repository.SecurityEvent{ID: "event1", RequestID: "request1", AgentInstanceID: "agent1", MatchedSummary: map[string]any{"category": "prompt_injection", "prompt": "private-content", "password": "private-secret"}, EvidenceRef: "http://unsafe.test?key=secret"}
	b, err := json.Marshal(connectorRiskMetadata(e))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"private-content", "private-secret", "unsafe.test", "matched_summary", "evidence_ref", "key_hash", "key_ciphertext"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("projection leaked %s", bad)
		}
	}
	if !strings.Contains(string(b), `"agent_instance_id":"agent1"`) || !strings.Contains(string(b), `"risk_category":"prompt_injection"`) {
		t.Fatalf("missing attribution %s", b)
	}
}

func TestIntegrationCredentialAcceptsEnforcementContract(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"agent_instance_id":"a","project_id":"p","scopes":["chat"],"model_restriction":"allowlist","model_allowlist":["模型甲"],"enforcement":"record","dlp_enforcement":"record"}`))
	var req integrationCredentialRequest
	if !integrationDecode(w, r, &req) {
		t.Fatalf("契约字段被拒绝：%s", w.Body.String())
	}
}
