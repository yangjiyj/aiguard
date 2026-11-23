package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func ws5ConsumeControlPlane(t *testing.T, consumed bool, status int, received *map[string]any, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agentguard/confirmations/consume" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		calls.Add(1)
		if r.Header.Get("X-Tenant-ID") != "tenant-1" || r.Header.Get("X-JJDGuard-Internal-Token") != "secret" {
			t.Errorf("missing tenant or internal token")
		}
		if received != nil {
			_ = json.NewDecoder(r.Body).Decode(received)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if consumed {
			_, _ = w.Write([]byte(`{"data":{"consumed":true,"confirmation_id":"agcf_ok"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"consumed":false}}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func ws5ConfirmDecision() agentguard.Decision {
	return agentguard.Decision{
		RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm,
		RiskLevel: "high", Reason: "needs human confirm",
	}
}

func ws5Envelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{TenantID: "tenant-1", UserID: "u_requester", ClientID: "key_1", RequestID: "req-retry"}
}

// W5 5.2: a retry of an approved call is released once and recorded.
func TestWS5RedeemApprovedConfirmationReleasesRetry(t *testing.T) {
	var calls atomic.Int32
	var received map[string]any
	cp := ws5ConsumeControlPlane(t, true, http.StatusOK, &received, &calls)
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(cp.URL, "secret"), auditWriter: audit}
	tc := ToolCall{ID: "call_2", Function: ToolCallFunc{Name: "network.upload", Arguments: `{"url":"https://x.example/up"}`}}

	got := h.redeemApprovedAgentGuardConfirmation(context.Background(), ws5Envelope(), tc, ws5ConfirmDecision())
	if got.EffectiveDecision != agentguard.DecisionAudit || got.EffectiveReason != agentGuardConfirmationConsumedReason {
		t.Fatalf("approved retry must be released as audit, got %+v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("consume calls = %d", calls.Load())
	}
	for key, want := range map[string]string{"tool_call_id": "call_2", "tool_name": "network.upload", "requester_user_id": "u_requester", "requester_client_id": "key_1"} {
		if received[key] != want {
			t.Fatalf("%s = %v, want %s", key, received[key], want)
		}
	}
	found := false
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_audit" {
			found = true
		}
	}
	if !found {
		t.Fatal("release must leave a security_audit trail")
	}
}

// W5 5.2: no approval / control-plane failure keeps the confirm decision.
func TestWS5RedeemApprovedConfirmationFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		consumed bool
		status   int
	}{
		"not_approved":  {false, http.StatusOK},
		"control_plane": {true, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			cp := ws5ConsumeControlPlane(t, tc.consumed, tc.status, nil, &calls)
			h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(cp.URL, "secret"), auditWriter: &MockAuditWriter{}}
			call := ToolCall{ID: "call_1", Function: ToolCallFunc{Name: "network.upload", Arguments: `{}`}}
			got := h.redeemApprovedAgentGuardConfirmation(context.Background(), ws5Envelope(), call, ws5ConfirmDecision())
			if got.EffectiveDecision != agentguard.DecisionConfirm {
				t.Fatalf("must stay confirm, got %s", got.EffectiveDecision)
			}
		})
	}
}

// W5 5.2: only confirm decisions consult the control plane; anonymous callers never redeem.
func TestWS5RedeemApprovedConfirmationScope(t *testing.T) {
	var calls atomic.Int32
	cp := ws5ConsumeControlPlane(t, true, http.StatusOK, nil, &calls)
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(cp.URL, "secret"), auditWriter: &MockAuditWriter{}}
	call := ToolCall{ID: "call_1", Function: ToolCallFunc{Name: "network.upload", Arguments: `{}`}}
	block := ws5ConfirmDecision()
	block.EffectiveDecision = agentguard.DecisionBlock
	if got := h.redeemApprovedAgentGuardConfirmation(context.Background(), ws5Envelope(), call, block); got.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("block must not be redeemable, got %s", got.EffectiveDecision)
	}
	anonymous := &modelrouter.RequestEnvelope{TenantID: "tenant-1"}
	if got := h.redeemApprovedAgentGuardConfirmation(context.Background(), anonymous, call, ws5ConfirmDecision()); got.EffectiveDecision != agentguard.DecisionConfirm {
		t.Fatalf("anonymous retry must stay confirm, got %s", got.EffectiveDecision)
	}
	if calls.Load() != 0 {
		t.Fatalf("control plane must not be called, calls=%d", calls.Load())
	}
}

// W5 5.2/5.3: confirmations carry the requester so approvals bind to it.
func TestWS5CreateConfirmationSendsRequester(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "secret")
	if err := client.CreateAgentGuardConfirmation(context.Background(), ws5Envelope(), ws5ConfirmDecision(), "network.upload", "call_1", `{}`, 0, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if received["requester_user_id"] != "u_requester" || received["requester_client_id"] != "key_1" {
		t.Fatalf("requester not sent: %v", received)
	}
}
