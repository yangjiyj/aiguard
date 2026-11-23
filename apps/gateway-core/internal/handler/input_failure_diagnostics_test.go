package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"testing"
)

type failureContextAudit struct {
	MockAuditWriter
	context context.Context
}

func (w *failureContextAudit) WriteSecurityEvent(ctx context.Context, env *modelrouter.RequestEnvelope, findings []SecurityFinding, action, summary string) {
	w.context = ctx
	w.MockAuditWriter.WriteSecurityEvent(ctx, env, findings, action, summary)
}
func TestInputTimeoutRecordsStageReasonAndEffectiveAction(t *testing.T) {
	for _, audit := range []bool{true, false} {
		w := &failureContextAudit{}
		h := &ChatCompletionsHandler{cfg: &config.Config{GuardrailFailureMode: "close", SecurityAuditOnly: audit}, securityClient: &MockSecurityChecker{InputError: context.DeadlineExceeded}, auditWriter: w}
		_, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: jsonQuote("synthetic diagnostic")}}})
		// Inspection timeouts never block, in either posture.
		if err != nil {
			t.Fatalf("audit=%v err=%v", audit, err)
		}
		state, ok := semanticStatusFromContext(w.context)
		if !ok || state.Status != "incomplete" || state.Reason != "security_pipeline_timeout" {
			t.Fatalf("missing failure diagnostic: %+v", state)
		}
		summary := map[string]interface{}{}
		annotateSecurityEventStage(w.context, summary)
		if summary["stage"] != "input" {
			t.Fatalf("missing stage: %+v", summary)
		}
		expected := "audit"
		if w.context.Value(semanticEffectiveActionKey{}) != expected {
			t.Fatal("failure event must preserve actual request action")
		}
	}
}
