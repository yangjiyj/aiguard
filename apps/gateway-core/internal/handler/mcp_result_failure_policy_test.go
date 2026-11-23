package handler

import (
	"errors"
	"testing"
)

func TestMCPResultFailureUsesConfiguredGuardrailPolicy(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		for _, failClosed := range []bool{false, true} {
			env := ws1ResultEnv(t, auditOnly, ws1InjectedResult, "application/json", &ws1FakeResultChecker{err: errors.New("engine unavailable")})
			env.handler.toolRiskClient.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision,
				SecurityAuditOnly: auditOnly, SecurityExecutionModeManaged: true, GuardrailFailClosedEnabled: failClosed})
			w := env.post(t, ws1ToolCallRequest)
			blocked := rpcErrorCode(t, w.Body.String()) != 0
			if blocked != (failClosed && !auditOnly) {
				t.Fatalf("audit=%t fail_closed=%t blocked=%t response=%s", auditOnly, failClosed, blocked, w.Body.String())
			}
			if !ws1LogsContain(env, "mcp_tool_result_unverified") {
				t.Fatal("inspection failure lost its coverage-gap evidence")
			}
		}
	}
}
