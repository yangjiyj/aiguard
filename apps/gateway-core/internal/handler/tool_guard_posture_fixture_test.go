package handler

import (
	"strings"
	"testing"
)

func setToolGuardTestPosture(t *testing.T, client *ToolRiskClient, record, failClosed bool) {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision:                     strings.Repeat("0", 32),
		Enabled:                      true,
		InputEnabled:                 true,
		SecurityAuditOnly:            record,
		SecurityExecutionModeManaged: true,
		GuardrailFailClosedEnabled:   failClosed,
	})
}
