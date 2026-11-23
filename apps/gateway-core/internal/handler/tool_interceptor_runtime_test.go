package handler

import (
	"context"
	"net/http"
	"testing"
)

func TestToolRiskClientSecurityAuditOnlyCannotDisableForcedAudit(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	client := NewToolRiskClient("http://control-plane.invalid", "secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision:          gatewaySemanticRevision,
		Enabled:           false,
		InputEnabled:      false,
		AgentEnabled:      false,
		SecurityAuditOnly: false,
	})

	if got := client.SecurityAuditOnly(context.Background(), false); !got {
		t.Fatal("运行时快照为 false 时不得关闭 SECURITY_AUDIT_ONLY=true 的审计模式")
	}
}

func TestToolRiskClientSecurityAuditOnlyFallsBackWhenControlPlaneUnavailable(t *testing.T) {
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	client.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}

	if got := client.SecurityAuditOnly(context.Background(), true); !got {
		t.Fatalf("SecurityAuditOnly() = false, want fallback true")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestToolRiskClientSecurityAuditOnlyFirstFailureFailsSafeToRecord(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	if got := client.SecurityAuditOnly(context.Background(), false); !got {
		t.Fatal("without last-good and without deployment force, runtime must fail safe to record")
	}
}

func TestToolRiskClientSecurityAuditOnlyKeepsLastGoodProtect(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: false})
	if got := client.SecurityAuditOnly(context.Background(), true); got {
		t.Fatal("last-good protect must survive refresh failure/fallback")
	}
}
