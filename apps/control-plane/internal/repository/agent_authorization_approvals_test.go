package repository

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validT15ApprovalInput() AgentAuthorizationApprovalInput {
	return AgentAuthorizationApprovalInput{
		Action: "tool_execute", ResourceType: "tool", ResourceID: "ticket.update",
		ArgumentsSHA256:             strings.Repeat("a", 64),
		AuthorizationIdempotencyKey: "t13-request-key-000001",
		ApprovalIdempotencyKey:      "t15:req:" + strings.Repeat("b", 64),
	}
}

func validT15ClaimInput() AgentAuthorizationApprovalClaimInput {
	return AgentAuthorizationApprovalClaimInput{
		Action: "tool_execute", ResourceType: "tool", ResourceID: "ticket.update",
		ArgumentsSHA256:             strings.Repeat("a", 64),
		AuthorizationIdempotencyKey: "t13-request-key-000001",
		ClaimIdempotencyKey:         "t15:claim:" + strings.Repeat("c", 64),
	}
}

func TestT15ApprovalBindingValidationAndIdempotencyHashes(t *testing.T) {
	valid := validT15ApprovalInput()
	if err := ValidateAgentAuthorizationApprovalInput(valid); err != nil {
		t.Fatalf("valid approval input rejected: %v", err)
	}
	claim := validT15ClaimInput()
	if err := ValidateAgentAuthorizationApprovalClaimInput(claim); err != nil {
		t.Fatalf("valid claim input rejected: %v", err)
	}
	bad := []AgentAuthorizationApprovalInput{
		func() AgentAuthorizationApprovalInput { v := valid; v.ArgumentsSHA256 = "raw-arguments"; return v }(),
		func() AgentAuthorizationApprovalInput {
			v := valid
			v.ApprovalIdempotencyKey = "t15:claim:" + strings.Repeat("b", 64)
			return v
		}(),
		func() AgentAuthorizationApprovalInput { v := valid; v.ResourceID = "*"; return v }(),
		func() AgentAuthorizationApprovalInput { v := valid; v.AuthorizationIdempotencyKey = "short"; return v }(),
	}
	for i, value := range bad {
		if err := ValidateAgentAuthorizationApprovalInput(value); err == nil {
			t.Errorf("bad approval input %d was accepted", i)
		}
	}
	hash, err := agentAuthorizationApprovalRequestHash("tenant-a", "principal-a", "grant-a", valid)
	if err != nil {
		t.Fatal(err)
	}
	changed := valid
	changed.ArgumentsSHA256 = strings.Repeat("d", 64)
	changedHash, err := agentAuthorizationApprovalRequestHash("tenant-a", "principal-a", "grant-a", changed)
	if err != nil {
		t.Fatal(err)
	}
	if hash == changedHash {
		t.Fatal("changed arguments digest reused an approval request binding")
	}
}

func TestT15ApprovalClaimEligibilityFailsClosedForExpiredAndRevokedState(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	cases := []struct {
		name     string
		approval AgentAuthorizationApproval
		want     bool
	}{
		{name: "approved", approval: AgentAuthorizationApproval{Status: "approved", ExpiresAt: now.Add(time.Minute)}, want: true},
		{name: "pending", approval: AgentAuthorizationApproval{Status: "pending", ExpiresAt: now.Add(time.Minute)}},
		{name: "expired-status", approval: AgentAuthorizationApproval{Status: "expired", ExpiresAt: now.Add(time.Minute)}},
		{name: "expired-time", approval: AgentAuthorizationApproval{Status: "approved", ExpiresAt: now.Add(-time.Second)}},
		{name: "revoked", approval: AgentAuthorizationApproval{Status: "revoked", ExpiresAt: now.Add(time.Minute)}},
		{name: "already-claimed", approval: AgentAuthorizationApproval{Status: "approved", ExpiresAt: now.Add(time.Minute), Claimed: true}},
	}
	for _, tc := range cases {
		if got := agentAuthorizationApprovalClaimable(&tc.approval, now); got != tc.want {
			t.Errorf("%s claimable=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestT15ClaimRetryIsStableAndNeverAllowsAcrossExpiredOrRevokedState(t *testing.T) {
	const storedKey = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const otherKey = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	for _, status := range []string{"approved", "expired", "revoked"} {
		approval := &AgentAuthorizationApproval{ID: "agap_12345678", Status: status, Claimed: true, ClaimID: "agcl_original"}
		got, err := replayAgentAuthorizationClaimResult(approval, storedKey, storedKey)
		if err != nil || got == nil || got.Allowed || got.ClaimID != "agcl_original" || got.Reason != "approval_already_claimed" {
			t.Errorf("same-key retry at status %s = %+v, %v", status, got, err)
		}
		if result, err := replayAgentAuthorizationClaimResult(approval, storedKey, otherKey); result != nil || !errors.Is(err, ErrAgentAuthorizationApprovalConflict) {
			t.Errorf("different-key retry at status %s = %+v, %v; want conflict", status, result, err)
		}
	}
}

func TestT15ExceptionExactScopeAndLifetimeValidation(t *testing.T) {
	valid := AgentAuthorizationApprovalExceptionInput{
		PrincipalID: "02ac6a21-4090-4e45-a6f1-7057bd9a0440",
		GrantID:     "e1bfc491-2d53-417b-bb09-86c9a3c9e82a",
		Action:      "tool_execute", ResourceType: "tool", ResourceID: "ticket.update",
		ArgumentsSHA256: strings.Repeat("a", 64), Reason: "bounded maintenance",
		TTLSeconds: 60, IdempotencyKey: "t15:exception:" + strings.Repeat("e", 64),
	}
	if err := ValidateAgentAuthorizationApprovalExceptionInput(valid); err != nil {
		t.Fatalf("valid exception rejected: %v", err)
	}
	mutants := []AgentAuthorizationApprovalExceptionInput{
		func() AgentAuthorizationApprovalExceptionInput { v := valid; v.TTLSeconds = 301; return v }(),
		func() AgentAuthorizationApprovalExceptionInput { v := valid; v.ResourceID = "*"; return v }(),
		func() AgentAuthorizationApprovalExceptionInput {
			v := valid
			v.IdempotencyKey = "t15:exception:short"
			return v
		}(),
		func() AgentAuthorizationApprovalExceptionInput {
			v := valid
			v.ArgumentsSHA256 = strings.Repeat("A", 64)
			return v
		}(),
	}
	for i, value := range mutants {
		if err := ValidateAgentAuthorizationApprovalExceptionInput(value); err == nil {
			t.Errorf("invalid exception %d was accepted", i)
		}
	}
}

func TestT15ApprovalMigrationKeepsExactBindingAndLegacyConfirmationsSeparate(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "870_agent_authorization_approvals.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"agent_authorization_principal_id", "agent_authorization_grant_id",
		"agent_authorization_arguments_sha256", "agent_authorization_request_sha256",
		"agent_authorization_claim_key_sha256", "agent_authorization_claimed_at",
		"agent_authorization_approval_exceptions", "idx_agent_authorization_approval_idempotency",
		"status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')",
		"FOREIGN KEY (tenant_id, principal_id, grant_id)",
		"agent_authorization_arguments_sha256 IS NOT NULL",
		"agent_authorization_claim_key_sha256 IS NOT NULL",
		"position('*' in resource_id) = 0",
	} {
		if !strings.Contains(string(migration), required) {
			t.Errorf("migration missing required T15 invariant %q", required)
		}
	}
	legacySource, err := os.ReadFile("agentguard_policies.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacySource), "query += ` AND COALESCE(source, '') <> 'agent_authorization'`") {
		t.Fatal("generic confirmation path does not always exclude the dedicated T15 queue")
	}
	approvalSource, err := os.ReadFile("agent_authorization_approvals.go")
	if err != nil {
		t.Fatal(err)
	}
	claimSource := string(approvalSource)
	claimStart := strings.Index(claimSource, "func (r *AgentAuthorizationRepository) ClaimAgentAuthorizationApproval(")
	if claimStart < 0 {
		t.Fatal("T15 claim implementation is missing")
	}
	claimSource = claimSource[claimStart:]
	claimedAt := strings.Index(claimSource, "if approval.Claimed {")
	expiryAt := strings.Index(claimSource, "if !approval.ExpiresAt.After(now)")
	exceptionAt := strings.Index(claimSource, "if approval.ExceptionID != ")
	if claimedAt < 0 || expiryAt < 0 || exceptionAt < 0 || claimedAt > expiryAt || claimedAt > exceptionAt {
		t.Fatal("claimed retries must be decided before expiry or exception state can hide the stable claim ID")
	}
	for _, required := range []string{
		"source='agent_authorization'",
		"FOR UPDATE",
		"status='approved' AND expires_at>clock_timestamp() AND agent_authorization_claimed_at IS NULL",
		"SET agent_authorization_claim_key_sha256=$3",
		"LIMIT $2 FOR UPDATE SKIP LOCKED",
		"SET status='expired', resolved_at=COALESCE(resolved_at,clock_timestamp())",
	} {
		if !strings.Contains(string(approvalSource), required) {
			t.Errorf("T15 repository missing atomicity/binding guard %q", required)
		}
	}
}
