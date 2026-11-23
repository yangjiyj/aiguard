package repository

import (
	"context"
	"errors"
	"testing"
	"time"
)

// T22.accept integration: SoD must follow the delegation chain. The admin that
// registered (or rotated) a root principal holds its credential and can mint a
// delegated child, so it must not resolve or pre-approve the child's approvals.
func TestT22IntegDelegatedChildApprovalRejectsAncestorCredentialHolders(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	fileGrant := func(expiry time.Time) AgentAuthorizationGrant {
		return AgentAuthorizationGrant{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22integ-sod.txt",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: expiry, QuotaMax: 100, QuotaWindowSeconds: 3600}
	}
	root, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "t22integ-root", now.Add(2*time.Hour), []AgentAuthorizationGrant{
		{Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(time.Hour), QuotaMax: 100, QuotaWindowSeconds: 3600},
		fileGrant(now.Add(time.Hour)),
	})
	if _, ok, err := authRepo.RotatePrincipalCredential(ctx, tenantID, root.ID, "t22integ-rotator"); err != nil || !ok {
		t.Fatalf("rotate root: ok=%v err=%v", ok, err)
	}
	if err := db.QueryRow(ctx, `SELECT credential_hash FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2`, tenantID, root.ID).Scan(&root.CredentialHash); err != nil {
		t.Fatal(err)
	}
	created, err := delegateChild(ctx, authRepo, delegRepo, root, "project-a", "t22integ-auth-sod-01", "t22integ-create-sod-1",
		"t22integ-child", now.Add(50*time.Minute), []AgentAuthorizationGrant{fileGrant(now.Add(45 * time.Minute))})
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	child := TrustedAgentPrincipal{ID: created.Delegation.ChildPrincipalID, TenantID: tenantID, CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Delegation.ExpiresAt}
	key := "t22integ-sod-call-0001"
	decision, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22integ-sod.txt",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: key})
	if err != nil || !decision.Allowed {
		t.Fatalf("child T13: %+v %v", decision, err)
	}
	approval, _, err := authRepo.CreateAgentAuthorizationApproval(ctx, child, decision.GrantID, AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22integ-sod.txt", ArgumentsSHA256: t15DevDigest("t22integ-sod"),
		AuthorizationIdempotencyKey: key, ApprovalIdempotencyKey: t15DevKey("t15:req:", "t22integ-sod-req")})
	if err != nil {
		t.Fatalf("child approval request: %v", err)
	}
	for _, actor := range []string{"t22-negatives-test", "t22integ-rotator"} {
		if _, changed, err := authRepo.ResolveAgentAuthorizationApproval(ctx, tenantID, approval.ID, "approved", actor, "self"); !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || changed {
			t.Fatalf("ancestor holder %s resolved child approval: changed=%v err=%v", actor, changed, err)
		}
	}
	if _, changed, err := authRepo.ResolveAgentAuthorizationApproval(ctx, tenantID, approval.ID, "approved", "t22integ-independent", "ok"); err != nil || !changed {
		t.Fatalf("independent reviewer: changed=%v err=%v", changed, err)
	}
}
