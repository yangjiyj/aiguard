package repository

import (
	"context"
	"errors"
	"testing"
	"time"
)

// G1 separation of duties: whoever registered the T13 principal (and therefore its
// grants, which are only ever created inside the same RegisterPrincipal transaction)
// must not resolve that principal's T15 approvals or create exceptions for it.
type t15SoDFixture struct {
	*t15DevFixture
	secondGrantID string
}

func newT15SoDFixture(t *testing.T) *t15SoDFixture {
	t.Helper()
	repo, db := newT15DevIntegrationRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	created, err := repo.RegisterPrincipal(ctx, "tenant-a", AgentAuthorizationPrincipalCreate{
		Name: "t15-sod", ExpiresAt: now.Add(24 * time.Hour), CreatedBy: "creator-a",
		Grants: []AgentAuthorizationGrant{
			{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt",
				ExpiresAt: now.Add(12 * time.Hour), QuotaMax: 1000, QuotaWindowSeconds: 3600},
			{Action: "file_read", ResourceType: "file", ResourceID: "/tmp/t15-read.txt",
				ExpiresAt: now.Add(12 * time.Hour), QuotaMax: 1000, QuotaWindowSeconds: 3600},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := repo.ResolvePrincipalCredential(ctx, HashAgentToken(created.Credential))
	if err != nil || principal == nil {
		t.Fatalf("resolve principal: %v %v", principal, err)
	}
	return &t15SoDFixture{
		t15DevFixture: &t15DevFixture{repo: repo, db: db, principal: *principal, grantID: created.Grants[0].ID},
		secondGrantID: created.Grants[1].ID,
	}
}

func (f *t15SoDFixture) pending(t *testing.T, seed string) *AgentAuthorizationApproval {
	t.Helper()
	key := t15DevKey("t13-sod-", seed)[:40]
	f.authorize(t, key)
	approval := f.request(t, key, t15DevDigest(seed), "req-"+seed)
	if approval.Status != "pending" {
		t.Fatalf("expected pending approval, got %+v", approval)
	}
	return approval
}

func (f *t15SoDFixture) status(t *testing.T, id string) (string, string) {
	t.Helper()
	var status, resolvedBy string
	if err := f.db.QueryRow(context.Background(),
		`SELECT status, COALESCE(resolved_by,'') FROM agentguard_confirmations WHERE id=$1`, id).Scan(&status, &resolvedBy); err != nil {
		t.Fatal(err)
	}
	return status, resolvedBy
}

func TestT15SoDPostgresPrincipalCreatorCannotResolveOwnApproval(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	for _, decision := range []string{"approved", "rejected"} {
		approval := f.pending(t, "creator-"+decision)
		got, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", approval.ID, decision, "creator-a", "self")
		if !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || changed || got != nil {
			t.Fatalf("%s by principal creator: approval=%+v changed=%v err=%v", decision, got, changed, err)
		}
		if status, by := f.status(t, approval.ID); status != "pending" || by != "" {
			t.Fatalf("%s self-resolution mutated approval: status=%s resolved_by=%s", decision, status, by)
		}
	}
}

func TestT15SoDPostgresGrantCreatorCannotResolveApprovalOnAnyGrant(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	var grantCreator string
	if err := f.db.QueryRow(ctx, `
		SELECT p.created_by FROM agent_authorization_grants g
		JOIN agent_authorization_principals p ON p.tenant_id=g.tenant_id AND p.id=g.principal_id
		WHERE g.id=$1`, f.secondGrantID).Scan(&grantCreator); err != nil || grantCreator != "creator-a" {
		t.Fatalf("grant creator lineage: %q %v", grantCreator, err)
	}
	key := "t13-sod-second-grant-000000001"
	if decision, err := f.repo.Authorize(ctx, f.principal, AgentAuthorizationRequest{
		Action: "file_read", ResourceType: "file", ResourceID: "/tmp/t15-read.txt", IdempotencyKey: key}); err != nil || !decision.Allowed {
		t.Fatalf("authorize second grant: %+v %v", decision, err)
	}
	approval, _, err := f.repo.CreateAgentAuthorizationApproval(ctx, f.principal, f.secondGrantID, AgentAuthorizationApprovalInput{
		Action: "file_read", ResourceType: "file", ResourceID: "/tmp/t15-read.txt", ArgumentsSHA256: t15DevDigest("second"),
		AuthorizationIdempotencyKey: key, ApprovalIdempotencyKey: t15DevKey("t15:req:", "second")})
	if err != nil || approval.GrantID != f.secondGrantID {
		t.Fatalf("second grant approval: %+v %v", approval, err)
	}
	if _, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", approval.ID, "approved", grantCreator, "self"); !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || changed {
		t.Fatalf("grant creator resolved: changed=%v err=%v", changed, err)
	}
	if status, _ := f.status(t, approval.ID); status != "pending" {
		t.Fatalf("grant creator self-resolution mutated approval: %s", status)
	}
}

func TestT15SoDPostgresOtherAdminCanResolveAndClaim(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	approval := f.pending(t, "other-approve")
	if got, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", approval.ID, "approved", "reviewer-b", "ok"); err != nil || !changed || got.Status != "approved" {
		t.Fatalf("independent approver: %+v %v %v", got, changed, err)
	}
	if status, by := f.status(t, approval.ID); status != "approved" || by != "reviewer-b" {
		t.Fatalf("stored resolution: %s %s", status, by)
	}
	claim, err := f.claim(approval.ID, t15DevKey("t13-sod-", "other-approve")[:40], t15DevDigest("other-approve"), "claim-other")
	if err != nil || !claim.Allowed {
		t.Fatalf("independently approved ticket not claimable: %+v %v", claim, err)
	}
	rejected := f.pending(t, "other-reject")
	if got, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", rejected.ID, "rejected", "reviewer-b", "no"); err != nil || !changed || got.Status != "rejected" {
		t.Fatalf("independent rejecter: %+v %v %v", got, changed, err)
	}
}

func (f *t15SoDFixture) exceptionInput(seed string) AgentAuthorizationApprovalExceptionInput {
	return AgentAuthorizationApprovalExceptionInput{
		PrincipalID: f.principal.ID, GrantID: f.grantID, Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt",
		ArgumentsSHA256: t15DevDigest(seed), Reason: "sod exception", TTLSeconds: 60, IdempotencyKey: t15DevKey("t15:exception:", seed)}
}

func TestT15SoDPostgresPrincipalCreatorCannotCreateException(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	got, created, err := f.repo.CreateAgentAuthorizationApprovalException(ctx, "tenant-a", "creator-a", f.exceptionInput("self"))
	if !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || created || got != nil {
		t.Fatalf("creator exception: %+v created=%v err=%v", got, created, err)
	}
	var count int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM agent_authorization_approval_exceptions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("self exception persisted: count=%d err=%v", count, err)
	}
	other, created, err := f.repo.CreateAgentAuthorizationApprovalException(ctx, "tenant-a", "reviewer-b", f.exceptionInput("other"))
	if err != nil || !created || other.CreatedBy != "reviewer-b" {
		t.Fatalf("independent exception: %+v created=%v err=%v", other, created, err)
	}
}

// Pre-existing T14/T15 data (principal created by an admin who never resolves) keeps its behaviour.
func TestT15SoDPostgresExistingPrincipalLifecycleUnchanged(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	key := "t13-sod-compat-call-000000001"
	if decision := f.authorize(t, key); !decision.Allowed || decision.GrantID != f.grantID {
		t.Fatalf("T13 authorize changed: %+v", decision)
	}
	if list, err := f.repo.ListPrincipals(ctx, "tenant-a"); err != nil || len(list) != 1 || list[0].CreatedBy != "creator-a" {
		t.Fatalf("principal list changed: %+v %v", list, err)
	}
}
