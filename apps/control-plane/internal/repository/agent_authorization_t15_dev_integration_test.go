package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func t15DevKey(prefix, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return prefix + hex.EncodeToString(sum[:])
}

func t15DevDigest(seed string) string {
	sum := sha256.Sum256([]byte("args:" + seed))
	return hex.EncodeToString(sum[:])
}

func newT15DevIntegrationRepo(t *testing.T) (*AgentAuthorizationRepository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("t15_dev_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})
	if _, err := db.Exec(ctx, `CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY); INSERT INTO tenants(id) VALUES ('tenant-a'),('tenant-b')`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"054_agentguard_policy_governance.sql", "065_agentguard_confirmation_replay.sql",
		"100_mcp_confirmation_source.sql", "861_trusted_agent_authorization.sql",
		"864_agent_authorization_retention_index.sql", "870_agent_authorization_approvals.sql",
		"872_agent_authorization_principal_rotated_by.sql",
		"874_agent_delegation_lifecycle.sql",
	} {
		body, err := os.ReadFile("../../../../deploy/migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	return NewAgentAuthorizationRepository(db), db
}

type t15DevFixture struct {
	repo      *AgentAuthorizationRepository
	db        *pgxpool.Pool
	principal TrustedAgentPrincipal
	grantID   string
}

func newT15DevFixture(t *testing.T) *t15DevFixture {
	t.Helper()
	repo, db := newT15DevIntegrationRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	created, err := repo.RegisterPrincipal(ctx, "tenant-a", AgentAuthorizationPrincipalCreate{
		Name: "t15-dev", ExpiresAt: now.Add(24 * time.Hour), CreatedBy: "t15-dev-registrar",
		Grants: []AgentAuthorizationGrant{{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt",
			ExpiresAt: now.Add(12 * time.Hour), QuotaMax: 1000, QuotaWindowSeconds: 3600}},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := repo.ResolvePrincipalCredential(ctx, HashAgentToken(created.Credential))
	if err != nil || principal == nil {
		t.Fatalf("resolve principal: %v %v", principal, err)
	}
	return &t15DevFixture{repo: repo, db: db, principal: *principal, grantID: created.Grants[0].ID}
}

func (f *t15DevFixture) authorize(t *testing.T, key string) *AgentAuthorizationDecision {
	t.Helper()
	decision, err := f.repo.Authorize(context.Background(), f.principal, AgentAuthorizationRequest{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt", IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func (f *t15DevFixture) request(t *testing.T, t13Key, digest, seed string) *AgentAuthorizationApproval {
	t.Helper()
	approval, _, err := f.repo.CreateAgentAuthorizationApproval(context.Background(), f.principal, f.grantID, AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt", ArgumentsSHA256: digest,
		AuthorizationIdempotencyKey: t13Key, ApprovalIdempotencyKey: t15DevKey("t15:req:", seed)})
	if err != nil {
		t.Fatal(err)
	}
	return approval
}

func (f *t15DevFixture) claim(approvalID, t13Key, digest, seed string) (*AgentAuthorizationApprovalClaim, error) {
	return f.repo.ClaimAgentAuthorizationApproval(context.Background(), f.principal, f.grantID, approvalID, AgentAuthorizationApprovalClaimInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt", ArgumentsSHA256: digest,
		AuthorizationIdempotencyKey: t13Key, ClaimIdempotencyKey: t15DevKey("t15:claim:", seed)})
}

// Requirements 1/5/6: exact binding, pending never claims, one-shot claim, changed digest conflicts.
func TestT15DevPostgresApprovalLifecycleIsExactAndOneShot(t *testing.T) {
	f := newT15DevFixture(t)
	ctx := context.Background()
	t13Key := "t13-dev-call-000000000001"
	if decision := f.authorize(t, t13Key); !decision.Allowed || decision.GrantID != f.grantID {
		t.Fatalf("T13 did not allow the exact grant: %+v", decision)
	}
	digest := t15DevDigest("v1")
	pending := f.request(t, t13Key, digest, "req-1")
	if pending.Status != "pending" || !pending.ExpiresAt.After(time.Now()) || pending.ExpiresAt.After(time.Now().Add(121*time.Second)) {
		t.Fatalf("pending ticket state/expiry wrong: %+v", pending)
	}
	if again := f.request(t, t13Key, digest, "req-1"); again.ID != pending.ID {
		t.Fatalf("identical poll created a second ticket: %s vs %s", again.ID, pending.ID)
	}
	if _, _, err := f.repo.CreateAgentAuthorizationApproval(ctx, f.principal, f.grantID, AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt", ArgumentsSHA256: t15DevDigest("v2"),
		AuthorizationIdempotencyKey: t13Key, ApprovalIdempotencyKey: t15DevKey("t15:req:", "req-1")}); !errors.Is(err, ErrAgentAuthorizationApprovalConflict) {
		t.Fatalf("same request key with changed digest was not a conflict: %v", err)
	}
	claim, err := f.claim(pending.ID, t13Key, digest, "claim-1")
	if err != nil || claim.Allowed || claim.Status != "pending" {
		t.Fatalf("pending ticket was claimable: %+v %v", claim, err)
	}
	if _, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-b", pending.ID, "approved", "admin-b", "cross tenant"); err != nil || changed {
		t.Fatalf("cross-tenant approver resolved the ticket: changed=%v err=%v", changed, err)
	}
	if _, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", pending.ID, "approved", "admin-a", "ok"); err != nil || !changed {
		t.Fatalf("resolve: changed=%v err=%v", changed, err)
	}
	if _, err := f.claim(pending.ID, t13Key, t15DevDigest("v2"), "claim-x"); !errors.Is(err, ErrAgentAuthorizationApprovalConflict) {
		t.Fatalf("claim with changed digest consumed approval: %v", err)
	}
	if _, err := f.claim(pending.ID, "t13-dev-call-000000000099", digest, "claim-y"); !errors.Is(err, ErrAgentAuthorizationApprovalConflict) {
		t.Fatalf("claim with another T13 key consumed approval: %v", err)
	}
	first, err := f.claim(pending.ID, t13Key, digest, "claim-1")
	if err != nil || !first.Allowed || first.Status != "claimed" || first.ClaimID == "" {
		t.Fatalf("exact claim failed: %+v %v", first, err)
	}
	replay, err := f.claim(pending.ID, t13Key, digest, "claim-1")
	if err != nil || replay.Allowed || replay.ClaimID != first.ClaimID {
		t.Fatalf("replayed claim was allowed again or unstable: %+v %v", replay, err)
	}
	if _, err := f.claim(pending.ID, t13Key, digest, "claim-2"); !errors.Is(err, ErrAgentAuthorizationApprovalConflict) {
		t.Fatalf("second claim key on a consumed ticket: %v", err)
	}
	var claimed int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM agentguard_confirmations WHERE agent_authorization_claimed_at IS NOT NULL`).Scan(&claimed); err != nil || claimed != 1 {
		t.Fatalf("claimed rows=%d err=%v", claimed, err)
	}
}

// Requirement 6: rejection, expiry, exception revocation and principal revocation never claim.
func TestT15DevPostgresRejectExpiryAndRevocationNeverClaim(t *testing.T) {
	f := newT15DevFixture(t)
	ctx := context.Background()

	rejectKey := "t13-dev-call-reject-00001"
	f.authorize(t, rejectKey)
	rejected := f.request(t, rejectKey, t15DevDigest("reject"), "req-reject")
	if _, _, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", rejected.ID, "rejected", "admin-a", "no"); err != nil {
		t.Fatal(err)
	}
	if claim, err := f.claim(rejected.ID, rejectKey, t15DevDigest("reject"), "claim-reject"); err != nil || claim.Allowed {
		t.Fatalf("rejected ticket claimed: %+v %v", claim, err)
	}

	expiryKey := "t13-dev-call-expiry-00001"
	f.authorize(t, expiryKey)
	expiring := f.request(t, expiryKey, t15DevDigest("expiry"), "req-expiry")
	if _, _, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", expiring.ID, "approved", "admin-a", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(ctx, `UPDATE agentguard_confirmations SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, expiring.ID); err != nil {
		t.Fatal(err)
	}
	if claim, err := f.claim(expiring.ID, expiryKey, t15DevDigest("expiry"), "claim-expiry"); err != nil || claim.Allowed || claim.Status != "expired" {
		t.Fatalf("expired approval claimed: %+v %v", claim, err)
	}

	exceptionDigest := t15DevDigest("exception")
	exception, _, err := f.repo.CreateAgentAuthorizationApprovalException(ctx, "tenant-a", "admin-a", AgentAuthorizationApprovalExceptionInput{
		PrincipalID: f.principal.ID, GrantID: f.grantID, Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t15.txt",
		ArgumentsSHA256: exceptionDigest, Reason: "short exact exception", TTLSeconds: 60, IdempotencyKey: t15DevKey("t15:exception:", "exc-1")})
	if err != nil {
		t.Fatal(err)
	}
	exceptionKey := "t13-dev-call-exception-01"
	f.authorize(t, exceptionKey)
	autoApproved := f.request(t, exceptionKey, exceptionDigest, "req-exception")
	if autoApproved.Status != "approved" || autoApproved.ExceptionID != exception.ID {
		t.Fatalf("exact exception did not pre-approve: %+v", autoApproved)
	}
	otherKey := "t13-dev-call-exception-02"
	f.authorize(t, otherKey)
	if other := f.request(t, otherKey, t15DevDigest("other-args"), "req-exception-other"); other.Status != "pending" {
		t.Fatalf("exception leaked to different arguments: %+v", other)
	}
	if _, changed, err := f.repo.RevokeAgentAuthorizationApprovalException(ctx, "tenant-a", exception.ID, "admin-a"); err != nil || !changed {
		t.Fatalf("revoke exception: %v %v", changed, err)
	}
	if claim, err := f.claim(autoApproved.ID, exceptionKey, exceptionDigest, "claim-exception"); err != nil || claim.Allowed {
		t.Fatalf("approval from revoked exception claimed: %+v %v", claim, err)
	}

	revokeKey := "t13-dev-call-principal-01"
	f.authorize(t, revokeKey)
	approved := f.request(t, revokeKey, t15DevDigest("principal"), "req-principal")
	if _, _, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", approved.ID, "approved", "admin-a", "ok"); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.repo.RevokePrincipal(ctx, "tenant-a", f.principal.ID); err != nil || !ok {
		t.Fatalf("revoke principal: %v %v", ok, err)
	}
	if claim, err := f.claim(approved.ID, revokeKey, t15DevDigest("principal"), "claim-principal"); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) || claim != nil {
		t.Fatalf("revoked principal claimed approval: %+v %v", claim, err)
	}
}
