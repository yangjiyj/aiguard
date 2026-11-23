package repository

import (
	"context"
	"errors"
	"testing"
)

// Defence in depth, independent of the rotation-time revocation: if a holder-authorized ticket or
// exception still exists (e.g. a rotation racing a resolve, or rows written outside the rotation
// path), claim and auto-approval re-check holders = {created_by} ∪ rotated_by.
func TestG1SoD4ClaimRechecksHolders(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	g1s4Rotate(t, f, "admin-b")
	// Approval resolved by a current holder (simulated: layer 1 cannot produce it).
	seed := "s4-holder-resolved"
	a := f.pending(t, seed)
	if _, err := f.db.Exec(ctx, `UPDATE agentguard_confirmations SET status='approved', resolved_by='admin-b', resolved_at=clock_timestamp() WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := f.claim(a.ID, g1s4Key(seed), t15DevDigest(seed), "claim-"+seed)
	if !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || g1s4Allowed(claim, err) {
		t.Fatalf("holder-resolved claim: %+v err=%v", claim, err)
	}
	if st, _ := f.status(t, a.ID); st != "approved" {
		t.Fatalf("refused claim mutated ticket: %s", st)
	}
	// Exception created by a current holder (simulated insert that bypasses the create-time check).
	seed = "s4-holder-exception"
	in := f.exceptionInput(seed)
	if _, err := f.db.Exec(ctx, `INSERT INTO agent_authorization_approval_exceptions (id, tenant_id, principal_id, grant_id, action,
		resource_type, resource_id, arguments_sha256, created_by, reason, idempotency_key_sha256, request_sha256, expires_at)
		VALUES (gen_random_uuid(),'tenant-a',$1,$2,$3,$4,$5,$6,'admin-b','sim',$7,$7,clock_timestamp()+interval '60 seconds')`,
		in.PrincipalID, in.GrantID, in.Action, in.ResourceType, in.ResourceID, in.ArgumentsSHA256, HashAgentToken(seed)); err != nil {
		t.Fatal(err)
	}
	key := g1s4Key(seed)
	f.authorize(t, key)
	b := f.request(t, key, t15DevDigest(seed), "req-"+seed)
	if b.Status != "pending" || b.ExceptionID != "" {
		t.Fatalf("holder exception auto-approved: %+v", b)
	}
}
