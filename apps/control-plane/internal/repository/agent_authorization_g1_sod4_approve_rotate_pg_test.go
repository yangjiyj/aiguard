package repository

import (
	"context"
	"testing"
)

// N2 (ported from g1-sod3-review TestG1R3ApproveThenRotateClaim): admin-b approves a request made
// under creator-a's credential, then rotates and claims it with the new credential. The rotation
// must invalidate the approved-but-unclaimed ticket.
func TestG1SoD4ApproveThenRotateClaimRefused(t *testing.T) {
	f := newT15SoDFixture(t)
	seed := "s4-approve-then-rotate"
	a := f.pending(t, seed)
	if _, _, err := f.repo.ResolveAgentAuthorizationApproval(context.Background(), "tenant-a", a.ID, "approved", "admin-b", "s4"); err != nil {
		t.Fatalf("independent approve: %v", err)
	}
	g1s4Rotate(t, f, "admin-b")
	if status, _ := f.status(t, a.ID); status != "revoked" {
		t.Fatalf("approved ticket survived rotation: status=%s", status)
	}
	if claim, err := f.claim(a.ID, g1s4Key(seed), t15DevDigest(seed), "claim-"+seed); g1s4Allowed(claim, err) {
		t.Fatalf("BYPASS: rotator claimed a ticket he approved: %+v", claim)
	}
}
