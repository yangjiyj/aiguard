package repository

import (
	"context"
	"testing"
)

// N1 (ported from g1-sod3-review TestG1R3ExceptionThenRotateSelfUse): admin-b creates an exception
// while independent, rotates the credential, then drives the exact request as the agent. The
// rotation must revoke the exception, so the request stays pending and cannot be claimed.
func TestG1SoD4ExceptionThenRotateSelfUseRefused(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	seed := "s4-exc-then-rotate"
	ex, created, err := f.repo.CreateAgentAuthorizationApprovalException(ctx, "tenant-a", "admin-b", f.exceptionInput(seed))
	if err != nil || !created {
		t.Fatalf("exception by independent admin-b: %v %v", created, err)
	}
	g1s4Rotate(t, f, "admin-b")
	var revokedBy string
	if err := f.db.QueryRow(ctx, `SELECT COALESCE(revoked_by,'') FROM agent_authorization_approval_exceptions WHERE id=$1`, ex.ID).Scan(&revokedBy); err != nil || revokedBy != "admin-b" {
		t.Fatalf("exception not revoked by rotation: revoked_by=%q err=%v", revokedBy, err)
	}
	key := g1s4Key(seed)
	f.authorize(t, key)
	a := f.request(t, key, t15DevDigest(seed), "req-"+seed)
	if a.Status != "pending" || a.ExceptionID != "" {
		t.Fatalf("rotator's request auto-approved by his own exception: %+v", a)
	}
	if claim, err := f.claim(a.ID, key, t15DevDigest(seed), "claim-"+seed); g1s4Allowed(claim, err) {
		t.Fatalf("BYPASS: rotator claimed via own exception: %+v", claim)
	}
}
