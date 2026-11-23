package repository

import (
	"context"
	"testing"
)

// Regression: an exception created by an independent admin (never a holder) still auto-approves
// and claims exactly once; a second claim with a new claim key is refused.
func TestG1SoD4IndependentExceptionStillAutoApprovesOnce(t *testing.T) {
	f := newT15SoDFixture(t)
	seed := "s4-independent"
	ex, created, err := f.repo.CreateAgentAuthorizationApprovalException(context.Background(), "tenant-a", "reviewer-b", f.exceptionInput(seed))
	if err != nil || !created {
		t.Fatalf("independent exception: %v %v", created, err)
	}
	key := g1s4Key(seed)
	f.authorize(t, key)
	a := f.request(t, key, t15DevDigest(seed), "req-"+seed)
	if a.Status != "approved" || a.ExceptionID != ex.ID {
		t.Fatalf("independent exception did not auto-approve: %+v", a)
	}
	claim, err := f.claim(a.ID, key, t15DevDigest(seed), "claim-"+seed)
	if !g1s4Allowed(claim, err) {
		t.Fatalf("first claim: %+v %v", claim, err)
	}
	if again, err := f.claim(a.ID, key, t15DevDigest(seed), "claim-"+seed+"-2"); g1s4Allowed(again, err) {
		t.Fatalf("second claim allowed: %+v", again)
	}
}
