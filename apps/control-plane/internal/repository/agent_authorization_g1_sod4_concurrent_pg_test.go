package repository

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// Rotate vs resolve/claim race: in each round an admin who is not yet a holder resolves a pending
// ticket while he concurrently rotates the credential, then claims with the new credential. Either
// the rotation revokes the approved ticket, or (resolve read holders before the rotation committed)
// the claim-time holder re-check refuses it. The rotator must never end up with a granted claim.
func TestG1SoD4ConcurrentRotateResolveClaimNeverGrantsRotator(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	const rounds = 20
	granted, resolvedFirst := 0, 0
	for round := 0; round < rounds; round++ {
		actor := fmt.Sprintf("admin-r%02d", round)
		seed := fmt.Sprintf("s4-race-%02d", round)
		a := f.pending(t, seed)
		var wg sync.WaitGroup
		var token string
		var rotErr, resErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, _, resErr = f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", a.ID, "approved", actor, "race")
		}()
		go func() {
			defer wg.Done()
			<-start
			var ok bool
			token, ok, rotErr = f.repo.RotatePrincipalCredential(ctx, "tenant-a", f.principal.ID, actor)
			if rotErr == nil && !ok {
				rotErr = fmt.Errorf("rotation found no principal")
			}
		}()
		close(start)
		wg.Wait()
		if rotErr != nil {
			t.Fatalf("round %d rotate: %v", round, rotErr)
		}
		if resErr == nil {
			resolvedFirst++
		}
		p, err := f.repo.ResolvePrincipalCredential(ctx, HashAgentToken(token))
		if err != nil || p == nil {
			t.Fatalf("round %d resolve credential: %v %v", round, p, err)
		}
		f.principal = *p
		if claim, err := f.claim(a.ID, g1s4Key(seed), t15DevDigest(seed), "claim-"+seed); g1s4Allowed(claim, err) {
			granted++
			t.Errorf("round %d: rotator %s claimed ticket he approved: %+v", round, actor, claim)
		}
	}
	t.Logf("rounds=%d resolve_succeeded=%d rotator_claims_granted=%d", rounds, resolvedFirst, granted)
	if granted != 0 {
		t.Fatalf("rotator_claims_granted=%d, want 0", granted)
	}
}
