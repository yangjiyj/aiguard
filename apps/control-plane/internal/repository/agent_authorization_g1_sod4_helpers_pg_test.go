package repository

import (
	"context"
	"testing"
)

// G1 batch 4 helpers: authorization granted before a credential rotation must not reach the
// new holder (N1 exception-then-rotate, N2 approve-then-rotate).

func g1s4Rotate(t *testing.T, f *t15SoDFixture, actor string) {
	t.Helper()
	token, ok, err := f.repo.RotatePrincipalCredential(context.Background(), "tenant-a", f.principal.ID, actor)
	if err != nil || !ok {
		t.Fatalf("rotate by %s: ok=%v err=%v", actor, ok, err)
	}
	p, err := f.repo.ResolvePrincipalCredential(context.Background(), HashAgentToken(token))
	if err != nil || p == nil {
		t.Fatalf("resolve rotated credential: %v %v", p, err)
	}
	f.principal = *p
}

func g1s4Key(seed string) string { return t15DevKey("t13-sod-", seed)[:40] }

// g1s4Allowed reports whether a claim was granted (error or refusal both count as not allowed).
func g1s4Allowed(claim *AgentAuthorizationApprovalClaim, err error) bool {
	return err == nil && claim != nil && claim.Allowed
}
