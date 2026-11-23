package repository

import (
	"context"
	"errors"
	"testing"
	"time"
)

// F1, ported from g1-review (results/T15-accept/workbuddy-g1-sod-review-20260929-attempt1/
// tests/zz_g1r_rotate_test.go). The review test asserted the bypass succeeded; here the same
// sequence must be refused: reviewer-b (not the creator) rotates the credential, drives a
// request as the agent and tries to resolve it himself.
func TestG1RRotateThenSelfApproveByNonCreator(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	token, ok, err := f.repo.RotatePrincipalCredential(ctx, "tenant-a", f.principal.ID, "reviewer-b")
	if err != nil || !ok {
		t.Fatalf("rotate: %v %v", ok, err)
	}
	p, err := f.repo.ResolvePrincipalCredential(ctx, HashAgentToken(token))
	if err != nil || p == nil {
		t.Fatalf("resolve rotated: %v", err)
	}
	f.principal = *p
	a := f.pending(t, "rotate-self")
	got, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", a.ID, "approved", "reviewer-b", "self via rotate")
	if !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || changed || got != nil {
		t.Fatalf("rotator self-approval must be refused: %+v changed=%v err=%v", got, changed, err)
	}
	if status, by := f.status(t, a.ID); status != "pending" || by != "" {
		t.Fatalf("refused self-approval mutated approval: %s %s", status, by)
	}
	if claim, err := f.claim(a.ID, t15DevKey("t13-sod-", "rotate-self")[:40], t15DevDigest("rotate-self"), "claim-rotate"); err == nil && claim != nil && claim.Allowed {
		t.Fatalf("pending approval claimable after refused self-approval: %+v", claim)
	}
	if _, created, err := f.repo.CreateAgentAuthorizationApprovalException(ctx, "tenant-a", "reviewer-b", f.exceptionInput("rotator")); !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || created {
		t.Fatalf("rotator exception: created=%v err=%v", created, err)
	}
	if got, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", a.ID, "approved", "approver-c", "independent"); err != nil || !changed || got.Status != "approved" {
		t.Fatalf("independent approver: %+v %v %v", got, changed, err)
	}
}

// Every rotator stays excluded after later rotations, and repeat rotation by the same
// admin does not grow the list.
func TestG1SoD3RotatedByAccumulatesAllRotators(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	for _, actor := range []string{"rotator-1", "rotator-2", "rotator-1", "creator-a"} {
		if _, ok, err := f.repo.RotatePrincipalCredential(ctx, "tenant-a", f.principal.ID, actor); err != nil || !ok {
			t.Fatalf("rotate by %s: %v %v", actor, ok, err)
		}
	}
	items, err := f.repo.ListPrincipals(ctx, "tenant-a")
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %d %v", len(items), err)
	}
	if got := items[0].RotatedBy; len(got) != 3 || got[0] != "rotator-1" || got[1] != "rotator-2" || got[2] != "creator-a" || items[0].CredentialRotatedAt == nil {
		t.Fatalf("rotated_by=%v rotated_at=%v", got, items[0].CredentialRotatedAt)
	}
	if _, _, err := f.repo.RotatePrincipalCredential(ctx, "tenant-a", f.principal.ID, "  "); !errors.Is(err, ErrAgentAuthorizationInvalid) {
		t.Fatalf("blank rotator accepted: %v", err)
	}
	var token string
	if token, _, err = f.repo.RotatePrincipalCredential(ctx, "tenant-a", f.principal.ID, "rotator-2"); err != nil {
		t.Fatal(err)
	}
	p, _ := f.repo.ResolvePrincipalCredential(ctx, HashAgentToken(token))
	f.principal = *p
	for i, actor := range []string{"rotator-1", "rotator-2", "creator-a"} {
		a := f.pending(t, "accum-"+actor)
		if _, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", a.ID, []string{"approved", "rejected", "approved"}[i], actor, "x"); !errors.Is(err, ErrAgentAuthorizationApprovalSelfResolution) || changed {
			t.Fatalf("%s resolved: changed=%v err=%v", actor, changed, err)
		}
	}
}

// F3 + legacy rows: a blank created_by, or a credential rotated before rotated_by existed
// (credential_rotated_at set, rotated_by empty), cannot prove requester != approver.
func TestG1SoD3UnknownCredentialHolderFailsClosed(t *testing.T) {
	f := newT15SoDFixture(t)
	ctx := context.Background()
	cases := []struct{ name, setup, reset string }{
		{"empty creator", `UPDATE agent_authorization_principals SET created_by='' WHERE id=$1`, `UPDATE agent_authorization_principals SET created_by='creator-a' WHERE id=$1`},
		{"whitespace creator", `UPDATE agent_authorization_principals SET created_by=E' \t ' WHERE id=$1`, `UPDATE agent_authorization_principals SET created_by='creator-a' WHERE id=$1`},
		{"rotated before 872", `UPDATE agent_authorization_principals SET credential_rotated_at=now(), rotated_by='{}' WHERE id=$1`, `UPDATE agent_authorization_principals SET credential_rotated_at=NULL WHERE id=$1`},
		{"blank rotator entry", `UPDATE agent_authorization_principals SET credential_rotated_at=now(), rotated_by=ARRAY[' '] WHERE id=$1`, `UPDATE agent_authorization_principals SET credential_rotated_at=NULL, rotated_by='{}' WHERE id=$1`},
	}
	for i, tc := range cases {
		a := f.pending(t, "unknown-"+string(rune('a'+i)))
		if _, err := f.db.Exec(ctx, tc.setup, f.principal.ID); err != nil {
			t.Fatal(err)
		}
		if _, changed, err := f.repo.ResolveAgentAuthorizationApproval(ctx, "tenant-a", a.ID, "approved", "reviewer-b", "x"); !errors.Is(err, ErrAgentAuthorizationApprovalHolderUnknown) || changed {
			t.Fatalf("%s resolve: changed=%v err=%v", tc.name, changed, err)
		}
		if _, created, err := f.repo.CreateAgentAuthorizationApprovalException(ctx, "tenant-a", "reviewer-b", f.exceptionInput("unknown-"+tc.name)); !errors.Is(err, ErrAgentAuthorizationApprovalHolderUnknown) || created {
			t.Fatalf("%s exception: created=%v err=%v", tc.name, created, err)
		}
		if status, _ := f.status(t, a.ID); status != "pending" {
			t.Fatalf("%s mutated approval: %s", tc.name, status)
		}
		if _, err := f.db.Exec(ctx, tc.reset, f.principal.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.repo.RegisterPrincipal(ctx, "tenant-a", AgentAuthorizationPrincipalCreate{Name: "blank", ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedBy: "  \t"}); !errors.Is(err, ErrAgentAuthorizationInvalid) {
		t.Fatalf("whitespace created_by registered: %v", err)
	}
}
