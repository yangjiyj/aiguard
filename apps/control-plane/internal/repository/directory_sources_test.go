package repository

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDirectorySourceDraftIsTenantIsolated(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantA := setupIdentityTenant(t, db)
	tenantB := setupIdentityTenant(t, db)
	repo := NewDirectorySourceRepository(db)

	source := &DirectorySource{
		TenantID:        tenantA,
		DisplayName:     "企业 AD",
		Kind:            DirectoryKindActiveDirectory,
		ConnectionURL:   "ldaps://dc.corp.test:636",
		BindDN:          "svc-jjdguard@corp.test",
		BindPasswordEnc: "enc:v1:opaque",
	}
	if err := repo.UpsertDraft(ctx, source); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}

	got, err := repo.GetDraft(ctx, tenantB)
	if err != nil {
		t.Fatalf("GetDraft tenant B: %v", err)
	}
	if got != nil {
		t.Fatalf("tenant B must not read tenant A source: %+v", got)
	}
}

func TestDirectoryActivationClaimRejectsDraftMutationUntilIdempotentRelease(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewDirectorySourceRepository(db)
	source := &DirectorySource{
		TenantID:        tenantID,
		DisplayName:     "Original LDAP",
		Kind:            DirectoryKindLDAP,
		ConnectionURL:   "ldaps://ldap.example.test:636",
		BindDN:          "cn=bind,dc=example,dc=test",
		BindPasswordEnc: "enc:v1:opaque",
	}
	if err := repo.UpsertDraft(ctx, source); err != nil {
		t.Fatal(err)
	}
	claimedVersion := source.Version

	claim, err := repo.ClaimActivation(ctx, tenantID)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	second, err := repo.ClaimActivation(ctx, tenantID)
	if !errors.Is(err, ErrDirectorySourceActivating) || second != nil {
		t.Fatalf("second claim=%#v err=%v", second, err)
	}

	update := *source
	update.DisplayName = "Concurrent LDAP"
	if err := repo.UpsertDraft(ctx, &update); !errors.Is(err, ErrDirectorySourceActivating) {
		t.Fatalf("concurrent UpsertDraft err=%v", err)
	}
	current, err := repo.GetByID(ctx, tenantID, source.ID)
	if err != nil || current == nil || current.Version != claimedVersion || current.DisplayName != source.DisplayName {
		t.Fatalf("source changed under claim: %#v err=%v", current, err)
	}

	if err := claim.Release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := claim.Release(ctx); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	next, err := repo.ClaimActivation(ctx, tenantID)
	if err != nil || next == nil {
		t.Fatalf("claim after release=%#v err=%v", next, err)
	}
	if err := next.Release(ctx); err != nil {
		t.Fatalf("release next claim: %v", err)
	}
}

func TestDirectorySourceRuntimeReconciliationStateUsesStableReasonAndClears(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewDirectorySourceRepository(db)
	source := &DirectorySource{
		TenantID:        tenantID,
		DisplayName:     "Reconciliation LDAP",
		Kind:            DirectoryKindLDAP,
		ConnectionURL:   "ldaps://ldap.example.test:636",
		BindDN:          "cn=bind,dc=example,dc=test",
		BindPasswordEnc: "enc:v1:opaque",
	}
	if err := repo.UpsertDraft(ctx, source); err != nil {
		t.Fatal(err)
	}

	if err := repo.MarkRuntimeReconciliationRequired(
		ctx,
		tenantID,
		source.ID,
		DirectoryReconciliationReasonFullSyncFailed,
	); err != nil {
		t.Fatalf("mark reconciliation: %v", err)
	}
	got, err := repo.GetByID(ctx, tenantID, source.ID)
	if err != nil || got == nil {
		t.Fatalf("get marked source=%#v err=%v", got, err)
	}
	if !got.RuntimeReconciliationRequired ||
		got.RuntimeReconciliationReason != DirectoryReconciliationReasonFullSyncFailed {
		t.Fatalf("unexpected reconciliation state: %#v", got)
	}

	if err := repo.MarkRuntimeReconciliationRequired(
		ctx,
		tenantID,
		source.ID,
		"password leaked: raw runtime error",
	); !errors.Is(err, ErrDirectoryReconciliationReasonInvalid) {
		t.Fatalf("unsafe reason err=%v", err)
	}
	if err := repo.ClearRuntimeReconciliation(ctx, tenantID, source.ID); err != nil {
		t.Fatalf("clear reconciliation: %v", err)
	}
	got, err = repo.GetByID(ctx, tenantID, source.ID)
	if err != nil || got == nil || got.RuntimeReconciliationRequired || got.RuntimeReconciliationReason != "" {
		t.Fatalf("reconciliation state not cleared: %#v err=%v", got, err)
	}
}

func TestDirectoryActivationClaimCanceledReleaseClosesSessionAndIsIdempotent(t *testing.T) {
	db := setupIdentityTestDB(t)
	tenantID := setupIdentityTenant(t, db)
	repo := NewDirectorySourceRepository(db)
	claim, err := repo.ClaimActivation(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := claim.Release(canceled); err == nil {
		t.Fatal("canceled release must report the unlock failure")
	}
	if err := claim.Release(context.Background()); err != nil {
		t.Fatalf("release remains idempotent after hijack close: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		next, claimErr := repo.ClaimActivation(context.Background(), tenantID)
		if claimErr == nil {
			if err := next.Release(context.Background()); err != nil {
				t.Fatalf("release replacement claim: %v", err)
			}
			break
		}
		if !errors.Is(claimErr, ErrDirectorySourceActivating) || time.Now().After(deadline) {
			t.Fatalf("claim after canceled release: %v", claimErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
