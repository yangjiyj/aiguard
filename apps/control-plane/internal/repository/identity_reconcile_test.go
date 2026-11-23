package repository

import (
	"context"
	"testing"
)

func TestIdentityPublicationReconcilesActiveVersion(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{
		TenantID: tenantID, DisplayName: "企业 IdP", IssuerURL: "https://idp.example.com",
		ClientID: "client-a", ClientSecretEnc: "enc:v1:test",
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src.ID, src.Version, &TestResult{Success: true}); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkPublishing(ctx, tenantID, src.ID, src.Version); err != nil {
		t.Fatal(err)
	}
	if err := repo.CommitPublication(ctx, PublicationCommit{
		TenantID: tenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: "enterprise", ConfigDigest: "sha256:old",
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRuntimeStatus(ctx, tenantID, src.ID, "drifted"); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkPublishing(ctx, tenantID, src.ID, src.Version); err != nil {
		t.Fatalf("active source must enter publishing for reconciliation: %v", err)
	}
	if err := repo.CommitPublication(ctx, PublicationCommit{
		TenantID: tenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: "enterprise", ConfigDigest: "sha256:new",
	}); err != nil {
		t.Fatalf("commit reconciliation: %v", err)
	}
	active, err := repo.GetActive(ctx, tenantID)
	if err != nil || active == nil || active.ConfigDigest != "sha256:new" || active.PublishStatus != "active" {
		t.Fatalf("unexpected reconciled source: %#v %v", active, err)
	}
}
