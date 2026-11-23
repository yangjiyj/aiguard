package repository

import (
	"context"
	"testing"
)

func TestDirectoryUserLinkPreservesOIDCSubject(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewDirectorySourceRepository(db)

	source := &DirectorySource{
		TenantID: tenantID, DisplayName: "企业 AD",
		Kind: DirectoryKindActiveDirectory,
		ConnectionURL: "ldaps://dc.corp.test:636",
		BindDN: "svc@corp.test", BindPasswordEnc: "enc:v1:opaque",
	}
	if err := repo.UpsertDraft(ctx, source); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}
	userID := "usr_directory_link"
	if _, err := db.Exec(ctx, "INSERT INTO users (id, tenant_id, username, role, status, external_subject) VALUES ($1,$2,'alice','operator','active','oidc-subject')", userID, tenantID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(ctx, "DELETE FROM users WHERE id=$1", userID) })

	if err := repo.BindDirectoryUser(ctx, DirectoryUserLink{
		TenantID: tenantID, DirectorySourceID: source.ID, ExternalObjectID: "guid-alice", UserID: userID,
	}); err != nil {
		t.Fatalf("BindDirectoryUser: %v", err)
	}
	var subject string
	if err := db.QueryRow(ctx, "SELECT external_subject FROM users WHERE id=$1", userID).Scan(&subject); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if subject != "oidc-subject" {
		t.Fatalf("OIDC subject changed: %q", subject)
	}
}

