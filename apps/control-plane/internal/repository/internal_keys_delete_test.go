package repository

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
)

func TestInternalKeyDeletionRetainsReferencesRevokesAndAudits(t *testing.T) {
	db, tenant, project, user := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)
	if _, err := db.Exec(ctx, "UPDATE users SET status='active' WHERE id=$1", user); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "disabled", "revoked"} {
		key := &InternalKey{TenantID: tenant, ProjectID: project, UserID: user, Status: status, Name: status}
		if err := repo.Create(ctx, key, "sk-delete-"+tenant+status); err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, "foreign", key.ID, user); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("foreign tenant deletion accepted")
		}
		if err := repo.DeleteOwned(ctx, tenant, key.ID, ""); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("empty owner deletion accepted")
		}
		if err := repo.DeleteOwned(ctx, tenant, key.ID, "foreign-user"); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("foreign owner deletion accepted")
		}
		var err error
		if status == "active" {
			err = repo.DeleteOwned(ctx, tenant, key.ID, user)
		} else {
			err = repo.Delete(ctx, tenant, key.ID, user)
		}
		if err != nil {
			t.Fatal(err)
		}
		stored, e := repo.GetByHash(ctx, key.KeyHash)
		if e != nil || stored.IsValid() || stored.Status != "revoked" || stored.KeyCiphertext != "" {
			t.Fatal("deleted key still usable or credential retained")
		}
		if found, e := repo.GetByID(ctx, tenant, key.ID); e != nil || found != nil {
			t.Fatal("deleted key visible")
		}
		if _, e = db.Exec(ctx, "UPDATE internal_keys SET status='active' WHERE id=$1", key.ID); e == nil {
			t.Fatal("legacy write restored key")
		}
		if _, e = db.Exec(ctx, "UPDATE internal_keys SET deleted_at=NULL WHERE id=$1", key.ID); e == nil {
			t.Fatal("deleted key restored")
		}
	}
	for name, list := range map[string]func() ([]*InternalKey, error){"all": func() ([]*InternalKey, error) { return repo.ListAll(ctx, tenant) }, "project": func() ([]*InternalKey, error) { return repo.List(ctx, tenant, project) }, "user": func() ([]*InternalKey, error) { return repo.ListByUser(ctx, tenant, user) }} {
		keys, err := list()
		if err != nil || len(keys) != 0 {
			t.Fatalf("%s archived list %+v %v", name, keys, err)
		}
	}
	var count int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type IN ('delete_key','portal_delete_key')", tenant).Scan(&count); err != nil || count != 3 {
		t.Fatalf("audit count %d %v", count, err)
	}
}

func TestInternalKeyDeleteAuditFailureRollsBack(t *testing.T) {
	db, tenant, project, user := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)
	key := &InternalKey{TenantID: tenant, ProjectID: project, UserID: user, Status: "active"}
	if err := repo.Create(ctx, key, "sk-delete-audit-"+tenant); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, tenant, key.ID, "nonexistent-audit-actor"); err == nil {
		t.Fatal("delete succeeded without audit")
	}
	current, err := repo.GetByID(ctx, tenant, key.ID)
	if err != nil || current == nil || !current.IsValid() {
		t.Fatal("audit failure left partial key deletion")
	}
}

func TestDeletedEmployeeKeyHiddenUntilExplicitEnsurePreservesGeneration(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	employee := NewEmployeeAPIKeyRepository(db)
	keys := NewInternalKeyRepository(db)
	old, _, err := employee.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := employee.Credential(ctx, tenant, user)
	if err != nil || raw == "" {
		t.Fatal("missing initial Chat credential")
	}
	if err = keys.DeleteOwned(ctx, tenant, old.ID, user); err != nil {
		t.Fatal(err)
	}
	if current, err := employee.Current(ctx, tenant, user); err != nil || current != nil {
		t.Fatal("deleted employee metadata reappeared")
	}
	if _, _, err = employee.Credential(ctx, tenant, user); !errors.Is(err, ErrEmployeeKeyDenied) {
		t.Fatal("deleted default key still usable")
	}
	fresh, created, err := employee.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil || !created || fresh.ID == old.ID || fresh.Generation != old.Generation+1 {
		t.Fatalf("new generation %+v %v %v", fresh, created, err)
	}
	var oldStatus string
	var hidden bool
	if err = db.QueryRow(ctx, "SELECT status,deleted_at IS NOT NULL FROM internal_keys WHERE id=$1", old.ID).Scan(&oldStatus, &hidden); err != nil || oldStatus != "revoked" || !hidden {
		t.Fatal("old default key resurrected")
	}
	list, err := keys.ListByUser(ctx, tenant, user)
	if err != nil || len(list) != 1 || list[0].ID != fresh.ID {
		t.Fatal("old default key remains in user list")
	}
}
