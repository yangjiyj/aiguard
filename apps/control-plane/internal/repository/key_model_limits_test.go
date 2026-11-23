package repository

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/jackc/pgx/v5"
	"reflect"
	"testing"
)

func TestOwnedKeyModelEditAndEmployeeResetPreserveLimits(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	ctx := context.Background()
	provider := tenant + "_provider"
	if _, err := db.Exec(ctx, "INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'fixture','openai')", provider, tenant); err != nil {
		t.Fatal(err)
	}
	for _, model := range []string{"model-a", "model-b"} {
		if _, err := db.Exec(ctx, "INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,$3)", provider+model, provider, model); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		db.Exec(ctx, "DELETE FROM models WHERE provider_id=$1", provider)
		db.Exec(ctx, "DELETE FROM providers WHERE id=$1", provider)
	})
	managed := NewEmployeeAPIKeyRepository(db)
	repo := NewInternalKeyRepository(db)
	current, _, err := managed.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	models := []string{"model-a"}
	name := "受限个人 Key"
	if err = repo.UpdateOwned(ctx, tenant, current.ID, user, OwnedKeyUpdate{Name: &name, ModelAllowlist: &models}); err != nil {
		t.Fatal(err)
	}
	saved, err := repo.GetByID(ctx, tenant, current.ID)
	if err != nil || !reflect.DeepEqual(saved.ModelAllowlist, models) {
		t.Fatalf("limits not persisted: %v", err)
	}
	bad := []string{"model-outside"}
	if err = repo.UpdateOwned(ctx, tenant, current.ID, user, OwnedKeyUpdate{ModelAllowlist: &bad}); !errors.Is(err, modelaccess.ErrKeyModelUnauthorized) {
		t.Fatalf("unauthorized edit=%v", err)
	}
	if err = repo.UpdateOwned(ctx, tenant, current.ID, "another-user", OwnedKeyUpdate{ModelAllowlist: &models}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("owner isolation=%v", err)
	}
	reset, raw, err := managed.Reset(ctx, tenant, user, current.ID, current.Generation, project, dept, version)
	if err != nil || raw == "" || !reflect.DeepEqual(reset.ModelAllowlist, models) {
		t.Fatalf("reset did not retain limits: %v", err)
	}
	old, err := repo.GetByID(ctx, tenant, current.ID)
	if err != nil || old.Status != "revoked" {
		t.Fatal("old generation still usable")
	}
	empty := []string{}
	if err = repo.UpdateOwned(ctx, tenant, reset.ID, user, OwnedKeyUpdate{ModelAllowlist: &empty}); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedLegacyKeyRotationCreatesRecoverableKeyAndRevokesOld(t *testing.T) {
	db, tenant, user, _, project, _ := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)
	old := &InternalKey{TenantID: tenant, UserID: user, ProjectID: project, Name: "legacy", Scopes: []string{"chat", "models"}, Status: "active", ModelAllowlist: []string{"previously-authorized-model"}}
	if err := repo.Create(ctx, old, "fixture-only-legacy-key-material"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "UPDATE internal_keys SET key_ciphertext=NULL WHERE id=$1", old.ID); err != nil {
		t.Fatal(err)
	}
	fresh, raw, err := repo.RotateOwned(ctx, tenant, old.ID, user)
	if err != nil || fresh == nil || raw == "" || fresh.KeyCiphertext == "" {
		t.Fatalf("legacy rotation failed: %v", err)
	}
	if fresh.Name != old.Name || !reflect.DeepEqual(fresh.ModelAllowlist, old.ModelAllowlist) || !reflect.DeepEqual(fresh.Scopes, old.Scopes) {
		t.Fatal("rotation changed key restrictions")
	}
	before, err := repo.GetByID(ctx, tenant, old.ID)
	if err != nil || before.Status != "revoked" {
		t.Fatal("old key not revoked")
	}
	if _, _, err := repo.RotateOwned(ctx, tenant, fresh.ID, "foreign-user"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("foreign rotation accepted")
	}
}

func TestOwnedKeyEnableCannotBypassExistingActiveKeyLimit(t *testing.T) {
	db, tenant, user, _, project, _ := employeeKeyFixture(t)
	repo := NewInternalKeyRepository(db)
	ctx := context.Background()
	for index := 0; index < 5; index++ {
		key := &InternalKey{TenantID: tenant, UserID: user, ProjectID: project, Status: "active", Scopes: []string{"chat"}}
		if err := repo.Create(ctx, key, "fixture-active-limit-"+string(rune('a'+index))); err != nil {
			t.Fatal(err)
		}
	}
	disabled := &InternalKey{TenantID: tenant, UserID: user, ProjectID: project, Status: "disabled", Scopes: []string{"chat"}}
	if err := repo.Create(ctx, disabled, "fixture-disabled-limit"); err != nil {
		t.Fatal(err)
	}
	active := "active"
	if err := repo.UpdateOwned(ctx, tenant, disabled.ID, user, OwnedKeyUpdate{Status: &active}); !errors.Is(err, ErrOwnedKeyLimitReached) {
		t.Fatalf("activation limit was bypassed: %v", err)
	}
}
func TestEmployeeLegacyClaimReturnsRecoveryReasonAndResetWorks(t *testing.T) {
	db, tenant, user, dept, project, version := employeeKeyFixture(t)
	repo := NewEmployeeAPIKeyRepository(db)
	ctx := context.Background()
	key, _, err := repo.Ensure(ctx, tenant, user, project, dept, version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "UPDATE internal_keys SET key_ciphertext=NULL WHERE id=$1", key.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.Claim(ctx, tenant, user, key.ID, key.Generation); !errors.Is(err, ErrEmployeeKeyEncryptionUnavailable) {
		t.Fatalf("missing encryption reason lost: %v", err)
	}
	next, raw, err := repo.Reset(ctx, tenant, user, key.ID, key.Generation, project, dept, version)
	if err != nil || raw == "" || next.Generation != key.Generation+1 {
		t.Fatal("explicit reset cannot recover legacy managed key")
	}
}
