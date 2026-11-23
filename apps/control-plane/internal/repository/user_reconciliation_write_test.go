package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ordinaryWritePauseFixture(t *testing.T) (*pgxpool.Pool, *UserRepository, *User) {
	t.Helper()
	db := setupUserRepositoryTestDB(t)
	ctx := context.Background()
	nonce := uuid.NewString()[:8]
	tenant, id := "pause_t_"+nonce, "pause_u_"+nonce
	if _, err := db.Exec(ctx, "INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role,status,local_credential_version)
 VALUES($1,$2,$1,'old-password-hash','chat_user','active',1)`, id, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(context.Background(), "DELETE FROM audit_operations WHERE tenant_id=$1", tenant)
		db.Exec(context.Background(), "DELETE FROM users WHERE tenant_id=$1", tenant)
		db.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenant)
	})
	repo := NewUserRepository(db)
	user, err := repo.GetByID(ctx, id)
	if err != nil || user == nil {
		t.Fatalf("read fixture: %v", err)
	}
	return db, repo, user
}

func TestOrdinaryUserMetadataCannotClearConcurrentPasswordPause(t *testing.T) {
	db, repo, stale := ordinaryWritePauseFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `UPDATE users SET status='reconciliation_required',local_credential_version=local_credential_version+1 WHERE id=$1`, stale.ID); err != nil {
		t.Fatal(err)
	}
	stale.Username = "stale-profile-write"
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { close(started); done <- repo.Update(ctx, stale) }()
	<-started
	select {
	case err := <-done:
		t.Fatalf("metadata crossed password row lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrUserReconciliationRequired) {
		t.Fatalf("stale metadata error: %v", err)
	}
	current, err := repo.GetByID(ctx, stale.ID)
	if err != nil || current == nil {
		t.Fatalf("read paused user: %v", err)
	}
	var version int64
	if err = db.QueryRow(ctx, "SELECT local_credential_version FROM users WHERE id=$1", stale.ID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if current.Status != "reconciliation_required" || current.Username == stale.Username || current.PasswordHash != "old-password-hash" || version != 2 {
		t.Fatal("stale metadata cleared pause or altered fenced credentials")
	}
	for _, status := range []string{"disabled", "active"} {
		changed, err := repo.UpdateStatusForTenant(ctx, stale.TenantID, stale.ID, status)
		if changed || !errors.Is(err, ErrUserReconciliationRequired) {
			t.Fatalf("status %s escaped pause: changed=%v err=%v", status, changed, err)
		}
	}
	changed, err := repo.UpdateStatusForTenant(ctx, "another-tenant", stale.ID, "active")
	if changed || err != nil {
		t.Fatalf("cross-tenant status exposed or changed paused row: %v", err)
	}
}

func TestOrdinaryUserWritesKeepNormalMetadataAndDispositionBehavior(t *testing.T) {
	_, repo, user := ordinaryWritePauseFixture(t)
	ctx := context.Background()
	user.Email = "updated@example.invalid"
	if err := repo.Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.GetByID(ctx, user.ID)
	if err != nil || updated.Email != user.Email || updated.Status != "active" {
		t.Fatal("normal metadata update failed")
	}
	changed, err := repo.UpdateStatusForTenant(ctx, user.TenantID, user.ID, "disabled")
	if err != nil || !changed {
		t.Fatalf("normal security disposition failed: %v", err)
	}
	updated, err = repo.GetByID(ctx, user.ID)
	if err != nil || updated.Status != "disabled" {
		t.Fatal("normal user disable failed")
	}
}
