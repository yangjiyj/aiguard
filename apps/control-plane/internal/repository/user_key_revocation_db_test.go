package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// W2.2 (migration 870): disabling / deleting / directory-deactivating a user
// revokes every internal key the user owns in the same transaction and writes
// an audit_operations row. Project-level keys (user_id NULL) and keys of other
// users are untouched. Restoring the user does not restore keys.
//
// Real-DB test: needs CONTENT_LOGS_TEST_DATABASE_URL pointing at a database
// migrated through 870; otherwise it is skipped.
func TestUserDeactivationRevokesOwnedKeys(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed key revocation test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(db.Close)

	ns := fmt.Sprintf("w22_%d", time.Now().UnixNano()%1_000_000_000_000)
	tenantID := "t_" + ns
	projectID := "p_" + ns
	w22Exec(t, db, `INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, TRUE)`, tenantID)
	w22Exec(t, db, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $1)`, projectID, tenantID)

	newUser := func(suffix string) string {
		id := "u_" + ns + "_" + suffix
		w22Exec(t, db, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $1, 'viewer', 'active')`, id, tenantID)
		return id
	}
	newKey := func(suffix, userID string) string {
		id := "k_" + ns + "_" + suffix
		var owner any
		if userID != "" {
			owner = userID
		}
		w22Exec(t, db, `
			INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, status)
			VALUES ($1, $2, $3, $4, $1, 'sk-w22', '["chat"]', 'active')`,
			id, tenantID, projectID, owner)
		return id
	}
	keyStatus := func(id string) string {
		var s string
		if err := db.QueryRow(ctx, `SELECT status FROM internal_keys WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatalf("read key %s: %v", id, err)
		}
		return s
	}

	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM users WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	leaver := newUser("leaver")
	colleague := newUser("colleague")
	dirUser := newUser("dir")
	retired := newUser("retired")
	leaverKeyA := newKey("leaver_a", leaver)
	leaverKeyB := newKey("leaver_b", leaver)
	colleagueKey := newKey("colleague", colleague)
	projectKey := newKey("project", "")
	dirKey := newKey("dir", dirUser)
	retiredKey := newKey("retired", retired)

	// 1. Console lifecycle path: users.status active -> disabled.
	w22Exec(t, db, `UPDATE users SET status='disabled', updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, tenantID, leaver)
	for _, k := range []string{leaverKeyA, leaverKeyB} {
		if got := keyStatus(k); got != "revoked" {
			t.Fatalf("key %s of disabled user: status=%q, want revoked", k, got)
		}
	}
	if got := keyStatus(colleagueKey); got != "active" {
		t.Fatalf("other user's key: status=%q, want active", got)
	}
	if got := keyStatus(projectKey); got != "active" {
		t.Fatalf("project-level key (user_id NULL): status=%q, want active", got)
	}
	assertRevokeAudit(t, db, tenantID, leaver, "user_status_disabled", []string{leaverKeyA, leaverKeyB})

	// 2. Re-enabling does not bring keys back.
	w22Exec(t, db, `UPDATE users SET status='active', updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, tenantID, leaver)
	if got := keyStatus(leaverKeyA); got != "revoked" {
		t.Fatalf("restoring a user must not restore keys: status=%q", got)
	}

	// 3. Directory sync path, inside the activation transaction; a rollback
	//    must also roll back the revocation (same transaction).
	repo := NewDirectorySyncPreviewRepository(db)
	rollbackErr := fmt.Errorf("forced rollback")
	err = repo.RunInTx(ctx, func(tx pgx.Tx) error {
		if n, err := repo.MarkDirectoryUserDisabledTx(ctx, tx, tenantID, []string{dirUser}); err != nil || n != 1 {
			t.Fatalf("MarkDirectoryUserDisabledTx n=%d err=%v", n, err)
		}
		var inTx string
		if err := tx.QueryRow(ctx, `SELECT status FROM internal_keys WHERE id=$1`, dirKey).Scan(&inTx); err != nil {
			t.Fatalf("read key in tx: %v", err)
		}
		if inTx != "revoked" {
			t.Fatalf("directory-disabled user key inside tx: %q, want revoked", inTx)
		}
		return rollbackErr
	})
	if err == nil {
		t.Fatal("RunInTx should return the forced rollback error")
	}
	if got := keyStatus(dirKey); got != "active" {
		t.Fatalf("rolled-back directory disable must not leave the key revoked: %q", got)
	}
	if err := repo.RunInTx(ctx, func(tx pgx.Tx) error {
		_, err := repo.MarkDirectoryUserDisabledTx(ctx, tx, tenantID, []string{dirUser})
		return err
	}); err != nil {
		t.Fatalf("directory disable: %v", err)
	}
	if got := keyStatus(dirKey); got != "revoked" {
		t.Fatalf("directory-disabled user key: %q, want revoked", got)
	}
	assertRevokeAudit(t, db, tenantID, dirUser, "user_status_disabled", []string{dirKey})

	// 4. Delete path that retires a referenced user (status='deleted').
	w22Exec(t, db, `UPDATE users SET status='deleted', updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, tenantID, retired)
	if got := keyStatus(retiredKey); got != "revoked" {
		t.Fatalf("retired (deleted) user key: %q, want revoked", got)
	}
	assertRevokeAudit(t, db, tenantID, retired, "user_status_deleted", []string{retiredKey})

	// Final: project-level key survived everything.
	if got := keyStatus(projectKey); got != "active" {
		t.Fatalf("project-level key after all transitions: %q, want active", got)
	}
}

func w22Exec(t *testing.T, db *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func assertRevokeAudit(t *testing.T, db *pgxpool.Pool, tenantID, userID, reason string, wantKeys []string) {
	t.Helper()
	var detail []byte
	err := db.QueryRow(context.Background(), `
		SELECT action_detail FROM audit_operations
		WHERE tenant_id=$1 AND action_type='user.keys.revoke' AND target_id=$2
		ORDER BY created_at DESC LIMIT 1`, tenantID, userID).Scan(&detail)
	if err != nil {
		t.Fatalf("revocation audit for %s: %v", userID, err)
	}
	var got struct {
		Reason string   `json:"reason"`
		KeyIDs []string `json:"key_ids"`
		Count  int      `json:"revoked_count"`
	}
	if err := json.Unmarshal(detail, &got); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	want := append([]string(nil), wantKeys...)
	sort.Strings(want)
	if got.Reason != reason || got.Count != len(want) || fmt.Sprint(got.KeyIDs) != fmt.Sprint(want) {
		t.Fatalf("audit for %s = %+v, want reason=%s keys=%v", userID, got, reason, want)
	}
}
