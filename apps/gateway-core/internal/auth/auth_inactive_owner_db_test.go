package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// W2.1: a key owned by a user who is no longer active must be rejected by the
// gateway even if the key row itself is still 'active' (e.g. revocation not yet
// run, restored from backup, or written by an older control plane). Project
// level keys (internal_keys.user_id NULL) keep working.
//
// This drives the real Middleware against a real database. The key rows are
// written directly as 'active' to prove the gateway checks users.status on its
// own and does not rely only on control-plane revocation (W2.2).
func TestMiddlewareRejectsKeyOfInactiveUser(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed auth test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(db.Close)

	ns := fmt.Sprintf("w21_%d", time.Now().UnixNano()%1_000_000_000_000)
	tenantID := "t_" + ns
	projectID := "p_" + ns
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, TRUE)`, tenantID)
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $1)`, projectID, tenantID)
	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM users WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	seedKey := func(name, userID string) string {
		raw := "sk-" + ns + "-" + name
		sum := sha256.Sum256([]byte(raw))
		var owner any
		if userID != "" {
			owner = userID
		}
		exec(`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, status)
			VALUES ($1, $2, $3, $4, $5, $6, '["chat"]', 'active')`,
			"k_"+ns+"_"+name, tenantID, projectID, owner, hex.EncodeToString(sum[:]), raw[:8])
		return raw
	}
	seedUser := func(name, status string) string {
		id := "u_" + ns + "_" + name
		exec(`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $1, 'viewer', $3)`, id, tenantID, status)
		return id
	}

	activeUser := seedUser("active", "active")
	activeKey := seedKey("active", activeUser)
	projectKey := seedKey("project", "")
	leaver := seedUser("leaver", "active")
	leaverKey := seedKey("leaver", leaver)
	// Seed the deleted user as active, add the key, then flip the status with
	// the trigger disabled so the key row stays 'active' whatever the schema.
	deleted := seedUser("deleted", "active")
	deletedKey := seedKey("deleted", deleted)
	provisioning := seedUser("prov", "provisioning")
	provisioningKey := seedKey("prov", provisioning)

	flipStatusKeepingKeysActive := func(userID, status string) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			t.Fatalf("disable triggers: %v", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET status=$2 WHERE id=$1`, userID, status); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	mw := NewAuthMiddleware(db, nil, nil)
	handler := mw.Middleware(&config.Config{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(key string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Error.Code
	}

	// Before: everyone with an active user (or no user) passes.
	for name, key := range map[string]string{"active": activeKey, "project": projectKey, "leaver": leaverKey} {
		if code, errCode := call(key); code != http.StatusNoContent {
			t.Fatalf("%s key before disable: status=%d code=%s, want 204", name, code, errCode)
		}
	}

	selfRevokeKey := seedKey("self-revoke", activeUser)
	if status, _ := call(selfRevokeKey); status != 204 {
		t.Fatal("fresh owned Key did not reach handler")
	}
	sum := sha256.Sum256([]byte(selfRevokeKey))
	exec("UPDATE internal_keys SET status='revoked' WHERE key_hash=$1", hex.EncodeToString(sum[:]))
	if status, code := call(selfRevokeKey); status != 401 || code != "key_revoked" {
		t.Fatalf("revoked Key still admitted: status=%d code=%s", status, code)
	}

	flipStatusKeepingKeysActive(leaver, "disabled")
	flipStatusKeepingKeysActive(deleted, "deleted")

	for name, key := range map[string]string{"disabled": leaverKey, "deleted": deletedKey, "provisioning": provisioningKey} {
		code, errCode := call(key)
		if code != http.StatusUnauthorized || errCode != "key_owner_inactive" {
			t.Fatalf("%s owner key: status=%d code=%q, want 401 key_owner_inactive", name, code, errCode)
		}
	}
	// Project-level key and an active colleague's key are unaffected.
	for name, key := range map[string]string{"active": activeKey, "project": projectKey} {
		if code, errCode := call(key); code != http.StatusNoContent {
			t.Fatalf("%s key after colleague disabled: status=%d code=%s, want 204", name, code, errCode)
		}
	}
	// Re-enabling the owner lets a still-active key work again (gateway check
	// only; W2.2 revocation is what makes the disable permanent for keys).
	flipStatusKeepingKeysActive(leaver, "active")
	if code, _ := call(leaverKey); code != http.StatusNoContent {
		t.Fatalf("key of re-enabled owner: status=%d, want 204", code)
	}
}

// W2.6 lifecycle rules, end to end through the real schema (migration 870
// trigger enabled):
//   - disabling a user through a normal status UPDATE revokes the key, and
//     re-enabling the user does NOT bring the key back (key_revoked);
//   - moving a user to another department keeps the key working, and usage
//     stays attributed to the key's application department (projects.team_id),
//     not to the user's new department.
func TestKeyLifecycleOnReenableAndDepartmentChange(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed auth test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(db.Close)

	ns := fmt.Sprintf("w26_%d", time.Now().UnixNano()%1_000_000_000_000)
	tenantID := "t_" + ns
	projectID := "p_" + ns
	deptA, deptB := "team_a_"+ns, "team_b_"+ns
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, TRUE)`, tenantID)
	exec(`INSERT INTO teams (id, tenant_id, name, path) VALUES ($1::text, $2, $1::text, '/' || $1::text)`, deptA, tenantID)
	exec(`INSERT INTO teams (id, tenant_id, name, path) VALUES ($1::text, $2, $1::text, '/' || $1::text)`, deptB, tenantID)
	exec(`INSERT INTO projects (id, tenant_id, name, team_id) VALUES ($1, $2, $1, $3)`, projectID, tenantID, deptA)
	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM users WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM teams WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	seedUserWithKey := func(name string) (string, string) {
		userID := "u_" + ns + "_" + name
		exec(`INSERT INTO users (id, tenant_id, username, role, status, department_id)
			VALUES ($1, $2, $1, 'viewer', 'active', $3)`, userID, tenantID, deptA)
		raw := "sk-" + ns + "-" + name
		sum := sha256.Sum256([]byte(raw))
		exec(`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, status)
			VALUES ($1, $2, $3, $4, $5, $6, '["chat"]', 'active')`,
			"k_"+ns+"_"+name, tenantID, projectID, userID, hex.EncodeToString(sum[:]), raw[:8])
		return userID, raw
	}

	var seenDepartment string
	mw := NewAuthMiddleware(db, nil, nil)
	handler := mw.Middleware(&config.Config{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenDepartment = ""
		if p := getPrincipalFromCtx(r.Context()); p != nil {
			seenDepartment = p.ApplicationDepartmentID
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(key string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Error.Code
	}

	// Re-enable does not restore keys.
	leaver, leaverKey := seedUserWithKey("leaver")
	exec(`UPDATE users SET status='disabled' WHERE id=$1`, leaver)
	if code, errCode := call(leaverKey); code != http.StatusUnauthorized {
		t.Fatalf("disabled owner: status=%d code=%s, want 401", code, errCode)
	}
	exec(`UPDATE users SET status='active' WHERE id=$1`, leaver)
	if code, errCode := call(leaverKey); code != http.StatusUnauthorized || errCode != "key_revoked" {
		t.Fatalf("re-enabled owner: status=%d code=%q, want 401 key_revoked (keys are not restored)", code, errCode)
	}

	// Department change keeps the key and its application department.
	mover, moverKey := seedUserWithKey("mover")
	if code, errCode := call(moverKey); code != http.StatusNoContent || seenDepartment != deptA {
		t.Fatalf("before move: status=%d code=%s dept=%q, want 204 %s", code, errCode, seenDepartment, deptA)
	}
	exec(`UPDATE users SET department_id=$2 WHERE id=$1`, mover, deptB)
	if code, errCode := call(moverKey); code != http.StatusNoContent {
		t.Fatalf("after move: status=%d code=%s, want 204 (department change must not revoke keys)", code, errCode)
	}
	if seenDepartment != deptA {
		t.Fatalf("after move: application department=%q, want %q (usage follows the key's project)", seenDepartment, deptA)
	}
	var keyStatus string
	if err := db.QueryRow(ctx, `SELECT status FROM internal_keys WHERE user_id=$1`, mover).Scan(&keyStatus); err != nil || keyStatus != "active" {
		t.Fatalf("mover key status=%q err=%v, want active", keyStatus, err)
	}
}
