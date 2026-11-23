package repository

// W3 迁移 880 真库测试：登录历史可记录不存在的账号；密码历史裁剪。

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func openConsoleLoginTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CONSOLE_LOGIN_TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("JJD_REQUIRE_CONSOLE_LOGIN_DB_TESTS") == "1" {
			t.Fatal("CONSOLE_LOGIN_TEST_DATABASE_URL is required when JJD_REQUIRE_CONSOLE_LOGIN_DB_TESTS=1")
		}
		t.Skip("CONSOLE_LOGIN_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedConsoleLoginUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID string) {
	t.Helper()
	ctx := context.Background()
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID, userID = "tclr_"+sfx, "uclr_"+sfx
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, tenant_id, username, password_hash, role, status) VALUES ($1, $2, $1, 'x', 'platform_admin', 'active')`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM user_login_history WHERE user_id = $1 OR attempted_username LIKE $2`, userID, tenantID+"%")
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	return tenantID, userID
}

func TestLoginHistoryRecordsUnknownAccountAndEvents(t *testing.T) {
	pool := openConsoleLoginTestPool(t)
	tenantID, userID := seedConsoleLoginUser(t, pool)
	repo := NewUserLoginHistoryRepository(pool)
	ctx := context.Background()

	if err := repo.Record(ctx, LoginAttempt{AttemptedUsername: tenantID + "_ghost", IP: "192.0.2.1", FailureReason: "unknown_user"}); err != nil {
		t.Fatalf("unknown account attempt must be storable: %v", err)
	}
	if err := repo.Record(ctx, LoginAttempt{UserID: userID, IP: "192.0.2.1", UserAgent: strings.Repeat("x", 900), Success: true}); err != nil {
		t.Fatalf("oversized user agent must be truncated, not rejected: %v", err)
	}
	if err := repo.Record(ctx, LoginAttempt{UserID: userID, Event: LoginEventLogout, Success: true}); err != nil {
		t.Fatal(err)
	}
	entries, err := repo.ListByUser(ctx, userID, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d (%v)", len(entries), err)
	}
	if entries[0].Event != LoginEventLogout || entries[1].Event != LoginEventLogin || len(entries[1].UserAgent) != 512 {
		t.Fatalf("unexpected entries: %+v %+v", entries[0], entries[1])
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM user_login_history WHERE user_id IS NULL AND attempted_username = $1`, tenantID+"_ghost").Scan(&n)
	if n != 1 {
		t.Fatalf("unknown account row missing, got %d", n)
	}
}

func TestConsoleUserSecurityPasswordHistoryTrims(t *testing.T) {
	pool := openConsoleLoginTestPool(t)
	_, userID := seedConsoleLoginUser(t, pool)
	repo := NewConsoleUserSecurityRepository(pool)
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		if err := repo.Record(ctx, userID, fmt.Sprintf("hash-%d", i), 4); err != nil {
			t.Fatal(err)
		}
	}
	hashes, err := repo.RecentHashes(ctx, userID, 10)
	if err != nil || len(hashes) != 4 || hashes[0] != "hash-6" || hashes[3] != "hash-3" {
		t.Fatalf("history must keep newest 4, got %v (%v)", hashes, err)
	}
	sec, err := repo.Get(ctx, userID)
	if err != nil || sec.TOTPEnabled {
		t.Fatalf("defaults: %+v %v", sec, err)
	}
	if err := repo.MarkPasswordChanged(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetTOTP(ctx, userID, "enc", true); err != nil {
		t.Fatal(err)
	}
	sec, _ = repo.Get(ctx, userID)
	if sec.PasswordChangedAt == nil || !sec.TOTPEnabled || sec.TOTPSecretEnc != "enc" {
		t.Fatalf("security fields not persisted: %+v", sec)
	}
	_ = repo.SetTOTP(ctx, userID, "", false)
	sec, _ = repo.Get(ctx, userID)
	if sec.TOTPEnabled || sec.TOTPSecretEnc != "" {
		t.Fatalf("reset must clear the secret: %+v", sec)
	}
}

// 迁移 880 必须写入全部默认设置，且不覆盖管理员已改的值（ON CONFLICT DO NOTHING）。
func TestMigration880SeedsConsoleLoginDefaults(t *testing.T) {
	pool := openConsoleLoginTestPool(t)
	want := map[string]string{
		"console_login_lockout_threshold": "5", "console_login_lockout_minutes": "30",
		"console_password_min_length": "12", "console_password_min_classes": "3",
		"console_password_history_count": "5", "console_password_max_age_days": "90",
		"console_session_idle_minutes": "30", "console_session_absolute_hours": "12",
		"console_session_max_concurrent": "3", "console_admin_totp_required": "false",
	}
	rows, err := pool.Query(context.Background(), `SELECT key, value FROM system_settings WHERE key LIKE 'console\_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		got[k] = v
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	if _, ok := got["console_admin_ip_allowlist"]; !ok {
		t.Error("console_admin_ip_allowlist must be seeded (empty = unrestricted)")
	}
	body, err := os.ReadFile("../../../../deploy/migrations/880_console_login_security.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ON CONFLICT (key) DO NOTHING") {
		t.Fatal("migration 880 must not overwrite administrator-changed settings")
	}
}
