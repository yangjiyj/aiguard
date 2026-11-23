package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Task 2.1 (P0-1, 支柱⑤): 内部 key 明文 -> 哈希存储 + 一次性明示。
// DB 驱动测试。需 CONTENT_LOGS_TEST_DATABASE_URL 指向已初始化的 newapi 库，
// 否则 t.Skip。internal_keys 对 project_id(NOT NULL) / user_id 有外键，
// 故 setup 同时 seed 一个 tenant + project + user。
func setupInternalKeysTestDB(t *testing.T) (*pgxpool.Pool, string, string, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed internal_keys test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	ns := fmt.Sprintf("ikt_%d", time.Now().UnixNano())
	tenantID := "tenant_" + ns
	projectID := "proj_" + ns
	userID := "user_" + ns

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, is_test) VALUES ($1, $2, TRUE)`, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, projectID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed project: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username) VALUES ($1, $2, $3)`, userID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed user: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE id = $1`, projectID)
		db.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		db.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID, projectID, userID
}

// 回归守护：Create 必须以 sha256 哈希落库，GetByHash 凭哈希取回。
// 删除 key_value 明文列前后都应 GREEN —— 证明鉴权链路（仅靠 key_hash）不受影响。
func TestInternalKeyCreateHashesAndGetByHash(t *testing.T) {
	db, tenantID, projectID, userID := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)

	rawKey := "sk-int-" + tenantID // >= 8 chars, 唯一
	key := &InternalKey{
		TenantID:  tenantID,
		ProjectID: projectID,
		UserID:    userID,
		Status:    "active",
	}
	if err := repo.Create(ctx, key, rawKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sum := sha256.Sum256([]byte(rawKey))
	expHash := hex.EncodeToString(sum[:])

	got, err := repo.GetByHash(ctx, expHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.KeyHash != expHash {
		t.Errorf("KeyHash = %q, want %q", got.KeyHash, expHash)
	}
	if got.KeyHash == rawKey {
		t.Errorf("KeyHash 不应等于明文 rawKey")
	}
	if got.KeyPrefix != rawKey[:8] {
		t.Errorf("KeyPrefix = %q, want %q", got.KeyPrefix, rawKey[:8])
	}
	if got.ID != key.ID {
		t.Errorf("ID = %q, want %q", got.ID, key.ID)
	}
}

// RED 驱动：DB 内不得再有 key_value 明文列。
// 现状 count=1（漂移列存在）-> 期望 0（migration 064 DROP COLUMN 后）。
func TestInternalKeysHasNoPlaintextColumn(t *testing.T) {
	db, _, _, _ := setupInternalKeysTestDB(t)
	ctx := context.Background()
	var n int
	err := db.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'internal_keys' AND column_name = 'key_value'`).Scan(&n)
	if err != nil {
		t.Fatalf("query information_schema: %v", err)
	}
	if n != 0 {
		t.Errorf("internal_keys 仍存在明文列 key_value (count=%d)；DROP COLUMN 后应为 0", n)
	}
}
