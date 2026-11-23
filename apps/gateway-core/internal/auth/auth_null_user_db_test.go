package auth

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

// chat-portal (G1) 回归守护：portal 发放的无归属 key（internal_keys.user_id=NULL）
// 必须能通过数据面鉴权。validateKey 若把 user_id 裸 Scan 进 string，NULL 行直接报错，
// 整条数据面 key 认证被打挂（middleware 回 internal_error）。
// DB 驱动测试，需 CONTENT_LOGS_TEST_DATABASE_URL 指向已初始化的 newapi 库，否则 t.Skip。
func TestValidateKeyHandlesNullUserID(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed auth test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}

	ns := fmt.Sprintf("authnu_%d", time.Now().UnixNano())
	tenantID := "tenant_" + ns
	projectID := "proj_" + ns
	keyID := "key_" + ns

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, is_test) VALUES ($1, $2, TRUE)`, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, projectID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed project: %v", err)
	}

	rawKey := "sk-nouser-" + ns
	sum := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(sum[:])
	// 直接落一条 user_id 为 NULL 的 key 行（模拟 portal-integration 无归属发放）
	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, status)
		VALUES ($1, $2, $3, NULL, $4, $5, '["chat"]', 'active')
	`, keyID, tenantID, projectID, keyHash, rawKey[:8]); err != nil {
		db.Close()
		t.Fatalf("seed null-user key: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE id = $1`, projectID)
		db.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})

	am := &AuthMiddleware{db: db}
	record, err := am.validateKey(ctx, keyHash)
	if err != nil {
		t.Fatalf("validateKey on NULL user_id row: %v", err)
	}
	if record == nil {
		t.Fatal("validateKey returned nil record for existing key")
	}
	if record.UserID != "" {
		t.Fatalf("record.UserID = %q, want empty string", record.UserID)
	}
	if record.TenantID != tenantID || record.ProjectID != projectID {
		t.Fatalf("record tenant/project = %q/%q, want %q/%q", record.TenantID, record.ProjectID, tenantID, projectID)
	}
}
