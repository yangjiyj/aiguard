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

// setupProxyAccessKeysTestDB opens a test DB and seeds a tenant.
func setupProxyAccessKeysTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("tenant_pxk_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM proxy_access_keys WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

// TestProxyAccessKeysIssuance is the spec for task 1.7 (P1-10): key 签发必须把
// 哈希后的密钥写入 proxy_access_keys（明文不落库），并保存 8 位前缀、模型白名单、限额默认值。
func TestProxyAccessKeysIssuance(t *testing.T) {
	pool, tenantID := setupProxyAccessKeysTestDB(t)
	repo := NewProxyAccessKeysRepository(pool)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	rawKey := "pxk-" + sfx + "-secret-plaintext-value"

	k := &ProxyAccessKey{
		ID:       "pxk_" + sfx,
		TenantID: tenantID,
		ModelIDs: []string{"gpt-4o", "deepseek-chat"},
	}

	// Create = 签发：传入明文，仓库内部哈希后入库。
	if err := repo.Create(ctx, k, rawKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 写回的哈希必须是 sha256(rawKey) 的十六进制，且绝不能等于明文。
	expHash := sha256.Sum256([]byte(rawKey))
	expHashHex := hex.EncodeToString(expHash[:])
	if k.ProxyKeyHash != expHashHex {
		t.Errorf("ProxyKeyHash = %q, want %q", k.ProxyKeyHash, expHashHex)
	}
	if k.ProxyKeyHash == rawKey {
		t.Errorf("plaintext key must not be stored as hash")
	}
	if k.ProxyKeyPrefix != rawKey[:8] {
		t.Errorf("ProxyKeyPrefix = %q, want %q", k.ProxyKeyPrefix, rawKey[:8])
	}

	// 默认限额与状态。
	if k.RPMLimit != 60 {
		t.Errorf("default RPMLimit = %d, want 60", k.RPMLimit)
	}
	if k.DailyCap != 1000 {
		t.Errorf("default DailyCap = %d, want 1000", k.DailyCap)
	}
	if k.Status != "active" {
		t.Errorf("default Status = %q, want active", k.Status)
	}

	// Get：从库里读回，哈希/前缀/模型白名单必须一致，库里存的是哈希而非明文。
	got, err := repo.Get(ctx, k.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ProxyKeyHash != expHashHex {
		t.Errorf("stored hash = %q, want %q", got.ProxyKeyHash, expHashHex)
	}
	if got.ProxyKeyPrefix != rawKey[:8] {
		t.Errorf("stored prefix = %q, want %q", got.ProxyKeyPrefix, rawKey[:8])
	}
	if len(got.ModelIDs) != 2 || got.ModelIDs[0] != "gpt-4o" || got.ModelIDs[1] != "deepseek-chat" {
		t.Errorf("stored ModelIDs = %v, want [gpt-4o deepseek-chat]", got.ModelIDs)
	}
	if got.Status != "active" {
		t.Errorf("stored Status = %q, want active", got.Status)
	}

	// ListByTenant：能按租户列出刚签发的 key。
	list, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	found := false
	for _, item := range list {
		if item.ID == k.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("ListByTenant did not return issued key %s", k.ID)
	}
}

// TestProxyAccessKeysManage 覆盖「管理」：改限额/模型白名单/状态，以及删除。
func TestProxyAccessKeysManage(t *testing.T) {
	pool, tenantID := setupProxyAccessKeysTestDB(t)
	repo := NewProxyAccessKeysRepository(pool)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	rawKey := "pxk-" + sfx + "-manage-plaintext"
	k := &ProxyAccessKey{
		ID:       "pxk_" + sfx,
		TenantID: tenantID,
		ModelIDs: []string{"gpt-4o"},
	}
	if err := repo.Create(ctx, k, rawKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Update：调整模型白名单、限额、状态（吊销）。
	if err := repo.Update(ctx, tenantID, k.ID, []string{"gpt-4o", "claude-3-5"}, 120, 5000, "revoked"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := repo.Get(ctx, k.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.RPMLimit != 120 || got.DailyCap != 5000 {
		t.Errorf("after Update RPMLimit=%d DailyCap=%d, want 120/5000", got.RPMLimit, got.DailyCap)
	}
	if got.Status != "revoked" {
		t.Errorf("after Update Status=%q, want revoked", got.Status)
	}
	if len(got.ModelIDs) != 2 {
		t.Errorf("after Update ModelIDs=%v, want 2 entries", got.ModelIDs)
	}

	// Delete：删除后 Get 应报错（无行）。
	if err := repo.Delete(ctx, tenantID, k.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.Get(ctx, k.ID); err == nil {
		t.Errorf("Get after Delete should error, got nil")
	}
}
