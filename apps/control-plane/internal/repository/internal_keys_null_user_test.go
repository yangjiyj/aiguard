package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// chat-portal (G1) 回归守护：CreatePortalKey 允许 user_id 留空（机器通道无"当前用户"可默认）。
// internal_keys.user_id 带外键 REFERENCES users(id)，空串是非 NULL 值会撞 23503 外键违约；
// 写侧必须 NULLIF 落 NULL，读侧必须 COALESCE 规整回空串（裸 string Scan 在 NULL 行上会报错，
// 连带打挂同表读路径——含 gateway-core 的 validateKey）。
func TestInternalKeyCreateWithoutUserFallsBackToNull(t *testing.T) {
	db, tenantID, projectID, _ := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)

	rawKey := "sk-nouser-" + tenantID // >= 8 chars, 唯一
	key := &InternalKey{
		TenantID:  tenantID,
		ProjectID: projectID,
		UserID:    "",
		Scopes:    []string{"chat"},
		Status:    "active",
	}
	if err := repo.Create(ctx, key, rawKey); err != nil {
		t.Fatalf("Create with empty user_id: %v", err)
	}

	// 落库必须是 NULL 而非空串（空串会挂 users(id) 外键）
	var isNull bool
	if err := db.QueryRow(ctx, `SELECT user_id IS NULL FROM internal_keys WHERE id = $1`, key.ID).Scan(&isNull); err != nil {
		t.Fatalf("query stored user_id: %v", err)
	}
	if !isNull {
		t.Fatal("stored user_id should be NULL, got non-NULL value")
	}

	// 三处读路径在 NULL 行上不得报错，且规整为空串
	sum := sha256.Sum256([]byte(rawKey))
	got, err := repo.GetByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("GetByHash on NULL user_id row: %v", err)
	}
	if got.UserID != "" {
		t.Fatalf("GetByHash UserID = %q, want empty string", got.UserID)
	}

	listed, err := repo.List(ctx, tenantID, projectID)
	if err != nil {
		t.Fatalf("List on NULL user_id row: %v", err)
	}
	if len(listed) != 1 || listed[0].UserID != "" {
		t.Fatalf("List = %d rows (UserID %q), want 1 row with empty UserID", len(listed), listed[0].UserID)
	}

	all, err := repo.ListAll(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListAll on NULL user_id row: %v", err)
	}
	if len(all) != 1 || all[0].UserID != "" {
		t.Fatalf("ListAll = %d rows, want 1 row with empty UserID", len(all))
	}
}

// 有归属的 key 行为不变（回归护栏：NULLIF 只影响空串）。
func TestInternalKeyCreateWithUserKeepsAttribution(t *testing.T) {
	db, tenantID, projectID, userID := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)

	rawKey := "sk-owned-" + tenantID
	key := &InternalKey{
		TenantID:  tenantID,
		ProjectID: projectID,
		UserID:    userID,
		Scopes:    []string{"chat"},
		Status:    "active",
	}
	if err := repo.Create(ctx, key, rawKey); err != nil {
		t.Fatalf("Create with user_id: %v", err)
	}

	sum := sha256.Sum256([]byte(rawKey))
	got, err := repo.GetByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.UserID != userID {
		t.Fatalf("GetByHash UserID = %q, want %q", got.UserID, userID)
	}
}
