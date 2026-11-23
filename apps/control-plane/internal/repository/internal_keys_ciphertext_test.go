package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// key-reveal（后台复制完整密钥）：Create 必须把完整明文 AES-GCM 加密落 key_ciphertext，
// 且 GetByHash / GetByID 能取回该密文并解回原始明文（供后台受保护 reveal 端点复制）。
func TestInternalKeyCreateStoresRecoverableCiphertext(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "key-reveal-unit-test-secret-0001")
	db, tenantID, projectID, userID := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)

	rawKey := "sk-int-recoverable-" + tenantID // >= 8 chars, 唯一
	key := &InternalKey{
		TenantID:  tenantID,
		ProjectID: projectID,
		UserID:    userID,
		Status:    "active",
	}
	if err := repo.Create(ctx, key, rawKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Create 后内存对象即带密文
	if key.KeyCiphertext == "" {
		t.Fatal("Create 后 key.KeyCiphertext 不应为空")
	}
	if !strings.HasPrefix(key.KeyCiphertext, "enc:v1:") {
		t.Errorf("KeyCiphertext 应为 enc:v1: 前缀密文，got %q", key.KeyCiphertext)
	}
	if strings.Contains(key.KeyCiphertext, rawKey) {
		t.Error("KeyCiphertext 绝不能含明文 rawKey")
	}

	// GetByID：reveal 端点取密文的读路径
	got, err := repo.GetByID(ctx, tenantID, key.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetByID 返回 nil")
	}
	if got.KeyCiphertext == "" {
		t.Fatal("GetByID 返回的 KeyCiphertext 为空")
	}
	plain, err := secrets.DecryptProviderSecret(got.KeyCiphertext)
	if err != nil {
		t.Fatalf("DecryptProviderSecret: %v", err)
	}
	if plain != rawKey {
		t.Errorf("解密结果 = %q, want %q", plain, rawKey)
	}

	// GetByHash 同步带密文（读侧列对位回归守护）
	byHash, err := repo.GetByHash(ctx, got.KeyHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if byHash.KeyCiphertext != got.KeyCiphertext {
		t.Errorf("GetByHash 密文 = %q, want %q", byHash.KeyCiphertext, got.KeyCiphertext)
	}
}

// GetByID 必须租户隔离：错误租户或不存在的 id 返回 (nil, nil)，供 handler 判 404。
func TestInternalKeyGetByIDTenantIsolationAndMissing(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "key-reveal-unit-test-secret-0001")
	db, tenantID, projectID, userID := setupInternalKeysTestDB(t)
	ctx := context.Background()
	repo := NewInternalKeyRepository(db)

	key := &InternalKey{TenantID: tenantID, ProjectID: projectID, UserID: userID, Status: "active"}
	if err := repo.Create(ctx, key, "sk-int-iso-"+tenantID); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 正确租户命中
	got, err := repo.GetByID(ctx, tenantID, key.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID 命中失败: got=%v err=%v", got, err)
	}

	// 错误租户 -> nil,nil
	other, err := repo.GetByID(ctx, "tenant_not_owner", key.ID)
	if err != nil {
		t.Fatalf("GetByID 错误租户不应报错: %v", err)
	}
	if other != nil {
		t.Errorf("GetByID 跨租户应返回 nil，got %#v", other)
	}

	// 不存在 id -> nil,nil
	missing, err := repo.GetByID(ctx, tenantID, "key_does_not_exist")
	if err != nil {
		t.Fatalf("GetByID 不存在 id 不应报错: %v", err)
	}
	if missing != nil {
		t.Errorf("GetByID 不存在 id 应返回 nil，got %#v", missing)
	}
}
