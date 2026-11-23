package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const revealTestSecret = "key-reveal-handler-test-secret-0001"

// setupRevealKeyTestDB 连测试库并 seed 一个 tenant+project+user（internal_keys 外键）。
func setupRevealKeyTestDB(t *testing.T) (*pgxpool.Pool, string, string, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed reveal_key test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	ns := fmt.Sprintf("rvk_%d", time.Now().UnixNano())
	tenantID := "tenant_" + ns
	projectID := "proj_" + ns
	userID := "user_" + ns
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, is_test) VALUES ($1,$2,TRUE)`, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1,$2,$3)`, projectID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed project: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username) VALUES ($1,$2,$3)`, userID, tenantID, ns); err != nil {
		db.Close()
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE id=$1`, projectID)
		db.Exec(c, `DELETE FROM users WHERE id=$1`, userID)
		db.Exec(c, `DELETE FROM tenants WHERE id=$1`, tenantID)
		db.Close()
	})
	return db, tenantID, projectID, userID
}

// revealRequest 构造带 auth user + chi URL 参数 id 的 GET 请求。
func revealRequest(tenantID, userID, keyID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys/"+keyID+"/reveal", nil)
	user := &repository.User{ID: userID, TenantID: tenantID, Role: "platform_admin", Status: "active"}
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", keyID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	return req
}

type revealBody struct {
	FullKey *string `json:"full_key"`
	Reason  string  `json:"reason"`
}

// 新建 key（有密文）reveal 应 200 返完整明文，且写 1 条 reveal_key 审计。
func TestRevealKeyReturnsFullKeyAndAudits(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", revealTestSecret)
	db, tenantID, projectID, userID := setupRevealKeyTestDB(t)
	repo := repository.NewInternalKeyRepository(db)
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{KeyRepo: repo, SystemRepo: auditRepo}

	rawKey := "na_reveal_full_" + tenantID
	key := &repository.InternalKey{TenantID: tenantID, ProjectID: projectID, UserID: userID, Status: "active"}
	if err := repo.Create(context.Background(), key, rawKey); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rr := httptest.NewRecorder()
	RevealKey(deps)(rr, revealRequest(tenantID, userID, key.ID))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp revealBody
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if resp.FullKey == nil || *resp.FullKey != rawKey {
		t.Fatalf("full_key = %v, want %q", resp.FullKey, rawKey)
	}
	if resp.Reason != "" {
		t.Errorf("reason 应为空，got %q", resp.Reason)
	}
	if auditRepo.count != 1 {
		t.Errorf("审计应写 1 条 reveal_key，got %d", auditRepo.count)
	}
}

// 改造前老 key（密文 NULL）reveal 应 200 但 full_key=null + reason，且不写审计（未揭示任何明文）。
func TestRevealKeyCreatedBeforeEncryptionReturnsReason(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", revealTestSecret)
	db, tenantID, projectID, userID := setupRevealKeyTestDB(t)
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{KeyRepo: repository.NewInternalKeyRepository(db), SystemRepo: auditRepo}

	keyID := fmt.Sprintf("key_legacy_%d", time.Now().UnixNano())
	if _, err := db.Exec(context.Background(),
		`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, name, status, key_ciphertext)
		 VALUES ($1,$2,$3,$4,$5,$6,'[]','','active',NULL)`,
		keyID, tenantID, projectID, userID, "hash_"+keyID, "na_legac"); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}

	rr := httptest.NewRecorder()
	RevealKey(deps)(rr, revealRequest(tenantID, userID, keyID))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp revealBody
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if resp.FullKey != nil {
		t.Errorf("full_key 应为 null，got %q", *resp.FullKey)
	}
	if resp.Reason != "created_before_encryption" {
		t.Errorf("reason = %q, want created_before_encryption", resp.Reason)
	}
	if auditRepo.count != 0 {
		t.Errorf("未揭示明文不应写审计，got %d", auditRepo.count)
	}
}

// 密文损坏（无法解密）reveal 应 500，绝不静默返回坏值。
func TestRevealKeyDecryptFailureReturns500(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", revealTestSecret)
	db, tenantID, projectID, userID := setupRevealKeyTestDB(t)
	deps := &Dependencies{KeyRepo: repository.NewInternalKeyRepository(db), SystemRepo: &agentGuardAuditSystemRepo{}}

	keyID := fmt.Sprintf("key_corrupt_%d", time.Now().UnixNano())
	if _, err := db.Exec(context.Background(),
		`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, name, status, key_ciphertext)
		 VALUES ($1,$2,$3,$4,$5,$6,'[]','','active',$7)`,
		keyID, tenantID, projectID, userID, "hash_"+keyID, "na_corru", "enc:v1:@@@not-base64@@@"); err != nil {
		t.Fatalf("seed corrupt key: %v", err)
	}

	rr := httptest.NewRecorder()
	RevealKey(deps)(rr, revealRequest(tenantID, userID, keyID))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%s", rr.Code, rr.Body.String())
	}
}

// 目标 key 不存在（或跨租户）reveal 应 404。
func TestRevealKeyNotFoundReturns404(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", revealTestSecret)
	db, tenantID, _, userID := setupRevealKeyTestDB(t)
	deps := &Dependencies{KeyRepo: repository.NewInternalKeyRepository(db), SystemRepo: &agentGuardAuditSystemRepo{}}

	rr := httptest.NewRecorder()
	RevealKey(deps)(rr, revealRequest(tenantID, userID, "key_does_not_exist"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", rr.Code, rr.Body.String())
	}
}

// 无 auth user（受保护组前提）应 401，且在触碰任何数据前短路。
func TestRevealKeyRequiresAuthenticatedUser(t *testing.T) {
	deps := &Dependencies{}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys/key_x/reveal", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "key_x")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	RevealKey(deps)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rr.Code, rr.Body.String())
	}
}
