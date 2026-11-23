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

// setupUserUsageDB 建库 + 租户 + 两个用户（一个 admin、一个普通成员）+ usage_rollup_hourly 种子数据。
func setupUserUsageDB(t *testing.T) (*pgxpool.Pool, string, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "tuu_" + sfx
	adminID := "uua_" + sfx
	memberID := "uum_" + sfx

	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	for _, u := range []struct{ id, role string }{{adminID, "tenant_admin"}, {memberID, "team_member"}} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
			 VALUES ($1, $2, $3, $4, 'x', $5, 'active')`,
			u.id, tenantID, u.id, u.id+"@test.com", u.role,
		); err != nil {
			t.Fatalf("insert user %s: %v", u.id, err)
		}
	}

	// 种子 rollup：member 在近 30 天内有调用记录。
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)
	bucket := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC()
	for i := 0; i < 3; i++ {
		b := bucket.AddDate(0, 0, -i).Truncate(time.Hour)
		if _, err := pool.Exec(ctx, `
			INSERT INTO usage_rollup_hourly
			  (tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id,
			   request_count, success_count, priced_request_count, ai_request_count, non_ai_request_count, ai_success_count,
			   input_tokens, output_tokens, total_cost, latency_ms_sum, latency_count, first_seen_at, last_seen_at, updated_at)
			VALUES ($1,$2,'', $3,'','','m_test',
			        10, 9, 10, 10, 0, 9,
			        100, 200, 0.5, 1500, 10, $2, $2, NOW())
			ON CONFLICT (tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id) DO NOTHING
		`, tenantID, b, memberID); err != nil {
			t.Fatalf("seed rollup: %v", err)
		}
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM usage_rollup_hourly WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM audit_operations WHERE target_id = $1`, memberID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})

	return pool, tenantID, adminID, memberID
}

func buildUserUsageDeps(t *testing.T, pool *pgxpool.Pool) *Dependencies {
	t.Helper()
	return &Dependencies{
		UserRepo:        repository.NewUserRepository(pool),
		UsageDailyRepo:  repository.NewUsageDailyRepository(pool),
		UsageRollupRepo: repository.NewRollupReadModelRepository(pool),
		SystemRepo:      repository.NewSystemRepository(pool),
	}
}

// withUserUsageTestUser 注入指定身份的当前登录者上下文。
func withUserUsageTestUser(user *repository.User, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), auth.UserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newUsageRouter(deps *Dependencies, currentUser *repository.User) *chi.Mux {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return withUserUsageTestUser(currentUser, next)
	})
	r.Get("/admin/v1/users/{user_id}/usage/summary", GetUserUsageSummary(deps))
	r.Get("/admin/v1/users/{user_id}/usage/trend", GetUserUsageTrend(deps))
	r.Get("/admin/v1/users/{user_id}/usage/by-model", GetUserUsageByModel(deps))
	r.Get("/admin/v1/users/{user_id}/usage/records", GetUserUsageRecords(deps))
	return r
}

// TestPctChange 单测环比计算纯函数。
func TestPctChange(t *testing.T) {
	cases := []struct {
		curr, prev float64
		wantNil    bool
		wantVal    float64
	}{
		{100, 50, false, 100},
		{50, 100, false, -50},
		{0, 0, true, 0},
		{10, 0, false, 100},
	}
	for _, c := range cases {
		got := pctChange(c.curr, c.prev)
		if c.wantNil {
			if got != nil {
				t.Errorf("pctChange(%v,%v): want nil, got %v", c.curr, c.prev, *got)
			}
			continue
		}
		if got == nil {
			t.Fatalf("pctChange(%v,%v): want %.2f, got nil", c.curr, c.prev, c.wantVal)
		}
		if diff := *got - c.wantVal; diff < -0.01 || diff > 0.01 {
			t.Errorf("pctChange(%v,%v): want %.2f, got %.2f", c.curr, c.prev, c.wantVal, *got)
		}
	}
}

// TestUserUsageSummary_AdminOK 管理员能正常拿到指定用户的汇总。
func TestUserUsageSummary_AdminOK(t *testing.T) {
	pool, tenantID, adminID, memberID := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	router := newUsageRouter(deps, &repository.User{ID: adminID, TenantID: tenantID, Role: "tenant_admin"})

	req := httptest.NewRequest("GET", "/admin/v1/users/"+memberID+"/usage/summary", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp userUsageSummaryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Requests == 0 {
		t.Errorf("expected requests > 0, got 0")
	}
	if resp.SuccessRate <= 0 || resp.SuccessRate > 100 {
		t.Errorf("success rate out of range: %v", resp.SuccessRate)
	}
	if resp.TotalTokens != resp.InputTokens+resp.OutputTokens {
		t.Errorf("total tokens mismatch: %d != %d + %d", resp.TotalTokens, resp.InputTokens, resp.OutputTokens)
	}
}

// TestUserUsageSummary_NonAdminForbidden 非管理员调用 → 403。
func TestUserUsageSummary_NonAdminForbidden(t *testing.T) {
	pool, tenantID, adminID, memberID := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	router := newUsageRouter(deps, &repository.User{ID: memberID, TenantID: tenantID, Role: "team_member"})

	req := httptest.NewRequest("GET", "/admin/v1/users/"+adminID+"/usage/summary", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d: %s", w.Code, w.Body.String())
	}
}

// TestUserUsageSummary_NotFound 目标用户不存在 → 404。
func TestUserUsageSummary_NotFound(t *testing.T) {
	pool, tenantID, _, _ := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	router := newUsageRouter(deps, &repository.User{ID: "uua_" + tenantID, TenantID: tenantID, Role: "tenant_admin"})

	req := httptest.NewRequest("GET", "/admin/v1/users/nonexistent_user/usage/summary", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

// TestUserUsageSummary_CrossTenant 跨租户 → 404（非 platform_admin）。
func TestUserUsageSummary_CrossTenant(t *testing.T) {
	pool, _, _, memberID := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	// 当前登录者属于另一个租户。
	router := newUsageRouter(deps, &repository.User{ID: "outsider", TenantID: "other_tenant", Role: "tenant_admin"})

	req := httptest.NewRequest("GET", "/admin/v1/users/"+memberID+"/usage/summary", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-tenant, got %d: %s", w.Code, w.Body.String())
	}
}

// TestUserUsageTrend_AdminOK 管理员拿到趋势点序列。
func TestUserUsageTrend_AdminOK(t *testing.T) {
	pool, tenantID, adminID, memberID := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	router := newUsageRouter(deps, &repository.User{ID: adminID, TenantID: tenantID, Role: "tenant_admin"})

	req := httptest.NewRequest("GET", "/admin/v1/users/"+memberID+"/usage/trend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data) == 0 {
		t.Errorf("expected trend points, got empty")
	}
}

// TestUserUsageByModel_AdminOK 管理员拿到模型分布。
func TestUserUsageByModel_AdminOK(t *testing.T) {
	pool, tenantID, adminID, memberID := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	router := newUsageRouter(deps, &repository.User{ID: adminID, TenantID: tenantID, Role: "tenant_admin"})

	req := httptest.NewRequest("GET", "/admin/v1/users/"+memberID+"/usage/by-model", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestUserUsageRecords_ForceUserID 即使 query 带 user_id=别人，records 仍强制按路径 user_id 过滤。
func TestUserUsageRecords_ForceUserID(t *testing.T) {
	pool, tenantID, adminID, memberID := setupUserUsageDB(t)
	deps := buildUserUsageDeps(t, pool)
	router := newUsageRouter(deps, &repository.User{ID: adminID, TenantID: tenantID, Role: "tenant_admin"})

	// 故意在 query 里塞别人的 user_id，期望被路径参数覆盖。
	req := httptest.NewRequest("GET", "/admin/v1/users/"+memberID+"/usage/records?user_id=someone_else", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// 可能 200（有明细）也可能 200 空列表（无 request_logs 明细），但不应 500/403。
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}