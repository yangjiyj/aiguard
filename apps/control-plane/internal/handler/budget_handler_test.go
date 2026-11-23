package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupBudgetHandlerDB opens a test database and seeds tenant + user fixtures.
func setupBudgetHandlerDB(t *testing.T) (*pgxpool.Pool, string, string) {
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
	tenantID := "tbh_" + sfx
	userID := "ubh_" + sfx

	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, 'enterprise', 'active')`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1, $2, $3, $4, 'x', 'platform_admin', 'active')`,
		userID, tenantID, userID, userID+"@test.com",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM pause_log WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})
	return pool, tenantID, userID
}

// withBudgetUserCtx injects a repository.User into the chi request context.
func withBudgetUserCtx(r *http.Request, tenantID, userID string) *http.Request {
	u := &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}
	ctx := context.WithValue(r.Context(), auth.UserKey, u)
	return r.WithContext(ctx)
}

// budgetTestSystemRepo is a minimal SystemRepo stub for logAudit.
type budgetTestSystemRepo struct{}

func (r *budgetTestSystemRepo) Get(_ context.Context, _ string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (r *budgetTestSystemRepo) GetAll(_ context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (r *budgetTestSystemRepo) Set(_ context.Context, _, _ string) error { return nil }
func (r *budgetTestSystemRepo) SetMultiple(_ context.Context, _ map[string]string) error {
	return nil
}
func (r *budgetTestSystemRepo) CreateAuditOperation(_ context.Context, _ *repository.AuditOperation) error {
	return nil
}
func (r *budgetTestSystemRepo) ListAuditOperations(_ context.Context, _, _ int, _ string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *budgetTestSystemRepo) GetBool(_ context.Context, _ string) (bool, error) { return false, nil }

// buildBudgetDeps creates Dependencies with all budget-relevant fields populated.
func buildBudgetDeps(pool *pgxpool.Pool, rdb *redis.Client) *Dependencies {
	teamRepo := repository.NewTeamRepository(pool)
	teamMemberRepo := repository.NewTeamMemberRepository(pool)
	quotaRepo := repository.NewQuotaPolicyRepository(pool)
	orgSvc := org.NewService(teamRepo, teamMemberRepo, quotaRepo)

	return &Dependencies{
		PauseLogRepo:   repository.NewPauseLogRepository(pool),
		BudgetSnapshot: budget.NewSnapshotReader(rdb),
		RedisClient:    rdb,
		OrgService:     orgSvc,
		SystemRepo:     &budgetTestSystemRepo{},
	}
}

// TestGetBudgetSnapshot_ReturnsStructure verifies the snapshot endpoint returns
// the expected JSON fields for a scope with seeded Redis data.
func TestGetBudgetSnapshot_ReturnsStructure(t *testing.T) {
	_, _, orgService, tenantID, _, _ := setupKeyReadModelDB(t)
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()

	// 与 GetBudgetSnapshot 一致，用 Asia/Shanghai 日界计算键名。
	// 否则 16:00–24:00 UTC 窗口内 UTC 与上海分属不同日期，
	// daily key 读不到导致 day_tokens=0（时区相关的偶发失败）。
	loc, _ := time.LoadLocation("Asia/Shanghai")
	if loc == nil {
		loc = time.Local
	}
	now := time.Now().In(loc)
	yyyymm := now.Format("2006-01")
	yyyymmdd := now.Format("2006-01-02")
	s.SetTime(now)
	rdb.HSet(ctx, "budget:tenant:"+tenantID+":"+yyyymm, "tokens", "9000", "cost_micros", "450000", "requests", "10")
	rdb.HSet(ctx, "budget:tenant:"+tenantID+":"+yyyymmdd, "tokens", "300", "cost_micros", "15000", "requests", "1")
	// Legacy float field is no longer written by the gateway and must be ignored.
	rdb.HSet(ctx, "budget:tenant:"+tenantID+":"+yyyymm, "cost", "123.45")

	deps := &Dependencies{
		BudgetSnapshot: budget.NewSnapshotReader(rdb),
		OrgService:     orgService,
		SystemRepo:     &budgetTestSystemRepo{},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/budgets/snapshot?scope_type=tenant&scope_id="+tenantID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "u_snap",
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}))
	rr := httptest.NewRecorder()
	GetBudgetSnapshot(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["scope_type"] != "tenant" {
		t.Errorf("scope_type: %v", resp["scope_type"])
	}
	if resp["scope_id"] != tenantID {
		t.Errorf("scope_id: %v", resp["scope_id"])
	}
	// month_tokens should be 9000
	if mt, ok := resp["month_tokens"].(float64); !ok || mt != 9000 {
		t.Errorf("month_tokens: %v", resp["month_tokens"])
	}
	// day_tokens should be 300
	if dt, ok := resp["day_tokens"].(float64); !ok || dt != 300 {
		t.Errorf("day_tokens: %v", resp["day_tokens"])
	}
	if mc, ok := resp["month_cost_micros"].(float64); !ok || mc != 450000 {
		t.Errorf("month_cost_micros: %v", resp["month_cost_micros"])
	}
	if resp["month_cost"] != "0.45" || resp["day_cost"] != "0.015" {
		t.Errorf("month_cost/day_cost must be exact decimal strings from micros: %v / %v", resp["month_cost"], resp["day_cost"])
	}
}

// TestPauseUnpauseKey_Roundtrip verifies the full pause→unpause lifecycle:
// 1. POST pause creates a pause_log record and sets Redis marker
// 2. POST unpause clears the DB record and removes the Redis marker
func TestPauseUnpauseKey_Roundtrip(t *testing.T) {
	pool, tenantID, userID := setupBudgetHandlerDB(t)
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	deps := buildBudgetDeps(pool, rdb)
	ctx := context.Background()

	keyPrefix := "sk-rndtrp-" + tenantID[:8]

	// --- Pause ---
	pauseBody, _ := json.Marshal(map[string]string{"reason": "over budget"})
	pauseReq := httptest.NewRequest(http.MethodPost, "/admin/v1/budgets/keys/"+keyPrefix+"/pause",
		bytes.NewBuffer(pauseBody))
	pauseReq = withBudgetUserCtx(pauseReq, tenantID, userID)

	// Inject chi URL param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("key_prefix", keyPrefix)
	pauseReq = pauseReq.WithContext(context.WithValue(pauseReq.Context(), chi.RouteCtxKey, rctx))

	pauseRR := httptest.NewRecorder()
	PauseKey(deps)(pauseRR, pauseReq)

	if pauseRR.Code != http.StatusCreated {
		t.Fatalf("pause: expected 201, got %d: %s", pauseRR.Code, pauseRR.Body.String())
	}

	// Verify Redis marker is set
	val, err := rdb.Get(ctx, budget.PauseKey(keyPrefix)).Result()
	if err != nil || val != "1" {
		t.Errorf("Redis pause marker not set: val=%q err=%v", val, err)
	}

	// Verify DB active record
	active, err := deps.PauseLogRepo.ListActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) != 1 || active[0].KeyPrefix != keyPrefix {
		t.Errorf("expected 1 active pause, got %d", len(active))
	}

	// --- Unpause ---
	unpauseReq := httptest.NewRequest(http.MethodPost, "/admin/v1/budgets/keys/"+keyPrefix+"/unpause", nil)
	unpauseReq = withBudgetUserCtx(unpauseReq, tenantID, userID)

	rctx2 := chi.NewRouteContext()
	rctx2.URLParams.Add("key_prefix", keyPrefix)
	unpauseReq = unpauseReq.WithContext(context.WithValue(unpauseReq.Context(), chi.RouteCtxKey, rctx2))

	unpauseRR := httptest.NewRecorder()
	UnpauseKey(deps)(unpauseRR, unpauseReq)

	if unpauseRR.Code != http.StatusOK {
		t.Fatalf("unpause: expected 200, got %d: %s", unpauseRR.Code, unpauseRR.Body.String())
	}

	// Redis marker should be gone
	if n, _ := rdb.Exists(ctx, budget.PauseKey(keyPrefix)).Result(); n != 0 {
		t.Errorf("Redis pause marker should be removed after unpause")
	}

	// DB active records should be empty
	active2, err := deps.PauseLogRepo.ListActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListActive after unpause: %v", err)
	}
	if len(active2) != 0 {
		t.Errorf("expected 0 active after unpause, got %d", len(active2))
	}
}

func (r *budgetTestSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
