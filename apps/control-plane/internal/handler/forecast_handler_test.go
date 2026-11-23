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

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)


func setupForecastHandlerDB(t *testing.T) (*pgxpool.Pool, string, string) {
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
	tenantID := "tfh_" + sfx
	userID := "ufh_" + sfx
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1,$2,$3,$4,'x','platform_admin','active')`,
		userID, tenantID, userID, userID+"@test.com",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM forecast_jobs WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})
	return pool, tenantID, userID
}

func buildForecastDeps(pool *pgxpool.Pool) *Dependencies {
	return &Dependencies{
		ForecastJobRepo: repository.NewForecastJobRepository(pool),
		SystemRepo:      &budgetTestSystemRepo{},
	}
}

func withForecastUserCtx(r *http.Request, tenantID, userID string) *http.Request {
	u := &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, u))
}

func TestCreateForecastJobHandler(t *testing.T) {
	pool, tenantID, userID := setupForecastHandlerDB(t)
	deps := buildForecastDeps(pool)

	body := map[string]any{
		"range_days": 30,
		"quota_params": map[string]any{
			"monthly_budget_limit": 100.0,
			"overage_action":       "rate_limit",
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/forecast/jobs", bytes.NewReader(b))
	req = withForecastUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()

	CreateForecastJob(deps)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["id"] == "" || resp["id"] == nil {
		t.Error("expected job id in response")
	}
	if resp["status"] != "pending" {
		t.Errorf("expected status=pending, got %v", resp["status"])
	}
}

func TestListForecastJobsHandler(t *testing.T) {
	pool, tenantID, userID := setupForecastHandlerDB(t)
	deps := buildForecastDeps(pool)
	ctx := context.Background()

	// Pre-create 2 jobs
	repo := repository.NewForecastJobRepository(pool)
	ts := time.Now().UnixNano()
	for i := 0; i < 2; i++ {
		job := &repository.ForecastJob{
			ID:         fmt.Sprintf("fcst_htest_%d_%d", ts, i),
			TenantID:   tenantID,
			ParamsJSON: map[string]any{"range_days": i + 1},
			CreatedBy:  userID,
		}
		if err := repo.Create(ctx, job); err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/forecast/jobs", nil)
	req = withForecastUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()

	ListForecastJobs(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	items := resp["items"].([]any)
	if len(items) < 2 {
		t.Errorf("expected >= 2 items, got %d", len(items))
	}
}

func TestGetForecastJobHandler(t *testing.T) {
	pool, tenantID, userID := setupForecastHandlerDB(t)
	deps := buildForecastDeps(pool)
	ctx := context.Background()

	repo := repository.NewForecastJobRepository(pool)
	jobID := fmt.Sprintf("fcst_hget_%d", time.Now().UnixNano())
	if err := repo.Create(ctx, &repository.ForecastJob{
		ID:         jobID,
		TenantID:   tenantID,
		ParamsJSON: map[string]any{"range_days": 7},
		CreatedBy:  userID,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("id", jobID)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/forecast/jobs/"+jobID, nil)
	req = withForecastUserCtx(req, tenantID, userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
	w := httptest.NewRecorder()

	GetForecastJob(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var job map[string]any
	if err := json.NewDecoder(w.Body).Decode(&job); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if job["ID"] != jobID && job["id"] != jobID {
		t.Errorf("expected job id=%s, got %v", jobID, job)
	}
}
