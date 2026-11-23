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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupSavingHandlerDB opens a test DB and seeds a tenant + saving_metrics fixture row.
// Returns the pool, tenantID, and projectID. Caller must close the pool in a cleanup.
func setupSavingHandlerDB(t *testing.T) (*pgxpool.Pool, string, string) {
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
	tenantID := "tsav_" + sfx
	projectID := "psav_" + sfx

	// Insert tenant
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, 'enterprise', 'active')`,
		tenantID, tenantID,
	); err != nil {
		pool.Close()
		t.Fatalf("insert tenant: %v", err)
	}
	// Insert project
	if _, err := pool.Exec(ctx,
		`INSERT INTO projects (id, name, tenant_id) VALUES ($1, $2, $3)`,
		projectID, projectID, tenantID,
	); err != nil {
		pool.Close()
		t.Fatalf("insert project: %v", err)
	}
	// Insert saving_metrics fixture
	if _, err := pool.Exec(ctx, `
		INSERT INTO saving_metrics (tenant_id, team_id, project_id, user_id, date, source, saving_usd, saving_cny, request_count)
		VALUES ($1, '', $2, '', CURRENT_DATE, 'cache_hit', 5.0, 36.0, 10)
		ON CONFLICT DO NOTHING
	`, tenantID, projectID); err != nil {
		pool.Close()
		t.Fatalf("insert saving_metrics: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO saving_metrics (tenant_id, team_id, project_id, user_id, date, source, saving_usd, saving_cny, request_count)
		VALUES ($1, '', $2, '', CURRENT_DATE, 'model_downgraded', 2.5, 18.0, 5)
		ON CONFLICT DO NOTHING
	`, tenantID, projectID); err != nil {
		pool.Close()
		t.Fatalf("insert saving_metrics: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM saving_metrics WHERE tenant_id = $1`, tenantID)
		pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID)
		pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})
	return pool, tenantID, projectID
}

func buildSavingDeps(pool *pgxpool.Pool) *Dependencies {
	return &Dependencies{
		SavingDB: pool,
	}
}

func withSavingAdmin(req *http.Request, tenantID string) *http.Request {
	user := &repository.User{ID: "saving-admin", TenantID: tenantID, Role: "platform_admin", Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func TestGetSavingsSummary_Basic(t *testing.T) {
	pool, tenantID, projectID := setupSavingHandlerDB(t)
	deps := buildSavingDeps(pool)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/savings/summary?range=30d&scope_type=project&scope_id="+projectID, nil)
	req = withSavingAdmin(req, tenantID)
	rec := httptest.NewRecorder()
	GetSavingsSummary(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	totalUSD, _ := resp["total_usd"].(float64)
	if totalUSD < 7.0 { // at least cache_hit (5.0) + model_downgraded (2.5)
		t.Errorf("expected total_usd >= 7.5, got %f", totalUSD)
	}

	bySource, ok := resp["by_source"].(map[string]interface{})
	if !ok {
		t.Fatal("missing by_source in response")
	}
	if _, exists := bySource["cache_hit"]; !exists {
		t.Error("expected by_source.cache_hit in response")
	}
}

func TestGetSavingsSummary_EmptyResult(t *testing.T) {
	pool, tenantID, _ := setupSavingHandlerDB(t)
	deps := buildSavingDeps(pool)

	// Use a non-existent project_id
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/savings/summary?scope_type=project&scope_id=nonexistent_proj_xyz", nil)
	req = withSavingAdmin(req, tenantID)
	rec := httptest.NewRecorder()
	GetSavingsSummary(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	totalUSD, _ := resp["total_usd"].(float64)
	if totalUSD != 0 {
		t.Errorf("expected 0 for nonexistent project, got %f", totalUSD)
	}
}

func TestGetSavingsTrend_BySource(t *testing.T) {
	pool, tenantID, _ := setupSavingHandlerDB(t)
	deps := buildSavingDeps(pool)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/savings/trend?range=30d&groupBy=source", nil)
	req = withSavingAdmin(req, tenantID)
	rec := httptest.NewRecorder()
	GetSavingsTrend(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	data, ok := resp["data"].([]interface{})
	if !ok {
		t.Fatal("missing data array in response")
	}
	if len(data) == 0 {
		t.Error("expected at least 1 trend row")
	}
}

func TestGetSavingsTrend_InvalidGroupBy(t *testing.T) {
	pool, tenantID, _ := setupSavingHandlerDB(t)
	deps := buildSavingDeps(pool)

	// Invalid groupBy should fall back to "source" without error
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/savings/trend?groupBy=INVALID_COLUMN", nil)
	req = withSavingAdmin(req, tenantID)
	rec := httptest.NewRecorder()
	GetSavingsTrend(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (fallback to source groupBy), got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["group_by"] != "source" {
		t.Errorf("expected group_by=source (fallback), got %v", resp["group_by"])
	}
}
