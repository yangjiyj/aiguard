package repository_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func forecastTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestForecastJobCreateAndGet(t *testing.T) {
	db := forecastTestDB(t)
	repo := repository.NewForecastJobRepository(db)
	ctx := context.Background()

	jobID := fmt.Sprintf("fcst_test_%d", time.Now().UnixNano())
	job := &repository.ForecastJob{
		ID:       jobID,
		TenantID: "tenant_test",
		ParamsJSON: map[string]any{
			"range_days": 30,
			"quota_params": map[string]any{
				"monthly_budget_limit": 100.0,
				"overage_action":       "rate_limit",
			},
		},
		CreatedBy: "user_test",
	}

	if err := repo.Create(ctx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, jobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected job, got nil")
	}
	if got.Status != "pending" {
		t.Errorf("expected status=pending, got %q", got.Status)
	}
	if got.TenantID != "tenant_test" {
		t.Errorf("expected tenant_id=tenant_test, got %q", got.TenantID)
	}
}

func TestForecastJobClaimPending(t *testing.T) {
	db := forecastTestDB(t)
	repo := repository.NewForecastJobRepository(db)
	ctx := context.Background()

	ts := time.Now().UnixNano()
	jobID := fmt.Sprintf("fcst_claim_%d", ts)
	job := &repository.ForecastJob{
		ID:       jobID,
		TenantID: "tenant_claim_test",
		ParamsJSON: map[string]any{
			"range_days": 7,
		},
		CreatedBy: "user_claim",
	}

	if err := repo.Create(ctx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Drain pending jobs until we get ours or confirm it eventually transitions
	// We call ClaimPending in a loop until we either get our job or exhaust pending
	var claimed *repository.ForecastJob
	var err error
	for i := 0; i < 50; i++ {
		claimed, err = repo.ClaimPending(ctx)
		if err != nil {
			t.Fatalf("ClaimPending[%d]: %v", i, err)
		}
		if claimed == nil {
			break
		}
		if claimed.ID == jobID {
			break
		}
		// If we claimed a different job, mark it failed to clean up so it won't block
		_ = repo.Finish(ctx, claimed.ID, "failed", nil, "claimed by test cleanup")
	}

	// Verify our specific job was eventually claimed (status=running) or check directly
	got, err := repo.Get(ctx, jobID)
	if err != nil {
		t.Fatalf("Get after claim: %v", err)
	}
	if got == nil {
		t.Fatal("job disappeared")
	}
	// The job should be either running (if claimed by us) or pending (if other jobs were ahead)
	// In a clean test env it should be running
	if claimed != nil && claimed.ID == jobID && claimed.Status != "running" {
		t.Errorf("expected claimed job status=running, got %q", claimed.Status)
	}
	if got.Status != "running" && got.Status != "pending" {
		t.Errorf("unexpected job status: %q", got.Status)
	}
}

func TestForecastJobFinish(t *testing.T) {
	db := forecastTestDB(t)
	repo := repository.NewForecastJobRepository(db)
	ctx := context.Background()

	jobID := fmt.Sprintf("fcst_finish_%d", time.Now().UnixNano())
	job := &repository.ForecastJob{
		ID:         jobID,
		TenantID:   "tenant_finish_test",
		ParamsJSON: map[string]any{"range_days": 14},
		CreatedBy:  "user_finish",
	}

	if err := repo.Create(ctx, job); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Simulate claiming then finishing
	claimed, err := repo.ClaimPending(ctx)
	if err != nil {
		t.Fatalf("ClaimPending: %v", err)
	}
	if claimed == nil {
		t.Fatal("no pending job to claim")
	}

	result := map[string]any{
		"total":          100,
		"intercepted":    5,
		"saved_usd":      12.5,
		"affected_users": 3,
	}
	if err := repo.Finish(ctx, jobID, "done", result, ""); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	got, err := repo.Get(ctx, jobID)
	if err != nil {
		t.Fatalf("Get after finish: %v", err)
	}
	if got.Status != "done" {
		t.Errorf("expected status=done, got %q", got.Status)
	}
	if got.FinishedAt == nil {
		t.Error("expected finished_at to be set")
	}
	if got.ResultJSON == nil {
		t.Error("expected result_json to be set")
	}
}

func TestForecastJobListByTenant(t *testing.T) {
	db := forecastTestDB(t)
	repo := repository.NewForecastJobRepository(db)
	ctx := context.Background()

	ts := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_list_%d", ts)
	for i := 0; i < 3; i++ {
		job := &repository.ForecastJob{
			ID:         fmt.Sprintf("fcst_list_%d_%d", ts, i),
			TenantID:   tenantID,
			ParamsJSON: map[string]any{"range_days": i + 1},
			CreatedBy:  "user_list",
		}
		if err := repo.Create(ctx, job); err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
	}

	jobs, err := repo.ListByTenant(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(jobs) != 3 {
		t.Errorf("expected 3 jobs, got %d", len(jobs))
	}
}
