package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupCGCTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	tenantID := fmt.Sprintf("tenant_cgc_%d", time.Now().UnixNano())
	ctx := context.Background()
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM cost_governance_config WHERE tenant_id = $1`, tenantID)
		db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestCostGovernanceConfigGetDefault(t *testing.T) {
	db, tenantID := setupCGCTestDB(t)
	ctx := context.Background()
	repo := NewCostGovernanceConfigRepository(db)

	// No row exists → should return defaults.
	cfg, err := repo.Get(ctx, tenantID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cfg.TenantID != tenantID {
		t.Errorf("expected tenant_id=%s, got %s", tenantID, cfg.TenantID)
	}
	if cfg.LaborHourlyRate != 250 {
		t.Errorf("expected default labor_hourly_rate=250, got %f", cfg.LaborHourlyRate)
	}
	if cfg.LaborHoursPerOp != 0.5 {
		t.Errorf("expected default labor_hours_per_op=0.5, got %f", cfg.LaborHoursPerOp)
	}
}

func TestCostGovernanceConfigUpsertAndGet(t *testing.T) {
	db, tenantID := setupCGCTestDB(t)
	ctx := context.Background()
	repo := NewCostGovernanceConfigRepository(db)

	cfg := &CostGovernanceConfig{
		TenantID:                  tenantID,
		SelfResearchSavingMonthly: 5000.0,
		LaborHourlyRate:           300.0,
		LaborHoursPerOp:           0.75,
	}
	if err := repo.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := repo.Get(ctx, tenantID)
	if err != nil {
		t.Fatalf("Get after upsert: %v", err)
	}
	if got.LaborHourlyRate != 300 {
		t.Errorf("expected 300, got %f", got.LaborHourlyRate)
	}
	if got.SelfResearchSavingMonthly != 5000 {
		t.Errorf("expected 5000, got %f", got.SelfResearchSavingMonthly)
	}

	// Upsert again to test update.
	cfg.LaborHourlyRate = 350
	if err := repo.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}
	got2, _ := repo.Get(ctx, tenantID)
	if got2.LaborHourlyRate != 350 {
		t.Errorf("expected updated 350, got %f", got2.LaborHourlyRate)
	}
}
