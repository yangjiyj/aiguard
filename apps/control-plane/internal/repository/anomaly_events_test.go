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

func anomalyTestDB(t *testing.T) *pgxpool.Pool {
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

func TestAnomalyEventUpsertIfNew(t *testing.T) {
	db := anomalyTestDB(t)
	repo := repository.NewAnomalyEventRepository(db)
	ctx := context.Background()

	tenant := fmt.Sprintf("t_anom_%d", time.Now().UnixNano())
	today := time.Now().UTC().Format("2006-01-02")

	ev := &repository.AnomalyEvent{
		ID:           fmt.Sprintf("ae_%d", time.Now().UnixNano()),
		TenantID:     tenant,
		DetectedDate: today,
		Dimension:    "absolute_spike",
		ScopeType:    "",
		ScopeID:      "",
		Baseline:     100.0,
		Actual:       500.0,
		Severity:     "high",
		DetailJSON:   map[string]any{"k": 3.0, "mad": 5.2},
	}

	isNew, err := repo.UpsertIfNew(ctx, ev)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !isNew {
		t.Error("first insert should return isNew=true")
	}

	// Duplicate should not insert again
	ev2 := *ev
	ev2.ID = fmt.Sprintf("ae_%d", time.Now().UnixNano())
	isNew2, err := repo.UpsertIfNew(ctx, &ev2)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if isNew2 {
		t.Error("duplicate should return isNew=false")
	}

	// List should return at least 1
	list, err := repo.ListByTenant(ctx, tenant, "", 7)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) == 0 {
		t.Error("list should have at least 1 event")
	}

	// Ack
	if err := repo.Ack(ctx, ev.ID); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Cleanup
	db.Exec(ctx, "DELETE FROM anomaly_events WHERE tenant_id = $1", tenant)
}
