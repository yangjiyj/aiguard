package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestBillingCompensationDisabledWorker(t *testing.T) {
	for _, deps := range []ReadModelDeps{
		{},
		{BillingStore: billing.NewStore(nil), BillingCompensationMonitor: billing.NewReconciliationMonitor(false)},
	} {
		got := billingCompensationComponent(context.Background(), deps)
		if got["status"] != "disabled" || got["worker_status"] != "disabled" || got["worker_reason_code"] != "not_required" {
			t.Fatalf("billing off or metering = %+v", got)
		}
	}
}

func billingCompensationTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("BILLING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("BILLING_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	schema := fmt.Sprintf("worker_health_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		admin.Close()
	})
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, table := range []string{"billing_reservations", "billing_request_leases"} {
		statement := "CREATE TABLE " + quotedSchema + "." + pgx.Identifier{table}.Sanitize() + " (LIKE public." + pgx.Identifier{table}.Sanitize() + " INCLUDING ALL)"
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("copy migrated table %s: %v", table, err)
		}
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("isolated pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestBillingCompensationWorkerAndCleanBacklog(t *testing.T) {
	pool := billingCompensationTestDB(t)
	for _, tc := range []struct {
		name   string
		setup  func(*billing.ReconciliationMonitor, time.Time)
		status string
		reason string
	}{
		{"awaiting startup", nil, "processing", "awaiting_first_run"},
		{"running", func(m *billing.ReconciliationMonitor, now time.Time) { m.Start(now) }, "processing", "running"},
		{"healthy with pending", func(m *billing.ReconciliationMonitor, now time.Time) {
			m.Start(now)
			m.Complete(now, billing.ReconciliationResult{Pending: 4}, nil)
		}, "healthy", ""},
		{"error", func(m *billing.ReconciliationMonitor, now time.Time) {
			m.Start(now)
			m.Complete(now, billing.ReconciliationResult{}, errors.New("postgres://private-secret"))
		}, "degraded", "execution_failed"},
		{"item failure", func(m *billing.ReconciliationMonitor, now time.Time) {
			m.Start(now)
			m.Complete(now, billing.ReconciliationResult{Failed: 1}, nil)
		}, "degraded", "items_failed"},
		{"stale", func(m *billing.ReconciliationMonitor, now time.Time) {
			m.Start(now.Add(-3 * time.Minute))
			m.Complete(now.Add(-3*time.Minute), billing.ReconciliationResult{}, nil)
		}, "degraded", "heartbeat_stale"},
		{"stopped", func(m *billing.ReconciliationMonitor, now time.Time) { m.Start(now); m.Stop() }, "degraded", "worker_stopped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			monitor := billing.NewReconciliationMonitor(true)
			if tc.setup != nil {
				tc.setup(monitor, time.Now().UTC())
			}
			got := billingCompensationComponent(context.Background(), ReadModelDeps{DB: pool, BillingStore: billing.NewStore(pool), BillingCompensationMonitor: monitor})
			if got["status"] != tc.status || got["worker_status"] != tc.status || got["worker_reason_code"] != tc.reason || got["backlog_status"] != "clean" {
				t.Fatalf("worker/backlog = %+v", got)
			}
			for _, field := range []string{"worker_last_started_at", "worker_last_completed_at", "worker_running", "stale_reserved_count", "active_lease_count", "expired_unreleased_lease_count"} {
				if _, ok := got[field]; !ok {
					t.Fatalf("missing diagnostic %s", field)
				}
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("encode component: %v", err)
			}
			if strings.Contains(string(encoded), "private-secret") {
				t.Fatal("raw error leaked")
			}
			if tc.name == "healthy with pending" && got["worker_result"].(map[string]int)["pending"] != 4 {
				t.Fatalf("latest result missing: %+v", got)
			}
		})
	}
	got := billingCompensationComponent(context.Background(), ReadModelDeps{DB: pool, BillingStore: billing.NewStore(pool)})
	if got["status"] != "unknown" || got["worker_status"] != "unknown" || got["backlog_status"] != "clean" {
		t.Fatalf("missing monitor fabricated health: %+v", got)
	}
}

func TestBillingCompensationBacklogOverridesHealthyWorker(t *testing.T) {
	pool := billingCompensationTestDB(t)
	_, err := pool.Exec(context.Background(), `INSERT INTO billing_request_leases (tenant_id, user_id, request_id, acquired_at, expires_at) VALUES ('health_tenant', 'health_user', 'health_request', NOW() - INTERVAL '2 minutes', NOW() - INTERVAL '1 minute')`)
	if err != nil {
		t.Fatalf("seed expired lease: %v", err)
	}
	monitor := billing.NewReconciliationMonitor(true)
	monitor.Start(time.Now().UTC())
	monitor.Complete(time.Now().UTC(), billing.ReconciliationResult{}, nil)
	got := billingCompensationComponent(context.Background(), ReadModelDeps{DB: pool, BillingStore: billing.NewStore(pool), BillingCompensationMonitor: monitor})
	if got["status"] != "degraded" || got["worker_status"] != "healthy" || got["backlog_status"] != "backlog" || got["expired_unreleased_lease_count"] != int64(1) {
		t.Fatalf("backlog hidden by worker health: %+v", got)
	}
}

func TestBillingCompensationQueryFailureDoesNotFabricateHealth(t *testing.T) {
	pool := billingCompensationTestDB(t)
	pool.Close()
	monitor := billing.NewReconciliationMonitor(true)
	monitor.Start(time.Now().UTC())
	monitor.Complete(time.Now().UTC(), billing.ReconciliationResult{}, nil)
	got := billingCompensationComponent(context.Background(), ReadModelDeps{DB: pool, BillingStore: billing.NewStore(pool), BillingCompensationMonitor: monitor})
	if got["status"] != "unknown" || got["worker_status"] != "healthy" || got["backlog_status"] != "unknown" || got["reason_code"] != "evidence_query_failed" {
		t.Fatalf("query failure fabricated health: %+v", got)
	}
}
