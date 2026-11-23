package saving_v2

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// mockBreakerFx implements BreakerFxProvider.
type mockBreakerFx struct{ rate float64 }

func (m *mockBreakerFx) Current(_ context.Context) (float64, error) { return m.rate, nil }

// mockBreakerWm implements BreakerWatermarkStore.
type mockBreakerWm struct{ ts time.Time }

func (m *mockBreakerWm) Init(_ context.Context) error { return nil }
func (m *mockBreakerWm) Get(_ context.Context, _ string) (time.Time, error) {
	return m.ts, nil
}
func (m *mockBreakerWm) Set(_ context.Context, _ string, t time.Time) error {
	m.ts = t
	return nil
}

func setupBreakerTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	tenantID := fmt.Sprintf("tenant_brk_%d", time.Now().UnixNano())
	ctx := context.Background()
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM saving_metrics WHERE tenant_id = $1`, tenantID)
		db.Exec(ctx, `DELETE FROM alert_inbox WHERE tenant_id = $1`, tenantID)
		db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestBreakerRunOnce(t *testing.T) {
	db, tenantID := setupBreakerTestDB(t)
	ctx := context.Background()

	// Insert 3 governor interception events: 2 rate_limit + 1 pause_key.
	for i := 0; i < 3; i++ {
		alertID := fmt.Sprintf("alert_brk_%d_%d", time.Now().UnixNano(), i)
		evType := "rate_limit"
		if i == 2 {
			evType = "pause_key"
		}
		_, err := db.Exec(ctx, `
			INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, created_at)
			VALUES ($1, $2, 'high', $3, 'test', '{}', NOW())
		`, alertID, tenantID, evType)
		if err != nil {
			t.Fatalf("insert alert_inbox: %v", err)
		}
	}

	// No request_logs → avg cost = 0 → saving = 0 but still should write a row.
	// We verify the row is written with request_count = 3.
	wm := &mockBreakerWm{ts: time.Now().UTC().AddDate(0, 0, -1)}
	brk := NewBreaker(db, &mockBreakerFx{rate: 7.2}, wm)

	n, err := brk.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 row, got 0")
	}

	var reqCount int
	err = db.QueryRow(ctx, `
		SELECT request_count FROM saving_metrics
		WHERE tenant_id = $1 AND source = 'circuit_breaker'
		LIMIT 1
	`, tenantID).Scan(&reqCount)
	if err != nil {
		t.Fatalf("read saving_metrics: %v", err)
	}
	if reqCount != 3 {
		t.Errorf("expected request_count=3, got %d", reqCount)
	}
}
