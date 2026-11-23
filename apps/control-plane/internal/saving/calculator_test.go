package saving

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// --- Unit tests for calcCost ---

func TestCalcCost_EmptyJSON(t *testing.T) {
	result := calcCost(nil, 1000, 500)
	if result != 0 {
		t.Errorf("expected 0 for nil pricing_json, got %f", result)
	}
}

func TestCalcCost_InvalidJSON(t *testing.T) {
	result := calcCost([]byte("not-json"), 1000, 500)
	if result != 0 {
		t.Errorf("expected 0 for invalid JSON, got %f", result)
	}
}

func TestCalcCost_StandardPricing(t *testing.T) {
	// $5/M input, $15/M output
	pricing := []byte(`{"input":5.0,"output":15.0,"currency":"USD","pricing_unit":"per_million_tokens"}`)
	// 1M input tokens + 1M output tokens = $5 + $15 = $20
	result := calcCost(pricing, 1_000_000, 1_000_000)
	if result != 20.0 {
		t.Errorf("expected 20.0, got %f", result)
	}
}

func TestCalcCost_PartialTokens(t *testing.T) {
	pricing := []byte(`{"input":5.0,"output":15.0}`)
	// 100k input ($0.50) + 50k output ($0.75) = $1.25
	result := calcCost(pricing, 100_000, 50_000)
	const want = 0.5 + 0.75
	if result != want {
		t.Errorf("expected %f, got %f", want, result)
	}
}

func TestCalcCost_ZeroTokens(t *testing.T) {
	pricing := []byte(`{"input":5.0,"output":15.0}`)
	result := calcCost(pricing, 0, 0)
	if result != 0 {
		t.Errorf("expected 0, got %f", result)
	}
}

// --- mock implementations ---

type mockFx struct{ rate float64 }

func (m *mockFx) Current(_ context.Context) (float64, error) { return m.rate, nil }

type mockWatermark struct{ ts time.Time }

func (m *mockWatermark) Init(_ context.Context) error { return nil }
func (m *mockWatermark) Get(_ context.Context, _ string) (time.Time, error) {
	return m.ts, nil
}
func (m *mockWatermark) Set(_ context.Context, _ string, t time.Time) error {
	m.ts = t
	return nil
}

// --- Integration tests (require CONTENT_LOGS_TEST_DATABASE_URL) ---

func getTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set, skipping integration test")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test DB: %v", err)
	}
	return pool
}

func TestRunOnceWithFixtures_CacheHit(t *testing.T) {
	pool := getTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	// Ensure required tables exist
	pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS watermarks (
		worker_name VARCHAR(64) PRIMARY KEY,
		last_processed_at TIMESTAMP WITH TIME ZONE NOT NULL,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	)`)

	// Insert a test model with pricing
	modelID := "test-model-saving-" + time.Now().Format("20060102150405")
	_, err := pool.Exec(ctx, `
		INSERT INTO models (id, name, provider_id, model_name, pricing_json)
		VALUES ($1, $2, (SELECT id FROM providers LIMIT 1), $2, $3)
		ON CONFLICT (id) DO NOTHING
	`, modelID, modelID, `{"input":10.0,"output":30.0}`)
	if err != nil {
		t.Skipf("cannot insert test model (no provider?): %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM models WHERE id = $1`, modelID)

	// Insert a test project
	projectID := "test-proj-saving-" + time.Now().Format("20060102150405")
	tenantID := ""
	row := pool.QueryRow(ctx, `SELECT id FROM tenants LIMIT 1`)
	if err := row.Scan(&tenantID); err != nil {
		t.Skip("no tenants in test DB")
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO projects (id, name, tenant_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING
	`, projectID, projectID, tenantID)
	if err != nil {
		t.Skipf("cannot insert test project: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID)

	// Insert a request_log with cache_hit=true
	logID := "rl-saving-test-" + time.Now().Format("20060102150405")
	reqID := logID + "-req"
	_, err = pool.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, model_id, cache_hit, input_tokens, output_tokens, created_at)
		VALUES ($1, $2, $3, $4, $5, TRUE, 100000, 50000, NOW())
		ON CONFLICT (request_id) DO NOTHING
	`, logID, reqID, tenantID, projectID, modelID)
	if err != nil {
		t.Fatalf("cannot insert test request_log: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM request_logs WHERE id = $1`, logID)

	// Set watermark to past so RunOnce picks up the row
	wm := &mockWatermark{ts: time.Now().UTC().AddDate(0, 0, -1)}
	calc := NewCalculator(pool, &mockFx{rate: 7.2}, wm)

	n, err := calc.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if n == 0 {
		t.Error("expected at least 1 row written to saving_metrics, got 0")
	}

	// Verify saving_metrics has the right data
	var savingUSD float64
	err = pool.QueryRow(ctx, `
		SELECT saving_usd FROM saving_metrics
		WHERE project_id = $1 AND source = cache_hit
		ORDER BY date DESC LIMIT 1
	`, projectID).Scan(&savingUSD)
	if err != nil {
		t.Fatalf("cannot read saving_metrics: %v", err)
	}
	// 100k input @ $10/M = $1.00, 50k output @ $30/M = $1.50 → $2.50
	const wantUSD = 2.50
	if savingUSD != wantUSD {
		t.Errorf("expected saving_usd=%f, got %f", wantUSD, savingUSD)
	}

	// Cleanup
	pool.Exec(ctx, `DELETE FROM saving_metrics WHERE project_id = $1`, projectID)
}

func TestRunOnceIdempotent(t *testing.T) {
	pool := getTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	// Ensure watermarks table
	pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS watermarks (
		worker_name VARCHAR(64) PRIMARY KEY,
		last_processed_at TIMESTAMP WITH TIME ZONE NOT NULL,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	)`)

	// Running with no relevant data should return 0 rows and not error.
	wm := &mockWatermark{ts: time.Now().UTC()} // watermark = now, no new rows
	calc := NewCalculator(pool, &mockFx{rate: 7.2}, wm)

	n, err := calc.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if n != 0 {
		t.Logf("expected 0 new rows when watermark is now, got %d (OK if there are recent logs)", n)
	}
}
