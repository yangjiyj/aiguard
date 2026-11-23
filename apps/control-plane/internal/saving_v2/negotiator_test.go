package saving_v2

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// mockNegFx implements NegotiatorFxProvider.
type mockNegFx struct{ rate float64 }

func (m *mockNegFx) Current(_ context.Context) (float64, error) { return m.rate, nil }

// mockNegWatermark implements NegotiatorWatermarkStore.
type mockNegWatermark struct{ ts time.Time }

func (m *mockNegWatermark) Init(_ context.Context) error { return nil }
func (m *mockNegWatermark) Get(_ context.Context, _ string) (time.Time, error) {
	return m.ts, nil
}
func (m *mockNegWatermark) Set(_ context.Context, _ string, t time.Time) error {
	m.ts = t
	return nil
}

func setupNegotiatorTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}

	// Create a unique tenant for this test run.
	tenantID := fmt.Sprintf("tenant_neg_%d", time.Now().UnixNano())
	ctx := context.Background()
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM saving_metrics WHERE tenant_id = $1`, tenantID)
		db.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestNegotiatorRunOnce(t *testing.T) {
	db, tenantID := setupNegotiatorTestDB(t)
	ctx := context.Background()

	// Need a provider in DB
	providerID := fmt.Sprintf("prov_neg_%d", time.Now().UnixNano())
	providerIDHigh := fmt.Sprintf("prov_neg_high_%d", time.Now().UnixNano())
	_, err := db.Exec(ctx, `
		INSERT INTO providers (id, name, tenant_id, provider_type, status)
		VALUES ($1, $1, $2, 'openai', 'active'),
		       ($3, $3, $2, 'openai', 'active')
	`, providerID, tenantID, providerIDHigh)
	if err != nil {
		t.Skipf("insert providers: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM providers WHERE id IN ($1, $2)`, providerID, providerIDHigh)
	})

	// Create models for each provider.
	modelID := fmt.Sprintf("model_neg_%d", time.Now().UnixNano())
	_, err = db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, pricing_json, status)
		VALUES ($1, $2, $1, $3, 'active')
	`, modelID, providerID, `{"input":5.0,"output":15.0,"currency":"USD"}`)
	if err != nil {
		t.Skipf("insert model: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM models WHERE id = $1`, modelID)
	})

	// Create a project
	projectID := fmt.Sprintf("proj_neg_%d", time.Now().UnixNano())
	_, err = db.Exec(ctx, `INSERT INTO projects (id, name, tenant_id) VALUES ($1, $1, $2)`, projectID, tenantID)
	if err != nil {
		t.Skipf("insert project: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID)
	})

	// Insert a request_log for our provider (cheaper).
	logID := fmt.Sprintf("rl_neg_%d", time.Now().UnixNano())
	reqID := logID + "_req"
	_, err = db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, model_id, provider_id, input_tokens, output_tokens, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, 1000000, 500000, NOW())
	`, logID, reqID, tenantID, projectID, modelID, providerID)
	if err != nil {
		t.Fatalf("insert request_log: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM request_logs WHERE id = $1`, logID)
	})

	// Insert price snapshot for today: our provider = 5/15, competitor = 10/30.
	today := time.Now().UTC().Format("2006-01-02")
	_, err = db.Exec(ctx, `
		INSERT INTO provider_price_snapshots (snapshot_date, provider_id, model_id, input_price, output_price, currency)
		VALUES ($1, $2, $3, 5.0, 15.0, 'USD'),
		       ($1, $4, $3, 10.0, 30.0, 'USD')
		ON CONFLICT (snapshot_date, provider_id, model_id) DO UPDATE
		SET input_price = EXCLUDED.input_price, output_price = EXCLUDED.output_price
	`, today, providerID, modelID, providerIDHigh)
	if err != nil {
		t.Fatalf("insert snapshots: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM provider_price_snapshots WHERE model_id = $1 AND snapshot_date = $2`, modelID, today)
	})

	// Run negotiator with watermark = yesterday.
	wm := &mockNegWatermark{ts: time.Now().UTC().AddDate(0, 0, -1)}
	neg := NewNegotiator(db, &mockNegFx{rate: 7.2}, wm)

	n, err := neg.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 row written, got 0")
	}

	// Verify saving_metrics.
	var savingUSD float64
	err = db.QueryRow(ctx, `
		SELECT saving_usd FROM saving_metrics
		WHERE tenant_id = $1 AND project_id = $2 AND source = 'negotiated_price'
		ORDER BY date DESC LIMIT 1
	`, tenantID, projectID).Scan(&savingUSD)
	if err != nil {
		t.Fatalf("read saving_metrics: %v", err)
	}

	// Expected: (10-5)*1M/1M + (30-15)*0.5M/1M = 5.0 + 7.5 = 12.5 USD
	const wantUSD = 12.5
	if savingUSD != wantUSD {
		t.Errorf("expected saving_usd=%f, got %f", wantUSD, savingUSD)
	}
}
