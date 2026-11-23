package saving_v2

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// mockLaborFx implements LaborFxProvider.
type mockLaborFx struct{ rate float64 }

func (m *mockLaborFx) Current(_ context.Context) (float64, error) { return m.rate, nil }

// mockLaborWm implements LaborWatermarkStore.
type mockLaborWm struct{ ts time.Time }

func (m *mockLaborWm) Init(_ context.Context) error { return nil }
func (m *mockLaborWm) Get(_ context.Context, _ string) (time.Time, error) {
	return m.ts, nil
}
func (m *mockLaborWm) Set(_ context.Context, _ string, t time.Time) error {
	m.ts = t
	return nil
}

func setupLaborTestDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	tenantID := fmt.Sprintf("tenant_labor_%d", time.Now().UnixNano())
	userID := fmt.Sprintf("user_labor_%d", time.Now().UnixNano())
	ctx := context.Background()

	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	userEmail := userID + "@test.local"
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, role, status) VALUES ($1, $2, $1, $3, 'admin', 'active')`,
		userID, tenantID, userEmail,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		db.Exec(ctx, `DELETE FROM saving_metrics WHERE tenant_id = $1`, tenantID)
		db.Exec(ctx, `DELETE FROM audit_operations WHERE user_id = $1`, userID)
		db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID, userID
}

func TestLaborRunOnce(t *testing.T) {
	db, tenantID, userID := setupLaborTestDB(t)
	ctx := context.Background()

	// Insert 4 audit operations: 2 budget.pause_key + 1 quota_policy.update + 1 notify_channel.create
	ops := []struct{ id, actionType string }{
		{fmt.Sprintf("ao_labor_%d_1", time.Now().UnixNano()), "budget.pause_key"},
		{fmt.Sprintf("ao_labor_%d_2", time.Now().UnixNano()), "budget.pause_key"},
		{fmt.Sprintf("ao_labor_%d_3", time.Now().UnixNano()), "quota_policy.update"},
		{fmt.Sprintf("ao_labor_%d_4", time.Now().UnixNano()), "notify_channel.create"},
	}
	for _, op := range ops {
		_, err := db.Exec(ctx,
			`INSERT INTO audit_operations (id, user_id, action_type, action_detail) VALUES ($1, $2, $3, '{}')`,
			op.id, userID, op.actionType,
		)
		if err != nil {
			t.Fatalf("insert audit_operation %s: %v", op.actionType, err)
		}
	}

	// Run labor with watermark = yesterday, defaults (0.5h × 250 CNY = 125 CNY/op).
	wm := &mockLaborWm{ts: time.Now().UTC().AddDate(0, 0, -1)}
	lab := NewLabor(db, &mockLaborFx{rate: 7.2}, wm, nil)

	n, err := lab.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 row, got 0")
	}

	// Verify saving_metrics.
	var savingCNY float64
	var reqCount int
	err = db.QueryRow(ctx, `
		SELECT saving_cny, request_count FROM saving_metrics
		WHERE tenant_id = $1 AND source = 'key_mgmt_labor'
		LIMIT 1
	`, tenantID).Scan(&savingCNY, &reqCount)
	if err != nil {
		t.Fatalf("read saving_metrics: %v", err)
	}

	// 4 ops × 0.5h × 250 CNY = 500 CNY
	const wantCNY = 500.0
	if savingCNY != wantCNY {
		t.Errorf("expected saving_cny=%f, got %f", wantCNY, savingCNY)
	}
	if reqCount != 4 {
		t.Errorf("expected request_count=4, got %d", reqCount)
	}
}

func TestLaborRunOnce_UnrelatedActionsIgnored(t *testing.T) {
	db, tenantID, userID := setupLaborTestDB(t)
	ctx := context.Background()

	// Insert 1 unrelated operation - should NOT be counted.
	_, err := db.Exec(ctx,
		`INSERT INTO audit_operations (id, user_id, action_type, action_detail) VALUES ($1, $2, 'revoke_key', '{}')`,
		fmt.Sprintf("ao_labor_unrel_%d", time.Now().UnixNano()), userID,
	)
	if err != nil {
		t.Fatalf("insert unrelated audit_operation: %v", err)
	}

	wm := &mockLaborWm{ts: time.Now().UTC().AddDate(0, 0, -1)}
	lab := NewLabor(db, &mockLaborFx{rate: 7.2}, wm, nil)

	n, err := lab.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Verify no saving_metrics row for this tenant (unrelated op should be ignored).
	var count int
	db.QueryRow(ctx, `SELECT COUNT(*) FROM saving_metrics WHERE tenant_id = $1 AND source = 'key_mgmt_labor'`, tenantID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 rows for unrelated actions, got %d (n=%d)", count, n)
	}
	_ = tenantID
}
