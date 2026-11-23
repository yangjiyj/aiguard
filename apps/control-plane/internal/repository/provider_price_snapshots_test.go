package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupSnapshotTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	return db
}

func TestProviderPriceSnapshotUpsertAndListByDate(t *testing.T) {
	db := setupSnapshotTestDB(t)
	ctx := context.Background()

	repo := NewProviderPriceSnapshotRepository(db)
	date := fmt.Sprintf("2099-%02d-%02d", time.Now().Month(), time.Now().Day())
	providerA := "test_prov_a_" + fmt.Sprint(time.Now().UnixNano())
	providerB := "test_prov_b_" + fmt.Sprint(time.Now().UnixNano())
	modelID := "test_model_snap_" + fmt.Sprint(time.Now().UnixNano())

	// db.Close() 放 t.Cleanup 末尾：defer 会先于 t.Cleanup 执行，先关池会让 DELETE 静默失败。
	t.Cleanup(func() {
		if _, err := db.Exec(ctx, `DELETE FROM provider_price_snapshots WHERE snapshot_date = $1 AND provider_id IN ($2, $3)`, date, providerA, providerB); err != nil {
			t.Logf("cleanup snapshots %s: %v", date, err)
		}
		db.Close()
	})

	s1 := &ProviderPriceSnapshot{
		SnapshotDate: date,
		ProviderID:   providerA,
		ModelID:      modelID,
		InputPrice:   10.0,
		OutputPrice:  30.0,
		Currency:     "USD",
	}
	s2 := &ProviderPriceSnapshot{
		SnapshotDate: date,
		ProviderID:   providerB,
		ModelID:      modelID,
		InputPrice:   5.0,
		OutputPrice:  15.0,
		Currency:     "USD",
	}

	if err := repo.Upsert(ctx, s1); err != nil {
		t.Fatalf("upsert s1: %v", err)
	}
	if err := repo.Upsert(ctx, s2); err != nil {
		t.Fatalf("upsert s2: %v", err)
	}

	// Test upsert idempotency - update s1 prices
	s1b := &ProviderPriceSnapshot{
		SnapshotDate: date,
		ProviderID:   providerA,
		ModelID:      modelID,
		InputPrice:   12.0,
		OutputPrice:  35.0,
		Currency:     "USD",
	}
	if err := repo.Upsert(ctx, s1b); err != nil {
		t.Fatalf("upsert s1b: %v", err)
	}

	snaps, err := repo.ListByDate(ctx, date)
	if err != nil {
		t.Fatalf("list by date: %v", err)
	}

	found := 0
	for _, s := range snaps {
		if s.ProviderID == providerA && s.ModelID == modelID {
			found++
			if s.InputPrice != 12.0 {
				t.Errorf("expected updated input_price=12.0, got %f", s.InputPrice)
			}
		}
		if s.ProviderID == providerB && s.ModelID == modelID {
			found++
			if s.InputPrice != 5.0 {
				t.Errorf("expected input_price=5.0, got %f", s.InputPrice)
			}
		}
	}
	if found != 2 {
		t.Errorf("expected 2 snapshots, found %d", found)
	}
}

func TestProviderPriceSnapshotListDates(t *testing.T) {
	db := setupSnapshotTestDB(t)
	ctx := context.Background()
	repo := NewProviderPriceSnapshotRepository(db)

	suffix := fmt.Sprint(time.Now().UnixNano())
	prov := "test_dates_prov_" + suffix
	model := "test_dates_model_" + suffix
	d1 := "2099-01-01"
	d2 := "2099-01-02"
	// db.Close() 放 t.Cleanup 末尾：defer 会先于 t.Cleanup 执行，先关池会让 DELETE 静默失败。
	t.Cleanup(func() {
		if _, err := db.Exec(ctx, `DELETE FROM provider_price_snapshots WHERE provider_id = $1`, prov); err != nil {
			t.Logf("cleanup snapshots %s: %v", prov, err)
		}
		db.Close()
	})

	for _, d := range []string{d1, d2} {
		if err := repo.Upsert(ctx, &ProviderPriceSnapshot{
			SnapshotDate: d, ProviderID: prov, ModelID: model,
			InputPrice: 1, OutputPrice: 2, Currency: "USD",
		}); err != nil {
			t.Fatalf("upsert %s: %v", d, err)
		}
	}

	dates, err := repo.ListDates(ctx)
	if err != nil {
		t.Fatalf("list dates: %v", err)
	}
	i1, i2 := -1, -1
	for i, d := range dates {
		if d == d1 {
			i1 = i
		}
		if d == d2 {
			i2 = i
		}
	}
	if i1 == -1 || i2 == -1 {
		t.Fatalf("expected both dates present, got %v", dates)
	}
	if i2 > i1 {
		t.Errorf("expected descending order (d2 before d1), got d2=%d d1=%d", i2, i1)
	}
}
