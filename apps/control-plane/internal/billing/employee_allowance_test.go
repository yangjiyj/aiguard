package billing

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmployeeAllowanceConcurrentAdmissionAndNextMonth(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(100_000_000)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &amount}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	w, err := store.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for _, id := range []string{"parallel-a", "parallel-b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _, e := store.Reserve(ctx, tenant, w.ID, id, 60_000_000)
			if e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, ErrInsufficientBalance) {
				t.Errorf("reserve: %v", e)
			}
		}(id)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("atomic wallet admissions=%d", accepted.Load())
	}
	_, next, _ := allowanceMonth(at, "Asia/Shanghai")
	w, err = store.ensureMonthlyForTest(ctx, tenant, user, "CNY", next)
	if err != nil || w.AvailableMicros() != 100_000_000 {
		t.Fatalf("new period funding=%+v %v", w, err)
	}
	for _, id := range []string{"parallel-a", "parallel-b"} {
		if _, _, e := store.Release(ctx, tenant, id); e != nil && !errors.Is(e, ErrReservationNotFound) {
			t.Fatal(e)
		}
	}
	if w, e := store.GetWallet(ctx, tenant, w.ID); e != nil || w.BalanceMicros != 100_000_000 || w.ReservedMicros != 0 {
		t.Fatalf("old unused frozen gift carried over: %+v %v", w, e)
	}
}
func TestEmployeeAllowanceDefaultsOverridesAndTenantIsolation(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	cap := int64(500_000_000)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC", DefaultMonthlyMicros: &cap}); err != nil {
		t.Fatal(err)
	}
	second := user + "-new"
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role,status) VALUES($1,$2,$1,'x','developer','active')`, second, tenant); err != nil {
		t.Fatal(err)
	}
	if yes, err := store.HasEmployeeAllowance(ctx, tenant, second); err != nil || !yes {
		t.Fatalf("new employee must inherit default: %v %v", yes, err)
	}
	smaller := int64(100_000_000)
	if err := store.SetEmployeeAllowances(ctx, tenant, []string{user}, &smaller); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, "too-large", "USD", 101_000_000, now); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("individual override not enforced: %v", err)
	}
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, "wrong-currency", "CNY", 1, now); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("currency must not convert: %v", err)
	}
	if err := store.SetEmployeeAllowances(ctx, tenant, []string{user}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, "inherit", "USD", 500_000_000, now); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatal(err)
	}
	if err := store.SetEmployeeAllowances(ctx, tenant+"-foreign", []string{user}, &smaller); err == nil {
		t.Fatal("cross-tenant employee update accepted")
	}
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &cap}); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("enabled balance redenominated: %v", err)
	}
}
func TestEmployeeAllowanceMonthUsesCalendarAndDST(t *testing.T) {
	start, end, err := allowanceMonth(time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), "America/New_York")
	if err != nil || start != time.Date(2026, 3, 1, 5, 0, 0, 0, time.UTC) || end != time.Date(2026, 4, 1, 4, 0, 0, 0, time.UTC) {
		t.Fatalf("calendar/DST boundaries=%v %v err=%v", start, end, err)
	}
}
