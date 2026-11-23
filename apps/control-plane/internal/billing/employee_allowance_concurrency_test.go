package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEmployeeAllowanceReadsSettingsAfterPendingCurrencyChange(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	start, _, err := allowanceMonth(at, "Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, key := range []string{"allowance-settings:" + tenant, "employee:" + tenant + ":" + user + ":" + start.Format(time.RFC3339)} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE billing_employee_settings SET currency='USD',default_monthly_micros=100000000 WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- store.ReserveEmployeeAllowance(ctx, tenant, user, "currency-transition", "CNY", 1, at)
	}()
	// Wait for the admission's advisory lock instead of relying on scheduling.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var blocked bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admission never reached settings/month lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("admission used stale denomination: %v", err)
	}
	var holds int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_employee_reservations WHERE tenant_id=$1`, tenant).Scan(&holds); err != nil || holds != 0 {
		t.Fatalf("invalid-denomination holds=%d err=%v", holds, err)
	}
}

func TestEmployeeAllowanceSettlementTransitionNeverFreesConsumedBudget(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(100)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); err != nil {
		t.Fatal(err)
	}
	w, err := store.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Reserve(ctx, tenant, w.ID, "first", 60); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, _, e := store.Reserve(ctx, tenant, w.ID, "second", 60); result <- e }()
	if _, _, err = store.Settle(ctx, tenant, "first", 60); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("wallet transition admitted consumed money: %v", err)
	}
}

func TestEmployeeAllowanceSettingsRejectUnknownTenantAndTimezone(t *testing.T) {
	store, _, tenant, _ := setupBillingStoreTest(t)
	if err := store.SaveEmployeeSettings(context.Background(), tenant+"_missing", EmployeeSettings{Currency: "CNY", Timezone: "UTC"}); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("unknown tenant=%v", err)
	}
	if err := store.SaveEmployeeSettings(context.Background(), tenant, EmployeeSettings{Currency: "CNY", Timezone: "Not/A/Timezone"}); !errors.Is(err, ErrInvalidPrice) {
		t.Fatalf("invalid timezone=%v", err)
	}
}
