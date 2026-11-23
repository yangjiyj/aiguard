package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 7.5: reconciliation recovers usage from request_logs, which have no cache
// breakdown, so every prompt token is billed at the full input rate. The
// charge must be flagged for the operator and a verified breakdown must be
// booked as an idempotent ledger correction.
func TestRecoveredChargeWithoutCacheIsFlaggedAndTrueUpRefundsDifference(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_trueup_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "trueup-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{
			InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000,
			CachedInputPerMillionMicros: 100_000, HasCachedInputPrice: true,
		},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet, err = store.Credit(ctx, tenantID, wallet.ID, "trueup-credit", 10_000, "test"); err != nil {
		t.Fatal(err)
	}
	recoveredID := "trueup-recovered-" + tenantID
	liveID := "trueup-live-" + tenantID
	for _, requestID := range []string{recoveredID, liveID} {
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 1000, 500, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs
			(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
		VALUES ($1,$1,$2,$3,$4,'chat_completion','success',1000,500,NOW()-INTERVAL '48 hours')
	`, recoveredID, tenantID, projectID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, recoveredID); err != nil {
		t.Fatal(err)
	}
	// The live request settles through the gateway path with a real breakdown.
	if _, _, err := store.SettleCharge(ctx, tenantID, liveID, price, Usage{
		PromptTokens: 1000, CachedInputTokens: 800, OutputTokens: 500,
	}, []byte(`{"usage_source":"provider"}`), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 500); err != nil {
		t.Fatal(err)
	}

	var recoveredAmount int64
	if err := db.QueryRow(ctx, `SELECT amount_micros FROM billing_charge_records WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, recoveredID).Scan(&recoveredAmount); err != nil {
		t.Fatal(err)
	}
	// 1000 prompt tokens at the full input rate plus 500 output tokens.
	if recoveredAmount != 2000 {
		t.Fatalf("recovered charge amount=%d want 2000", recoveredAmount)
	}
	exceptions, err := store.ListBillingExceptions(ctx, tenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if kinds := exceptionKinds(exceptions); kinds[recoveredID] != ExceptionRecoveredWithoutCache || kinds[liveID] != "" {
		t.Fatalf("exceptions=%+v, want only the recovered charge flagged", exceptions)
	}

	if _, err := store.TrueUpRecoveredCharge(ctx, tenantID, liveID, 800, 0, "admin-1"); !errors.Is(err, ErrCacheTrueUpNotApplicable) {
		t.Fatalf("true-up of a provider-metered charge err=%v", err)
	}
	before, err := store.GetWallet(ctx, tenantID, wallet.ID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.TrueUpRecoveredCharge(ctx, tenantID, recoveredID, 800, 0, "admin-1")
	if err != nil {
		t.Fatal(err)
	}
	// 200 uncached + 800 cached at 0.1 + 500 output at 2 = 200 + 80 + 1000.
	if result.OriginalMicros != 2000 || result.CorrectedMicros != 1280 || result.DeltaMicros != -720 {
		t.Fatalf("true-up result=%+v", result)
	}
	if result.Wallet.BalanceMicros != before.BalanceMicros+720 || result.Wallet.ReservedMicros != before.ReservedMicros {
		t.Fatalf("wallet before=%+v after=%+v", before, result.Wallet)
	}
	var eventType, reason string
	var delta int64
	if err := db.QueryRow(ctx, `
		SELECT event_type, balance_delta_micros, metadata_json->>'reason'
		FROM billing_ledger_entries WHERE wallet_id=$1 AND idempotency_key=$2
	`, wallet.ID, "cache-true-up:"+recoveredID).Scan(&eventType, &delta, &reason); err != nil {
		t.Fatal(err)
	}
	if eventType != "refund" || delta != 720 || reason != "cache_true_up" {
		t.Fatalf("ledger event=%s delta=%d reason=%s", eventType, delta, reason)
	}
	exceptions, err = store.ListBillingExceptions(ctx, tenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if kinds := exceptionKinds(exceptions); kinds[recoveredID] != "" {
		t.Fatalf("resolved charge still listed: %+v", exceptions)
	}

	again, err := store.TrueUpRecoveredCharge(ctx, tenantID, recoveredID, 800, 0, "admin-1")
	if err != nil || again.DeltaMicros != -720 || again.Wallet.BalanceMicros != result.Wallet.BalanceMicros {
		t.Fatalf("idempotent retry=%+v err=%v", again, err)
	}
	if _, err := store.TrueUpRecoveredCharge(ctx, tenantID, recoveredID, 500, 0, "admin-1"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting true-up err=%v", err)
	}
	var ledgerRows int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_ledger_entries WHERE wallet_id=$1 AND idempotency_key=$2`,
		wallet.ID, "cache-true-up:"+recoveredID).Scan(&ledgerRows); err != nil || ledgerRows != 1 {
		t.Fatalf("true-up ledger rows=%d err=%v", ledgerRows, err)
	}
}

func exceptionKinds(items []BillingException) map[string]string {
	kinds := make(map[string]string, len(items))
	for _, item := range items {
		kinds[item.RequestID] = item.Kind
	}
	return kinds
}
