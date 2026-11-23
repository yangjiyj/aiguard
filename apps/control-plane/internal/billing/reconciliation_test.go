package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReconcileStaleReservationsSettlesDurableUsageReleasesFailuresAndKeepsUnknown(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-credit", 10_000, "test")
	if err != nil {
		t.Fatal(err)
	}
	successID := "reconcile-success-" + tenantID
	failedID := "reconcile-failed-" + tenantID
	pendingID := "reconcile-pending-" + tenantID
	statuses := map[string]string{
		successID: "success",
		failedID:  "provider_unavailable",
		pendingID: "received",
	}
	for requestID, status := range statuses {
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 100, 30, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
			VALUES ($1,$1,$2,$3,$4,'chat_completion',$5,10,5,NOW()-INTERVAL '48 hours')
		`, requestID, tenantID, projectID, userID, status); err != nil {
			t.Fatalf("insert request log %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 500)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 || result.Released < 1 || result.Pending < 1 {
		t.Fatalf("reconciliation result=%+v", result)
	}
	var amount int64
	var promptTokens, outputTokens int64
	var rawUsage []byte
	if err := db.QueryRow(ctx, `
		SELECT amount_micros,prompt_tokens,output_tokens,raw_usage_json
		FROM billing_charge_records WHERE tenant_id=$1 AND request_id=$2
	`, tenantID, successID).Scan(&amount, &promptTokens, &outputTokens, &rawUsage); err != nil {
		t.Fatal(err)
	}
	if amount != 20 || promptTokens != 10 || outputTokens != 5 {
		t.Fatalf("recovered charge amount=%d prompt=%d output=%d", amount, promptTokens, outputTokens)
	}
	var evidence map[string]any
	if err := json.Unmarshal(rawUsage, &evidence); err != nil || evidence["usage_source"] != "recovered_request_log" {
		t.Fatalf("recovery evidence=%s err=%v", rawUsage, err)
	}
	for requestID, want := range map[string]string{
		successID: ReservationSettled,
		failedID:  ReservationReleased,
		pendingID: ReservationReserved,
	} {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != want {
			t.Fatalf("reservation %s=%+v err=%v want=%s", requestID, reservation, err, want)
		}
	}
}

// Cancel, stream abort and provider timeout must share the incomplete
// terminal state with the real-time path: reconciliation settles them from
// request_log usage evidence instead of releasing the reservation, unknown
// statuses are never released for being stale, and a reservation without any
// request log is released as unevidenceable after the window.
func TestReconcileStaleReservationsSharesTerminalStatesWithRealtime(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile2_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-terminal-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-terminal-credit", 100_000, "test"); err != nil {
		t.Fatal(err)
	}
	canceledID := "rec2-cancel-" + tenantID
	abortedID := "rec2-abort-" + tenantID
	timeoutID := "rec2-timeout-" + tenantID
	unknownID := "rec2-unknown-" + tenantID
	orphanID := "rec2-orphan-" + tenantID
	loggedStatuses := map[string]string{
		canceledID: "client_canceled",
		abortedID:  "stream_aborted",
		timeoutID:  "provider_timeout",
		unknownID:  "some_future_status",
	}
	// The incomplete family settles only from an authoritative usage source
	// backed by the admission snapshot; the marker is what the gateway would
	// have persisted for an estimated incomplete finalize.
	estimatedSource := []byte(`{"response_metadata":{"usage_source":"estimated_incomplete"}}`)
	for requestID, status := range loggedStatuses {
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 100, 30, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at,output_audit_result)
			VALUES ($1,$1,$2,$3,$4,'chat_completion',$5,10,5,NOW()-INTERVAL '48 hours',$6)
		`, requestID, tenantID, projectID, userID, status, estimatedSource); err != nil {
			t.Fatalf("insert request log %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, orphanID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatalf("reserve orphan: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, orphanID); err != nil {
		t.Fatal(err)
	}

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 500)
	if err != nil {
		t.Fatal(err)
	}
	// Pending counts stale received rows across all tenants, so only the
	// settled/failed outcomes are asserted exactly here; the
	// per-reservation states below are the authoritative check.
	if result.Settled < 3 || result.Failed != 0 {
		t.Fatalf("reconciliation result=%+v", result)
	}
	for requestID, want := range map[string]string{
		canceledID: ReservationSettled,
		abortedID:  ReservationSettled,
		timeoutID:  ReservationSettled,
		unknownID:  ReservationReserved,
		orphanID:   ReservationReserved,
	} {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != want {
			t.Fatalf("reservation %s=%+v err=%v want=%s", requestID, reservation, err, want)
		}
	}
	// The orphan reservation keeps its wallet freeze: missing evidence never
	// frees money automatically. 5x100 reserved initially, 3 settled -> 200.
	wallet, err = store.GetWalletByUser(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet.ReservedMicros != 200 {
		t.Fatalf("wallet reserved=%d want 200 (orphan+unknown frozen)", wallet.ReservedMicros)
	}
	var amount int64
	var rawUsage []byte
	if err := db.QueryRow(ctx, `
		SELECT amount_micros,raw_usage_json
		FROM billing_charge_records WHERE tenant_id=$1 AND request_id=$2
	`, tenantID, canceledID).Scan(&amount, &rawUsage); err != nil {
		t.Fatal(err)
	}
	if amount != 20 {
		t.Fatalf("canceled charge amount=%d want=20", amount)
	}
	var evidence map[string]any
	if err := json.Unmarshal(rawUsage, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["usage_source"] != "recovered_request_log" || evidence["terminal_status"] != "client_canceled" {
		t.Fatalf("canceled evidence=%s", rawUsage)
	}
}

// A backlog of unknown statuses and orphan reservations that sorts before
// resolvable rows must not starve compensation: unknown statuses and rows
// without a request log never occupy the batch limit, so a small limit still
// settles the executable terminal rows behind them.
func TestReconcileStaleReservationsUnknownBacklogDoesNotStarveSuccesses(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile3_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-fairness-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-fairness-credit", 100_000, "test"); err != nil {
		t.Fatal(err)
	}
	// Request IDs sort so the unknown backlog and the orphan come before the
	// success rows: with the old LIMIT-consuming behavior and limit=2 the
	// successes behind them would never be reached.
	unknownIDs := []string{
		"rec3-a-unk-0-" + tenantID,
		"rec3-a-unk-1-" + tenantID,
		"rec3-a-unk-2-" + tenantID,
	}
	orphanID := "rec3-b-orphan-" + tenantID
	successIDs := []string{
		"rec3-z-ok-0-" + tenantID,
		"rec3-z-ok-1-" + tenantID,
	}
	for _, requestID := range unknownIDs {
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 100, 30, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
			VALUES ($1,$1,$2,$3,$4,'chat_completion','some_future_status',10,5,NOW()-INTERVAL '48 hours')
		`, requestID, tenantID, projectID, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, orphanID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatalf("reserve orphan: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, orphanID); err != nil {
		t.Fatal(err)
	}
	for _, requestID := range successIDs {
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 100, 30, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
			VALUES ($1,$1,$2,$3,$4,'chat_completion','success',10,5,NOW()-INTERVAL '48 hours')
		`, requestID, tenantID, projectID, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Global counters: assert the floor this test contributes, not equality,
	// because the sweep covers every tenant on a shared database. The
	// per-reservation states below are the authoritative check.
	if result.Settled < 2 || result.Failed != 0 {
		t.Fatalf("reconciliation result=%+v want settled>=2", result)
	}
	for _, requestID := range successIDs {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != ReservationSettled {
			t.Fatalf("reservation %s=%+v err=%v want settled", requestID, reservation, err)
		}
	}
	frozen := append(append([]string{}, unknownIDs...), orphanID)
	for _, requestID := range frozen {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != ReservationReserved {
			t.Fatalf("reservation %s=%+v err=%v want reserved", requestID, reservation, err)
		}
	}
	if result.Pending < len(frozen) {
		t.Fatalf("pending=%d want >= %d (unknown+orphan counted)", result.Pending, len(frozen))
	}
	// 6x100 reserved initially, 2 settled -> the 4 evidence-less rows keep
	// their 400 freeze.
	wallet, err = store.GetWalletByUser(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet.ReservedMicros != 400 {
		t.Fatalf("wallet reserved=%d want 400 (3 unknown + orphan frozen)", wallet.ReservedMicros)
	}
}

// pendingCountFailingDB fails only the reconciliation pending-count query,
// leaving every other statement untouched, to prove a count error propagates
// to the caller instead of being swallowed.
type pendingCountFailingDB struct {
	*pgxpool.Pool
}

func (d *pendingCountFailingDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "reconciliation_pending_count") {
		return &failingRow{err: fmt.Errorf("injected pending count failure")}
	}
	return d.Pool.QueryRow(ctx, sql, args...)
}

type failingRow struct {
	err error
}

func (r *failingRow) Scan(dest ...any) error { return r.err }

func TestReconcileStaleReservationsPropagatesPendingCountFailure(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile4_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-countfail-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-countfail-credit", 10_000, "test"); err != nil {
		t.Fatal(err)
	}
	successID := "rec4-ok-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, successID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs
			(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
		VALUES ($1,$1,$2,$3,$4,'chat_completion','success',10,5,NOW()-INTERVAL '48 hours')
	`, successID, tenantID, projectID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, successID); err != nil {
		t.Fatal(err)
	}

	wrapped := &pendingCountFailingDB{Pool: db}
	store.db = wrapped
	_, err = store.ReconcileStaleReservations(ctx, 24*time.Hour, 500)
	if err == nil {
		t.Fatal("expected pending count failure to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "count pending stale billing reservations") {
		t.Fatalf("error does not identify the pending count failure: %v", err)
	}
}

// Generic error and provider_error do not prove the request was never
// dispatched upstream, so reconciliation must keep those reservations
// reserved with the wallet freeze intact and count them as pending — they
// must never be released for being stale, and must not occupy the batch
// limit ahead of resolvable rows.
func TestReconcileStaleReservationsGenericErrorsStayPending(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile5_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-generic-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-generic-credit", 10_000, "test"); err != nil {
		t.Fatal(err)
	}
	// The generic-error rows sort before the success row so a limit of 1
	// proves they do not consume the batch limit either.
	errorID := "rec5-a-err-" + tenantID
	providerErrID := "rec5-a-perr-" + tenantID
	successID := "rec5-z-ok-" + tenantID
	statuses := map[string]string{
		errorID:       "error",
		providerErrID: "provider_error",
	}
	for requestID, status := range statuses {
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 100, 30, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
			VALUES ($1,$1,$2,$3,$4,'chat_completion',$5,10,5,NOW()-INTERVAL '48 hours')
		`, requestID, tenantID, projectID, userID, status); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, successID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs
			(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
		VALUES ($1,$1,$2,$3,$4,'chat_completion','success',10,5,NOW()-INTERVAL '48 hours')
	`, successID, tenantID, projectID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, successID); err != nil {
		t.Fatal(err)
	}

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 {
		t.Fatalf("result=%+v want the resolvable success row settled", result)
	}
	if result.Pending < 2 {
		t.Fatalf("pending=%d want >= 2 (generic error+provider_error counted)", result.Pending)
	}
	for requestID, want := range map[string]string{
		errorID:       ReservationReserved,
		providerErrID: ReservationReserved,
		successID:     ReservationSettled,
	} {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != want {
			t.Fatalf("reservation %s=%+v err=%v want=%s", requestID, reservation, err, want)
		}
	}
	// 3x100 reserved, 1 settled -> the two generic-error rows keep 200 frozen.
	wallet, err = store.GetWalletByUser(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet.ReservedMicros != 200 {
		t.Fatalf("wallet reserved=%d want 200 (generic errors stay frozen)", wallet.ReservedMicros)
	}
}

// A settle-family status without recorded usage evidence must NOT settle:
// input_tokens/output_tokens are NULL exactly when the gateway finalize never
// ran, so the row is conservatively pending with the wallet freeze intact.
// COALESCEing the tokens would fake a zero-usage settle out of missing
// evidence — the regression this test pins.
func TestReconcileStaleReservationsSettleStatusWithoutUsageEvidenceStaysPending(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile6_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-noevidence-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-noevidence-credit", 10_000, "test"); err != nil {
		t.Fatal(err)
	}
	// request_log with success status but NULL token columns: no finalize
	// evidence ever landed.
	noEvidenceID := "rec6-noev-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, noEvidenceID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs
			(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,created_at)
		VALUES ($1,$1,$2,$3,$4,'chat_completion','success',NOW()-INTERVAL '48 hours')
	`, noEvidenceID, tenantID, projectID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, noEvidenceID); err != nil {
		t.Fatal(err)
	}

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 500)
	if err != nil {
		t.Fatal(err)
	}
	// This row must NOT be settled, and the authoritative proof is its
	// reservation state below plus the intact wallet freeze. The global
	// counters are not asserted for equality: another tenant rows may
	// legitimately settle during the same sweep.
	if result.Failed != 0 {
		t.Fatalf("result=%+v want no per-item failures", result)
	}
	if result.Pending < 1 {
		t.Fatalf("pending=%d want >= 1 (no-evidence row counted as pending)", result.Pending)
	}
	reservation, err := store.GetReservation(ctx, tenantID, noEvidenceID)
	if err != nil || reservation.Status != ReservationReserved {
		t.Fatalf("reservation %s=%+v err=%v want reserved", noEvidenceID, reservation, err)
	}
	wallet, err = store.GetWalletByUser(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet.ReservedMicros != 100 {
		t.Fatalf("wallet reserved=%d want 100 (freeze intact)", wallet.ReservedMicros)
	}
}

// Fairness and evidence-source gates: rows whose evidence chain is not
// executable (a legacy cancel row without any usage_source, and a success row
// the gateway already recorded as billing_outcome=released) sort BEFORE a
// resolvable estimated-success row. With limit=1 the resolvable row must
// still settle — the non-executable rows are counted pending and never
// consume the batch limit. The estimated row settles only because its
// reservation admission snapshot exists; the recovery marker carries the
// gateway source.
func TestReconcileStaleReservationsEvidenceGatesDoNotStarveLimit(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile7_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-gate-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-gate-credit", 10_000, "test"); err != nil {
		t.Fatal(err)
	}
	reserve := func(requestID string) {
		t.Helper()
		if _, _, err := store.ReservePricedWithUsageForGroup(
			ctx, tenantID, wallet.ID, requestID, 100, 30, price, DefaultCustomerGroup, ratioScale,
		); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}
	insertLog := func(requestID, status string, tokens bool, auditResult []byte) {
		t.Helper()
		columns := "id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,created_at"
		values := "$1,$1,$2,$3,$4,'chat_completion',$5,NOW()-INTERVAL '48 hours'"
		args := []any{requestID, tenantID, projectID, userID, status}
		if tokens {
			columns += ",input_tokens,output_tokens"
			values += ",6,3"
		}
		if auditResult != nil {
			columns += ",output_audit_result"
			values += ",$6"
			args = append(args, auditResult)
		}
		query := "INSERT INTO request_logs (" + columns + ") VALUES (" + values + ")"
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatalf("insert log %s: %v", requestID, err)
		}
	}
	// Row A: legacy cancel — tokens present but NO usage_source anywhere.
	rowA := "rec7-a-cancel-" + tenantID
	reserve(rowA)
	insertLog(rowA, "client_canceled", true, nil)
	// Row B: the gateway recorded a real-time release; a compensating settle
	// would contradict it.
	rowB := "rec7-b-released-" + tenantID
	reserve(rowB)
	insertLog(rowB, "success", true, []byte(`{"response_metadata":{"usage_source":"upstream"}}`))
	if _, err := db.Exec(ctx, `UPDATE request_logs SET billing_outcome='released' WHERE request_id=$1`, rowB); err != nil {
		t.Fatal(err)
	}
	// Row C: resolvable — estimated success with an admission snapshot
	// (the reservation row itself) and the gateway source marker.
	rowC := "rec7-z-ok-" + tenantID
	reserve(rowC)
	insertLog(rowC, "success", true, []byte(`{"response_metadata":{"usage_source":"estimated_reservation"}}`))

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 {
		t.Fatalf("result=%+v want the resolvable row settled despite limit=1", result)
	}
	if result.Pending < 2 {
		t.Fatalf("pending=%d want >= 2 (non-executable rows counted)", result.Pending)
	}
	for requestID, want := range map[string]string{
		rowA: ReservationReserved,
		rowB: ReservationReserved,
		rowC: ReservationSettled,
	} {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != want {
			t.Fatalf("reservation %s=%+v err=%v want=%s", requestID, reservation, err, want)
		}
	}
	var rawUsage []byte
	if err := db.QueryRow(ctx, `SELECT raw_usage_json FROM billing_charge_records WHERE tenant_id=$1 AND request_id=$2`, tenantID, rowC).Scan(&rawUsage); err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(rawUsage, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["gateway_source"] != "estimated_reservation" || evidence["legacy_recovered"] != false {
		t.Fatalf("recovery marker=%s want gateway_source + non-legacy", rawUsage)
	}
}

// HasApprovedEstimate must rest on real evidence, not on columns that are
// always populated. Two rows carry the same estimated_reservation source and
// sort AHEAD of a resolvable row:
//
//	A: a priced admission (price_id frozen) — the estimate was really quoted
//	   and reserved, so it settles;
//	B: an unpriced reservation (no price_id) — nothing was ever quoted, so the
//	   estimate is not approved evidence and the row must stay pending.
//
// The negative sample matters because admitted_at is NOT NULL DEFAULT NOW()
// and the amount constraint forces a positive micros-or-tokens reservation, so
// the obvious "admitted_at IS NOT NULL AND reserved>0" test would approve B
// and make HasApprovedEstimate hardcoded true. With limit=1 the resolvable row
// must still settle, proving B is counted pending and never occupies the limit.
//
// The second half pins the free-admission case: a legitimately free admission
// (reserved_micros 0 with reserved tokens, which ck_billing_reservation_amount
// explicitly allows) still carries a price_id and MUST settle. Rejecting it
// would be a false refusal of a real, priced, zero-amount admission.
func TestReconcileStaleReservationsAdmissionEvidenceMustBeReal(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_rec9_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "rec9-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "rec9-credit", 100_000, "test"); err != nil {
		t.Fatal(err)
	}
	age := func(requestID string) {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID); err != nil {
			t.Fatal(err)
		}
	}
	insertLog := func(requestID, status string, tokens bool, source string) {
		t.Helper()
		audit := []byte(`{"response_metadata":{"usage_source":"` + source + `"}}`)
		if tokens {
			if _, err := db.Exec(ctx, `
				INSERT INTO request_logs
					(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at,output_audit_result)
				VALUES ($1,$1,$2,$3,$4,'chat_completion',$5,10,5,NOW()-INTERVAL '48 hours',$6)
			`, requestID, tenantID, projectID, userID, status, audit); err != nil {
				t.Fatalf("insert log %s: %v", requestID, err)
			}
			return
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,created_at,output_audit_result)
			VALUES ($1,$1,$2,$3,$4,'chat_completion',$5,NOW()-INTERVAL '48 hours',$6)
		`, requestID, tenantID, projectID, userID, status, audit); err != nil {
			t.Fatalf("insert log %s: %v", requestID, err)
		}
	}

	// Row A: priced admission -> a real approved estimate.
	rowA := "rec9-a-priced-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, rowA, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	insertLog(rowA, "success", true, "estimated_reservation")
	age(rowA)

	// Row B: NO price was ever quoted, so no estimate was approved. Sort it
	// before the resolvable row.
	rowB := "rec9-b-noprice-" + tenantID
	if _, _, err := store.Reserve(ctx, tenantID, wallet.ID, rowB, 100); err != nil {
		t.Fatal(err)
	}
	insertLog(rowB, "success", true, "estimated_reservation")
	age(rowB)

	// Row C: a legitimately FREE priced admission: zero micros, positive
	// reserved tokens, price_id frozen. Must NOT be refused.
	rowC := "rec9-z-free-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, rowC, 0, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatalf("free priced reservation must be admitted: %v", err)
	}
	insertLog(rowC, "success", true, "estimated_reservation")
	age(rowC)

	var rowBPrice, rowCPrice *string
	var rowCReserved int64
	if err := db.QueryRow(ctx, `
		SELECT
			(SELECT price_id FROM billing_reservations WHERE tenant_id=$1 AND request_id=$2),
			(SELECT price_id FROM billing_reservations WHERE tenant_id=$1 AND request_id=$3),
		COALESCE((SELECT reserved_micros FROM billing_reservations WHERE tenant_id=$1 AND request_id=$3),-1)
	`, tenantID, rowB, rowC).Scan(&rowBPrice, &rowCPrice, &rowCReserved); err != nil {
		t.Fatal(err)
	}
	if rowBPrice != nil {
		t.Fatalf("fixture broken: unpriced row has price_id=%v", *rowBPrice)
	}
	if rowCPrice == nil || *rowCPrice == "" || rowCReserved != 0 {
		t.Fatalf("fixture broken: free row price_id=%v reserved_micros=%d", rowCPrice, rowCReserved)
	}

	// limit=1: rowB must be counted pending, never consume the limit, and rowA
	// must settle behind it.
	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 {
		t.Fatalf("result=%+v want rowA settled with limit=1", result)
	}
	if result.Pending < 1 {
		t.Fatalf("pending=%d want >= 1 (unpriced estimated row counted)", result.Pending)
	}
	for requestID, want := range map[string]string{
		rowA: ReservationSettled,
		rowB: ReservationReserved,
		rowC: ReservationReserved,
	} {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != want {
			t.Fatalf("reservation %s=%+v err=%v want=%s", requestID, reservation, err, want)
		}
	}

	// The free priced admission settles on the next pass: free is admitted, not
	// refused. Its wallet freeze is 0 either way, so assert the reservation.
	result, err = store.ReconcileStaleReservations(ctx, 24*time.Hour, 500)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 {
		t.Fatalf("second pass result=%+v want the free priced row settled", result)
	}
	freeReservation, err := store.GetReservation(ctx, tenantID, rowC)
	if err != nil || freeReservation.Status != ReservationSettled {
		t.Fatalf("free priced reservation=%+v err=%v want settled (free must not be refused)", freeReservation, err)
	}
	// The unpriced row is still pending: no approved estimate exists, so its
	// freeze survives for an operator.
	unpriced, err := store.GetReservation(ctx, tenantID, rowB)
	if err != nil || unpriced.Status != ReservationReserved {
		t.Fatalf("unpriced reservation=%+v err=%v want reserved", unpriced, err)
	}
	wallet, err = store.GetWalletByUser(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet.ReservedMicros != 100 {
		t.Fatalf("wallet reserved=%d want 100 (unpriced row keeps its freeze)", wallet.ReservedMicros)
	}
}

// The gateway marks a live request it could not attribute with an explicit
// unknown sentinel rather than an empty marker, because an empty usage_source
// is how a pre-942 row is represented and would earn a legacy success-recovery
// settle. This test proves the control plane agrees on both halves of that
// decision: a sentinel row is held pending (and never occupies the batch
// limit), while the genuinely absent-marker legacy row still recovers.
//
// It is the cross-path contract for the gateway's sentinel: the value is
// produced in gateway-core and consumed here, so neither side may drift.
func TestReconcileStaleReservationsHoldsGatewayUnknownSentinelButRecoversLegacy(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_rec10_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "rec10-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "rec10-credit", 100_000, "test"); err != nil {
		t.Fatal(err)
	}
	// The sentinel the gateway writes. Keep it in sync with
	// unknownUsageSource in apps/gateway-core/internal/handler/billing.go.
	const gatewayUnknownSource = "unknown_no_admission_evidence"

	sentinelID := "rec10-a-sentinel-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, sentinelID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	// A legacy row: no output_audit_result at all, so usage_source is absent.
	legacyID := "rec10-z-legacy-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, legacyID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ id, audit string }{
		{sentinelID, `{"response_metadata":{"usage_source":"` + gatewayUnknownSource + `"}}`},
		{legacyID, ""},
	} {
		if row.audit == "" {
			if _, err := db.Exec(ctx, `
				INSERT INTO request_logs
					(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
				VALUES ($1,$1,$2,$3,$4,'chat_completion','success',10,5,NOW()-INTERVAL '48 hours')
			`, row.id, tenantID, projectID, userID); err != nil {
				t.Fatal(err)
			}
		} else if _, err := db.Exec(ctx, `
			INSERT INTO request_logs
				(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at,output_audit_result)
			VALUES ($1,$1,$2,$3,$4,'chat_completion','success',10,5,NOW()-INTERVAL '48 hours',$5)
		`, row.id, tenantID, projectID, userID, []byte(row.audit)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, row.id); err != nil {
			t.Fatal(err)
		}
	}

	// limit=1: the sentinel sorts FIRST and must not consume the limit, so the
	// resolvable legacy row behind it still settles.
	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 {
		t.Fatalf("result=%+v want the legacy row settled with limit=1", result)
	}
	if result.Pending < 1 {
		t.Fatalf("pending=%d want >= 1 (sentinel row counted, not processed)", result.Pending)
	}
	for requestID, want := range map[string]string{
		sentinelID: ReservationReserved,
		legacyID:   ReservationSettled,
	} {
		reservation, err := store.GetReservation(ctx, tenantID, requestID)
		if err != nil || reservation.Status != want {
			t.Fatalf("reservation %s=%+v err=%v want=%s", requestID, reservation, err, want)
		}
	}
	// The sentinel row keeps its freeze: only the legacy recovery released it.
	wallet, err = store.GetWalletByUser(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if wallet.ReservedMicros != 100 {
		t.Fatalf("wallet reserved=%d want 100 (sentinel row keeps its freeze)", wallet.ReservedMicros)
	}
}

// A legacy success row (no usage_source marker anywhere) recovers with the
// explicit legacy_recovered flag; a legacy cancel row would not recover.
func TestReconcileStaleReservationsLegacySuccessMarkedRecovered(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	projectID := "project_reconcile8_" + tenantID
	if _, err := db.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,owner_user_id,status)
		VALUES ($1,$2,$1,$3,'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "reconcile-legacy-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "reconcile-legacy-credit", 10_000, "test"); err != nil {
		t.Fatal(err)
	}
	legacyID := "rec8-ok-" + tenantID
	if _, _, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, legacyID, 100, 30, price, DefaultCustomerGroup, ratioScale,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs
			(id,request_id,tenant_id,project_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,created_at)
		VALUES ($1,$1,$2,$3,$4,'chat_completion','success',10,5,NOW()-INTERVAL '48 hours')
	`, legacyID, tenantID, projectID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '48 hours' WHERE tenant_id=$1 AND request_id=$2`, tenantID, legacyID); err != nil {
		t.Fatal(err)
	}

	result, err := store.ReconcileStaleReservations(ctx, 24*time.Hour, 500)
	if err != nil {
		t.Fatal(err)
	}
	if result.Settled < 1 {
		t.Fatalf("result=%+v want legacy success recovered", result)
	}
	var rawUsage []byte
	if err := db.QueryRow(ctx, `SELECT raw_usage_json FROM billing_charge_records WHERE tenant_id=$1 AND request_id=$2`, tenantID, legacyID).Scan(&rawUsage); err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(rawUsage, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["legacy_recovered"] != true {
		t.Fatalf("legacy recovery marker=%s want legacy_recovered=true", rawUsage)
	}
	if evidence["usage_source"] != "recovered_request_log" {
		t.Fatalf("recovery marker=%s want recovered_request_log", rawUsage)
	}
}
