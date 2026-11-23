package billing

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonthlyWalletGrantIsRealCreditAndConcurrentIdempotent(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &amount}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
			if e != nil || w == nil {
				t.Errorf("grant failed: %v", e)
			}
		}()
	}
	wg.Wait()
	w, e := s.GetWalletByUser(ctx, tenant, user, "CNY")
	if e != nil || w.BalanceMicros != 1000 {
		t.Fatalf("real wallet balance=%+v err=%v", w, e)
	}
	var count int
	var credited int64
	if err := db.QueryRow(ctx, `SELECT count(*),sum(balance_delta_micros) FROM billing_ledger_entries WHERE tenant_id=$1 AND metadata_json->>'monthly_wallet_event'='grant'`, tenant).Scan(&count, &credited); err != nil || count != 1 || credited != 1000 {
		t.Fatalf("grant ledger count=%d credited=%d err=%v", count, credited, err)
	}
}

func TestMonthlyWalletExpiryPreservesManualCredit(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	_, end, _ := allowanceMonth(at, "Asia/Shanghai")
	w, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", end)
	if e != nil || w.BalanceMicros != 1300 {
		t.Fatalf("rollover must retain manual 300 and new grant 1000: %+v %v", w, e)
	}
	status, e := s.MonthlyWalletStatus(ctx, tenant, user, end)
	if e != nil || status.GrantedMicros != 1000 || status.RemainingMicros != 1000 {
		t.Fatalf("monthly status=%+v %v", status, e)
	}
}

func TestMonthlyWalletCrossMonthReleaseExpiresOnlyOldFrozenGrant(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Reserve(ctx, tenant, w.ID, "old-stream", 600); e != nil {
		t.Fatal(e)
	}
	_, end, _ := allowanceMonth(at, "Asia/Shanghai")
	w, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", end)
	if e != nil || w.BalanceMicros != 1900 || w.ReservedMicros != 600 {
		t.Fatalf("frozen old grant must survive rollover: %+v %v", w, e)
	}
	_, w, e = s.Release(ctx, tenant, "old-stream")
	if e != nil || w.BalanceMicros != 1300 || w.ReservedMicros != 0 {
		t.Fatalf("release must expire old grant without affecting permanent/new funds: %+v %v", w, e)
	}
}

func TestMonthlyWalletCrossMonthSettlePreservesPermanentAndNewGrant(t *testing.T) {
	for _, actual := range []Micros{400, 800} {
		t.Run(fmt.Sprint(actual), func(t *testing.T) {
			s, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			amount := int64(1000)
			at := time.Now().UTC()
			if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &amount}); e != nil {
				t.Fatal(e)
			}
			w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
				t.Fatal(e)
			}
			if _, _, e = s.Reserve(ctx, tenant, w.ID, "old-stream", 600); e != nil {
				t.Fatal(e)
			}
			_, end, _ := allowanceMonth(at, "Asia/Shanghai")
			if _, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", end); e != nil {
				t.Fatal(e)
			}
			_, w, e = s.Settle(ctx, tenant, "old-stream", actual)
			want := Micros(1300)
			if actual == 800 {
				want = 1100
			}
			if e != nil || w.BalanceMicros != want || w.ReservedMicros != 0 {
				t.Fatalf("cross-month settle wallet=%+v err=%v", w, e)
			}
			status, e := s.MonthlyWalletStatus(ctx, tenant, user, end)
			if e != nil || status.RemainingMicros != 1000 || status.ReservedMicros != 0 {
				t.Fatalf("new gift consumed by old request: %+v %v", status, e)
			}
			var gift, permanent int64
			if e = db.QueryRow(ctx, `SELECT (metadata_json->>'monthly_grant_consumed_micros')::bigint,(metadata_json->>'permanent_consumed_micros')::bigint FROM billing_ledger_entries WHERE tenant_id=$1 AND request_id='old-stream' AND event_type='settle'`, tenant).Scan(&gift, &permanent); e != nil {
				t.Fatal(e)
			}
			expectedGift := int64(actual)
			if expectedGift > 600 {
				expectedGift = 600
			}
			if gift != expectedGift || permanent != int64(actual)-expectedGift {
				t.Fatalf("incorrect permanent/gift split=%d/%d", gift, permanent)
			}
			_, again, e := s.Settle(ctx, tenant, "old-stream", actual)
			if e != nil || again.BalanceMicros != want {
				t.Fatalf("settlement retry changed funding: %+v %v", again, e)
			}
			var ledgerBalance int64
			if e = db.QueryRow(ctx, `SELECT sum(balance_delta_micros) FROM billing_ledger_entries WHERE tenant_id=$1 AND wallet_id=$2`, tenant, w.ID).Scan(&ledgerBalance); e != nil || ledgerBalance != int64(w.BalanceMicros) {
				t.Fatalf("financial ledger sum=%d wallet=%d %v", ledgerBalance, w.BalanceMicros, e)
			}
		})
	}
}

func TestMonthlyWalletRedeemedAndManualFundsNeverExpire(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	codes, e := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "permanent-test", AmountMicros: 200, Count: 1, CreatedBy: "admin"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.RedeemCode(ctx, tenant, user, codes[0].Code); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Reserve(ctx, tenant, w.ID, "gift-first", 400); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Settle(ctx, tenant, "gift-first", 400); e != nil {
		t.Fatal(e)
	}
	zero := int64(0)
	if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &zero}); e != nil {
		t.Fatal(e)
	}
	_, end, _ := allowanceMonth(at, "UTC")
	w, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", end)
	if e != nil || w.BalanceMicros != 500 {
		t.Fatalf("permanent credit/redemption lost: %+v %v", w, e)
	}
	if e = s.ReserveEmployeeAllowance(ctx, tenant, user, "manual-only", "CNY", 500, end); e != nil {
		t.Fatalf("auto funding 0 falsely hard-caps permanent balance: %v", e)
	}
	if _, _, e = s.Reserve(ctx, tenant, w.ID, "manual-only", 500); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Settle(ctx, tenant, "manual-only", 500); e != nil {
		t.Fatal(e)
	}
}

func TestMonthlyWalletZeroNullOverrideDisabledAndMachine(t *testing.T) {
	for _, mode := range []string{"zero", "null", "disabled", "machine"} {
		t.Run(mode, func(t *testing.T) {
			s, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			amount := int64(1000)
			var configured *int64 = &amount
			if mode == "null" {
				configured = nil
			}
			if mode == "zero" {
				zero := int64(0)
				configured = &zero
			}
			if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: configured}); e != nil {
				t.Fatal(e)
			}
			if mode == "disabled" {
				if _, e := db.Exec(ctx, `UPDATE users SET status='disabled' WHERE tenant_id=$1 AND id=$2`, tenant, user); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "machine" {
				if _, e := db.Exec(ctx, `UPDATE users SET role='platform_connector' WHERE tenant_id=$1 AND id=$2`, tenant, user); e != nil {
					t.Fatal(e)
				}
			}
			w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now())
			if e != nil {
				t.Fatal(e)
			}
			if mode == "disabled" || mode == "machine" {
				if w != nil {
					t.Fatalf("inactive/machine got wallet: %+v", w)
				}
			} else {
				if w == nil || w.BalanceMicros != 0 {
					t.Fatalf("zero/null funding=%+v", w)
				}
			}
			var count int
			if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1`, tenant).Scan(&count); e != nil || count != 0 {
				t.Fatalf("zero funding generated ledger: %d %v", count, e)
			}
		})
	}
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	zero := int64(0)
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	if e := s.SetEmployeeAllowances(ctx, tenant, []string{user}, &zero); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now())
	if e != nil || w.BalanceMicros != 0 {
		t.Fatalf("zero override ignored: %+v %v", w, e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.ReserveEmployeeAllowance(ctx, tenant, user, "manual", "CNY", 200, time.Now()); e != nil {
		t.Fatalf("zero rule rejected manual balance: %v", e)
	}
}

func TestMonthlyWalletConfigEditIsNextCycleAndRestartIsIdempotent(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at); e != nil {
		t.Fatal(e)
	}
	amount = 2000
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	restarted := NewStore(db)
	w, e := restarted.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil || w.BalanceMicros != 1000 {
		t.Fatalf("restart/edit double-funded: %+v %v", w, e)
	}
	_, end, _ := allowanceMonth(at, "UTC")
	w, e = restarted.ensureMonthlyForTest(ctx, tenant, user, "CNY", end)
	if e != nil || w.BalanceMicros != 2000 {
		t.Fatalf("new cycle ignored new amount: %+v %v", w, e)
	}
	var count int
	if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1 AND metadata_json->>'monthly_wallet_event'='grant'`, tenant).Scan(&count); e != nil || count != 2 {
		t.Fatalf("restart grant ledger count=%d %v", count, e)
	}
}

func TestMonthlyWalletBackgroundReachesBeyondFirst500(t *testing.T) {
	s, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role,status) SELECT $1||'-'||g,$1,$1||'-'||g,'x','chat_user','active' FROM generate_series(1,600) g`, tenant); e != nil {
		t.Fatal(e)
	}
	count := 0
	for i := 0; i < 10; i++ {
		restarted := NewStore(db)
		if _, e := restarted.GrantMonthlyWallets(ctx, at, 500); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRow(ctx, `SELECT count(*) FROM billing_wallet_monthly_grants WHERE tenant_id=$1`, tenant).Scan(&count); e != nil {
			t.Fatal(e)
		}
		if count == 601 {
			break
		}
	}
	if count != 601 {
		t.Fatalf("background funding starved users beyond first batch: %d", count)
	}
	if _, e := s.GrantMonthlyWallets(ctx, at, 500); e != nil {
		t.Fatal(e)
	}
	var total int64
	if e := db.QueryRow(ctx, `SELECT sum(balance_micros) FROM billing_wallets WHERE tenant_id=$1`, tenant).Scan(&total); e != nil || total != 601000 {
		t.Fatalf("background duplicated or missed credit: %d %v", total, e)
	}
}

func TestMonthlyWalletTokenOnlyReserveActualDebitHasLedgerAndGiftSplit(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "token-only", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ReservePricedWithUsage(ctx, tenant, w.ID, "token-only", 0, 1, p); e != nil {
		t.Fatal(e)
	}
	_, w, e = s.Settle(ctx, tenant, "token-only", 100)
	if e != nil || w.BalanceMicros != 900 {
		t.Fatalf("token-only actual debit=%+v %v", w, e)
	}
	var actual, gift int64
	if e = db.QueryRow(ctx, `SELECT -balance_delta_micros,(metadata_json->>'monthly_grant_consumed_micros')::bigint FROM billing_ledger_entries WHERE tenant_id=$1 AND event_type='settle' AND request_id='token-only'`, tenant).Scan(&actual, &gift); e != nil || actual != 100 || gift != 100 {
		t.Fatalf("invisible token-only debit/split=%d/%d %v", actual, gift, e)
	}
	if _, _, e = s.Settle(ctx, tenant+"-foreign", "token-only", 100); !errors.Is(e, ErrReservationNotFound) {
		t.Fatalf("cross-tenant token settlement=%v", e)
	}
}

func TestMonthlyWalletLegacyReservationUsesPermanentFunds(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	at := time.Now().UTC()
	w, e := s.EnsureWallet(ctx, tenant, user, "CNY")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 2000, "admin"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Reserve(ctx, tenant, w.ID, "legacy", 500); e != nil {
		t.Fatal(e)
	}
	amount := int64(1000)
	if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at); e != nil {
		t.Fatal(e)
	}
	_, w, e = s.Settle(ctx, tenant, "legacy", 500)
	if e != nil || w.BalanceMicros != 2500 {
		t.Fatalf("legacy settlement=%+v %v", w, e)
	}
	var remaining int64
	if e = db.QueryRow(ctx, `SELECT remaining_micros FROM billing_wallet_monthly_grants WHERE tenant_id=$1`, tenant).Scan(&remaining); e != nil || remaining != 1000 {
		t.Fatalf("legacy settlement acquired new gift retrospectively=%d %v", remaining, e)
	}
}

func TestMonthlyWalletNegativeAdjustmentKeepsLotsAndPermanentMoneyConsistent(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	w, e = s.Adjust(ctx, tenant, w.ID, "negative-adjust", -500, "admin", "test correction")
	if e != nil || w.BalanceMicros != 800 {
		t.Fatalf("negative correction=%+v %v", w, e)
	}
	status, e := s.MonthlyWalletStatus(ctx, tenant, user, at)
	if e != nil || status.RemainingMicros != 500 || status.AdjustedMicros != 500 || status.UsedMicros != 0 {
		t.Fatalf("gift correction invisible/misclassified: %+v %v", status, e)
	}
	if _, e = s.Adjust(ctx, tenant, w.ID, "negative-adjust", -500, "admin", "test correction"); e != nil {
		t.Fatalf("correction retry=%v", e)
	}
	_, end, _ := allowanceMonth(at, "UTC")
	w, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", end)
	if e != nil || w.BalanceMicros != 1300 {
		t.Fatalf("correction invaded permanent 300 or new gift: %+v %v", w, e)
	}
	var gift, permanent int64
	if e = db.QueryRow(ctx, `SELECT (metadata_json->>'monthly_grant_adjusted_micros')::bigint,(metadata_json->>'permanent_adjusted_micros')::bigint FROM billing_ledger_entries WHERE tenant_id=$1 AND idempotency_key='negative-adjust'`, tenant).Scan(&gift, &permanent); e != nil || gift != 500 || permanent != 0 {
		t.Fatalf("operator split=%d/%d %v", gift, permanent, e)
	}
}

func TestMonthlyWalletIssuedCycleLocksTimezoneEvenWhenFullyConsumed(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Reserve(ctx, tenant, w.ID, "all-gift", 1000); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Settle(ctx, tenant, "all-gift", 1000); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC"}); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai"}); !errors.Is(e, ErrAllowanceCurrency) {
		t.Fatalf("spent cycle changed calendar and could issue twice: %v", e)
	}
	if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); !errors.Is(e, ErrAllowanceCurrency) {
		t.Fatalf("spent cycle changed denomination: %v", e)
	}
}

func TestMonthlyWalletConcurrentFailedRequestsReleaseAllFunds(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := fmt.Sprintf("failed-%d", i)
			instance := NewStore(db)
			if _, _, e := instance.Reserve(ctx, tenant, w.ID, request, 10); e != nil {
				t.Errorf("reserve %v", e)
				return
			}
			if _, _, e := instance.Release(ctx, tenant, request); e != nil {
				t.Errorf("release %v", e)
			}
		}(i)
	}
	wg.Wait()
	w, e = s.GetWallet(ctx, tenant, w.ID)
	if e != nil || w.BalanceMicros != 1000 || w.ReservedMicros != 0 {
		t.Fatalf("failed request holds leaked: %+v %v", w, e)
	}
	status, e := s.MonthlyWalletStatus(ctx, tenant, user, at)
	if e != nil || status.ReservedMicros != 0 || status.RemainingMicros != 1000 || status.UsedMicros != 0 {
		t.Fatalf("gift reservations leaked: %+v %v", status, e)
	}
}

func TestMonthlyWalletOpeningWithFundingOffDoesNotFreezeFirstPositiveGrant(t *testing.T) {
	for _, mode := range []string{"null", "zero"} {
		t.Run(mode, func(t *testing.T) {
			s, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			at := time.Now().UTC()
			var amount *int64
			if mode == "zero" {
				zero := int64(0)
				amount = &zero
			}
			if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: amount}); e != nil {
				t.Fatal(e)
			}
			initial, e := s.MonthlyWalletStatus(ctx, tenant, user, at)
			if e != nil || initial == nil || initial.GrantedMicros != 0 {
				t.Fatalf("opening empty wallet=%+v %v", initial, e)
			}
			positive := int64(1000)
			if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &positive}); e != nil {
				t.Fatal(e)
			}
			w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
			if e != nil || w.BalanceMicros != 1000 {
				t.Fatalf("first positive amount did not fund this month: %+v %v", w, e)
			}
			positive = 500
			if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &positive}); e != nil {
				t.Fatal(e)
			}
			w, e = s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
			if e != nil || w.BalanceMicros != 1000 {
				t.Fatalf("already funded cycle changed retroactively: %+v %v", w, e)
			}
			var grants int
			if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_wallet_monthly_grants WHERE tenant_id=$1`, tenant).Scan(&grants); e != nil || grants != 1 {
				t.Fatalf("positive funding count=%d %v", grants, e)
			}
		})
	}
}

func TestMonthlyWalletPrepaidAndMeteringSettleActualGiftWithTariffAndEstimate(t *testing.T) {
	for _, mode := range []string{"prepaid", "metering"} {
		t.Run(mode, func(t *testing.T) {
			s, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			amount := int64(1000)
			at := time.Now().UTC()
			if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
				t.Fatal(e)
			}
			w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
				t.Fatal(e)
			}
			p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "monthly-priced", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: at.Add(-time.Hour)})
			if e != nil {
				t.Fatal(e)
			}
			tariff := DefaultTariffQuote(at, "UTC")
			tariff.MultiplierPPM = 2 * ratioScale
			attr, e := s.ResolveBillingAttribution(ctx, tenant, user)
			if e != nil {
				t.Fatal(e)
			}
			reservation, _, e := s.ReservePricedWithUsageForGroupAndTariff(ctx, tenant, w.ID, "priced", 20, 5, p, DefaultCustomerGroup, ratioScale, attr, tariff)
			if e != nil {
				t.Fatal(e)
			}
			_, end, _ := allowanceMonth(at, "UTC")
			if _, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", end); e != nil {
				t.Fatal(e)
			}
			usage := Usage{PromptTokens: 2, OutputTokens: 3}
			raw := []byte(`{"usage_source":"estimated_incomplete","usage":{"prompt_tokens":2,"completion_tokens":3}}`)
			settle := func() error {
				if mode == "prepaid" {
					_, _, e := s.SettleCharge(ctx, tenant, "priced", p, usage, raw, nil)
					return e
				}
				_, e := s.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: "priced", ModelName: p.ModelName, RequestStatus: "incomplete", Usage: usage, AdmittedAt: reservation.AdmittedAt, QuotePriceID: p.ID, QuoteTariff: &tariff, Estimated: true, RawUsage: raw})
				return e
			}
			if e = settle(); e != nil {
				t.Fatal(e)
			}
			if e = settle(); e != nil {
				t.Fatalf("repeat finalize=%v", e)
			}
			w, e = s.GetWallet(ctx, tenant, w.ID)
			if e != nil || w.BalanceMicros != 1300 || w.ReservedMicros != 0 {
				t.Fatalf("old incomplete stream changed permanent/new funds: %+v %v", w, e)
			}
			var fact, gift, debit int64
			var estimated bool
			if e = db.QueryRow(ctx, `SELECT f.billable_amount_micros,f.estimated,-l.balance_delta_micros,(l.metadata_json->>'monthly_grant_consumed_micros')::bigint FROM billing_usage_facts f JOIN billing_ledger_entries l ON l.tenant_id=f.tenant_id AND l.request_id=f.request_id AND l.event_type='settle' WHERE f.tenant_id=$1 AND f.request_id='priced'`, tenant).Scan(&fact, &estimated, &debit, &gift); e != nil || fact != 16 || debit != 16 || gift != 16 || !estimated {
				t.Fatalf("tariff/estimated financial evidence fact=%d debit=%d gift=%d estimated=%v err=%v", fact, debit, gift, estimated, e)
			}
		})
	}
}

func TestMonthlyWalletWorkerAdvancesPastPermanentFailuresAfterRestart(t *testing.T) {
	s, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	at := time.Now().UTC()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	// A preexisting legacy mismatch is never repaired by silently creating a
	// second currency wallet. More than one full page permanently fails 409.
	if _, e := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role,status) SELECT $1||'-aaa-'||lpad(g::text,4,'0'),$1,$1||'-bad-'||g,'x','chat_user','active' FROM generate_series(1,501) g`, tenant); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(ctx, `INSERT INTO billing_wallets(id,tenant_id,user_id,currency,balance_micros,prepaid_configured) SELECT 'wallet-'||u.id,u.tenant_id,u.id,'USD',1,true FROM users u WHERE u.tenant_id=$1 AND u.id LIKE $1||'-aaa-%'`, tenant); e != nil {
		t.Fatal(e)
	}
	good := tenant + "-zzz-good"
	if _, e := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role,status) VALUES($1,$2,$1,'x','chat_user','active')`, good, tenant); e != nil {
		t.Fatal(e)
	}
	funded := int64(0)
	seenFailure := false
	for i := 0; i < 6; i++ {
		instance := NewStore(db)
		result, e := instance.GrantMonthlyWallets(ctx, at, 500)
		if result.Attempted > 500 {
			t.Fatalf("worker exceeded bound: %+v", result)
		}
		if e != nil {
			if result.Failed == 0 {
				t.Fatalf("non-scoped worker failure: %v", e)
			}
			seenFailure = true
		}
		if e = db.QueryRow(ctx, `SELECT COALESCE(sum(balance_micros),0) FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2 AND currency='CNY'`, tenant, good).Scan(&funded); e != nil {
			t.Fatal(e)
		}
		if funded == 1000 {
			break
		}
	}
	if !seenFailure || funded != 1000 {
		t.Fatalf("persistent failed head starved healthy tail: failure=%v funded=%d", seenFailure, funded)
	}
	var badGrants int
	if e := db.QueryRow(ctx, `SELECT count(*) FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND user_id LIKE $1||'-aaa-%'`, tenant).Scan(&badGrants); e != nil || badGrants != 0 {
		t.Fatalf("foreign funded accounts got gifts: %d %v", badGrants, e)
	}
}

func TestMonthlyWalletEmptyMarkerCanChooseInitialUSDWithoutReinterpretingMoney(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			s, db, tenant, user := setupBillingStoreTest(t)
			ctx := context.Background()
			at := time.Now().UTC()
			if explicit {
				zero := int64(0)
				if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &zero}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := s.MonthlyWalletStatus(ctx, tenant, user, at); e != nil {
				t.Fatal(e)
			}
			if explicit {
				zero := int64(0)
				if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC", DefaultMonthlyMicros: &zero}); e != nil {
					t.Fatalf("empty marker froze initial denomination: %v", e)
				}
			}
			p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "initial-usd", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}})
			if e != nil || p.Currency != "USD" {
				t.Fatalf("initial USD price=%+v %v", p, e)
			}
			w, e := s.FindWalletForUser(ctx, tenant, user, "USD")
			if e != nil || w == nil || w.Currency != "USD" || w.BalanceMicros != 0 {
				t.Fatalf("canonical empty USD wallet=%+v %v", w, e)
			}
			var old int
			if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2 AND currency='CNY' AND balance_micros=0`, tenant, user).Scan(&old); e != nil || old != 1 {
				t.Fatalf("old empty marker destroyed: %d %v", old, e)
			}
			if _, e = s.Credit(ctx, tenant, w.ID, "real-usd-credit", 100, "admin"); e != nil {
				t.Fatal(e)
			}
			if _, e = s.Adjust(ctx, tenant, w.ID, "spent-usd", -100, "admin"); e != nil {
				t.Fatal(e)
			}
			if e = s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC"}); !errors.Is(e, ErrAllowanceCurrency) {
				t.Fatalf("fully spent real money lost denomination lock: %v", e)
			}
		})
	}
}

func TestMonthlyWalletHumanListExcludesMachineAndCrossTenant(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	machine := user + "-machine"
	if _, e := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role,status) VALUES($1,$2,$1,'x','platform_connector','active')`, machine, tenant); e != nil {
		t.Fatal(e)
	}
	rows, e := s.ListEmployeeAllowances(ctx, tenant, time.Now())
	if e != nil || len(rows) != 1 || rows[0].UserID != user || rows[0].MonthlyStatus == nil || rows[0].MonthlyStatus.GrantedMicros != 1000 {
		t.Fatalf("human list includes machine or wrong funding: %+v %v", rows, e)
	}
	rows, e = s.ListEmployeeAllowances(ctx, tenant+"-foreign", time.Now())
	if e != nil || len(rows) != 0 {
		t.Fatalf("cross-tenant human list=%+v %v", rows, e)
	}
	var grants int
	if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_wallet_monthly_grants WHERE user_id=$1`, machine).Scan(&grants); e != nil || grants != 0 {
		t.Fatalf("machine got monthly credit: %d %v", grants, e)
	}
}

func TestMonthlyWalletInactiveTenantCannotReceiveLazyGrant(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(ctx, `UPDATE tenants SET status='disabled' WHERE id=$1`, tenant); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now())
	if e != nil || w != nil {
		t.Fatalf("inactive tenant received lazy funding: %+v %v", w, e)
	}
}

func (s *Store) ensureMonthlyForTest(ctx context.Context, tenant, user, currency string, at time.Time) (*Wallet, error) {
	s.fundingClock = func() time.Time { return at }
	return s.EnsureMonthlyWalletGrant(ctx, tenant, user, currency, at)
}

func waitMonthlyWalletRowLock(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if e := db.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%billing_wallets%')`).Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if blocked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("wallet waiter never reached row lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMonthlyWalletReserveWaitCrossesMonthUsesCurrentGiftAndCounterPeriod(t *testing.T) {
	t.Setenv("BILLING_TIMEZONE", "UTC")
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	_, end, _ := allowanceMonth(time.Now(), "UTC")
	before := end.Add(-time.Second)
	after := end.Add(time.Second)
	var clock atomic.Int64
	clock.Store(before.UnixNano())
	s.fundingClock = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", before)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "boundary-priced", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(ctx, `INSERT INTO billing_customer_limits(tenant_id,user_id,daily_amount_micros,monthly_amount_micros,daily_token_limit,monthly_token_limit) VALUES($1,$2,1000,2000,10,20)`, tenant, user); e != nil {
		t.Fatal(e)
	}
	holder, e := db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer holder.Rollback(ctx)
	if _, e = holder.Exec(ctx, `SELECT id FROM billing_wallets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, w.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, _, e := s.ReservePricedWithUsageForGroupAndTariff(ctx, tenant, w.ID, "wait-month", 100, 2, p, DefaultCustomerGroup, ratioScale, BillingAttribution{UserID: user}, DefaultTariffQuote(before, "UTC"))
		done <- e
	}()
	waitMonthlyWalletRowLock(t, db)
	clock.Store(after.UnixNano())
	if e = holder.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	r, e := s.GetReservation(ctx, tenant, "wait-month")
	if e != nil || !r.CreatedAt.Equal(after) || !r.AdmittedAt.Equal(before) {
		t.Fatalf("money and price times were mixed: %+v %v", r, e)
	}
	var fundingMonth time.Time
	if e = db.QueryRow(ctx, `SELECT g.month_start FROM billing_wallet_monthly_allocations a JOIN billing_wallet_monthly_grants g ON g.id=a.grant_id WHERE a.tenant_id=$1 AND a.reservation_id=$2`, tenant, r.ID).Scan(&fundingMonth); e != nil || !fundingMonth.Equal(end) {
		t.Fatalf("expired pre-lock gift was frozen: %v %v", fundingMonth, e)
	}
	if _, _, e = s.Release(ctx, tenant, "wait-month"); e != nil {
		t.Fatal(e)
	}
	var money, tokens int64
	if e = db.QueryRow(ctx, `SELECT sum(reserved_amount_micros),sum(reserved_tokens) FROM billing_limit_counters WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&money, &tokens); e != nil || money != 0 || tokens != 0 {
		t.Fatalf("new day/month counter leak=%d/%d %v", money, tokens, e)
	}
	w, e = s.GetWallet(ctx, tenant, w.ID)
	if e != nil || w.BalanceMicros != 1000 || w.ReservedMicros != 0 {
		t.Fatalf("boundary wallet=%+v %v", w, e)
	}
}

func TestMonthlyWalletSettlementWaitCannotConsumeExpiredUnfrozenGift(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	_, end, _ := allowanceMonth(time.Now(), "UTC")
	before := end.Add(-time.Second)
	after := end.Add(time.Second)
	var clock atomic.Int64
	clock.Store(before.UnixNano())
	s.fundingClock = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", before)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Reserve(ctx, tenant, w.ID, "wait-settle", 600); e != nil {
		t.Fatal(e)
	}
	// Keep the next cycle's gift visible while the original request settles.
	nextID := "future-" + user
	if _, e = db.Exec(ctx, `INSERT INTO billing_wallet_monthly_grants(id,tenant_id,wallet_id,user_id,currency,month_start,month_end,timezone,amount_micros,remaining_micros) VALUES($1,$2,$3,$4,'CNY',$5,$6,'UTC',1000,1000)`, nextID, tenant, w.ID, user, end, end.AddDate(0, 1, 0)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "future-test-credit", 1000, "test"); e != nil {
		t.Fatal(e)
	}
	holder, e := db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer holder.Rollback(ctx)
	if _, e = holder.Exec(ctx, `SELECT id FROM billing_wallets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, w.ID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, _, e := s.Settle(ctx, tenant, "wait-settle", 800); done <- e }()
	waitMonthlyWalletRowLock(t, db)
	clock.Store(after.UnixNano())
	if e = holder.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var gift, permanent int64
	if e = db.QueryRow(ctx, `SELECT (metadata_json->>'monthly_grant_consumed_micros')::bigint,(metadata_json->>'permanent_consumed_micros')::bigint FROM billing_ledger_entries WHERE tenant_id=$1 AND event_type='settle'`, tenant).Scan(&gift, &permanent); e != nil || gift != 600 || permanent != 200 {
		t.Fatalf("old unfrozen gift was consumed=%d permanent=%d %v", gift, permanent, e)
	}
	var nextRemaining int64
	if e = db.QueryRow(ctx, `SELECT remaining_micros FROM billing_wallet_monthly_grants WHERE id=$1`, nextID).Scan(&nextRemaining); e != nil || nextRemaining != 1000 {
		t.Fatalf("old request consumed next cycle=%d %v", nextRemaining, e)
	}
	w, e = s.GetWallet(ctx, tenant, w.ID)
	if e != nil || w.BalanceMicros != 1100 || w.ReservedMicros != 0 {
		t.Fatalf("permanent/new gift invariant=%+v %v", w, e)
	}
}

func TestMonthlyWalletForeignMoneyRedemptionReturns409WithoutConsumingCode(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC"}); e != nil {
		t.Fatal(e)
	}
	foreign := legacyWalletForTest(t, s, tenant, user, "USD")
	if _, e := s.Credit(ctx, tenant, foreign.ID, "legacy-usd", 100, "test"); e != nil {
		t.Fatal(e)
	}
	codes, e := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "currency-check", AmountMicros: 200, Count: 1, CreatedBy: "test"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.RedeemCode(ctx, tenant, user, codes[0].Code); !errors.Is(e, ErrAllowanceCurrency) {
		t.Fatalf("foreign redemption=%v", e)
	}
	var status string
	var wallets, events int
	if e = db.QueryRow(ctx, `SELECT status FROM billing_redemption_codes WHERE id=$1`, codes[0].ID).Scan(&status); e != nil || status != "active" {
		t.Fatalf("failed redemption consumed code: %s %v", status, e)
	}
	if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_wallets WHERE tenant_id=$1 AND currency='CNY'`, tenant).Scan(&wallets); e != nil || wallets != 0 {
		t.Fatalf("failed redemption created foreign wallet=%d %v", wallets, e)
	}
	if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1 AND event_type='redemption'`, tenant).Scan(&events); e != nil || events != 0 {
		t.Fatalf("failed redemption mutated money=%d %v", events, e)
	}
}

func TestMonthlyWalletNegativeAdjustmentUsesOneFundingInstant(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(1000)
	_, end, _ := allowanceMonth(time.Now(), "UTC")
	before := end.Add(-time.Second)
	after := end.Add(time.Second)
	if e := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); e != nil {
		t.Fatal(e)
	}
	w, e := s.ensureMonthlyForTest(ctx, tenant, user, "CNY", before)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Credit(ctx, tenant, w.ID, "manual", 300, "admin"); e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int64
	s.fundingClock = func() time.Time {
		if calls.Add(1) == 1 {
			return before
		}
		return after
	}
	w, e = s.Adjust(ctx, tenant, w.ID, "single-clock-adjust", -800, "admin")
	if e != nil || w.BalanceMicros != 500 || calls.Load() != 1 {
		t.Fatalf("adjust mixed financial instants: wallet=%+v calls=%d err=%v", w, calls.Load(), e)
	}
	w, e = s.ensureMonthlyForTest(ctx, tenant, user, "CNY", after)
	if e != nil || w.BalanceMicros != 1300 {
		t.Fatalf("month rollover consumed permanent funds after adjustment: %+v %v", w, e)
	}
}
