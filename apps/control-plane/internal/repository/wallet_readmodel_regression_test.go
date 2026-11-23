package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type walletReadModelFixture struct {
	db                                                             *pgxpool.Pool
	store                                                          *billing.Store
	tenant, user, otherUser, otherTenant, otherTenantUser, project string
	wallet                                                         *billing.Wallet
	at                                                             time.Time
	paid, prepaid, free, unpriced, failed, legacy, anomaly         string
}

// This regression uses real reserve/fact/debit transactions. Fixture history is
// append-only and lives only in a disposable test database.
func seedWalletReadModelFixture(t *testing.T, currency string) walletReadModelFixture {
	t.Helper()
	url := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config.ConnConfig.Database, "test") {
		t.Fatal("readmodel regression requires a disposable test database")
	}
	ctx := context.Background()
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	id := uuid.NewString()
	f := walletReadModelFixture{db: db, store: billing.NewStore(db), tenant: "wr_t_" + id, user: "wr_u_" + id, otherUser: "wr_o_" + id, otherTenant: "wr_b_" + id, otherTenantUser: "wr_v_" + id, project: "wr_p_" + id, at: time.Now().UTC().Truncate(time.Microsecond)}
	if _, err = db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true),($2,$2,'enterprise','active',true)`, f.tenant, f.otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$4,$1,'developer','active'),($2,$4,$2,'developer','active'),($3,$5,$3,'developer','active')`, f.user, f.otherUser, f.otherTenantUser, f.tenant, f.otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,owner_user_id,status) VALUES($1,$2,$1,$3,'active')`, f.project, f.tenant, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO internal_keys(id,tenant_id,project_id,user_id,key_hash,key_prefix,name,status) VALUES($1,$2,$3,$4,$1,'sk-wr','readmodel','active')`, "wr_k_"+id, f.tenant, f.project, f.user); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.tenant, f.otherTenant} {
		if err = f.store.SaveEmployeeSettings(ctx, tenant, billing.EmployeeSettings{Currency: currency, Timezone: "UTC"}); err != nil {
			t.Fatal(err)
		}
	}
	f.wallet, err = f.store.CreditUserWallet(ctx, f.tenant, f.user, "fund", 1000, "test")
	if err != nil {
		t.Fatal(err)
	}
	price, err := f.store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: f.tenant, ModelName: "readmodel-paid", Currency: currency, PricingMode: billing.PricingModeDirect, DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: f.at.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := f.store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: f.tenant, ModelName: "readmodel-free", Currency: currency, PricingMode: billing.PricingModeDirect, DirectPrice: billing.DirectPrice{}, EffectiveAt: f.at.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	f.paid, f.prepaid, f.free, f.unpriced, f.failed, f.legacy, f.anomaly = "paid-"+id, "prepaid-"+id, "free-"+id, "unpriced-"+id, "failed-"+id, "legacy-"+id, "anomaly-"+id
	for _, request := range []string{f.paid, f.prepaid, f.free, f.unpriced, f.failed, f.legacy, f.anomaly} {
		if _, err = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,endpoint_type,request_status,input_tokens,output_tokens,created_at) VALUES($1,$1,$2,$3,$4,$5,'chat_completion','success',2,3,$6)`, request, f.tenant, f.project, f.user, "wr_k_"+id, f.at); err != nil {
			t.Fatal(err)
		}
	}
	attr, err := f.store.ResolveBillingAttribution(ctx, f.tenant, f.user)
	if err != nil {
		t.Fatal(err)
	}
	tariff := billing.DefaultTariffQuote(f.at, "UTC")
	tariff.MultiplierPPM = 2_000_000
	for _, item := range []struct {
		request string
		price   *billing.ModelPrice
		prepaid bool
		usage   billing.Usage
	}{
		{f.paid, price, false, billing.Usage{PromptTokens: 2, OutputTokens: 3}},
		{f.prepaid, price, true, billing.Usage{PromptTokens: 4, OutputTokens: 1}},
		{f.free, zero, false, billing.Usage{PromptTokens: 2, OutputTokens: 3}},
	} {
		r, _, e := f.store.ReservePricedWithUsageForGroupAndTariff(ctx, f.tenant, f.wallet.ID, item.request, 20, 5, item.price, billing.DefaultCustomerGroup, 1_000_000, attr, tariff)
		if e != nil {
			t.Fatal(e)
		}
		if item.prepaid {
			if _, _, e = f.store.SettleCharge(ctx, f.tenant, item.request, item.price, item.usage, nil, nil); e != nil {
				t.Fatal(e)
			}
		} else {
			if _, e = f.store.RecordMeteringUsage(ctx, billing.MeteringInput{TenantID: f.tenant, UserID: f.user, RequestID: item.request, ModelName: item.price.ModelName, RequestStatus: "success", Usage: item.usage, AdmittedAt: r.AdmittedAt, QuotePriceID: item.price.ID}); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, err = f.store.RecordMeteringUsage(ctx, billing.MeteringInput{TenantID: f.tenant, UserID: f.user, RequestID: f.unpriced, ModelName: "readmodel-unpriced", RequestStatus: "success", Unpriced: true, Usage: billing.Usage{PromptTokens: 2, OutputTokens: 3}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.ReservePricedWithUsage(ctx, f.tenant, f.wallet.ID, f.failed, 20, 5, price); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.RecordMeteringUsage(ctx, billing.MeteringInput{TenantID: f.tenant, UserID: f.user, RequestID: f.failed, ModelName: price.ModelName, RequestStatus: "failed"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.Release(ctx, f.tenant, f.failed); err != nil {
		t.Fatal(err)
	}
	// A pre-fact prepaid charge must remain visible, with no synthetic history repair.
	if _, err = db.Exec(ctx, `INSERT INTO billing_charge_records(id,tenant_id,wallet_id,request_id,model_name,prompt_tokens,output_tokens,amount_micros,pricing_mode,currency,status,customer_group,created_at) VALUES($1,$2,$3,$1,'readmodel-legacy',1,2,7,'direct',$4,'settled','default',$5)`, f.legacy, f.tenant, f.wallet.ID, currency, f.at); err != nil {
		t.Fatal(err)
	}
	// A prepaid settled reservation without its charge is still an anomaly.
	if _, err = db.Exec(ctx, `INSERT INTO billing_reservations(id,tenant_id,wallet_id,request_id,reserved_micros,settled_micros,status,finalized_at) VALUES($1,$2,$3,$1,20,77,'settled',NOW())`, f.anomaly, f.tenant, f.wallet.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,$1,'prepaid',$3,'readmodel-anomaly',77,$4,'settled',$5,$5)`, f.anomaly, f.tenant, f.user, currency, f.at); err != nil {
		t.Fatal(err)
	}
	// Same request ID in another tenant, another user, and outside the interval.
	for i, item := range []struct {
		tenant, user, request string
		at                    time.Time
	}{
		{f.otherTenant, f.otherTenantUser, f.paid, f.at},
		{f.tenant, f.otherUser, "other-" + id, f.at},
		{f.tenant, f.user, "old-" + id, f.at.AddDate(0, 0, -31)},
	} {
		if _, err = db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,prompt_tokens,output_tokens,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,$3,'metering',$4,'readmodel-hidden',1,1,999,$5,'settled',$6,$6)`, fmt.Sprintf("hidden%d-%s", i, id), item.tenant, item.request, item.user, currency, item.at); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestWalletReadModelCustomerSummaryCanonicalConsumption(t *testing.T) {
	for _, currency := range []string{"CNY", "USD"} {
		t.Run(currency, func(t *testing.T) {
			f := seedWalletReadModelFixture(t, currency)
			ctx := context.Background()
			before, err := f.store.GetWallet(ctx, f.tenant, f.wallet.ID)
			if err != nil || before.BalanceMicros != 972 || before.ReservedMicros != 0 {
				t.Fatalf("actual debit: %+v %v", before, err)
			}
			var ledgerBefore int
			if err = f.db.QueryRow(ctx, `SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1`, f.tenant).Scan(&ledgerBefore); err != nil {
				t.Fatal(err)
			}
			summary, err := f.store.CustomerSummary(ctx, f.tenant, f.user, f.at.AddDate(0, 0, -30), 20)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Wallet.Currency != currency || summary.Wallet.BalanceMicros != 972 || summary.Usage.Requests != 4 || summary.Usage.AmountMicros != 35 || summary.Usage.PromptTokens != 9 || summary.Usage.OutputTokens != 9 {
				t.Fatalf("canonical summary: %+v", summary)
			}
			if len(summary.Daily) != 1 || summary.Daily[0].Requests != 4 || summary.Daily[0].Tokens != 18 || summary.Daily[0].AmountMicros != 35 {
				t.Fatalf("daily: %+v", summary.Daily)
			}
			if len(summary.Models) != 3 {
				t.Fatalf("models: %+v", summary.Models)
			}
			var modelRequests, modelTokens int64
			var modelAmount billing.Micros
			for _, m := range summary.Models {
				modelRequests += m.Requests
				modelTokens += m.Tokens
				modelAmount += m.AmountMicros
			}
			if modelRequests != 4 || modelTokens != 18 || modelAmount != 35 {
				t.Fatalf("model totals: %+v", summary.Models)
			}
			if len(summary.Charges) != 4 {
				t.Fatalf("charges must be once per consumption: %+v", summary.Charges)
			}
			want := map[string]billing.Micros{f.paid: 16, f.prepaid: 12, f.free: 0, f.legacy: 7}
			for _, c := range summary.Charges {
				amount, ok := want[c.RequestID]
				if !ok || c.AmountMicros != amount || c.Currency != currency || c.CustomerGroup != "default" {
					t.Fatalf("charge: %+v", c)
				}
				delete(want, c.RequestID)
			}
			if len(want) != 0 {
				t.Fatalf("missing charges: %v", want)
			}
			// Reads do not debit a second time or change immutable facts/ledger.
			after, err := f.store.GetWallet(ctx, f.tenant, f.wallet.ID)
			var ledgerAfter int
			if err != nil || *after != *before {
				t.Fatalf("read changed wallet: %+v %v", after, err)
			}
			if err = f.db.QueryRow(ctx, `SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1`, f.tenant).Scan(&ledgerAfter); err != nil || ledgerBefore != ledgerAfter {
				t.Fatalf("read changed ledger: %d %d %v", ledgerBefore, ledgerAfter, err)
			}
			for _, owner := range []struct{ tenant, user string }{{f.tenant, f.otherUser}, {f.otherTenant, f.otherTenantUser}} {
				isolated, e := f.store.CustomerSummary(ctx, owner.tenant, owner.user, f.at.AddDate(0, 0, -30), 20)
				if e != nil || isolated.Usage.Requests != 1 || isolated.Usage.AmountMicros != 999 {
					t.Fatalf("owner isolation: %+v %v", isolated, e)
				}
			}
		})
	}
}

func TestWalletReadModelUsageAndPortalAgreeWithDebit(t *testing.T) {
	f := seedWalletReadModelFixture(t, "CNY")
	ctx := context.Background()
	filter := UsageRecordFilter{StartDate: f.at.Add(-time.Hour), EndDate: f.at.Add(time.Hour), Limit: 50}
	scope := UsageScope{TenantID: f.tenant, UserID: f.user}
	repo := NewUsageDailyRepository(f.db)
	records, total, err := repo.ListUsageRecords(ctx, scope, filter)
	if err != nil || total != 7 {
		t.Fatalf("usage rows: %d %v", total, err)
	}
	byRequest := indexUsageRecordsByRequestID(records)
	for _, item := range []struct {
		request, mode string
		amount        int64
	}{{f.paid, "metering", 16}, {f.prepaid, "prepaid", 12}, {f.free, "metering", 0}, {f.legacy, "prepaid", 7}} {
		r := byRequest[item.request]
		if r.BillingState != "settled" || r.BillingMode != item.mode || r.BillingCurrency != "CNY" || r.BillingAmountMicros == nil || *r.BillingAmountMicros != item.amount {
			t.Fatalf("usage projection: %+v", r)
		}
	}
	if byRequest[f.anomaly].BillingState != "exception" || byRequest[f.unpriced].BillingState != "unpriced" || byRequest[f.failed].BillingState != "released" {
		t.Fatalf("anomalies/nonbillable: %+v", byRequest)
	}
	summary, err := repo.SummarizeUsageRecords(ctx, scope, filter)
	if err != nil || summary.SettledRequests != 4 || summary.BillingAmountMicros != 35 || summary.ExceptionRequests != 1 || summary.UnpricedRequests != 1 || summary.ReleasedRequests != 1 {
		t.Fatalf("usage summary: %+v %v", summary, err)
	}
	portal, total, err := NewRequestLogRepository(f.db).ListPortalCallRecords(ctx, PortalCallRecordFilter{TenantID: f.tenant, UserID: f.user, StartTime: filter.StartDate, Limit: 50})
	if err != nil || total != 7 {
		t.Fatalf("portal rows: %d %v", total, err)
	}
	for _, r := range portal {
		u := byRequest[r.RequestID]
		if r.BillingState != u.BillingState || r.BillingCurrency != u.BillingCurrency {
			t.Fatalf("record states/currencies differ: portal=%+v usage=%+v", r, u)
		}
		if r.BillingState == "settled" && (r.BillingAmountMicros == nil || *r.BillingAmountMicros != *u.BillingAmountMicros) {
			t.Fatalf("record amounts differ: portal=%+v usage=%+v", r, u)
		}
		if r.BillingState != "settled" && r.BillingAmountMicros != nil {
			t.Fatalf("nonsettled portal amount: %+v", r)
		}
	}
}
