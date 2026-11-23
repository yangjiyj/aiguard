package billing

import (
	"context"
	"testing"
	"time"
)

func TestProxyUsageStoreNeverCreatesMoneyFacts(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	for _, source := range []string{"forward_proxy", "reverse_proxy"} {
		fact, err := store.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: user + source, ModelName: "priced-model", RequestStatus: "success", UsageSource: source, Usage: Usage{PromptTokens: 100, OutputTokens: 100}})
		if err != nil || fact.Status != "observed" {
			t.Fatalf("fact=%+v err=%v", fact, err)
		}
	}
	var facts int64
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1`, tenant).Scan(&facts); err != nil || facts != 0 {
		t.Fatalf("facts=%d err=%v", facts, err)
	}
}

func TestHistoricalProxyFactsStayImmutableAndOutsideFinance(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	limit := int64(100)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &limit}); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"gateway", "forward_proxy"} {
		for _, status := range []string{"settled", "unpriced"} {
			id := user + "-" + source + "-" + status
			if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at,usage_source) VALUES($1,$2,$1,$3,$4,10,'CNY',$5,$6,$6,$7)`, id, tenant, user, source+"-model", status, now, source); err != nil {
				t.Fatal(err)
			}
		}
	}
	summary, err := store.GetAnalyticsSummary(ctx, AnalyticsFilter{TenantID: tenant, Start: now.Add(-time.Minute), End: now.Add(time.Minute), FullTenant: true})
	if err != nil || summary.Requests != 2 || summary.BillableMicros != 10 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	allowance, err := store.EmployeeAllowanceForUser(ctx, tenant, user, now)
	if err != nil || allowance == nil || allowance.UsedMicros != 10 {
		t.Fatalf("allowance=%+v err=%v", allowance, err)
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	statement, err := store.MonthlyStatement(ctx, tenant, now.In(loc).Format("2006-01"))
	if err != nil || statement.Total.Requests != 2 || statement.Total.BilledMicros != 10 {
		t.Fatalf("statement=%+v err=%v", statement, err)
	}
	unpriced, err := store.ListUnpricedModels(ctx, tenant, now.Add(-time.Minute), now.Add(time.Minute))
	if err != nil || len(unpriced) != 1 || unpriced[0].ModelName != "gateway-model" {
		t.Fatalf("unpriced=%+v err=%v", unpriced, err)
	}
	exceptions, err := store.ListBillingExceptions(ctx, tenant, 100)
	if err != nil || len(exceptions) != 1 || exceptions[0].ModelName != "gateway-model" {
		t.Fatalf("exceptions=%+v err=%v", exceptions, err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 4 {
		t.Fatalf("history count=%d err=%v", count, err)
	}
}

func TestProxyAuditCannotDriveStaleWalletReconciliation(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "reconcile-priced", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenant, wallet.ID, tenant+"-fund", 10000, "test"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"proxy-success", "proxy-failure", "direct-success"} {
		id := tenant + kind
		if _, _, err = store.ReservePricedWithUsageForGroup(ctx, tenant, wallet.ID, id, 100, 30, price, DefaultCustomerGroup, ratioScale); err != nil {
			t.Fatal(err)
		}
		status, ingress := "success", "reverse_proxy"
		if kind == "proxy-failure" {
			status = "provider_unavailable"
		}
		if kind == "direct-success" {
			ingress = "model_api"
		}
		if _, err = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,user_id,endpoint_type,request_status,input_tokens,output_tokens,output_audit_result,created_at) VALUES($1,$1,$2,$3,'chat_completion',$4,10,5,jsonb_build_object('response_metadata',jsonb_build_object('usage_source','upstream','billing_ingress',$5::text)),NOW()-INTERVAL '2 hours')`, id, tenant, user, status, ingress); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, `UPDATE billing_reservations SET created_at=NOW()-INTERVAL '2 hours' WHERE tenant_id=$1 AND request_id=$2`, tenant, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = store.ReconcileStaleReservations(ctx, time.Hour, 500); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"proxy-success", "proxy-failure", "direct-success"} {
		var status string
		if err = db.QueryRow(ctx, `SELECT status FROM billing_reservations WHERE tenant_id=$1 AND request_id=$2`, tenant, tenant+kind).Scan(&status); err != nil {
			t.Fatal(err)
		}
		expected := "reserved"
		if kind == "direct-success" {
			expected = "settled"
		}
		if status != expected {
			t.Fatalf("kind=%s status=%s expected=%s", kind, status, expected)
		}
	}
	var balance, reserved, charges int64
	if err = db.QueryRow(ctx, `SELECT balance_micros,reserved_micros FROM billing_wallets WHERE id=$1`, wallet.ID).Scan(&balance, &reserved); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_charge_records WHERE tenant_id=$1`, tenant).Scan(&charges); err != nil {
		t.Fatal(err)
	}
	if balance != 9980 || reserved != 200 || charges != 1 {
		t.Fatalf("balance=%d reserved=%d charges=%d", balance, reserved, charges)
	}
}
