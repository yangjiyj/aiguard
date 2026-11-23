package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Actual PostgreSQL, control-plane HTTP admission/settlement, gateway billing
// client and audit writer, plus an isolated upstream exercise money end-to-end.
func TestGovernmentBillingEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-module PostgreSQL billing integration")
	}
	if os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL") == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	gatewayDir, err := filepath.Abs("../../../gateway-core")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "govt-billing-bridge.test")
	build := exec.Command("/usr/local/go/bin/go", "test", "-buildvcs=false", "-c", "-o", binary, "./internal/handler")
	build.Dir = gatewayDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gateway bridge: %v\n%s", err, out)
	}
	for _, kind := range []string{"A-priced", "B-exhausted", "C-unpriced-exhausted", "D-mixed-key", "E-stream-disconnect", "F-concurrent-upstream-5xx", "G-tariff-retired", "H-summary-only", "I-funded-exhausted"} {
		t.Run(kind, func(t *testing.T) {
			db, store, tenant, user, project := billingEndToEndFixture(t)
			ctx := context.Background()
			if kind == "H-summary-only" {
				user = tenant + "-allowance-only"
				if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'developer','active')`, user, tenant); err != nil {
					t.Fatal(err)
				}
				if _, err := store.CustomerSummary(ctx, tenant, user, time.Now().Add(-time.Hour), 50); err != nil {
					t.Fatal(err)
				}
				var wallets int
				if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&wallets); err != nil || wallets != 1 {
					t.Fatalf("human summary must create an empty wallet: %d %v", wallets, err)
				}
			}
			if kind == "H-summary-only" {
				var count int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&count); err != nil || count != 0 {
					t.Fatalf("empty summary issued a grant: %d %v", count, err)
				}
			}
			key := tenant + "-key"
			if _, err := db.Exec(ctx, `INSERT INTO api_clients(id,tenant_id,project_id,client_name,status) VALUES($1,$2,$3,$1,'active')`, key, tenant, project); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: tenant, ModelName: "govt-paid", Currency: "CNY", PricingMode: billing.PricingModeDirect, DirectPrice: billing.DirectPrice{InputPerMillionMicros: 10_000_000, OutputPerMillionMicros: 20_000_000}, EffectiveAt: time.Now().Add(-time.Hour)}); err != nil {
				t.Fatal(err)
			}
			plan, err := store.CreateTariffPlan(ctx, billing.NewTariffPlan{TenantID: tenant, Name: "govt-tariff", Timezone: "Asia/Shanghai", EffectiveAt: time.Now().Add(-time.Hour), Rules: []billing.TariffRule{{Code: "all-day", Name: "all-day", ModelName: "govt-paid", Band: billing.TariffBandPeak, Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: 2_000_000}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.PublishTariffPlan(ctx, tenant, plan.ID); err != nil {
				t.Fatal(err)
			}
			if kind == "G-tariff-retired" {
				retired, err := store.RetireTariffPlan(ctx, tenant, plan.ID)
				if err != nil || retired.Status != "retired" {
					t.Fatalf("retire=%+v err=%v", retired, err)
				}
			}
			// Force the stream cap with real money, not an independent allowance.
			if kind == "E-stream-disconnect" {
				w, e := store.GetWalletByUser(ctx, tenant, user, "CNY")
				if e != nil {
					t.Fatal(e)
				}
				if _, e = store.Adjust(ctx, tenant, w.ID, tenant+"-stream-setup", -w.BalanceMicros, "test", "replace manual funding with monthly stream gift"); e != nil {
					t.Fatal(e)
				}
			}
			cap := int64(1_000_000)
			if kind == "B-exhausted" || kind == "C-unpriced-exhausted" {
				cap = 0
			}
			if kind == "E-stream-disconnect" {
				cap = 240
			}
			if err := store.SaveEmployeeSettings(ctx, tenant, billing.EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &cap}); err != nil {
				t.Fatal(err)
			}
			if kind == "I-funded-exhausted" || kind == "B-exhausted" || kind == "C-unpriced-exhausted" {
				wallet, err := store.FindWalletForUser(ctx, tenant, user, "CNY")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Adjust(ctx, tenant, wallet.ID, tenant+"-empty-wallet", -wallet.BalanceMicros, "test", "test exhausted wallet"); err != nil {
					t.Fatal(err)
				}
			}
			initialWallet, err := store.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now().UTC())
			if err != nil || initialWallet == nil {
				t.Fatalf("initial funding=%+v %v", initialWallet, err)
			}
			initialBalance := int64(initialWallet.BalanceMicros)
			deps := &Dependencies{BillingStore: store, BillingMode: "metering"}
			mux := http.NewServeMux()
			mux.HandleFunc("/internal/v1/billing/quotes", QuoteGatewayBilling(deps))
			mux.HandleFunc("/internal/v1/billing/measurements", RecordGatewayMeasurement(deps))
			mux.HandleFunc("/internal/v1/billing/releases", ReleaseGatewayBilling(deps))
			server := httptest.NewServer(mux)
			defer server.Close()
			cmd := exec.Command(binary, "-test.run=^TestGovernmentBillingGatewayBridge$", "-test.v")
			cmd.Env = append(os.Environ(), "GOVT_BILLING_ENDPOINT="+server.URL, "GOVT_BILLING_TENANT="+tenant, "GOVT_BILLING_USER="+user, "GOVT_BILLING_PROJECT="+project, "GOVT_BILLING_KEY="+key, "GOVT_BILLING_KIND="+kind)
			out, err := cmd.CombinedOutput()
			t.Logf("gateway %s:\n%s", kind, out)
			if err != nil {
				t.Fatal(err)
			}
			var used, reserved, holds int64
			if err := db.QueryRow(ctx, `SELECT COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0),COUNT(*) FILTER (WHERE status='unpriced') FROM billing_usage_facts WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&used, &holds); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(ctx, `SELECT COALESCE(SUM(amount_micros),0) FROM billing_employee_reservations WHERE tenant_id=$1`, tenant).Scan(&reserved); err != nil || reserved != 0 {
				t.Fatalf("allowance holds=%d err=%v", reserved, err)
			}
			expectedUsage := billing.Usage{PromptTokens: 2, OutputTokens: 3}
			if kind == "E-stream-disconnect" {
				expectedUsage.OutputTokens = 5
			}
			tariffMultiplier := int64(2_000_000)
			if kind == "G-tariff-retired" {
				tariffMultiplier = 1_000_000
			}
			rate, _ := billing.ApplyPriceRatios(billing.DirectPrice{InputPerMillionMicros: 10_000_000, OutputPerMillionMicros: 20_000_000}, 1_000_000, tariffMultiplier)
			charge, _ := billing.CalculateDirectCharge(expectedUsage, rate)
			want := int64(charge.TotalMicros)
			if kind == "B-exhausted" || kind == "C-unpriced-exhausted" || kind == "F-concurrent-upstream-5xx" || kind == "I-funded-exhausted" {
				want = 0
			}
			if used != want {
				t.Fatalf("settled=%d calculator=%d", used, want)
			}
			if (kind == "C-unpriced-exhausted" || kind == "D-mixed-key") && holds != 1 {
				t.Fatalf("unpriced facts=%d", holds)
			}
			if kind == "G-tariff-retired" {
				var factTariff string
				var multiplier int64
				if err := db.QueryRow(ctx, `SELECT COALESCE(tariff_plan_id,''),tariff_multiplier_ppm FROM billing_usage_facts WHERE tenant_id=$1`, tenant).Scan(&factTariff, &multiplier); err != nil || factTariff != "" || multiplier != 1_000_000 {
					t.Fatalf("retired fact tariff=%s multiplier=%d err=%v", factTariff, multiplier, err)
				}
				employee, err := store.EmployeeAllowanceForUser(ctx, tenant, user, time.Now())
				if err != nil || employee == nil || employee.UsedMicros != want || employee.ReservedMicros != 0 {
					t.Fatalf("employee=%+v expected=%d err=%v", employee, want, err)
				}
				var debit int64
				if err := db.QueryRow(ctx, `SELECT -COALESCE(SUM(balance_delta_micros),0) FROM billing_ledger_entries WHERE tenant_id=$1 AND event_type='settle'`, tenant).Scan(&debit); err != nil || debit != want {
					t.Fatalf("ledger debit=%d expected=%d err=%v", debit, want, err)
				}
			}
			if kind == "E-stream-disconnect" {
				var estimated bool
				var output int64
				if err := db.QueryRow(ctx, `SELECT estimated,output_tokens FROM billing_usage_facts WHERE tenant_id=$1`, tenant).Scan(&estimated, &output); err != nil || !estimated || output != 5 {
					t.Fatalf("estimated=%v output=%d err=%v", estimated, output, err)
				}
			}
			{
				var balance, walletReserved, settles int64
				if err := db.QueryRow(ctx, `SELECT balance_micros,reserved_micros FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&balance, &walletReserved); err != nil {
					t.Fatal(err)
				}
				initial := initialBalance
				if balance != initial-want || walletReserved != 0 {
					t.Fatalf("wallet balance=%d reserved=%d want=%d", balance, walletReserved, initial-want)
				}
				if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_ledger_entries WHERE tenant_id=$1 AND event_type='settle'`, tenant).Scan(&settles); err != nil {
					t.Fatal(err)
				}
				if (want > 0) != (settles == 1) {
					t.Fatalf("wallet ledger settlements=%d wantAmount=%d", settles, want)
				}
			}
			statement, err := store.MonthlyStatement(ctx, tenant, time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01"))
			if err != nil {
				t.Fatal(err)
			}
			if kind == "E-stream-disconnect" && statement.Total.EstimatedRequests != 1 {
				t.Fatalf("statement estimates=%d", statement.Total.EstimatedRequests)
			}
			t.Logf("calculator=%d employee-used=%d wallet-holds=0 allowance-holds=%d unpriced=%d", want, used, reserved, holds)
		})
	}
}

func TestUnpricedPrepaidAdmissionDoesNotRequireWalletOwner(t *testing.T) {
	_, store, tenant, _, _ := billingEndToEndFixture(t)
	payload, _ := json.Marshal(map[string]any{"tenant_id": tenant, "request_id": tenant + "-unowned-unpriced", "model_name": "unpriced-model", "usage": billing.Usage{PromptTokens: 1}})
	recorder := httptest.NewRecorder()
	ReserveGatewayBilling(&Dependencies{BillingStore: store})(recorder, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/reservations", bytes.NewReader(payload)))
	var response struct {
		Unpriced bool `json:"unpriced"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || recorder.Code != 200 || !response.Unpriced {
		t.Fatalf("admission=%d %s err=%v", recorder.Code, recorder.Body.String(), err)
	}
}
