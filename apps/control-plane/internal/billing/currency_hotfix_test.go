package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 模拟现场绕过接口改币种后，同一模型旧人民币价格比美元价格更新的状态。
func TestResolveModelPricePrefersTenantCurrencyAndRetiresLegacyPrices(t *testing.T) {
	s, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	input := NewModelPrice{TenantID: tenant, ModelName: "mixed-model", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 100}, EffectiveAt: time.Now().Add(-time.Hour)}
	usd, err := s.CreateModelPrice(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO billing_model_prices(id,tenant_id,model_name,customer_group,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) SELECT $1,tenant_id,model_name,customer_group,version+1,pricing_mode,'CNY',input_per_million_micros,output_per_million_micros,'active',NOW()-INTERVAL '1 minute' FROM billing_model_prices WHERE id=$2`, tenant+"-old-cny", usd.ID); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveModelPrice(ctx, tenant, input.ModelName, "default", time.Now())
	if err != nil || resolved.Currency != "USD" {
		t.Fatalf("应优先美元价格：%+v，错误：%v", resolved, err)
	}
	if _, err = s.CreateModelPrice(ctx, input); err != nil {
		t.Fatal(err)
	}
	var status string
	var expired bool
	if err = db.QueryRow(ctx, `SELECT status,expires_at<=NOW() FROM billing_model_prices WHERE id=$1`, tenant+"-old-cny").Scan(&status, &expired); err != nil || status != PriceStatusRetired || !expired {
		t.Fatalf("旧币种价格未退役：%s %v %v", status, expired, err)
	}
}

// 赠金路径与底层 EnsureWallet 都拒绝错误币种，不再留下空钱包（旧版 EnsureWallet 会建出空 CNY 钱包）。
func TestLegacyWrongCurrencyWalletCreationAndFundingProtection(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now()); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("赠金保护：%v", err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_wallets WHERE tenant_id=$1 AND currency='CNY'`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("错误币种赠金创建了钱包：%d %v", count, err)
	}
	if w, err := s.EnsureWallet(ctx, tenant, user, "CNY"); !errors.Is(err, ErrAllowanceCurrency) || w != nil {
		t.Fatalf("底层建钱包必须拒绝错误币种：%+v %v", w, err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_wallets WHERE tenant_id=$1 AND currency='CNY'`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("底层建钱包留下了错误币种空钱包：%d %v", count, err)
	}
}

func TestAnalyticsTenantDefaultAndExplicitCurrencyAreSeparated(t *testing.T) {
	s, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	for _, currency := range []string{"USD", "CNY"} {
		amount := 100
		if currency == "CNY" {
			amount = 999
		}
		_, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_name,model_name,prompt_tokens,output_tokens,currency,status,billable_amount_micros,occurred_at) VALUES($1,$2,$3,'metering','测试','模型',1,1,$4,'settled',$5,NOW())`, tenant+currency, tenant, "currency-"+currency, currency, amount)
		if err != nil {
			t.Fatal(err)
		}
	}
	f := AnalyticsFilter{TenantID: tenant, FullTenant: true, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	got, err := s.GetAnalyticsSummary(ctx, f)
	if err != nil || got.Currency != "USD" || got.BillableMicros != 100 {
		t.Fatalf("默认币种统计：%+v %v", got, err)
	}
	if len(got.OtherCurrencies) != 1 || got.OtherCurrencies[0] != "CNY" {
		t.Fatalf("历史币种提示：%+v", got)
	}
	f.Currency = "CNY"
	got, err = s.GetAnalyticsSummary(ctx, f)
	if err != nil || got.Currency != "CNY" || got.BillableMicros != 999 {
		t.Fatalf("显式币种统计：%+v %v", got, err)
	}
	if _, err = s.GetAnalyticsBreakdown(ctx, f, "model", 10); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetAnalyticsSeries(ctx, f, "day"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetAnalyticsTimeProfile(ctx, f, "UTC", 60); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetAnalyticsDepartmentProviderMatrix(ctx, f); err != nil {
		t.Fatal(err)
	}
}

// 报价与预占之间发生币种切换，旧报价不得按新钱包币种扣费或再建旧钱包。
func TestStalePriceCannotReserveAfterCurrencySwitch(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "before-switch", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 100}})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := s.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credit(ctx, tenant, wallet.ID, "stale-price-funds", 1000, user); err != nil {
		t.Fatal(err)
	}
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ReservePriced(ctx, tenant, wallet.ID, "stale-price-request", 100, price); !errors.Is(err, ErrPriceCurrencyMismatch) {
		t.Fatalf("旧报价必须重新定价：%v", err)
	}
	var oldWallets, reserved int64
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FILTER(WHERE currency='CNY'),COALESCE(SUM(reserved_micros),0) FROM billing_wallets WHERE tenant_id=$1`, tenant).Scan(&oldWallets, &reserved); err != nil || oldWallets != 0 || reserved != 0 {
		t.Fatalf("旧报价产生资金副作用：%d %d %v", oldWallets, reserved, err)
	}
}
