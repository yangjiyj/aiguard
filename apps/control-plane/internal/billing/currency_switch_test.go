package billing

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCurrencySwitchPreviewConfirmAndMerge(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	old, err := s.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credit(ctx, tenant, old.ID, "switch-credit", 120, user); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnsureWallet(ctx, tenant, user, "USD"); err != nil {
		t.Fatal(err)
	}
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.CurrentCurrency != "CNY" || len(p.Wallets) != 2 || p.Wallets[0].Count != 1 {
		t.Fatalf("预览错误：%+v", p)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, "wrong"); !errors.Is(err, ErrCurrencySwitchChanged) {
		t.Fatalf("应拒绝过期确认：%v", err)
	}
	result, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Executed {
		t.Fatal("未执行")
	}
	var count int
	var balance int64
	var currency string
	if err = db.QueryRow(ctx, `SELECT count(*),sum(balance_micros),min(currency) FROM billing_wallets WHERE tenant_id=$1`, tenant).Scan(&count, &balance, &currency); err != nil {
		t.Fatal(err)
	}
	if count != 1 || balance != 120 || currency != "USD" {
		t.Fatalf("钱包：%d %d %s", count, balance, currency)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.currency.switch'`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("审计：%d %v", count, err)
	}
}

func TestCurrencySwitchRejectsInFlightAndAuditRollback(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	w, err := s.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credit(ctx, tenant, w.ID, "switch-funds", 100, user); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Reserve(ctx, tenant, w.ID, "switch-hold", 10); err != nil {
		t.Fatal(err)
	}
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.ReservedWallets != 1 || p.Reservations != 1 {
		t.Fatalf("预占统计：%+v", p)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); !errors.Is(err, ErrCurrencySwitchInFlight) {
		t.Fatalf("未拒绝在途：%v", err)
	}
	if _, _, err = s.Release(ctx, tenant, "switch-hold"); err != nil {
		t.Fatal(err)
	}
	p, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	// 不存在的操作者触发审计外键失败，资金及设置必须整体回滚。
	if _, err = s.SwitchCurrency(ctx, tenant, "missing-actor", "", "USD", false, p.ConfirmToken); err == nil {
		t.Fatal("应因审计失败回滚")
	}
	var currency string
	if err = db.QueryRow(ctx, `SELECT currency FROM billing_wallets WHERE id=$1`, w.ID).Scan(&currency); err != nil || currency != "CNY" {
		t.Fatalf("发生部分提交：%s %v", currency, err)
	}
}

func TestPlanCurrencyWallets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wallets   []switchWallet
		deleted   int
		conflicts int
		keep      string
	}{
		{"删除目标空钱包保留原资金", []switchWallet{{ID: "cny", User: "u", Currency: "CNY", Balance: 10}, {ID: "usd", User: "u", Currency: "USD", Deletable: true}}, 1, 0, "cny"},
		{"删除旧空钱包", []switchWallet{{ID: "cny", User: "u", Currency: "CNY", Deletable: true}, {ID: "usd", User: "u", Currency: "USD", Balance: 10}}, 1, 0, "usd"},
		{"两个有资金钱包拒绝", []switchWallet{{ID: "cny", User: "u", Currency: "CNY", Balance: 10}, {ID: "usd", User: "u", Currency: "USD", Balance: 20}}, 0, 1, ""},
		{"余额零但有流水拒绝", []switchWallet{{ID: "cny", User: "u", Currency: "CNY"}, {ID: "usd", User: "u", Currency: "USD", Balance: 20}}, 0, 1, ""},
		{"两个空钱包保留目标", []switchWallet{{ID: "cny", User: "u", Currency: "CNY", Deletable: true}, {ID: "usd", User: "u", Currency: "USD", Deletable: true}}, 1, 0, "usd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deleted, conflicts := planCurrencyWallets(tc.wallets, "USD")
			if len(deleted) != tc.deleted || len(conflicts) != tc.conflicts {
				t.Fatalf("删除=%v 冲突=%v", deleted, conflicts)
			}
			for _, id := range deleted {
				if id == tc.keep {
					t.Fatal("误删保留钱包")
				}
			}
		})
	}
}

func TestCurrencySwitchCountsRetirementAndMonthlyContinuity(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(250)
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "UTC", DefaultMonthlyMicros: &amount}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	w, err := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-time.Hour), now.Add(time.Hour)} {
		if _, err = s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: at.String(), Currency: "CNY", PricingMode: PricingModeDirect, EffectiveAt: at, DirectPrice: DirectPrice{InputPerMillionMicros: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	// 历史审计事实在切换前后保持逐字节一致。
	for _, q := range []string{`INSERT INTO billing_usage_facts(id,tenant_id,request_id,currency,occurred_at,billable_amount_micros) VALUES($2,$1,$2,'CNY',NOW(),7)`, `INSERT INTO billing_charge_records(id,tenant_id,wallet_id,request_id,model_name,pricing_mode,currency,amount_micros) VALUES($2,$1,$3,$2,'history','direct','CNY',7)`} {
		var e error
		if strings.Contains(q, "billing_charge_records") {
			_, e = db.Exec(ctx, q, tenant, tenant+"_history", w.ID)
		} else {
			_, e = db.Exec(ctx, q, tenant, tenant+"_history")
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	var beforeFacts, beforeCharges string
	if err = db.QueryRow(ctx, `SELECT to_jsonb(f)::text FROM billing_usage_facts f WHERE tenant_id=$1`, tenant).Scan(&beforeFacts); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT to_jsonb(c)::text FROM billing_charge_records c WHERE tenant_id=$1`, tenant).Scan(&beforeCharges); err != nil {
		t.Fatal(err)
	}
	provider := tenant + "_p"
	for _, q := range []string{`INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($2,$1,$2,'openai')`, `INSERT INTO billing_upstream_rates(tenant_id,provider_id,model_name,currency,price_json) VALUES($1,$2,'m','CNY','{"currency":"CNY","input_micros":1}')`, `INSERT INTO billing_channel_fixed_costs(id,tenant_id,provider_id,currency,amount_micros,effective_from) VALUES($2,$1,$2,'CNY',123,CURRENT_DATE)`} {
		if _, err = db.Exec(ctx, q, tenant, provider); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.MonthlyGrants != 1 || len(p.ActivePrices) != 1 || p.ActivePrices[0].Count != 2 || len(p.UpstreamRates) != 1 || p.UpstreamRates[0].Count != 1 || len(p.FixedCosts) != 1 || p.FixedCosts[0].Count != 1 {
		t.Fatalf("计数不准确：%+v", p)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); err != nil {
		t.Fatal(err)
	}
	w, err = s.EnsureMonthlyWalletGrant(ctx, tenant, user, "USD", now)
	if err != nil || w.BalanceMicros != Micros(amount) {
		t.Fatalf("赠金重复或丢失：%+v %v", w, err)
	}
	var afterFacts, afterCharges string
	if err = db.QueryRow(ctx, `SELECT to_jsonb(f)::text FROM billing_usage_facts f WHERE tenant_id=$1`, tenant).Scan(&afterFacts); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT to_jsonb(c)::text FROM billing_charge_records c WHERE tenant_id=$1`, tenant).Scan(&afterCharges); err != nil {
		t.Fatal(err)
	}
	if beforeFacts != afterFacts || beforeCharges != afterCharges {
		t.Fatal("历史审计事实被改写")
	}
	var retired, grants int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM billing_model_prices WHERE tenant_id=$1 AND status='retired'`, tenant).Scan(&retired); err != nil || retired != 2 {
		t.Fatalf("旧价格未退役：%d %v", retired, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM billing_wallet_monthly_grants WHERE tenant_id=$1`, tenant).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("赠金被重复发放：%d %v", grants, err)
	}
	var currency, blobCurrency string
	if err = db.QueryRow(ctx, `SELECT currency,price_json->>'currency' FROM billing_upstream_rates WHERE tenant_id=$1`, tenant).Scan(&currency, &blobCurrency); err != nil || currency != "USD" || blobCurrency != "USD" {
		t.Fatalf("上游费率未同步：%s %s %v", currency, blobCurrency, err)
	}
}

func TestCurrencySwitchDetectsBalanceChangesAndConflicts(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	w, err := s.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credit(ctx, tenant, w.ID, "balance-change", 100, user); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); !errors.Is(err, ErrCurrencySwitchChanged) {
		t.Fatalf("余额变化未触发重新预览：%v", err)
	}
	other, err := s.EnsureWallet(ctx, tenant, user, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credit(ctx, tenant, other.ID, "conflicting-balance", 200, user); err != nil {
		t.Fatal(err)
	}
	p, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ConflictUsers) != 1 || p.ConflictUsers[0] != user {
		t.Fatalf("缺少冲突用户：%+v", p)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); !errors.Is(err, ErrCurrencySwitchConflict) {
		t.Fatalf("未拒绝冲突：%v", err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO billing_employee_reservations(tenant_id,request_id,user_id,month_start,month_end,amount_micros,currency) VALUES($1,'employee-hold',$2,now(),now()+interval '1 day',1,'CNY')`, tenant, user); err != nil {
		t.Fatal(err)
	}
	p, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Reservations != 1 {
		t.Fatalf("员工预占计数：%+v", p)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); !errors.Is(err, ErrCurrencySwitchInFlight) {
		t.Fatalf("未拒绝员工在途预占：%v", err)
	}
}
