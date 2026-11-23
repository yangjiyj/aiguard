package billing

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// 现场出现过「29 个 USD 钱包旁边多出 2 个空 CNY 钱包」：任何入口都不应在租户已明确币种后，
// 再创建另一种币种的钱包。本组测试覆盖全部创建入口。

// legacyWalletForTest 绕过 EnsureWallet 的币种守卫，直接造出「现场遗留」的钱包行，
// 用来验证保护逻辑对已存在的外币钱包仍然有效。
func legacyWalletForTest(t *testing.T, s *Store, tenant, user, currency string) *Wallet {
	t.Helper()
	id := "wallet_legacy_" + currency + "_" + user
	if _, err := s.db.Exec(context.Background(), `INSERT INTO billing_wallets(id,tenant_id,user_id,currency) VALUES($1,$2,$3,$4)`, id, tenant, user, currency); err != nil {
		t.Fatalf("造遗留钱包：%v", err)
	}
	w, err := s.GetWallet(context.Background(), tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func addGuardUser(t *testing.T, s *Store, tenant, name string) string {
	t.Helper()
	id := fmt.Sprintf("%s_%s", tenant, name)
	if _, err := s.db.Exec(context.Background(), `INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES ($1,$2,$1,$3,'x','developer','active')`, id, tenant, id+"@test.invalid"); err != nil {
		t.Fatalf("添加测试用户：%v", err)
	}
	return id
}

func walletCurrencies(t *testing.T, s *Store, tenant string) map[string]int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT currency,count(*) FROM billing_wallets WHERE tenant_id=$1 GROUP BY currency`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var c string
		var n int
		if err = rows.Scan(&c, &n); err != nil {
			t.Fatal(err)
		}
		out[c] = n
	}
	return out
}

// 底层 EnsureWallet 以前对任意币种都直接建钱包；租户已明确 USD 后必须拒绝 CNY，且不留下空钱包。
func TestEnsureWalletRejectsCurrencyDifferentFromExplicitTenantCurrency(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	if w, err := s.EnsureWallet(ctx, tenant, user, "CNY"); !errors.Is(err, ErrAllowanceCurrency) || w != nil {
		t.Fatalf("租户已是 USD，建 CNY 钱包必须被拒绝：%+v %v", w, err)
	}
	if got := walletCurrencies(t, s, tenant); got["CNY"] != 0 {
		t.Fatalf("被拒绝后不应留下 CNY 钱包：%v", got)
	}
	w, err := s.EnsureWallet(ctx, tenant, user, "USD")
	if err != nil || w.Currency != "USD" {
		t.Fatalf("租户币种钱包必须仍可创建：%+v %v", w, err)
	}
}

// 没有任何币种设置的老租户保持原行为（避免影响尚未配置币种的环境与既有夹具）。
func TestEnsureWalletKeepsLegacyBehaviourWithoutExplicitCurrency(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	if w, err := s.EnsureWallet(context.Background(), tenant, user, "CNY"); err != nil || w.Currency != "CNY" {
		t.Fatalf("无显式币种设置时不应拦截：%+v %v", w, err)
	}
}

// 月度赠金后台任务、首次使用、兑换码、管理员充值：USD 租户下只会出现 USD 钱包。
func TestAllWalletCreationEntriesUseTenantCurrency(t *testing.T) {
	s, db, tenant, firstUser := setupBillingStoreTest(t)
	ctx := context.Background()
	amount := int64(500)
	if err := s.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC", DefaultMonthlyMicros: &amount}); err != nil {
		t.Fatal(err)
	}
	workerUser := addGuardUser(t, s, tenant, "worker")
	redeemUser := addGuardUser(t, s, tenant, "redeem")
	creditUser := addGuardUser(t, s, tenant, "credit")
	useUser := addGuardUser(t, s, tenant, "firstuse")
	// 其它用户不应被月度任务以外的入口提前建钱包；先关闭月额度，避免它们被后台任务顺带创建。
	for _, u := range []string{redeemUser, creditUser, useUser, firstUser} {
		zero := int64(0)
		if _, err := db.Exec(ctx, `INSERT INTO billing_employee_allowances(tenant_id,user_id,monthly_micros) VALUES($1,$2,$3) ON CONFLICT (tenant_id,user_id) DO UPDATE SET monthly_micros=EXCLUDED.monthly_micros`, tenant, u, zero); err != nil {
			t.Fatal(err)
		}
	}

	// 1. 月度赠金后台任务（与 worker 同一事务路径）。
	at := time.Now().UTC()
	for i := 0; i < 20; i++ {
		if _, err := s.GrantMonthlyWallets(ctx, at, 500); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2`, tenant, workerUser).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
	}

	// 2. 员工首次使用（网关准入）：按租户币种建；按错误币种则拒绝且不建。
	if err := s.ReserveEmployeeAllowance(ctx, tenant, useUser, tenant+"-r1", "CNY", 1, at); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("错误币种的首次使用必须被拒绝：%v", err)
	}
	if err := s.ReserveEmployeeAllowance(ctx, tenant, useUser, tenant+"-r2", "USD", 1, at); err != nil && !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("租户币种首次使用：%v", err)
	}

	// 3. 兑换码。
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "guard", AmountMicros: 200, Count: 1, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if w, _, err := s.RedeemCode(ctx, tenant, redeemUser, codes[0].Code); err != nil || w.Currency != "USD" {
		t.Fatalf("兑换码钱包币种：%+v %v", w, err)
	}

	// 4. 管理员充值。
	if w, err := s.CreditUserWallet(ctx, tenant, creditUser, tenant+"-credit", 300, "admin"); err != nil || w.Currency != "USD" {
		t.Fatalf("充值钱包币种：%+v %v", w, err)
	}

	got := walletCurrencies(t, s, tenant)
	if got["CNY"] != 0 || got["USD"] < 3 {
		t.Fatalf("USD 租户下只应出现 USD 钱包：%v", got)
	}
}
