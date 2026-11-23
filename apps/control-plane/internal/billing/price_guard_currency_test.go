package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 同一模型同时有 CNY 与 USD 有效价格时，写入防护比较的必须是计费实际使用的那一行：
// 租户明确设置了 USD，计费取 USD 行，防护也只能拿 USD 行比较（CNY 行更新也不能抢先）。
func TestSaveModelPriceGuardComparesTenantCurrencyRowWhenPricesAreMixed(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	usd := pgSeed(t, store, tenantID, "mixed-model", pgFull())
	// 模拟现场遗留：USD 之后又出现了一条生效时间更晚的 CNY 行（直接写库，绕过写入校验）。
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_model_prices (id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
			input_per_million_micros, output_per_million_micros, status, effective_at)
		VALUES ('price_mixed_cny_'||$1, $1, 'mixed-model', 'default', 99, 'direct', 'CNY', 1, 1, 'active', NOW() - INTERVAL '1 minute')`,
		tenantID); err != nil {
		t.Fatalf("seed CNY row: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_employee_settings (tenant_id, currency) VALUES ($1, 'USD')
		ON CONFLICT (tenant_id) DO UPDATE SET currency = 'USD'`, tenantID); err != nil {
		t.Fatalf("set tenant currency: %v", err)
	}

	resolved, err := store.ResolveModelPrice(ctx, tenantID, "mixed-model", DefaultCustomerGroup, time.Now().UTC())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.ID != usd.ID || resolved.Currency != "USD" {
		t.Fatalf("billing must use the tenant-currency row, got %s %s", resolved.ID, resolved.Currency)
	}

	// 与 USD 行逐字段相同：防护必须判为「无变化」，不新增版本。
	result, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "mixed-model", pgFull()), SavePriceOptions{})
	if err != nil {
		t.Fatalf("identical save: %v", err)
	}
	if !result.Unchanged || result.Price == nil || result.Price.ID != usd.ID {
		t.Fatalf("guard must compare against the USD row billing uses: %#v", result)
	}

	// 把 USD 价改成 0：防护比较的是 USD 行（非零），必须要求确认。
	_, err = store.SaveModelPrice(ctx, pgSubmit(tenantID, "mixed-model", DirectPrice{}), SavePriceOptions{})
	var zeroErr *ZeroPriceError
	if !errors.As(err, &zeroErr) {
		t.Fatalf("zeroing the USD row must require confirmation, got %v", err)
	}

	// 生效价列表与计费口径一致：每个模型+客户组只返回计费会用的那一行。
	effective, err := store.ListEffectiveModelPricesForModel(ctx, tenantID, "mixed-model", 10)
	if err != nil {
		t.Fatalf("list effective: %v", err)
	}
	if len(effective) != 1 || effective[0].ID != usd.ID {
		t.Fatalf("effective list must show the billed USD row, got %#v", effective)
	}
}
