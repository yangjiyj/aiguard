package billing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// 本文件覆盖币种切换的审查整改项：未定价清单与确认、遗留孤儿价格、稳定指纹、锁超时、
// 同事务审计链、历史混币种租户取价。

func seedPrice(t *testing.T, s *Store, tenant, model, currency string, version int, effective time.Time) {
	t.Helper()
	if err := s.EnsureDefaultCustomerGroup(context.Background(), tenant); err != nil {
		t.Fatalf("默认客户组：%v", err)
	}
	id := fmt.Sprintf("price_%s_%s_%s_%d", tenant, model, currency, version)
	if _, err := s.db.Exec(context.Background(), `INSERT INTO billing_model_prices(id,tenant_id,model_name,customer_group,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) VALUES($1,$2,$3,'default',$4,'direct',$5,100,200,'active',$6)`, id, tenant, model, version, currency, effective); err != nil {
		t.Fatalf("造价格：%v", err)
	}
}

// seedModel 造出「模型 + 供应商」：providerStatus=deleted 且 modelStatus=inactive 代表被删除供应商留下的模型。
func seedModel(t *testing.T, s *Store, tenant, model, providerStatus, modelStatus string) {
	t.Helper()
	provider := fmt.Sprintf("prov_%s_%s", tenant, model)
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type,status) VALUES($1,$2,$1,'openai',$3)`, provider, tenant, providerStatus); err != nil {
		t.Fatalf("造供应商：%v", err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,$3,$4)`, "model_"+provider, provider, model, modelStatus); err != nil {
		t.Fatalf("造模型：%v", err)
	}
}

func setUSDTenant(t *testing.T, s *Store, tenant string) {
	t.Helper()
	if err := s.SaveEmployeeSettings(context.Background(), tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
}

// 切换到 USD 后，正在使用的模型如果只有 CNY 价格，就会变成未定价：预览必须列出，后端必须要求显式确认。
func TestCurrencySwitchListsUnpricedLiveModelsAndRequiresConfirmation(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour)
	seedModel(t, s, tenant, "live-cny-only", "active", "active")
	seedPrice(t, s, tenant, "live-cny-only", "CNY", 1, now)
	seedModel(t, s, tenant, "live-both", "active", "active")
	seedPrice(t, s, tenant, "live-both", "CNY", 1, now)
	seedPrice(t, s, tenant, "live-both", "USD", 2, now)

	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.UnpricedModels) != 1 || p.UnpricedModels[0].ModelName != "live-cny-only" || p.UnpricedModels[0].CustomerGroup != "default" || strings.Join(p.UnpricedModels[0].Currencies, ",") != "CNY" {
		t.Fatalf("应只列出没有目标币种价格的在用模型：%+v", p.UnpricedModels)
	}
	if p.LegacyOrphanPrices.Pairs != 0 {
		t.Fatalf("在用模型不应算孤儿：%+v", p.LegacyOrphanPrices)
	}
	// 没有确认标志：拒绝，什么都不改。
	result, err := s.SwitchCurrencyWithOptions(ctx, CurrencySwitchRequest{Tenant: tenant, Actor: user, Target: "USD", ConfirmToken: p.ConfirmToken})
	if !errors.Is(err, ErrCurrencySwitchUnpriced) {
		t.Fatalf("未确认应被拒绝：%v", err)
	}
	if result == nil || len(result.UnpricedModels) != 1 {
		t.Fatalf("拒绝时应带回清单：%+v", result)
	}
	var active int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM billing_model_prices WHERE tenant_id=$1 AND status='active'`, tenant).Scan(&active); err != nil || active != 3 {
		t.Fatalf("拒绝后价格不应变化：%d %v", active, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM billing_employee_settings WHERE tenant_id=$1 AND currency='USD'`, tenant).Scan(&active); err != nil || active != 0 {
		t.Fatalf("拒绝后币种不应变化：%d %v", active, err)
	}
	// 带确认标志：执行，CNY 价格全部作废，两种清单项都在审计里留痕。
	executed, err := s.SwitchCurrencyWithOptions(ctx, CurrencySwitchRequest{Tenant: tenant, Actor: user, Target: "USD", ConfirmToken: p.ConfirmToken, ConfirmUnpriced: true})
	if err != nil || !executed.Executed {
		t.Fatalf("确认后应执行：%+v %v", executed, err)
	}
	var detail string
	if err = db.QueryRow(ctx, `SELECT action_detail::text FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.currency.switch'`, tenant).Scan(&detail); err != nil || !strings.Contains(detail, `"confirmed_unpriced": true`) && !strings.Contains(detail, `"confirmed_unpriced":true`) {
		t.Fatalf("审计应记录已确认未定价：%s %v", detail, err)
	}
	if _, err = s.ResolveModelPrice(ctx, tenant, "live-cny-only", "default", time.Now()); !errors.Is(err, ErrPriceNotFound) {
		t.Fatalf("切换后该模型应为未定价：%v", err)
	}
	if got, err := s.ResolveModelPrice(ctx, tenant, "live-both", "default", time.Now()); err != nil || got.Currency != "USD" {
		t.Fatalf("有目标币种价格的模型继续可计费：%+v %v", got, err)
	}
}

// 孤儿价格：模型已停用/已删除、或所属供应商已删除。只计条数，不阻止执行，切换时照常作废。
func TestCurrencySwitchLegacyOrphanPricesDoNotBlock(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	// 已删除供应商 + inactive 模型（现场情形），glm 有 3 个版本。
	seedModel(t, s, tenant, "glm-orphan", "deleted", "inactive")
	for v := 1; v <= 3; v++ {
		seedPrice(t, s, tenant, "glm-orphan", "CNY", v, old.Add(time.Duration(v)*time.Minute))
	}
	// 供应商未删但模型停用。
	seedModel(t, s, tenant, "inactive-model", "active", "inactive")
	seedPrice(t, s, tenant, "inactive-model", "CNY", 1, old)
	// models 表里根本没有这个名字。
	seedPrice(t, s, tenant, "never-created", "CNY", 1, old)

	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.UnpricedModels) != 0 {
		t.Fatalf("孤儿价格不应进入需确认清单：%+v", p.UnpricedModels)
	}
	if p.LegacyOrphanPrices.Pairs != 3 || p.LegacyOrphanPrices.Rows != 5 {
		t.Fatalf("孤儿应为 3 个模型/客户组、5 行价格：%+v", p.LegacyOrphanPrices)
	}
	result, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken)
	if err != nil || !result.Executed {
		t.Fatalf("孤儿价格不应阻止执行：%+v %v", result, err)
	}
	var retired int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM billing_model_prices WHERE tenant_id=$1 AND status='retired' AND currency='CNY'`, tenant).Scan(&retired); err != nil || retired != 5 {
		t.Fatalf("孤儿价格应照常作废：%d %v", retired, err)
	}
}

// 同一模型的价格分属不同供应商状态时，只要有任一未删除供应商下的在用模型，就必须按「在用」处理。
func TestCurrencySwitchSameNameLiveElsewhereCountsAsLive(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	seedModel(t, s, tenant, "shared-name", "deleted", "inactive")
	if _, err := s.db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type,status) VALUES($1,$2,$1,'openai','active')`, "prov2_"+tenant, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,'shared-name','active')`, "model2_"+tenant, "prov2_"+tenant); err != nil {
		t.Fatal(err)
	}
	seedPrice(t, s, tenant, "shared-name", "CNY", 1, time.Now().Add(-time.Hour))
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.UnpricedModels) != 1 || p.LegacyOrphanPrices.Pairs != 0 {
		t.Fatalf("同名模型在别的未删供应商下仍在用，不能当孤儿：%+v %+v", p.UnpricedModels, p.LegacyOrphanPrices)
	}
}

// 别的租户的模型/供应商不应影响本租户的孤儿判定。
func TestCurrencySwitchUnpricedClassificationIsTenantScoped(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	other, otherUser := tenant+"_o", tenant+"_ou"
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status,is_test) VALUES ($1, $1, 'enterprise', 'active',TRUE)`, other); err != nil {
		t.Fatal(err)
	}
	_ = otherUser
	seedModel(t, s, other, "cross-tenant", "active", "active")
	seedPrice(t, s, tenant, "cross-tenant", "CNY", 1, time.Now().Add(-time.Hour))
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.UnpricedModels) != 0 || p.LegacyOrphanPrices.Pairs != 1 {
		t.Fatalf("别的租户的在用模型不应让本租户的价格变成在用：%+v %+v", p.UnpricedModels, p.LegacyOrphanPrices)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `UPDATE tenants SET status='disabled' WHERE id=$1`, other)
	})
}

// 指纹不能因为与切换无关的写入（比如普通充值产生的流水、钱包 updated_at）而失效，
// 但余额变化仍必须使令牌失效。
func TestCurrencySwitchTokenIgnoresVolatileFieldsButTracksBalances(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	w, err := s.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credit(ctx, tenant, w.ID, "token-credit", 100, user); err != nil {
		t.Fatal(err)
	}
	first, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	// 只改 updated_at / version，业务量不变。
	if _, err = db.Exec(ctx, `UPDATE billing_wallets SET updated_at=NOW()+INTERVAL '1 second',version=version+1 WHERE id=$1`, w.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfirmToken != second.ConfirmToken {
		t.Fatal("updated_at/version 变化不应改变确认令牌")
	}
	// 一笔余额净变化为 0 的“入账再出账”会新增流水和 updated_at，但余额合计不变：令牌应保持不变。
	if _, err = s.Credit(ctx, tenant, w.ID, "token-credit-2", 50, user); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE billing_wallets SET balance_micros=balance_micros-50 WHERE id=$1`, w.ID); err != nil {
		t.Fatal(err)
	}
	third, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfirmToken != third.ConfirmToken {
		t.Fatal("流水行变化而余额合计不变时，令牌不应变化")
	}
	// 余额真正变化：必须失效。
	if _, err = s.Credit(ctx, tenant, w.ID, "token-credit-3", 7, user); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, first.ConfirmToken); !errors.Is(err, ErrCurrencySwitchChanged) {
		t.Fatalf("余额变化必须使令牌失效：%v", err)
	}
}

// 价格集合变化（新增/作废一条生效价格）必须使令牌失效。
func TestCurrencySwitchTokenTracksPriceSet(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	seedPrice(t, s, tenant, "tracked", "CNY", 1, time.Now().Add(-time.Hour))
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	seedPrice(t, s, tenant, "tracked-2", "CNY", 1, time.Now().Add(-time.Hour))
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); !errors.Is(err, ErrCurrencySwitchChanged) {
		t.Fatalf("价格集合变化必须使令牌失效：%v", err)
	}
}

// 表被别的事务占着写锁时：等锁最多 lock_timeout，超时整体回滚，返回「计费表正忙」。
func TestCurrencySwitchLockTimeoutReturnsBusyAndChangesNothing(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	if _, err := s.EnsureWallet(ctx, tenant, user, "CNY"); err != nil {
		t.Fatal(err)
	}
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	oldLock := currencySwitchLockTimeout
	currencySwitchLockTimeout = "300ms"
	t.Cleanup(func() { currencySwitchLockTimeout = oldLock })
	// 另一个事务持有 billing_wallets 的行排他锁（模拟在途的钱包写入），与 SHARE ROW EXCLUSIVE 冲突。
	holder, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	if _, err = holder.Exec(ctx, `UPDATE billing_wallets SET updated_at=updated_at WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken)
	if !errors.Is(err, ErrCurrencySwitchBusy) {
		t.Fatalf("等锁超时应返回繁忙错误：%v", err)
	}
	if err.Error() != "计费表正忙，请在停流量窗口重试" {
		t.Fatalf("文案不符：%q", err.Error())
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("应在 lock_timeout 内放弃，实际 %v", elapsed)
	}
	_ = holder.Rollback(ctx)
	var currency string
	if err = db.QueryRow(ctx, `SELECT currency FROM billing_wallets WHERE tenant_id=$1`, tenant).Scan(&currency); err != nil || currency != "CNY" {
		t.Fatalf("超时后不应有任何改动：%s %v", currency, err)
	}
	// 释放后同一令牌仍可执行（超时不消耗令牌）。
	if result, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); err != nil || !result.Executed {
		t.Fatalf("释放后应能执行：%+v %v", result, err)
	}
}

// 预览是只读快照，不受写锁影响，也不设置会误伤预览的上限之外的行为。
func TestCurrencySwitchPreviewIsNotBlockedByWriters(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	if _, err := s.EnsureWallet(ctx, tenant, user, "CNY"); err != nil {
		t.Fatal(err)
	}
	holder, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	if _, err = holder.Exec(ctx, `UPDATE billing_wallets SET updated_at=updated_at WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", true, ""); err != nil {
		t.Fatalf("预览不应被写入阻塞：%v", err)
	}
}

// recordingChain 记录事务内审计链调用，并可注入失败。
type recordingChain struct {
	calls   atomic.Int32
	fail    error
	payload map[string]any
	typ     string
}

func (c *recordingChain) AppendTx(_ context.Context, _ pgx.Tx, _, eventType, _ string, payload map[string]any) error {
	c.calls.Add(1)
	c.typ, c.payload = eventType, payload
	return c.fail
}

// 审计链写入失败时，币种切换整体回滚：币种、钱包、价格都不变，audit_operations 也不留痕。
func TestCurrencySwitchRollsBackWhenAuditChainFails(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	w, err := s.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	seedPrice(t, s, tenant, "chain-model", "CNY", 1, time.Now().Add(-time.Hour))
	seedPrice(t, s, tenant, "chain-model", "USD", 2, time.Now().Add(-time.Hour))
	p, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", true, "")
	if err != nil {
		t.Fatal(err)
	}
	chain := &recordingChain{fail: errors.New("audit chain unavailable")}
	s.SetAuditChain(chain)
	if _, err = s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); err == nil || chain.calls.Load() != 1 {
		t.Fatalf("审计链失败应使切换失败：calls=%d err=%v", chain.calls.Load(), err)
	}
	var currency string
	var audits, retired int
	if err = db.QueryRow(ctx, `SELECT currency FROM billing_wallets WHERE id=$1`, w.ID).Scan(&currency); err != nil || currency != "CNY" {
		t.Fatalf("钱包不应被改标：%s %v", currency, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.currency.switch'`, tenant).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("回滚后不应留下审计：%d %v", audits, err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM billing_model_prices WHERE tenant_id=$1 AND status='retired'`, tenant).Scan(&retired); err != nil || retired != 0 {
		t.Fatalf("回滚后价格不应作废：%d %v", retired, err)
	}
	// 审计链恢复后成功，且记录里带有关键字段。
	chain.fail = nil
	if result, err := s.SwitchCurrency(ctx, tenant, user, "", "USD", false, p.ConfirmToken); err != nil || !result.Executed {
		t.Fatalf("恢复后应成功：%+v %v", result, err)
	}
	if chain.typ != "audit_op" || chain.payload["action_type"] != "billing.currency.switch" || chain.payload["currency"] != "USD" || chain.payload["previous_currency"] != "CNY" {
		t.Fatalf("审计链载荷：%s %+v", chain.typ, chain.payload)
	}
	if !s.AuditChainInTx() {
		t.Fatal("接入后应报告审计链在事务内")
	}
}

// 写入系统币种价格会作废其他币种价格：审计链同事务，失败则价格也不写入。
func TestRetireOtherCurrenciesAuditChainIsInSameTransaction(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	setUSDTenant(t, s, tenant)
	seedPrice(t, s, tenant, "retire-me", "CNY", 1, time.Now().Add(-time.Hour))
	chain := &recordingChain{fail: errors.New("audit chain unavailable")}
	s.SetAuditChain(chain)
	in := NewModelPrice{TenantID: tenant, ModelName: "retire-me", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 5}, EffectiveAt: time.Now().Add(-time.Minute), CreatedBy: user}
	if _, err := s.CreateModelPrice(ctx, in); err == nil || chain.calls.Load() != 1 {
		t.Fatalf("审计链失败应使价格写入失败：calls=%d err=%v", chain.calls.Load(), err)
	}
	var usd, activeCNY, audits int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM billing_model_prices WHERE tenant_id=$1 AND model_name='retire-me' AND currency='USD'`, tenant).Scan(&usd)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM billing_model_prices WHERE tenant_id=$1 AND model_name='retire-me' AND currency='CNY' AND status='active'`, tenant).Scan(&activeCNY)
	_ = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.price.retire_other_currencies'`, tenant).Scan(&audits)
	if usd != 0 || activeCNY != 1 || audits != 0 {
		t.Fatalf("回滚不完整：usd=%d activeCNY=%d audits=%d", usd, activeCNY, audits)
	}
	chain.fail = nil
	if _, err := s.CreateModelPrice(ctx, in); err != nil {
		t.Fatal(err)
	}
	if chain.payload["action_type"] != "billing.price.retire_other_currencies" || chain.payload["model_name"] != "retire-me" {
		t.Fatalf("审计链载荷：%+v", chain.payload)
	}
	_ = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.price.retire_other_currencies'`, tenant).Scan(&audits)
	if audits != 1 {
		t.Fatalf("成功后应有一条审计：%d", audits)
	}
}

// 历史上混用多种币种、又没有币种设置的租户：取价沿用 711 的「最近生效、版本最高」，不报 ErrMixedCurrency，
// 不因此整租户计费失败。
func TestResolveModelPriceMixedHistoricalTenantFallsBackWithoutError(t *testing.T) {
	s, _, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now()
	seedPrice(t, s, tenant, "model-a", "CNY", 1, now.Add(-3*time.Hour))
	seedPrice(t, s, tenant, "model-b", "USD", 1, now.Add(-2*time.Hour))
	// 推断币种确实是混用状态：
	if _, err := s.BillingCurrencyForTenant(ctx, tenant); !errors.Is(err, ErrMixedCurrency) {
		t.Fatalf("前提不成立，应推断为混用：%v", err)
	}
	for model, want := range map[string]string{"model-a": "CNY", "model-b": "USD"} {
		got, err := s.ResolveModelPrice(ctx, tenant, model, "default", now)
		if err != nil {
			t.Fatalf("%s 混用历史租户取价不应报错：%v", model, err)
		}
		if got.Currency != want {
			t.Fatalf("%s 应取自己的价格(%s)：%+v", model, want, got)
		}
	}
	// 同一模型两种币种：沿用 711，取最近生效的那条，不看币种。
	seedPrice(t, s, tenant, "model-c", "CNY", 1, now.Add(-5*time.Hour))
	seedPrice(t, s, tenant, "model-c", "USD", 2, now.Add(-1*time.Hour))
	got, err := s.ResolveModelPrice(ctx, tenant, "model-c", "default", now)
	if err != nil || got.Currency != "USD" || got.Version != 2 {
		t.Fatalf("711 取价顺序（最近生效、版本最高）：%+v %v", got, err)
	}
}

// 有币种设置时仍优先系统币种（33566 的行为不变）。
func TestResolveModelPriceStillPrefersExplicitTenantCurrency(t *testing.T) {
	s, _, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	setUSDTenant(t, s, tenant)
	now := time.Now()
	seedPrice(t, s, tenant, "pref", "USD", 1, now.Add(-3*time.Hour))
	seedPrice(t, s, tenant, "pref", "CNY", 2, now.Add(-1*time.Hour))
	got, err := s.ResolveModelPrice(ctx, tenant, "pref", "default", now)
	if err != nil || got.Currency != "USD" {
		t.Fatalf("有明确币种时应优先系统币种：%+v %v", got, err)
	}
}

// 历史混币种租户的计量记账（metering 模式的结算入口）不能整体失败：按各模型自己的价格结算，
// 不因为推断不出系统币种而返回 ErrMixedCurrency。
func TestMeteringForMixedHistoricalTenantStillRecordsFacts(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now()
	seedPrice(t, s, tenant, "mx-a", "CNY", 1, now.Add(-3*time.Hour))
	seedPrice(t, s, tenant, "mx-b", "USD", 1, now.Add(-2*time.Hour))
	if _, err := s.BillingCurrencyForTenant(ctx, tenant); !errors.Is(err, ErrMixedCurrency) {
		t.Fatalf("前提不成立，应推断为混用：%v", err)
	}
	for i, model := range []string{"mx-a", "mx-b"} {
		fact, err := s.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: fmt.Sprintf("%s-mx-%d", tenant, i), ModelName: model, RequestStatus: "success", Usage: Usage{PromptTokens: 1000, OutputTokens: 1000}, AdmittedAt: now})
		if err != nil {
			t.Fatalf("%s 混用历史租户计量不应失败：%v", model, err)
		}
		if fact == nil {
			t.Fatalf("%s 应记录事实", model)
		}
	}
}
