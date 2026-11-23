package billing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrCurrencySwitchChanged  = errors.New("币种切换预览已变化，请重新预览")
	ErrCurrencySwitchInFlight = errors.New("仍有在途预占，请等待请求结算后再切换币种")
	ErrCurrencySwitchConflict = errors.New("同一用户存在无法安全合并的钱包")
	// ErrCurrencySwitchUnpriced：切换后有「正在使用的模型」会失去价格（目标币种没有对应价格），
	// 必须由管理员在预览里看过清单并显式确认，后端才会执行。
	ErrCurrencySwitchUnpriced = errors.New("切换后有模型将变为未定价，请确认清单后再执行")
	// ErrCurrencySwitchBusy：取不到计费表锁，或语句超过上限。整个事务已回滚，什么都没改。
	ErrCurrencySwitchBusy = errors.New("计费表正忙，请在停流量窗口重试")
)

// 切换事务的等待上限。LOCK TABLE ... SHARE ROW EXCLUSIVE 会等所有在途写入结束，
// 不设上限就可能在业务高峰把计费写入整体堵住；超时即放弃并回滚，由运维在停流量窗口重试。
// 做成变量只为让测试能用更短的时间复现超时。
var (
	currencySwitchLockTimeout      = "5s"
	currencySwitchStatementTimeout = "60s"
)

type CurrencyCount struct {
	Currency         string `json:"currency"`
	Count            int64  `json:"count"`
	ZeroBalanceCount int64  `json:"zero_balance_count"`
}

// SwitchUnpricedModel 是切换后会失去价格的「模型 + 客户组」。Currencies 为它现有的、将被作废的价格币种。
type SwitchUnpricedModel struct {
	ModelName     string   `json:"model_name"`
	CustomerGroup string   `json:"customer_group"`
	Currencies    []string `json:"currencies"`
}

// LegacyOrphanPrices 统计「已删除模型的遗留价格」：模型不存在、已停用，或所属供应商已删除。
// 这类价格网关不会再用到，作废它们对计费没有影响，所以只报条数，不阻止执行。
type LegacyOrphanPrices struct {
	Pairs int64 `json:"pairs"`
	Rows  int64 `json:"rows"`
}

type CurrencySwitchPreview struct {
	AuditID            string                `json:"-"`
	CurrentCurrency    string                `json:"current_currency"`
	Currency           string                `json:"currency"`
	ConfirmToken       string                `json:"confirm_token"`
	Wallets            []CurrencyCount       `json:"wallets"`
	ActivePrices       []CurrencyCount       `json:"active_prices"`
	UpstreamRates      []CurrencyCount       `json:"upstream_rates"`
	FixedCosts         []CurrencyCount       `json:"fixed_costs"`
	Reservations       int64                 `json:"reservations"`
	ReservedWallets    int64                 `json:"reserved_wallets"`
	MonthlyGrants      int64                 `json:"monthly_grants"`
	ConflictUsers      []string              `json:"conflict_users"`
	UnpricedModels     []SwitchUnpricedModel `json:"unpriced_models"`
	LegacyOrphanPrices LegacyOrphanPrices    `json:"legacy_orphan_prices"`
	Executed           bool                  `json:"executed"`
}

// CurrencySwitchRequest 是切换（含预览）的全部入参。
type CurrencySwitchRequest struct {
	Tenant, Actor, IP, Target string
	Preview                   bool
	ConfirmToken              string
	// ConfirmUnpriced 表示管理员已看过「将变为未定价」清单并确认。清单为空时无意义。
	ConfirmUnpriced bool
}

type switchWallet struct {
	ID, User, Currency string
	Balance, Reserved  int64
	Deletable          bool
}

// planCurrencyWallets 只丢弃无余额、无预占、无资金或业务引用的空钱包。
func planCurrencyWallets(wallets []switchWallet, target string) ([]string, []string) {
	groups := map[string][]switchWallet{}
	for _, w := range wallets {
		groups[w.User] = append(groups[w.User], w)
	}
	deleted, conflicts := []string{}, []string{}
	for user, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			if group[i].Deletable != group[j].Deletable {
				return !group[i].Deletable
			}
			if (group[i].Currency == target) != (group[j].Currency == target) {
				return group[i].Currency == target
			}
			return group[i].ID < group[j].ID
		})
		for _, w := range group[1:] {
			if !w.Deletable {
				conflicts = append(conflicts, user)
				break
			}
			deleted = append(deleted, w.ID)
		}
	}
	sort.Strings(deleted)
	sort.Strings(conflicts)
	return deleted, conflicts
}

// currencySwitchUnpriced 找出切换后会失去价格的「模型 + 客户组」并分成两类：
//   - 正在使用：模型存在、status=active、所属供应商不是 deleted。这类会让请求变成未定价，需要管理员确认。
//   - 遗留孤儿：其余（模型已删除/停用、供应商已删除、或 models 里根本没有）。只统计条数。
//
// 「失去价格」指：现在有生效中的非目标币种价格，且没有生效中的目标币种价格。
// 价格按租户 + model_name 存放，models 没有租户列，只能经 providers.tenant_id 关联。
func currencySwitchUnpriced(ctx context.Context, tx pgx.Tx, tenant, target string) ([]SwitchUnpricedModel, LegacyOrphanPrices, error) {
	rows, err := tx.Query(ctx, `
WITH effective AS (
  SELECT model_name, customer_group,
         bool_or(currency=$2) AS has_target,
         COALESCE(array_agg(DISTINCT currency ORDER BY currency) FILTER (WHERE currency<>$2), ARRAY[]::varchar[]) AS others
  FROM billing_model_prices
  WHERE tenant_id=$1 AND status='active' AND effective_at<=NOW() AND (expires_at IS NULL OR expires_at>NOW())
  GROUP BY model_name, customer_group
), lost AS (
  SELECT model_name, customer_group, others FROM effective WHERE NOT has_target AND cardinality(others)>0
)
SELECT l.model_name, l.customer_group, l.others::text[],
       (SELECT count(*) FROM billing_model_prices x
         WHERE x.tenant_id=$1 AND x.model_name=l.model_name AND x.customer_group=l.customer_group
           AND x.status='active' AND x.currency<>$2) AS retire_rows,
       EXISTS(SELECT 1 FROM models m JOIN providers p ON p.id=m.provider_id
               WHERE p.tenant_id=$1 AND p.status<>'deleted' AND m.status='active' AND m.model_name=l.model_name) AS live
FROM lost l
ORDER BY l.model_name, l.customer_group`, tenant, target)
	if err != nil {
		return nil, LegacyOrphanPrices{}, err
	}
	defer rows.Close()
	unpriced := []SwitchUnpricedModel{}
	var legacy LegacyOrphanPrices
	for rows.Next() {
		var m SwitchUnpricedModel
		var retireRows int64
		var live bool
		if err = rows.Scan(&m.ModelName, &m.CustomerGroup, &m.Currencies, &retireRows, &live); err != nil {
			return nil, LegacyOrphanPrices{}, err
		}
		if live {
			unpriced = append(unpriced, m)
			continue
		}
		legacy.Pairs++
		legacy.Rows += retireRows
	}
	if err = rows.Err(); err != nil {
		return nil, LegacyOrphanPrices{}, err
	}
	return unpriced, legacy, nil
}

// currencySwitchFingerprint 生成确认令牌：只绑定「切换会改动、或会改变管理员决定」的业务事实，
// 刻意不含 updated_at、version、流水行等会随任何普通请求自行变化的字段：
//   - 预览本身（各类计数、在途预占、冲突用户、未定价清单、遗留价格条数）；
//   - 按币种汇总的钱包数、余额合计、预占合计、可丢弃空钱包数（余额或预占变化必须重新预览）；
//   - 将被丢弃的空钱包 id 清单；
//   - 当前生效价格 id 集合的摘要（有价格新增或作废就不同）；
//   - 币种设置行（是否存在、币种、时区、默认月度额度）。
//
// 取舍：令牌不再覆盖流水明细、各表时间戳、单个钱包的明细（只看按币种的合计），也不覆盖上游费率、
// 固定成本的金额。切换只改币种标记、不改数字，且执行时仍在表锁下重新计算在途预占、冲突、
// 未定价、待丢弃钱包并拒绝，所以漏掉它们不会改变执行结果，只是不再因无关写入使令牌失效。
// 安全影响：令牌的作用是「管理员看到的就是将要执行的」，防止预览后数据变化被无意执行；
// 它不是授权凭据（授权由角色闸门与审计保证），收窄覆盖面不会扩大越权风险。
func currencySwitchFingerprint(tenant string, cfg EmployeeSettings, settingsRow bool, p *CurrencySwitchPreview, wallets []switchWallet, deleted []string, priceSet string) string {
	type walletSum struct {
		Currency                      string
		Count, Deletable              int64
		BalanceMicros, ReservedMicros int64
	}
	sums := map[string]*walletSum{}
	for _, w := range wallets {
		sum := sums[w.Currency]
		if sum == nil {
			sum = &walletSum{Currency: w.Currency}
			sums[w.Currency] = sum
		}
		sum.Count++
		sum.BalanceMicros += w.Balance
		sum.ReservedMicros += w.Reserved
		if w.Deletable {
			sum.Deletable++
		}
	}
	ordered := make([]walletSum, 0, len(sums))
	for _, sum := range sums {
		ordered = append(ordered, *sum)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Currency < ordered[j].Currency })
	payload, _ := json.Marshal(struct {
		Tenant      string
		Settings    EmployeeSettings
		SettingsRow bool
		Preview     *CurrencySwitchPreview
		Wallets     []walletSum
		Deleted     []string
		PriceSet    string
	}{tenant, cfg, settingsRow, p, ordered, deleted, priceSet})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// mapCurrencySwitchLockError 把「等锁超时 / 语句超时」统一成 ErrCurrencySwitchBusy。
// 用户主动取消请求也是 57014，但消息不同，不能误报为繁忙。
func mapCurrencySwitchLockError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "55P03" || (pgErr.Code == "57014" && strings.Contains(pgErr.Message, "statement timeout")) {
			return ErrCurrencySwitchBusy
		}
	}
	return err
}

// SwitchCurrency 是不带「确认未定价」的便捷入口，行为同 SwitchCurrencyWithOptions。
func (s *Store) SwitchCurrency(ctx context.Context, tenant, actor, ip, target string, preview bool, confirm string) (*CurrencySwitchPreview, error) {
	return s.SwitchCurrencyWithOptions(ctx, CurrencySwitchRequest{Tenant: tenant, Actor: actor, IP: ip, Target: target, Preview: preview, ConfirmToken: confirm})
}

// SwitchCurrencyWithOptions 在单个事务内重新核对预览、改标现有资金并写审计（含审计链）；金额数字从不换算。
func (s *Store) SwitchCurrencyWithOptions(ctx context.Context, req CurrencySwitchRequest) (*CurrencySwitchPreview, error) {
	p, err := s.switchCurrency(ctx, req)
	return p, mapCurrencySwitchLockError(err)
}

func (s *Store) switchCurrency(ctx context.Context, req CurrencySwitchRequest) (*CurrencySwitchPreview, error) {
	tenant, actor, ip, target, preview := req.Tenant, req.Actor, req.IP, req.Target, req.Preview
	if tenant == "" || actor == "" || (target != "CNY" && target != "USD") {
		return nil, ErrInvalidUsage
	}
	var tx pgx.Tx
	var err error
	if preview {
		// 预览使用一致的只读快照，不阻塞任何租户的资金写入。
		tx, err = s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	} else {
		tx, err = s.db.Begin(ctx)
	}
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// 必须在取任何锁之前设置：等锁最多 lock_timeout，单条语句最多 statement_timeout，超时整体回滚。
	if _, err = tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, currencySwitchLockTimeout, currencySwitchStatementTimeout); err != nil {
		return nil, err
	}
	if !preview {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenant); err != nil {
			return nil, err
		}
		// 表级写屏障同时覆盖旧版写入方，防止预览重核后新增钱包、流水或预占的幻读。
		if _, err = tx.Exec(ctx, `LOCK TABLE billing_employee_settings,billing_wallets,billing_model_prices,billing_upstream_rates,billing_channel_fixed_costs,billing_employee_reservations,billing_reservations,billing_wallet_monthly_grants,billing_ledger_entries,billing_redemption_uses,billing_charge_records,billing_usage_facts IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return nil, err
		}
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenant).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrInvalidUsage
	}
	cfg, err := s.employeeSettings(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	var settingsRow bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_employee_settings WHERE tenant_id=$1)`, tenant).Scan(&settingsRow); err != nil {
		return nil, err
	}
	p := &CurrencySwitchPreview{CurrentCurrency: cfg.Currency, Currency: target, Wallets: []CurrencyCount{}, ActivePrices: []CurrencyCount{}, UpstreamRates: []CurrencyCount{}, FixedCosts: []CurrencyCount{}, ConflictUsers: []string{}, UnpricedModels: []SwitchUnpricedModel{}}
	for _, q := range []struct {
		table, where string
		out          *[]CurrencyCount
	}{
		{"billing_wallets", "", &p.Wallets}, {"billing_model_prices", " AND status='active'", &p.ActivePrices}, {"billing_upstream_rates", "", &p.UpstreamRates}, {"billing_channel_fixed_costs", "", &p.FixedCosts},
	} {
		zero := "0::bigint"
		if q.table == "billing_wallets" {
			zero = "count(*) FILTER(WHERE balance_micros=0)"
		}
		rows, e := tx.Query(ctx, `SELECT currency,count(*),`+zero+` FROM `+q.table+` WHERE tenant_id=$1`+q.where+` GROUP BY currency ORDER BY currency`, tenant)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var c CurrencyCount
			if e = rows.Scan(&c.Currency, &c.Count, &c.ZeroBalanceCount); e != nil {
				rows.Close()
				return nil, e
			}
			*q.out = append(*q.out, c)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_employee_reservations r WHERE r.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id))+(SELECT count(*) FROM billing_reservations WHERE tenant_id=$1 AND status='reserved'),(SELECT count(*) FROM billing_wallets WHERE tenant_id=$1 AND reserved_micros>0),(SELECT count(*) FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND month_start<=NOW() AND month_end>NOW())`, tenant).Scan(&p.Reservations, &p.ReservedWallets, &p.MonthlyGrants); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT w.id,w.user_id,w.currency,w.balance_micros,w.reserved_micros,w.balance_micros=0 AND w.reserved_micros=0 AND NOT EXISTS(SELECT 1 FROM billing_ledger_entries l WHERE l.tenant_id=w.tenant_id AND l.wallet_id=w.id) AND NOT EXISTS(SELECT 1 FROM billing_reservations r WHERE r.tenant_id=w.tenant_id AND r.wallet_id=w.id) AND NOT EXISTS(SELECT 1 FROM billing_wallet_monthly_grants g WHERE g.tenant_id=w.tenant_id AND g.wallet_id=w.id) AND NOT EXISTS(SELECT 1 FROM billing_redemption_uses u WHERE u.tenant_id=w.tenant_id AND u.wallet_id=w.id) AND NOT EXISTS(SELECT 1 FROM billing_charge_records c WHERE c.tenant_id=w.tenant_id AND c.wallet_id=w.id) FROM billing_wallets w WHERE tenant_id=$1 ORDER BY w.id`, tenant)
	if err != nil {
		return nil, err
	}
	wallets := []switchWallet{}
	for rows.Next() {
		var w switchWallet
		if err = rows.Scan(&w.ID, &w.User, &w.Currency, &w.Balance, &w.Reserved, &w.Deletable); err != nil {
			rows.Close()
			return nil, err
		}
		wallets = append(wallets, w)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	deleted, conflicts := planCurrencyWallets(wallets, target)
	p.ConflictUsers = conflicts
	if p.UnpricedModels, p.LegacyOrphanPrices, err = currencySwitchUnpriced(ctx, tx, tenant, target); err != nil {
		return nil, err
	}
	var priceSet string
	if err = tx.QueryRow(ctx, `SELECT COALESCE(md5(string_agg(id,',' ORDER BY id)),'') FROM billing_model_prices WHERE tenant_id=$1 AND status='active'`, tenant).Scan(&priceSet); err != nil {
		return nil, err
	}
	p.ConfirmToken = currencySwitchFingerprint(tenant, cfg, settingsRow, p, wallets, deleted, priceSet)
	if preview {
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		return p, nil
	}
	if req.ConfirmToken == "" || req.ConfirmToken != p.ConfirmToken {
		return p, ErrCurrencySwitchChanged
	}
	if p.Reservations > 0 || p.ReservedWallets > 0 {
		return p, ErrCurrencySwitchInFlight
	}
	if len(conflicts) > 0 {
		return p, ErrCurrencySwitchConflict
	}
	if len(p.UnpricedModels) > 0 && !req.ConfirmUnpriced {
		return p, ErrCurrencySwitchUnpriced
	}
	if len(deleted) > 0 {
		if _, err = tx.Exec(ctx, `DELETE FROM billing_wallets WHERE tenant_id=$1 AND id=ANY($2)`, tenant, deleted); err != nil {
			return nil, err
		}
	}
	retired, err := tx.Exec(ctx, `UPDATE billing_model_prices SET status='retired',expires_at=CASE WHEN effective_at<NOW() THEN NOW() ELSE expires_at END WHERE tenant_id=$1 AND currency<>$2 AND status='active'`, tenant, target)
	if err != nil {
		return nil, err
	}
	for _, q := range []string{
		`INSERT INTO billing_employee_settings(tenant_id,currency,timezone) VALUES($1,$2,'Asia/Shanghai') ON CONFLICT(tenant_id) DO UPDATE SET currency=EXCLUDED.currency,updated_at=NOW()`,
		`UPDATE billing_wallets SET currency=$2,version=version+1,updated_at=NOW() WHERE tenant_id=$1 AND currency<>$2`,
		`UPDATE billing_upstream_rates SET currency=$2::varchar,price_json=jsonb_set(price_json,'{currency}',to_jsonb($2::text)),updated_at=NOW() WHERE tenant_id=$1`,
		`UPDATE billing_channel_fixed_costs SET currency=$2,updated_at=NOW() WHERE tenant_id=$1`,
		// 赠金属于当前钱包的资金组成，随钱包改标，防止本月重复发放；用量事实与扣费记录不改。
		`UPDATE billing_wallet_monthly_grants SET currency=$2,updated_at=NOW() WHERE tenant_id=$1 AND month_start<=NOW() AND month_end>NOW()`,
	} {
		if _, err = tx.Exec(ctx, q, tenant, target); err != nil {
			return nil, err
		}
	}
	p.AuditID = uuid.NewString()
	payload, _ := json.Marshal(map[string]any{"preview": p, "deleted_empty_wallet_ids": deleted, "amounts_unchanged": true, "confirmed_unpriced": req.ConfirmUnpriced, "retired_price_rows": retired.RowsAffected()})
	if _, err = tx.Exec(ctx, `INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address) VALUES($1,$2::varchar,$3,'billing.currency.switch',$4::jsonb,'tenant',$2::varchar,$5)`, p.AuditID, tenant, actor, payload, ip); err != nil {
		return nil, err
	}
	// 审计链与业务变更同一个事务：审计链写不进去，币种、钱包、价格都不会改变。
	if err = s.appendAuditChainTx(ctx, tx, tenant, p.AuditID, map[string]any{
		"action_type": "billing.currency.switch", "tenant_id": tenant, "actor_user_id": actor,
		"currency": target, "previous_currency": p.CurrentCurrency, "confirmed_unpriced": req.ConfirmUnpriced,
		"unpriced_models": len(p.UnpricedModels), "legacy_orphan_pairs": p.LegacyOrphanPrices.Pairs,
		"retired_price_rows": retired.RowsAffected(), "deleted_empty_wallets": len(deleted),
	}); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	p.Executed = true
	return p, nil
}
