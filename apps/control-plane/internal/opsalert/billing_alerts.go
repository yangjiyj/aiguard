package opsalert

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 计费事件来源标识（billing_ops_alert_marks.source_kind）。
const (
	sourceRequestOutcome  = "request_outcome"
	sourceLedgerOverdraft = "ledger_overdraft"
)

// BillingScanner 定期扫描计费结果，把以下事件转成运维告警：
// 预算用尽断流、未定价模型被拒、额度状态无法确认被拒（request_logs.billing_outcome），
// finalize 结算失败（billing_outcome='failed'），钱包透支（账本流水 overdraft 标记）。
// 每条来源事件只计入一次（billing_ops_alert_marks），扫描带回看窗口以覆盖结算晚于建行的长请求。
type BillingScanner struct {
	db       *pgxpool.Pool
	emitter  *Emitter
	lookback time.Duration
	batch    int
}

func NewBillingScanner(db *pgxpool.Pool, emitter *Emitter) *BillingScanner {
	return &BillingScanner{db: db, emitter: emitter, lookback: 2 * time.Hour, batch: 2000}
}

type billingAggregate struct {
	tenantID, typ, scopeKey, scopeLabel string
	sources                             []string
	sourceKind                          string
	last                                time.Time
	detail                              map[string]any
}

// RunOnce 扫描一轮，返回产生/折叠的告警事件数。
func (s *BillingScanner) RunOnce(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.db == nil || s.emitter == nil {
		return 0, nil
	}
	since := now.Add(-s.lookback)
	aggs, err := s.requestOutcomes(ctx, since)
	if err != nil {
		return 0, err
	}
	overdrafts, err := s.overdrafts(ctx, since)
	if err != nil {
		return 0, err
	}
	aggs = append(aggs, overdrafts...)
	emitted := 0
	for _, agg := range aggs {
		fresh, err := s.claim(ctx, agg.tenantID, agg.sourceKind, agg.sources)
		if err != nil {
			return emitted, err
		}
		if fresh == 0 {
			continue
		}
		detail := map[string]any{"new_events": fresh}
		for k, v := range agg.detail {
			detail[k] = v
		}
		if _, err := s.emitter.Emit(ctx, Event{TenantID: agg.tenantID, Type: agg.typ, ScopeKey: agg.scopeKey,
			ScopeLabel: agg.scopeLabel, Count: fresh, OccurredAt: agg.last, Detail: detail}); err != nil {
			log.Printf("[billing_ops_alert] emit %s failed: %v", agg.typ, err)
			continue
		}
		emitted++
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM billing_ops_alert_marks WHERE created_at < $1`, now.Add(-72*time.Hour)); err != nil {
		log.Printf("[billing_ops_alert] prune marks failed: %v", err)
	}
	return emitted, nil
}

// claim 登记本轮的来源事件，返回首次登记（尚未计入告警）的数量。
func (s *BillingScanner) claim(ctx context.Context, tenantID, kind string, sources []string) (int, error) {
	if len(sources) == 0 {
		return 0, nil
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO billing_ops_alert_marks (tenant_id, source_kind, source_id)
		SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING`, tenantID, kind, sources)
	if err != nil {
		return 0, fmt.Errorf("claim billing alert sources: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func outcomeAlertType(outcome string) string {
	switch outcome {
	case "budget_exhausted":
		return TypeBudgetExhausted
	case "budget_unpriced":
		return TypeUnpricedRejected
	case "budget_unavailable":
		return TypeBudgetUnavailable
	case "failed":
		return TypeFinalizeFailed
	}
	return ""
}

// requestOutcomes 按（租户, 结果, 作用域）聚合被预算拒绝或结算失败的请求。
// 预算类按员工聚合；未定价与结算失败按模型聚合。
func (s *BillingScanner) requestOutcomes(ctx context.Context, since time.Time) ([]billingAggregate, error) {
	rows, err := s.db.Query(ctx, `
		SELECT r.tenant_id, r.billing_outcome,
		       CASE WHEN r.billing_outcome IN ('budget_unpriced','failed') THEN 'model:' || COALESCE(m.model_name, r.model_id, '')
		            ELSE 'user:' || COALESCE(r.user_id, '') END AS scope_key,
		       CASE WHEN r.billing_outcome IN ('budget_unpriced','failed') THEN COALESCE(m.model_name, '')
		            ELSE COALESCE(u.username, '') END AS scope_name,
		       array_agg(r.request_id ORDER BY r.created_at), max(r.created_at)
		FROM request_logs r
		LEFT JOIN models m ON m.id = r.model_id
		LEFT JOIN users u ON u.id = r.user_id AND u.tenant_id = r.tenant_id
		WHERE r.created_at >= $1
		  AND r.billing_outcome IN ('budget_exhausted','budget_unpriced','budget_unavailable','failed')
		GROUP BY 1, 2, 3, 4
		LIMIT $2`, since, s.batch)
	if err != nil {
		return nil, fmt.Errorf("scan billing outcomes: %w", err)
	}
	defer rows.Close()
	var out []billingAggregate
	for rows.Next() {
		var agg billingAggregate
		var outcome, scopeName string
		if err := rows.Scan(&agg.tenantID, &outcome, &agg.scopeKey, &scopeName, &agg.sources, &agg.last); err != nil {
			return nil, err
		}
		agg.typ = outcomeAlertType(outcome)
		agg.sourceKind = sourceRequestOutcome
		agg.scopeLabel = scopeLabel(agg.scopeKey, scopeName)
		agg.detail = map[string]any{"sample_request_id": agg.sources[len(agg.sources)-1]}
		out = append(out, agg)
	}
	return out, rows.Err()
}

// overdrafts 按钱包聚合打了透支标记的账本流水。
func (s *BillingScanner) overdrafts(ctx context.Context, since time.Time) ([]billingAggregate, error) {
	rows, err := s.db.Query(ctx, `
		SELECT l.tenant_id, l.wallet_id, COALESCE(u.username, w.user_id, ''), w.currency,
		       array_agg(l.id ORDER BY l.created_at), max(l.created_at),
		       (array_agg(l.balance_after_micros - l.reserved_after_micros ORDER BY l.created_at DESC))[1]
		FROM billing_ledger_entries l
		JOIN billing_wallets w ON w.id = l.wallet_id AND w.tenant_id = l.tenant_id
		LEFT JOIN users u ON u.id = w.user_id AND u.tenant_id = w.tenant_id
		WHERE l.created_at >= $1 AND (l.metadata_json->>'overdraft') = 'true'
		GROUP BY 1, 2, 3, 4
		LIMIT $2`, since, s.batch)
	if err != nil {
		return nil, fmt.Errorf("scan wallet overdrafts: %w", err)
	}
	defer rows.Close()
	var out []billingAggregate
	for rows.Next() {
		var agg billingAggregate
		var walletID, owner, currency string
		var available int64
		if err := rows.Scan(&agg.tenantID, &walletID, &owner, &currency, &agg.sources, &agg.last, &available); err != nil {
			return nil, err
		}
		agg.typ, agg.sourceKind = TypeWalletOverdraft, sourceLedgerOverdraft
		agg.scopeKey = "wallet:" + walletID
		agg.scopeLabel = "钱包 " + firstNonEmpty(owner, "未命名用户")
		agg.detail = map[string]any{"wallet_id": walletID, "currency": currency, "available_after_micros": available}
		out = append(out, agg)
	}
	return out, rows.Err()
}

func scopeLabel(scopeKey, name string) string {
	switch {
	case strings.HasPrefix(scopeKey, "model:"):
		return "模型 " + firstNonEmpty(name, strings.TrimPrefix(scopeKey, "model:"), "未知")
	case scopeKey == "user:":
		return "未识别员工"
	default:
		return "员工 " + firstNonEmpty(name, "未命名")
	}
}

// ReportReservationLeak 在过期预占清理释放了额度时产生“预占泄漏清理”告警。
func (e *Emitter) ReportReservationLeak(ctx context.Context, tenantID string, released int64) {
	if e == nil || released <= 0 {
		return
	}
	if _, err := e.Emit(ctx, Event{TenantID: tenantID, Type: TypeReservationLeak, ScopeKey: "employee_allowance",
		ScopeLabel: fmt.Sprintf("本次释放 %d 笔", released), Count: int(released), Detail: map[string]any{"released": released}}); err != nil {
		log.Printf("[billing_ops_alert] reservation leak alert failed: %v", err)
	}
}

// ReportProxyUsageUnknown 是“正向代理用量未知”事件的接入函数：由记录用量未知 fact 的一方（P1）调用，
// 按租户和站点聚合。requestID 用于去重之外的排查线索，可为空。
func (e *Emitter) ReportProxyUsageUnknown(ctx context.Context, tenantID, host, requestID string) {
	if e == nil {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	detail := map[string]any{"host": host}
	if requestID != "" {
		detail["sample_request_id"] = requestID
	}
	if _, err := e.Emit(ctx, Event{TenantID: tenantID, Type: TypeProxyUsageUnknown, ScopeKey: "host:" + host,
		ScopeLabel: "站点 " + firstNonEmpty(host, "未知"), Detail: detail}); err != nil {
		log.Printf("[billing_ops_alert] proxy usage unknown alert failed: %v", err)
	}
}
