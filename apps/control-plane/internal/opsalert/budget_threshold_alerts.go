package opsalert

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
)

// BudgetThresholdScanner 定期检查员工月额度、部门预算、组织预算，在每个预算周期用到 80% 和 100% 时
// 各通知一次：写告警组与消息中心，并走已配置的告警渠道（企业微信 / 飞书 / 钉钉 / 邮件 / Webhook）外发。
//
// 去重持久化在 billing_budget_threshold_notices（每作用域 × 周期 × 阈值一行），重启和多实例都不会重复外发；
// 直接越过 100% 时只发 100%，同时把 80% 记为已发。只读用量、只发通知，不参与断流判定。
type BudgetThresholdScanner struct {
	emitter *Emitter
	tenants func(ctx context.Context) ([]string, error)
	load    func(ctx context.Context, tenantID string, at time.Time) (billing.BudgetTreeInput, error)
	claim   func(ctx context.Context, c billing.BudgetThresholdCandidate, threshold int) (bool, error)
	// maxPerRun 限制单轮外发条数（机器人渠道有频率限制）；超出的候选不登记，下一轮继续发。
	maxPerRun int
}

type snapshotGetter interface {
	Get(ctx context.Context, tenantID string, scopes []budget.SnapshotScope) (map[string]budget.ScopeUsage, error)
}

func NewBudgetThresholdScanner(db *pgxpool.Pool, store *billing.Store, snapshot snapshotGetter, emitter *Emitter) *BudgetThresholdScanner {
	return &BudgetThresholdScanner{
		emitter: emitter,
		tenants: func(ctx context.Context) ([]string, error) {
			rows, err := db.Query(ctx, `SELECT id FROM tenants WHERE COALESCE(status,'active') NOT IN ('deleted','disabled') ORDER BY id LIMIT 1000`)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			var ids []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return nil, err
				}
				ids = append(ids, id)
			}
			return ids, rows.Err()
		},
		load: func(ctx context.Context, tenantID string, at time.Time) (billing.BudgetTreeInput, error) {
			in, err := store.LoadBudgetTreeInput(ctx, tenantID, at)
			if err != nil {
				return in, err
			}
			FillBudgetTreeUsage(ctx, snapshot, &in)
			return in, nil
		},
		claim: func(ctx context.Context, c billing.BudgetThresholdCandidate, threshold int) (bool, error) {
			tag, err := db.Exec(ctx, `INSERT INTO billing_budget_threshold_notices (tenant_id,scope_type,scope_id,period_start,threshold)
				VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, c.TenantID, c.ScopeType, c.ScopeID, c.PeriodStart, threshold)
			if err != nil {
				return false, fmt.Errorf("claim budget threshold notice: %w", err)
			}
			return tag.RowsAffected() == 1, nil
		},
		maxPerRun: 20,
	}
}

// FillBudgetTreeUsage 用预算快照（与断流判定同一数据源）补齐部门与组织的本月已用；快照不可用时保持未知。
func FillBudgetTreeUsage(ctx context.Context, snapshot snapshotGetter, in *billing.BudgetTreeInput) {
	if snapshot == nil || in == nil {
		return
	}
	scopes := make([]budget.SnapshotScope, 0, len(in.DepartmentBudgets)+1)
	if in.OrganizationBudget != nil {
		scopes = append(scopes, budget.SnapshotScope{Scope: "tenant", ID: in.TenantID, Timezone: in.OrganizationBudget.Timezone})
	}
	for id, p := range in.DepartmentBudgets {
		scopes = append(scopes, budget.SnapshotScope{Scope: "team", ID: id, Timezone: p.Timezone})
	}
	if len(scopes) == 0 {
		return
	}
	usage, err := snapshot.Get(ctx, in.TenantID, scopes)
	if err != nil {
		log.Printf("[budget_threshold] snapshot unavailable tenant=%s: %v", in.TenantID, err)
		return
	}
	if in.OrganizationBudget != nil {
		v := usage["tenant:"+in.TenantID].MonthCostMicros
		in.OrganizationUsed = &v
	}
	for id := range in.DepartmentBudgets {
		v := usage["team:"+id].MonthCostMicros
		in.DepartmentUsed[id] = &v
	}
}

var budgetScopeLabels = map[string]string{
	billing.BudgetScopeEmployee: "员工", billing.BudgetScopeDepartment: "部门", billing.BudgetScopeOrganization: "组织",
}

// RunOnce 扫描一轮，返回本轮外发的通知数。
func (s *BudgetThresholdScanner) RunOnce(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.emitter == nil || s.tenants == nil || s.load == nil || s.claim == nil {
		return 0, nil
	}
	tenants, err := s.tenants(ctx)
	if err != nil {
		return 0, fmt.Errorf("list tenants for budget thresholds: %w", err)
	}
	limit := s.maxPerRun
	if limit <= 0 {
		limit = 20
	}
	sent := 0
	for _, tenantID := range tenants {
		in, err := s.load(ctx, tenantID, now)
		if err != nil {
			log.Printf("[budget_threshold] load tenant=%s failed: %v", tenantID, err)
			continue
		}
		for _, c := range billing.BudgetThresholdCandidates(in, now) {
			if sent >= limit {
				return sent, nil
			}
			fresh, err := s.claim(ctx, c, c.Threshold)
			if err != nil {
				return sent, err
			}
			if c.Threshold >= 100 {
				// 越过 100% 时 80% 视为已通知，避免用量回落（如退款调账）后补发过时的 80%。
				if _, err := s.claim(ctx, c, 80); err != nil {
					return sent, err
				}
			}
			if !fresh {
				continue
			}
			if err := s.emit(ctx, c); err != nil {
				log.Printf("[budget_threshold] emit failed tenant=%s scope=%s:%s: %v", c.TenantID, c.ScopeType, c.ScopeID, err)
				continue
			}
			sent++
		}
	}
	return sent, nil
}

func (s *BudgetThresholdScanner) emit(ctx context.Context, c billing.BudgetThresholdCandidate) error {
	typ := TypeBudgetThreshold80
	if c.Threshold >= 100 {
		typ = TypeBudgetThreshold100
	}
	scope := budgetScopeLabels[c.ScopeType] + " " + firstNonEmpty(strings.TrimSpace(c.Name), "未命名")
	label := fmt.Sprintf("%s（%s / %s，已用 %d%%）", scope, formatYuan(c.UsedMicros, c.Currency), formatYuan(c.LimitMicros, c.Currency), c.Percent)
	_, err := s.emitter.Emit(ctx, Event{
		TenantID: c.TenantID, Type: typ, OccurredAt: time.Now().UTC(),
		ScopeKey:   fmt.Sprintf("budget:%s:%s:%s", c.ScopeType, c.ScopeID, c.PeriodStart.UTC().Format("2006-01-02")),
		ScopeLabel: label,
		Detail: map[string]any{"scope_type": c.ScopeType, "scope_id": c.ScopeID, "threshold": c.Threshold, "percent": c.Percent,
			"used_micros": c.UsedMicros, "limit_micros": c.LimitMicros, "currency": c.Currency, "period_start": c.PeriodStart.UTC()},
	})
	return err
}

// formatYuan 输出带千分位的金额：¥1,234.56；非人民币显示币种代码。
func formatYuan(micros int64, currency string) string {
	neg := micros < 0
	if neg {
		micros = -micros
	}
	cents := (micros + 5_000) / 10_000
	whole, frac := cents/100, cents%100
	digits := fmt.Sprintf("%d", whole)
	var b strings.Builder
	for i, r := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	amount := fmt.Sprintf("%s.%02d", b.String(), frac)
	prefix := "¥"
	if code := strings.ToUpper(strings.TrimSpace(currency)); code != "" && code != "CNY" {
		prefix = code + " "
	}
	if neg {
		prefix = "-" + prefix
	}
	return prefix + amount
}
