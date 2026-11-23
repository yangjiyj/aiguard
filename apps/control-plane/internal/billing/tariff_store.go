package billing

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	TariffBandPeak   = "peak"
	TariffBandFlat   = "flat"
	TariffBandValley = "valley"
	TariffBandCustom = "custom"
	TariffRatioFlat  = int64(1_000_000)
)

var (
	ErrInvalidTariff                 = errors.New("invalid billing tariff")
	ErrTariffNotFound                = errors.New("billing tariff not found")
	ErrTariffNotDraft                = errors.New("billing tariff is not a draft")
	ErrTariffDateRulesUnsupported    = fmt.Errorf("%w: date-specific rules are unavailable for new schedules", ErrInvalidTariff)
	ErrTariffLegacyDateRulesReadOnly = errors.New("historical date-specific billing tariff plans are read-only")
)

type TariffRule struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	PlanID        string     `json:"plan_id"`
	Code          string     `json:"code"`
	Name          string     `json:"name"`
	ModelName     string     `json:"model_name"`
	Band          string     `json:"band"`
	Weekdays      []int16    `json:"weekdays"`
	SpecialDate   *time.Time `json:"special_date,omitempty"`
	StartMinute   int        `json:"start_minute"`
	EndMinute     int        `json:"end_minute"`
	MultiplierPPM int64      `json:"multiplier_ppm"`
	Priority      int        `json:"priority"`
}

type TariffPlan struct {
	ID          string       `json:"id"`
	TenantID    string       `json:"tenant_id"`
	Name        string       `json:"name"`
	Version     int          `json:"version"`
	Status      string       `json:"status"`
	Timezone    string       `json:"timezone"`
	EffectiveAt time.Time    `json:"effective_at"`
	ExpiresAt   *time.Time   `json:"expires_at,omitempty"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	DeletedAt   *time.Time   `json:"deleted_at,omitempty"`
	Rules       []TariffRule `json:"rules"`
}

type NewTariffPlan struct {
	TenantID    string
	Name        string
	Timezone    string
	EffectiveAt time.Time
	ExpiresAt   *time.Time
	CreatedBy   string
	Rules       []TariffRule
}

type TariffQuote struct {
	PlanID        string    `json:"plan_id"`
	PlanVersion   int       `json:"plan_version"`
	RuleID        string    `json:"rule_id"`
	RuleName      string    `json:"rule_name"`
	Band          string    `json:"band"`
	MultiplierPPM int64     `json:"multiplier_ppm"`
	Timezone      string    `json:"timezone"`
	AdmittedAt    time.Time `json:"admitted_at"`
	LocalTime     time.Time `json:"local_time"`
}

func DefaultTariffQuote(at time.Time, timezone string) TariffQuote {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		timezone = "Asia/Shanghai"
		loc, _ = time.LoadLocation(timezone)
	}
	return TariffQuote{Band: TariffBandFlat, MultiplierPPM: TariffRatioFlat, Timezone: timezone, AdmittedAt: at.UTC(), LocalTime: at.In(loc)}
}

func normalizeTariffPlan(input NewTariffPlan) (NewTariffPlan, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.Name = strings.TrimSpace(input.Name)
	input.Timezone = strings.TrimSpace(input.Timezone)
	if input.Timezone == "" {
		input.Timezone = "Asia/Shanghai"
	}
	if input.TenantID == "" || input.Name == "" || len(input.Name) > 120 {
		return NewTariffPlan{}, ErrInvalidTariff
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		return NewTariffPlan{}, ErrInvalidTariff
	}
	if input.EffectiveAt.IsZero() {
		input.EffectiveAt = time.Now().UTC()
	} else {
		input.EffectiveAt = input.EffectiveAt.UTC()
	}
	if input.ExpiresAt != nil {
		expires := input.ExpiresAt.UTC()
		if !expires.After(input.EffectiveAt) {
			return NewTariffPlan{}, ErrInvalidTariff
		}
		input.ExpiresAt = &expires
	}
	expanded := make([]TariffRule, 0, len(input.Rules)+2)
	for _, rule := range input.Rules {
		if rule.SpecialDate != nil {
			return NewTariffPlan{}, ErrTariffDateRulesUnsupported
		}
		normalized, err := normalizeTariffRule(rule)
		if err != nil {
			return NewTariffPlan{}, err
		}
		if normalized.EndMinute > normalized.StartMinute {
			expanded = append(expanded, normalized)
			continue
		}
		// Persist cross-midnight input as two non-overlapping rules. The second
		// half belongs to the following weekday/date, matching how operators
		// read a schedule such as Monday 22:00-02:00.
		first := normalized
		first.Code += "-before-midnight"
		first.EndMinute = 1440
		second := normalized
		second.Code += "-after-midnight"
		second.StartMinute = 0
		second.Weekdays = nextWeekdays(normalized.Weekdays)
		if second.SpecialDate != nil {
			next := second.SpecialDate.AddDate(0, 0, 1)
			second.SpecialDate = &next
		}
		expanded = append(expanded, first, second)
	}
	if err := validateTariffRuleOverlaps(expanded); err != nil {
		return NewTariffPlan{}, err
	}
	input.Rules = expanded
	return input, nil
}

func normalizeTariffRule(rule TariffRule) (TariffRule, error) {
	rule.Code = strings.TrimSpace(rule.Code)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.ModelName = strings.TrimSpace(rule.ModelName)
	rule.Band = strings.ToLower(strings.TrimSpace(rule.Band))
	if rule.Band == "" {
		rule.Band = TariffBandFlat
	}
	if rule.MultiplierPPM == 0 {
		rule.MultiplierPPM = TariffRatioFlat
	}
	if rule.Code == "" || len(rule.Code) > 64 || rule.Name == "" || len(rule.Name) > 120 ||
		!validTariffBand(rule.Band) || rule.StartMinute < 0 || rule.StartMinute >= 1440 ||
		rule.EndMinute <= 0 || rule.EndMinute > 1440 || rule.EndMinute == rule.StartMinute ||
		rule.MultiplierPPM <= 0 || rule.MultiplierPPM > MaxCustomerGroupRatioPPM {
		return TariffRule{}, ErrInvalidTariff
	}
	if len(rule.Weekdays) == 0 {
		rule.Weekdays = []int16{1, 2, 3, 4, 5, 6, 7}
	}
	seen := map[int16]bool{}
	for _, weekday := range rule.Weekdays {
		if weekday < 1 || weekday > 7 || seen[weekday] {
			return TariffRule{}, ErrInvalidTariff
		}
		seen[weekday] = true
	}
	sort.Slice(rule.Weekdays, func(i, j int) bool { return rule.Weekdays[i] < rule.Weekdays[j] })
	if rule.SpecialDate != nil {
		date := time.Date(rule.SpecialDate.Year(), rule.SpecialDate.Month(), rule.SpecialDate.Day(), 0, 0, 0, 0, time.UTC)
		rule.SpecialDate = &date
	}
	return rule, nil
}

func validTariffBand(value string) bool {
	return value == TariffBandPeak || value == TariffBandFlat || value == TariffBandValley || value == TariffBandCustom
}

func nextWeekdays(values []int16) []int16 {
	result := make([]int16, len(values))
	for i, value := range values {
		result[i] = value%7 + 1
	}
	return result
}

func validateTariffRuleOverlaps(rules []TariffRule) error {
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].ModelName != rules[j].ModelName {
				continue
			}
			if !sameTariffCalendar(rules[i], rules[j]) || rules[i].EndMinute <= rules[j].StartMinute || rules[j].EndMinute <= rules[i].StartMinute {
				continue
			}
			return fmt.Errorf("%w: rules %s and %s overlap", ErrInvalidTariff, rules[i].Code, rules[j].Code)
		}
	}
	return nil
}

func sameTariffCalendar(left, right TariffRule) bool {
	if left.SpecialDate != nil || right.SpecialDate != nil {
		return left.SpecialDate != nil && right.SpecialDate != nil && left.SpecialDate.Equal(*right.SpecialDate)
	}
	for _, l := range left.Weekdays {
		for _, r := range right.Weekdays {
			if l == r {
				return true
			}
		}
	}
	return false
}

func matchTariffRule(rules []TariffRule, local time.Time) *TariffRule {
	return matchTariffRuleForModel(rules, "", local)
}

func matchTariffRuleForModel(rules []TariffRule, modelName string, local time.Time) *TariffRule {
	minute := local.Hour()*60 + local.Minute()
	weekday := int16(local.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	date := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
	var matches []TariffRule
	for _, rule := range rules {
		if strings.TrimSpace(rule.ModelName) != strings.TrimSpace(modelName) {
			continue
		}
		if minute < rule.StartMinute || minute >= rule.EndMinute {
			continue
		}
		if rule.SpecialDate != nil {
			if rule.SpecialDate.Equal(date) {
				matches = append(matches, rule)
			}
			continue
		}
		for _, value := range rule.Weekdays {
			if value == weekday {
				matches = append(matches, rule)
				break
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		leftSpecial, rightSpecial := matches[i].SpecialDate != nil, matches[j].SpecialDate != nil
		if leftSpecial != rightSpecial {
			return leftSpecial
		}
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		return matches[i].Code < matches[j].Code
	})
	result := matches[0]
	return &result
}

func (s *Store) CreateTariffPlan(ctx context.Context, input NewTariffPlan) (*TariffPlan, error) {
	normalized, err := normalizeTariffPlan(input)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin create billing tariff: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKey := normalized.TenantID + "|" + normalized.Name
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return nil, fmt.Errorf("lock billing tariff version: %w", err)
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM billing_tariff_plans WHERE tenant_id=$1 AND name=$2`, normalized.TenantID, normalized.Name).Scan(&version); err != nil {
		return nil, fmt.Errorf("next billing tariff version: %w", err)
	}
	plan := &TariffPlan{ID: "tariff_" + uuid.NewString(), TenantID: normalized.TenantID, Name: normalized.Name, Version: version, Status: "draft", Timezone: normalized.Timezone, EffectiveAt: normalized.EffectiveAt, ExpiresAt: normalized.ExpiresAt, CreatedBy: normalized.CreatedBy}
	if err := tx.QueryRow(ctx, `
		INSERT INTO billing_tariff_plans (id,tenant_id,name,version,status,timezone,effective_at,expires_at,created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')) RETURNING created_at
	`, plan.ID, plan.TenantID, plan.Name, plan.Version, plan.Status, plan.Timezone, plan.EffectiveAt, plan.ExpiresAt, plan.CreatedBy).Scan(&plan.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert billing tariff plan: %w", err)
	}
	for _, inputRule := range normalized.Rules {
		rule := inputRule
		rule.ID, rule.TenantID, rule.PlanID = "tariff_rule_"+uuid.NewString(), plan.TenantID, plan.ID
		if _, err := tx.Exec(ctx, `
		INSERT INTO billing_tariff_rules (id,tenant_id,plan_id,code,name,model_name,band,weekdays,special_date,start_minute,end_minute,multiplier_ppm,priority)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13)
	`, rule.ID, rule.TenantID, rule.PlanID, rule.Code, rule.Name, rule.ModelName, rule.Band, rule.Weekdays, rule.SpecialDate, rule.StartMinute, rule.EndMinute, rule.MultiplierPPM, rule.Priority); err != nil {
			return nil, fmt.Errorf("insert billing tariff rule: %w", err)
		}
		plan.Rules = append(plan.Rules, rule)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit billing tariff plan: %w", err)
	}
	return plan, nil
}

// rejectLegacyTariffPlanWrite runs while the caller holds the plan row lock.
// Historical date rules remain readable and billable, but cannot be silently
// replaced by a client that only understands weekly schedules.
func rejectLegacyTariffPlanWrite(ctx context.Context, tx pgx.Tx, tenantID, planID string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_tariff_rules WHERE tenant_id=$1 AND plan_id=$2 AND special_date IS NOT NULL)`, tenantID, planID).Scan(&exists); err != nil {
		return fmt.Errorf("check historical date-specific tariff rules: %w", err)
	}
	if exists {
		return ErrTariffLegacyDateRulesReadOnly
	}
	return nil
}

// UpdateTariffPlan updates a draft in place. Published/retired plans are immutable:
// editing them creates a new draft in the same version family, without changing
// the rules or multiplier snapshots attached to previously admitted requests.
func (s *Store) UpdateTariffPlan(ctx context.Context, planID string, input NewTariffPlan) (*TariffPlan, error) {
	if strings.TrimSpace(planID) == "" || strings.TrimSpace(input.TenantID) == "" {
		return nil, ErrInvalidTariff
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin edit billing tariff: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status, name string
	if err := tx.QueryRow(ctx, `SELECT status,name FROM billing_tariff_plans WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, input.TenantID, planID).Scan(&status, &name); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTariffNotFound
	} else if err != nil {
		return nil, fmt.Errorf("lock billing tariff for edit: %w", err)
	}
	if err := rejectLegacyTariffPlanWrite(ctx, tx, input.TenantID, planID); err != nil {
		return nil, err
	}
	// Keep the original name so all edits remain in one monotonically increasing
	// version family. Renaming is available by creating a separate new plan.
	input.Name = name
	normalized, err := normalizeTariffPlan(input)
	if err != nil {
		return nil, err
	}
	if status == "active" || status == "retired" {
		if err := tx.Rollback(ctx); err != nil {
			return nil, err
		}
		return s.CreateTariffPlan(ctx, normalized)
	}
	if status != "draft" {
		return nil, ErrInvalidTariff
	}
	if _, err := tx.Exec(ctx, `UPDATE billing_tariff_plans SET timezone=$3,effective_at=$4,expires_at=$5 WHERE tenant_id=$1 AND id=$2`, normalized.TenantID, planID, normalized.Timezone, normalized.EffectiveAt, normalized.ExpiresAt); err != nil {
		return nil, fmt.Errorf("update billing tariff draft: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM billing_tariff_rules WHERE tenant_id=$1 AND plan_id=$2`, normalized.TenantID, planID); err != nil {
		return nil, fmt.Errorf("replace billing tariff draft rules: %w", err)
	}
	for _, rule := range normalized.Rules {
		if _, err := tx.Exec(ctx, `
			INSERT INTO billing_tariff_rules (id,tenant_id,plan_id,code,name,model_name,band,weekdays,special_date,start_minute,end_minute,multiplier_ppm,priority)
			VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13)
		`, "tariff_rule_"+uuid.NewString(), normalized.TenantID, planID, rule.Code, rule.Name, rule.ModelName, rule.Band, rule.Weekdays, rule.SpecialDate, rule.StartMinute, rule.EndMinute, rule.MultiplierPPM, rule.Priority); err != nil {
			return nil, fmt.Errorf("insert edited billing tariff rule: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit edited billing tariff: %w", err)
	}
	return s.GetTariffPlan(ctx, normalized.TenantID, planID)
}

func (s *Store) DeleteTariffPlan(ctx context.Context, tenantID, planID string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(planID) == "" {
		return ErrInvalidTariff
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin delete billing tariff: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM billing_tariff_plans WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenantID, planID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return ErrTariffNotFound
	} else if err != nil {
		return fmt.Errorf("lock billing tariff for delete: %w", err)
	}
	if status == "active" {
		return ErrTariffNotDraft
	}
	statement := `DELETE FROM billing_tariff_plans WHERE tenant_id=$1 AND id=$2`
	if status == "retired" {
		statement = `UPDATE billing_tariff_plans SET deleted_at=NOW() WHERE tenant_id=$1 AND id=$2`
	}
	if _, err := tx.Exec(ctx, statement, tenantID, planID); err != nil {
		return fmt.Errorf("delete billing tariff plan: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete billing tariff: %w", err)
	}
	return nil
}

// Retirement affects new admissions only. Existing requests retain quote snapshots.
func (s *Store) RetireTariffPlan(ctx context.Context, tenantID, planID string) (*TariffPlan, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenantID+"|tariff-publication"); err != nil {
		return nil, err
	}
	var status string
	if err = tx.QueryRow(ctx, `SELECT status FROM billing_tariff_plans WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenantID, planID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTariffNotFound
	} else if err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, ErrInvalidTariff
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_tariff_plans SET status='retired' WHERE tenant_id=$1 AND id=$2`, tenantID, planID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetTariffPlan(ctx, tenantID, planID)
}

func (s *Store) PublishTariffPlan(ctx context.Context, tenantID, planID string) (*TariffPlan, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(planID) == "" {
		return nil, ErrInvalidTariff
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Only one plan may be active in a tenant. Lock publication across different
	// drafts too: a per-plan row lock alone lets concurrent publishers each miss
	// the other transaction's newly activated draft.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID+"|tariff-publication"); err != nil {
		return nil, fmt.Errorf("lock billing tariff publication: %w", err)
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM billing_tariff_plans WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenantID, planID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTariffNotFound
	} else if err != nil {
		return nil, err
	}
	if err := rejectLegacyTariffPlanWrite(ctx, tx, tenantID, planID); err != nil {
		return nil, err
	}
	if status != "draft" && status != "active" {
		return nil, ErrInvalidTariff
	}
	if _, err := tx.Exec(ctx, `UPDATE billing_tariff_plans SET status='retired' WHERE tenant_id=$1 AND status='active' AND id<>$2`, tenantID, planID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE billing_tariff_plans SET status='active' WHERE tenant_id=$1 AND id=$2`, tenantID, planID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetTariffPlan(ctx, tenantID, planID)
}

func (s *Store) GetTariffPlan(ctx context.Context, tenantID, planID string) (*TariffPlan, error) {
	plan := &TariffPlan{}
	if err := s.db.QueryRow(ctx, `
		SELECT id,tenant_id,name,version,status,timezone,effective_at,expires_at,COALESCE(created_by,''),created_at,deleted_at
		FROM billing_tariff_plans WHERE tenant_id=$1 AND id=$2
	`, tenantID, planID).Scan(&plan.ID, &plan.TenantID, &plan.Name, &plan.Version, &plan.Status, &plan.Timezone, &plan.EffectiveAt, &plan.ExpiresAt, &plan.CreatedBy, &plan.CreatedAt, &plan.DeletedAt); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTariffNotFound
	} else if err != nil {
		return nil, err
	}
	rules, err := s.listTariffRules(ctx, tenantID, planID)
	if err != nil {
		return nil, err
	}
	plan.Rules = rules
	return plan, nil
}

func (s *Store) ListTariffPlans(ctx context.Context, tenantID string, limit int) ([]TariffPlan, error) {
	limit = billingLimit(limit, 100, 500)
	rows, err := s.db.Query(ctx, `
		SELECT id FROM billing_tariff_plans WHERE tenant_id=$1 AND deleted_at IS NULL
		ORDER BY effective_at DESC, version DESC LIMIT $2
	`, tenantID, limit)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]TariffPlan, 0, len(ids))
	for _, id := range ids {
		plan, err := s.GetTariffPlan(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		result = append(result, *plan)
	}
	return result, nil
}

func (s *Store) listTariffRules(ctx context.Context, tenantID, planID string) ([]TariffRule, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id,tenant_id,plan_id,code,name,COALESCE(model_name,''),band,weekdays,special_date,start_minute,end_minute,multiplier_ppm,priority
		FROM billing_tariff_rules WHERE tenant_id=$1 AND plan_id=$2 ORDER BY priority DESC,start_minute,code
	`, tenantID, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []TariffRule
	for rows.Next() {
		var rule TariffRule
		if err := rows.Scan(&rule.ID, &rule.TenantID, &rule.PlanID, &rule.Code, &rule.Name, &rule.ModelName, &rule.Band, &rule.Weekdays, &rule.SpecialDate, &rule.StartMinute, &rule.EndMinute, &rule.MultiplierPPM, &rule.Priority); err != nil {
			return nil, err
		}
		result = append(result, rule)
	}
	return result, rows.Err()
}

func (s *Store) ResolveTariffQuote(ctx context.Context, tenantID string, at time.Time) (TariffQuote, error) {
	return s.ResolveTariffQuoteForModel(ctx, tenantID, "", at)
}

func (s *Store) ResolveTariffQuoteForModel(ctx context.Context, tenantID, modelName string, at time.Time) (TariffQuote, error) {
	return s.resolveTariffQuote(ctx, tenantID, strings.TrimSpace(modelName), at)
}

func (s *Store) resolveTariffQuote(ctx context.Context, tenantID, modelName string, at time.Time) (TariffQuote, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var planID, timezone string
	var version int
	err := s.db.QueryRow(ctx, `
		SELECT id,version,timezone FROM billing_tariff_plans
		WHERE tenant_id=$1 AND status='active' AND deleted_at IS NULL AND effective_at <= $2 AND (expires_at IS NULL OR expires_at > $2)
		ORDER BY effective_at DESC,version DESC LIMIT 1
	`, tenantID, at.UTC()).Scan(&planID, &version, &timezone)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultTariffQuote(at, billingTimeZone()), nil
	}
	if err != nil {
		return TariffQuote{}, err
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return TariffQuote{}, ErrInvalidTariff
	}
	local := at.In(loc)
	rules, err := s.listTariffRules(ctx, tenantID, planID)
	if err != nil {
		return TariffQuote{}, err
	}
	quote := DefaultTariffQuote(at, timezone)
	quote.PlanID, quote.PlanVersion, quote.LocalTime = planID, version, local
	if rule := matchTariffRuleForModel(rules, modelName, local); rule != nil {
		quote.RuleID, quote.RuleName, quote.Band, quote.MultiplierPPM = rule.ID, rule.Name, rule.Band, rule.MultiplierPPM
	}
	return quote, nil
}
