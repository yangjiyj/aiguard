package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLegacyDateTariffWritesCannotChangeRulesOrHistoricalFacts(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	input := NewTariffPlan{TenantID: tenant, Name: "legacy-date-history", Timezone: "UTC", CreatedBy: user, EffectiveAt: now.Add(-48 * time.Hour), Rules: []TariffRule{{Code: "weekly", Name: "weekly", ModelName: "model-a", Band: TariffBandFlat, StartMinute: 0, EndMinute: 1440, MultiplierPPM: TariffRatioFlat}}}
	plan, err := store.CreateTariffPlan(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.PublishTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	date := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	ruleID := "legacy-date-" + plan.ID
	// Seed a previous-release active date rule directly; new APIs cannot write it.
	if _, err = db.Exec(ctx, `INSERT INTO billing_tariff_rules(id,tenant_id,plan_id,code,name,model_name,band,weekdays,special_date,start_minute,end_minute,multiplier_ppm,priority) VALUES($1,$2,$3,'historical-date','historical-date','model-a','valley',ARRAY[1,2,3,4,5,6,7]::smallint[],$4,1439,1440,712345,2)`, ruleID, tenant, plan.ID, date); err != nil {
		t.Fatal(err)
	}
	admittedAt := date.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
	quote, err := store.ResolveTariffQuoteForModel(ctx, tenant, "model-a", admittedAt)
	if err != nil || quote.PlanID != plan.ID || quote.RuleID != ruleID || quote.MultiplierPPM != 712345 {
		t.Fatalf("historical quote=%+v err=%v", quote, err)
	}
	factID := "history-fact-" + plan.ID
	if _, err = db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,model_name,billable_amount_micros,currency,tariff_plan_id,tariff_plan_version,tariff_rule_id,tariff_band,tariff_multiplier_ppm,billing_timezone,status,occurred_at,admitted_at) VALUES($1,$2,$1,$3,'model-a',54321,'CNY',$4,$5,$6,'valley',712345,'UTC','settled',$7,$7)`, factID, tenant, user, quote.PlanID, quote.PlanVersion, quote.RuleID, admittedAt); err != nil {
		t.Fatal(err)
	}
	input.Rules[0].MultiplierPPM = 800_000
	if _, err = store.UpdateTariffPlan(ctx, plan.ID, input); !errors.Is(err, ErrTariffLegacyDateRulesReadOnly) {
		t.Fatalf("legacy weekly replacement=%v", err)
	}
	if _, err = store.PublishTariffPlan(ctx, tenant, plan.ID); !errors.Is(err, ErrTariffLegacyDateRulesReadOnly) {
		t.Fatalf("legacy republication=%v", err)
	}
	if _, err = store.UpdateTariffPlan(ctx, plan.ID, NewTariffPlan{TenantID: tenant + "_other", Name: input.Name, Rules: input.Rules}); !errors.Is(err, ErrTariffNotFound) {
		t.Fatalf("cross-tenant update=%v", err)
	}
	current, err := store.GetTariffPlan(ctx, tenant, plan.ID)
	if err != nil || current.Status != "active" || current.Version != 1 || len(current.Rules) != 2 {
		t.Fatalf("original changed=%+v err=%v", current, err)
	}
	var versions int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_tariff_plans WHERE tenant_id=$1 AND name=$2`, tenant, plan.Name).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("new version appeared=%d err=%v", versions, err)
	}
	if _, err = store.RetireTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	next, err := store.ResolveTariffQuoteForModel(ctx, tenant, "model-a", admittedAt)
	if err != nil || next.PlanID != "" || next.MultiplierPPM != TariffRatioFlat {
		t.Fatalf("retired request=%+v err=%v", next, err)
	}
	if err = store.DeleteTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	historical, err := store.GetTariffPlan(ctx, tenant, plan.ID)
	if err != nil || historical.DeletedAt == nil || len(historical.Rules) != 2 {
		t.Fatalf("historical rules lost=%+v err=%v", historical, err)
	}
	var found bool
	for _, rule := range historical.Rules {
		if rule.ID == ruleID {
			found = rule.SpecialDate != nil && rule.SpecialDate.Equal(date) && rule.MultiplierPPM == 712345 && rule.StartMinute == 1439 && rule.EndMinute == 1440
		}
	}
	if !found {
		t.Fatal("historical date rule or minute precision changed")
	}
	var factPlan, factRule string
	var factVersion int
	var multiplier, amount int64
	if err = db.QueryRow(ctx, `SELECT tariff_plan_id,tariff_plan_version,tariff_rule_id,tariff_multiplier_ppm,billable_amount_micros FROM billing_usage_facts WHERE tenant_id=$1 AND id=$2`, tenant, factID).Scan(&factPlan, &factVersion, &factRule, &multiplier, &amount); err != nil || factPlan != plan.ID || factVersion != 1 || factRule != ruleID || multiplier != 712345 || amount != 54321 {
		t.Fatalf("historical fact changed: plan=%s version=%d rule=%s multiplier=%d amount=%d err=%v", factPlan, factVersion, factRule, multiplier, amount, err)
	}
}

func TestLegacyDateDraftCannotBeReplacedOrPublished(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	input := NewTariffPlan{TenantID: tenant, Name: "legacy-date-draft", CreatedBy: user, Rules: []TariffRule{{Code: "original", Name: "original", ModelName: "model-a", StartMinute: 0, EndMinute: 1440, MultiplierPPM: 700_000}}}
	plan, err := store.CreateTariffPlan(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE billing_tariff_rules SET special_date='2026-10-01' WHERE tenant_id=$1 AND plan_id=$2`, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpdateTariffPlan(ctx, plan.ID, input); !errors.Is(err, ErrTariffLegacyDateRulesReadOnly) {
		t.Fatalf("draft replacement=%v", err)
	}
	if _, err = store.PublishTariffPlan(ctx, tenant, plan.ID); !errors.Is(err, ErrTariffLegacyDateRulesReadOnly) {
		t.Fatalf("draft publication=%v", err)
	}
	original, err := store.GetTariffPlan(ctx, tenant, plan.ID)
	if err != nil || original.Status != "draft" || len(original.Rules) != 1 || original.Rules[0].SpecialDate == nil || original.Rules[0].MultiplierPPM != 700_000 {
		t.Fatalf("legacy draft changed=%+v err=%v", original, err)
	}
}
