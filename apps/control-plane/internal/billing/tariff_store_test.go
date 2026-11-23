package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNormalizeTariffPlanSplitsCrossMidnightIntoNextWeekday(t *testing.T) {
	plan, err := normalizeTariffPlan(NewTariffPlan{TenantID: "tenant-a", Name: "峰谷计费", Timezone: "Asia/Shanghai", Rules: []TariffRule{{
		Code: "night", Name: "夜间", Band: TariffBandValley, Weekdays: []int16{1}, StartMinute: 22 * 60, EndMinute: 2 * 60, MultiplierPPM: 700_000,
	}}})
	if err != nil {
		t.Fatalf("normalize tariff: %v", err)
	}
	if len(plan.Rules) != 2 || plan.Rules[0].EndMinute != 1440 || plan.Rules[1].StartMinute != 0 || plan.Rules[1].Weekdays[0] != 2 {
		t.Fatalf("cross-midnight expansion = %#v", plan.Rules)
	}
}

func TestNormalizeTariffPlanRejectsOverlappingWeeklyRules(t *testing.T) {
	_, err := normalizeTariffPlan(NewTariffPlan{TenantID: "tenant-a", Name: "峰谷计费", Timezone: "Asia/Shanghai", Rules: []TariffRule{
		{Code: "a", Name: "A", Band: TariffBandPeak, Weekdays: []int16{1}, StartMinute: 540, EndMinute: 720, MultiplierPPM: 1_200_000},
		{Code: "b", Name: "B", Band: TariffBandFlat, Weekdays: []int16{1}, StartMinute: 600, EndMinute: 780, MultiplierPPM: 1_000_000},
	}})
	if !errors.Is(err, ErrInvalidTariff) {
		t.Fatalf("overlap error = %v, want ErrInvalidTariff", err)
	}
}

func TestMatchTariffRuleUsesHalfOpenMinuteBoundaryAndSpecialDate(t *testing.T) {
	date := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	rules := []TariffRule{
		{ID: "weekly", Code: "weekly", Band: TariffBandPeak, Weekdays: []int16{2}, StartMinute: 570, EndMinute: 690, MultiplierPPM: 1_200_000},
		{ID: "holiday", Code: "holiday", Band: TariffBandValley, SpecialDate: &date, StartMinute: 570, EndMinute: 690, MultiplierPPM: 700_000},
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	matched := matchTariffRule(rules, time.Date(2026, 8, 18, 9, 30, 0, 0, loc))
	if matched == nil || matched.ID != "holiday" {
		t.Fatalf("09:30 special-date match = %#v", matched)
	}
	if matched := matchTariffRule(rules, time.Date(2026, 8, 18, 11, 30, 0, 0, loc)); matched != nil {
		t.Fatalf("end boundary must be exclusive, got %#v", matched)
	}
}

func TestMatchTariffRuleUsesModelScope(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	rules := []TariffRule{
		{ID: "model-a", Code: "a", ModelName: "model-a", Band: TariffBandPeak, Weekdays: []int16{2}, StartMinute: 540, EndMinute: 600, MultiplierPPM: 1_300_000},
		{ID: "model-b", Code: "b", ModelName: "model-b", Band: TariffBandValley, Weekdays: []int16{2}, StartMinute: 540, EndMinute: 600, MultiplierPPM: 700_000},
	}
	at := time.Date(2026, 8, 18, 9, 30, 0, 0, loc)
	if got := matchTariffRuleForModel(rules, "model-a", at); got == nil || got.MultiplierPPM != 1_300_000 {
		t.Fatalf("model-a quote = %#v", got)
	}
	if got := matchTariffRuleForModel(rules, "model-b", at); got == nil || got.MultiplierPPM != 700_000 {
		t.Fatalf("model-b quote = %#v", got)
	}
	if got := matchTariffRuleForModel(rules, "model-c", at); got != nil {
		t.Fatalf("unconfigured model must not inherit another model rule: %#v", got)
	}
}

func TestDeleteTariffPlanOnlyDeletesTenantDraft(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	create := func() *TariffPlan {
		plan, err := store.CreateTariffPlan(ctx, NewTariffPlan{
			TenantID: tenantID, Name: "deletable-tariff", Timezone: "Asia/Shanghai", CreatedBy: userID,
			Rules: []TariffRule{{Code: "flat", Name: "flat", ModelName: "model-a", Band: TariffBandFlat, Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: TariffRatioFlat}},
		})
		if err != nil {
			t.Fatalf("create tariff: %v", err)
		}
		return plan
	}

	draft := create()
	if err := store.DeleteTariffPlan(ctx, tenantID, draft.ID); err != nil {
		t.Fatalf("delete draft: %v", err)
	}
	if _, err := store.GetTariffPlan(ctx, tenantID, draft.ID); !errors.Is(err, ErrTariffNotFound) {
		t.Fatalf("deleted draft lookup error = %v, want ErrTariffNotFound", err)
	}

	active := create()
	if _, err := store.PublishTariffPlan(ctx, tenantID, active.ID); err != nil {
		t.Fatalf("publish tariff: %v", err)
	}
	if err := store.DeleteTariffPlan(ctx, tenantID, active.ID); !errors.Is(err, ErrTariffNotDraft) {
		t.Fatalf("delete active error = %v, want ErrTariffNotDraft", err)
	}

	otherTenantID := tenantID + "_other"
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $1, 'enterprise', 'active')`, otherTenantID); err != nil {
		t.Fatalf("insert other tenant: %v", err)
	}
	if err := store.DeleteTariffPlan(ctx, otherTenantID, active.ID); !errors.Is(err, ErrTariffNotFound) {
		t.Fatalf("cross-tenant delete error = %v, want ErrTariffNotFound", err)
	}
}

func TestTariffPlanCreatePublishResolveAndVersion(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	create := func(multiplier int64) *TariffPlan {
		plan, err := store.CreateTariffPlan(ctx, NewTariffPlan{
			TenantID: tenantID, Name: "integration-tariff", Timezone: "Asia/Shanghai",
			EffectiveAt: now.Add(-time.Hour), CreatedBy: userID,
			Rules: []TariffRule{{
				Code: "all-day", Name: "all day", Band: TariffBandFlat,
				Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440,
				MultiplierPPM: multiplier,
			}},
		})
		if err != nil {
			t.Fatalf("create tariff: %v", err)
		}
		return plan
	}
	first := create(1_100_000)
	if first.Version != 1 || first.Status != "draft" {
		t.Fatalf("first plan=%+v", first)
	}
	if _, err := store.PublishTariffPlan(ctx, tenantID, first.ID); err != nil {
		t.Fatalf("publish first tariff: %v", err)
	}
	quote, err := store.ResolveTariffQuote(ctx, tenantID, now)
	if err != nil || quote.PlanVersion != 1 || quote.MultiplierPPM != 1_100_000 {
		t.Fatalf("first quote=%+v err=%v", quote, err)
	}
	second := create(900_000)
	if second.Version != 2 {
		t.Fatalf("second version=%d", second.Version)
	}
	if _, err := store.PublishTariffPlan(ctx, tenantID, second.ID); err != nil {
		t.Fatalf("publish second tariff: %v", err)
	}
	quote, err = store.ResolveTariffQuote(ctx, tenantID, now)
	if err != nil || quote.PlanVersion != 2 || quote.MultiplierPPM != 900_000 {
		t.Fatalf("second quote=%+v err=%v", quote, err)
	}
}

func TestEditTariffDraftAndPublishedVersionPreservesOriginal(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	input := NewTariffPlan{TenantID: tenantID, Name: "editable-tariff", Timezone: "Asia/Shanghai", CreatedBy: userID,
		EffectiveAt: time.Now().UTC().Add(-time.Hour), Rules: []TariffRule{{Code: "all-day", Name: "all day", ModelName: "model-a", Band: TariffBandFlat,
			Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: TariffRatioFlat}}}
	first, err := store.CreateTariffPlan(ctx, input)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	input.Rules[0].MultiplierPPM = 800_000
	edited, err := store.UpdateTariffPlan(ctx, first.ID, input)
	if err != nil || edited.ID != first.ID || edited.Version != 1 || edited.Rules[0].MultiplierPPM != 800_000 {
		t.Fatalf("draft edit = %#v, error %v", edited, err)
	}
	if _, err := store.PublishTariffPlan(ctx, tenantID, first.ID); err != nil {
		t.Fatalf("publish: %v", err)
	}
	admission, err := store.ResolveTariffQuoteForModel(ctx, tenantID, "model-a", time.Now().UTC())
	if err != nil || admission.MultiplierPPM != 800_000 {
		t.Fatalf("admission = %#v, error %v", admission, err)
	}
	input.Rules[0].MultiplierPPM = 600_000
	input.Name = "attempted-rename"
	next, err := store.UpdateTariffPlan(ctx, first.ID, input)
	if err != nil || next.ID == first.ID || next.Version != 2 || next.Status != "draft" || next.Name != first.Name {
		t.Fatalf("published edit = %#v, error %v", next, err)
	}
	original, err := store.GetTariffPlan(ctx, tenantID, first.ID)
	if err != nil || original.Status != "active" || original.Rules[0].MultiplierPPM != 800_000 || original.Rules[0].ID != edited.Rules[0].ID {
		t.Fatalf("original was changed = %#v, error %v", original, err)
	}
	if _, err := store.PublishTariffPlan(ctx, tenantID, next.ID); err != nil {
		t.Fatalf("publish new: %v", err)
	}
	current, err := store.ResolveTariffQuoteForModel(ctx, tenantID, "model-a", time.Now().UTC())
	if err != nil || current.PlanVersion != 2 || current.MultiplierPPM != 600_000 {
		t.Fatalf("new admission = %#v, error %v", current, err)
	}
	original, err = store.GetTariffPlan(ctx, tenantID, first.ID)
	if err != nil || original.Status != "retired" || original.Rules[0].MultiplierPPM != admission.MultiplierPPM {
		t.Fatalf("historical version = %#v, error %v", original, err)
	}
}

func TestEditTariffEnforcesTenantAndRollsBackInvalidRules(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	input := NewTariffPlan{TenantID: tenantID, Name: "tenant-edit", Timezone: "Asia/Shanghai", CreatedBy: userID,
		Rules: []TariffRule{{Code: "flat", Name: "flat", ModelName: "model-a", Band: TariffBandFlat,
			Weekdays: []int16{1}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: TariffRatioFlat}}}
	plan, err := store.CreateTariffPlan(ctx, input)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	other := tenantID + "_other"
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, other); err != nil {
		t.Fatal(err)
	}
	input.TenantID = other
	if _, err := store.UpdateTariffPlan(ctx, plan.ID, input); !errors.Is(err, ErrTariffNotFound) {
		t.Fatalf("cross-tenant edit error = %v", err)
	}
	input.TenantID = tenantID
	input.Rules = append(input.Rules, TariffRule{Code: "overlap", Name: "overlap", ModelName: "model-a", Band: TariffBandFlat,
		Weekdays: []int16{1}, StartMinute: 60, EndMinute: 120, MultiplierPPM: 700_000})
	if _, err := store.UpdateTariffPlan(ctx, plan.ID, input); !errors.Is(err, ErrInvalidTariff) {
		t.Fatalf("invalid edit error = %v", err)
	}
	unchanged, err := store.GetTariffPlan(ctx, tenantID, plan.ID)
	if err != nil || len(unchanged.Rules) != 1 || unchanged.Rules[0].ID != plan.Rules[0].ID {
		t.Fatalf("failed edit mutated draft = %#v, error %v", unchanged, err)
	}
}

func TestConcurrentTariffPublishKeepsSingleActiveVersion(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	plans := make([]*TariffPlan, 2)
	for i := range plans {
		var err error
		plans[i], err = store.CreateTariffPlan(ctx, NewTariffPlan{TenantID: tenantID, Name: "concurrent-publication", Timezone: "Asia/Shanghai", CreatedBy: userID,
			Rules: []TariffRule{{Code: "flat", Name: "flat", ModelName: "model-a", Band: TariffBandFlat, Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: TariffRatioFlat}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, len(plans))
	for _, plan := range plans {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			_, err := store.PublishTariffPlan(ctx, tenantID, id)
			errs <- err
		}(plan.ID)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent publication: %v", err)
		}
	}
	var active int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_tariff_plans WHERE tenant_id=$1 AND status='active'`, tenantID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active tariff versions=%d, want 1", active)
	}
}
