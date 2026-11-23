package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTariffRetirementAndSoftDeletionRetainHistoricalQuote(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	plan, err := store.CreateTariffPlan(ctx, NewTariffPlan{TenantID: tenant, Name: "retire-history", CreatedBy: user, Timezone: "UTC", EffectiveAt: now.Add(-time.Hour), Rules: []TariffRule{{Code: "all", Name: "all", ModelName: "m", Band: TariffBandPeak, StartMinute: 0, EndMinute: 1440, MultiplierPPM: 1_200_000}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.PublishTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	admitted, err := store.ResolveTariffQuoteForModel(ctx, tenant, "m", now)
	if err != nil || admitted.MultiplierPPM != 1_200_000 {
		t.Fatalf("admitted=%+v err=%v", admitted, err)
	}
	if err = store.DeleteTariffPlan(ctx, tenant, plan.ID); !errors.Is(err, ErrTariffNotDraft) {
		t.Fatalf("active deletion=%v", err)
	}
	if _, err = store.RetireTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	next, err := store.ResolveTariffQuoteForModel(ctx, tenant, "m", now.Add(time.Second))
	if err != nil || next.MultiplierPPM != TariffRatioFlat || next.PlanID != "" {
		t.Fatalf("retired new request=%+v err=%v", next, err)
	}
	if err = store.DeleteTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	plans, err := store.ListTariffPlans(ctx, tenant, 10)
	if err != nil || len(plans) != 0 {
		t.Fatalf("visible=%+v err=%v", plans, err)
	}
	historical, err := store.GetTariffPlan(ctx, tenant, admitted.PlanID)
	if err != nil || historical.DeletedAt == nil || historical.Version != admitted.PlanVersion || len(historical.Rules) != 1 || historical.Rules[0].MultiplierPPM != admitted.MultiplierPPM {
		t.Fatalf("historical=%+v err=%v", historical, err)
	}
	if _, err = store.UpdateTariffPlan(ctx, plan.ID, NewTariffPlan{TenantID: tenant, Name: plan.Name, Rules: plan.Rules}); !errors.Is(err, ErrTariffNotFound) {
		t.Fatalf("deleted edit=%v", err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_tariff_rules WHERE tenant_id=$1 AND plan_id=$2`, tenant, plan.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rules=%d err=%v", count, err)
	}
}
