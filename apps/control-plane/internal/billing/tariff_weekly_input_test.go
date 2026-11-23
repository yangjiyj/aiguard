package billing

import (
	"errors"
	"testing"
	"time"
)

func TestNewTariffSchedulesRejectDateSpecificRules(t *testing.T) {
	date := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	_, err := normalizeTariffPlan(NewTariffPlan{TenantID: "tenant-a", Name: "new-weekly-plan", Timezone: "UTC", Rules: []TariffRule{{
		Code: "legacy-date", Name: "legacy-date", ModelName: "model-a", Band: TariffBandFlat, SpecialDate: &date, StartMinute: 0, EndMinute: 1440, MultiplierPPM: 700_000,
	}}})
	if !errors.Is(err, ErrInvalidTariff) {
		t.Fatalf("new date rule accepted: %v", err)
	}
}

func TestWeeklyTariffRetainsTheFinalMinuteAndSundayRollover(t *testing.T) {
	input, err := normalizeTariffPlan(NewTariffPlan{TenantID: "tenant-a", Name: "weekly-minutes", Timezone: "UTC", Rules: []TariffRule{{
		Code: "final-minute", Name: "final-minute", ModelName: "model-a", Band: TariffBandPeak, Weekdays: []int16{7}, StartMinute: 1439, EndMinute: 1440, MultiplierPPM: 1_200_000,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 23, 59, 59, 0, time.UTC)
	if got := matchTariffRuleForModel(input.Rules, "model-a", at); got == nil || got.MultiplierPPM != 1_200_000 {
		t.Fatalf("final minute=%+v", got)
	}
	if got := matchTariffRuleForModel(input.Rules, "model-a", at.Add(time.Second)); got != nil {
		t.Fatalf("end must be exclusive: %+v", got)
	}
	crossed, err := normalizeTariffPlan(NewTariffPlan{TenantID: "tenant-a", Name: "weekly-crossing", Timezone: "UTC", Rules: []TariffRule{{
		Code: "crossing", Name: "crossing", ModelName: "model-a", Band: TariffBandValley, Weekdays: []int16{7}, StartMinute: 23*60 + 45, EndMinute: 15, MultiplierPPM: 700_000,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(crossed.Rules) != 2 || crossed.Rules[1].Weekdays[0] != 1 || crossed.Rules[1].StartMinute != 0 || crossed.Rules[1].EndMinute != 15 {
		t.Fatalf("Sunday rollover=%+v", crossed.Rules)
	}
	if got := matchTariffRuleForModel(crossed.Rules, "model-a", time.Date(2026, 10, 12, 0, 14, 59, 0, time.UTC)); got == nil {
		t.Fatal("next weekday final minute missing")
	}
	if got := matchTariffRuleForModel(crossed.Rules, "model-a", time.Date(2026, 10, 12, 0, 15, 0, 0, time.UTC)); got != nil {
		t.Fatalf("next weekday end must be exclusive: %+v", got)
	}
}
