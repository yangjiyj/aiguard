package repository

import (
	"errors"
	"math"
	"testing"
)

func quotaMicros(value int64) *int64 {
	return &value
}

func TestNormalizeQuotaPolicyMoneyCanonicalStates(t *testing.T) {
	tests := []struct {
		name        string
		micros      *int64
		blocked     bool
		wantMicros  *int64
		wantBlocked bool
		wantLegacy  float64
	}{
		{name: "inherit"},
		{name: "unlimited", micros: quotaMicros(0), wantMicros: quotaMicros(0)},
		{name: "limited", micros: quotaMicros(12_345_678), wantMicros: quotaMicros(12_345_678), wantLegacy: 12.345678},
		{name: "blocked", blocked: true, wantBlocked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &QuotaPolicy{
				DailyBudgetCanonical:   true,
				DailyBudgetMicros:      tt.micros,
				DailyBudgetBlocked:     tt.blocked,
				DailyBudgetLimit:       999,
				MonthlyBudgetCanonical: true,
			}
			if err := NormalizeQuotaPolicyMoney(policy); err != nil {
				t.Fatalf("NormalizeQuotaPolicyMoney: %v", err)
			}
			assertQuotaMicros(t, policy.DailyBudgetMicros, tt.wantMicros)
			if policy.DailyBudgetBlocked != tt.wantBlocked {
				t.Fatalf("blocked=%v, want %v", policy.DailyBudgetBlocked, tt.wantBlocked)
			}
			if policy.DailyBudgetLimit != tt.wantLegacy {
				t.Fatalf("legacy=%v, want %v", policy.DailyBudgetLimit, tt.wantLegacy)
			}
			if !policy.DailyBudgetCanonical || !policy.MonthlyBudgetCanonical {
				t.Fatal("normalized fields must be marked canonical")
			}
		})
	}
}

func TestNormalizeQuotaPolicyMoneyConvertsLegacyCNY(t *testing.T) {
	policy := &QuotaPolicy{
		DailyBudgetLimit:   12.345678,
		MonthlyBudgetLimit: 0,
	}
	if err := NormalizeQuotaPolicyMoney(policy); err != nil {
		t.Fatalf("NormalizeQuotaPolicyMoney: %v", err)
	}
	assertQuotaMicros(t, policy.DailyBudgetMicros, quotaMicros(12_345_678))
	assertQuotaMicros(t, policy.MonthlyBudgetMicros, quotaMicros(0))
	if policy.DailyBudgetBlocked || policy.MonthlyBudgetBlocked {
		t.Fatal("legacy CNY values must not become blocked")
	}
}

func TestNormalizeQuotaPolicyMoneyRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		policy *QuotaPolicy
	}{
		{
			name: "canonical negative",
			policy: &QuotaPolicy{
				DailyBudgetCanonical:   true,
				DailyBudgetMicros:      quotaMicros(-1),
				MonthlyBudgetCanonical: true,
			},
		},
		{
			name: "canonical overflow",
			policy: &QuotaPolicy{
				DailyBudgetCanonical:   true,
				DailyBudgetMicros:      quotaMicros(MaxQuotaBudgetMicros + 1),
				MonthlyBudgetCanonical: true,
			},
		},
		{
			name: "canonical blocked with value",
			policy: &QuotaPolicy{
				DailyBudgetCanonical:   true,
				DailyBudgetMicros:      quotaMicros(0),
				DailyBudgetBlocked:     true,
				MonthlyBudgetCanonical: true,
			},
		},
		{name: "legacy negative", policy: &QuotaPolicy{DailyBudgetLimit: -1}},
		{name: "legacy NaN", policy: &QuotaPolicy{DailyBudgetLimit: math.NaN()}},
		{name: "legacy positive infinity", policy: &QuotaPolicy{DailyBudgetLimit: math.Inf(1)}},
		{name: "legacy negative infinity", policy: &QuotaPolicy{DailyBudgetLimit: math.Inf(-1)}},
		{name: "legacy fractional micro", policy: &QuotaPolicy{DailyBudgetLimit: 0.0000001}},
		{name: "legacy overflow", policy: &QuotaPolicy{DailyBudgetLimit: 9_007_199_255}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NormalizeQuotaPolicyMoney(tt.policy)
			if !errors.Is(err, ErrInvalidQuotaBudget) {
				t.Fatalf("error=%v, want ErrInvalidQuotaBudget", err)
			}
		})
	}
}

func TestNormalizeQuotaPolicyMoneyDoesNotPartiallyMutateOnError(t *testing.T) {
	policy := &QuotaPolicy{
		DailyBudgetLimit:       1,
		MonthlyBudgetCanonical: true,
		MonthlyBudgetMicros:    quotaMicros(-1),
	}
	err := NormalizeQuotaPolicyMoney(policy)
	if !errors.Is(err, ErrInvalidQuotaBudget) {
		t.Fatalf("error=%v, want ErrInvalidQuotaBudget", err)
	}
	if policy.DailyBudgetCanonical || policy.DailyBudgetMicros != nil || policy.DailyBudgetLimit != 1 {
		t.Fatalf("daily budget was partially mutated: %+v", policy)
	}
}

func assertQuotaMicros(t *testing.T, got, want *int64) {
	t.Helper()
	if got == nil || want == nil {
		if got != nil || want != nil {
			t.Fatalf("micros=%v, want %v", got, want)
		}
		return
	}
	if *got != *want {
		t.Fatalf("micros=%d, want %d", *got, *want)
	}
}
