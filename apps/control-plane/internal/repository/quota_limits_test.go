package repository

import (
	"errors"
	"testing"
)

func quotaInt(value int) *int {
	return &value
}

func TestNormalizeQuotaPolicyCanonicalLimitStates(t *testing.T) {
	policy := &QuotaPolicy{
		DailyTokenCanonical:        true,
		DailyTokenLimitCanonical:   nil,
		MonthlyTokenCanonical:      true,
		MonthlyTokenLimitCanonical: quotaMicros(0),
		RPMCanonical:               true,
		RPMLimitCanonical:          quotaInt(25),
		ConcurrencyCanonical:       true,
		ConcurrencyBlocked:         true,
		DailyBudgetCanonical:       true,
		MonthlyBudgetCanonical:     true,
	}
	if err := NormalizeQuotaPolicy(policy); err != nil {
		t.Fatalf("NormalizeQuotaPolicy: %v", err)
	}
	if policy.DailyTokenLimitCanonical != nil || policy.DailyTokenLimit != 0 {
		t.Fatalf("daily inherit was not preserved: %+v", policy)
	}
	assertQuotaMicros(t, policy.MonthlyTokenLimitCanonical, quotaMicros(0))
	if policy.RPMLimitCanonical == nil || *policy.RPMLimitCanonical != 25 || policy.RPMLimit != 25 {
		t.Fatalf("RPM limit was not synchronized: %+v", policy)
	}
	if !policy.ConcurrencyBlocked || policy.ConcurrencyLimitCanonical != nil || policy.ConcurrencyLimit != 0 {
		t.Fatalf("concurrency block was not preserved: %+v", policy)
	}
	if policy.QuotaTimezone != DefaultQuotaTimezone {
		t.Fatalf("timezone=%q, want %q", policy.QuotaTimezone, DefaultQuotaTimezone)
	}
}

func TestNormalizeQuotaPolicyConvertsLegacyLimits(t *testing.T) {
	policy := &QuotaPolicy{
		DailyTokenLimit:        0,
		MonthlyTokenLimit:      200,
		RPMLimit:               30,
		ConcurrencyLimit:       4,
		DailyBudgetLimit:       0,
		MonthlyBudgetLimit:     0,
		QuotaTimezone:          " UTC ",
		QuotaTimezoneCanonical: true,
	}
	if err := NormalizeQuotaPolicy(policy); err != nil {
		t.Fatalf("NormalizeQuotaPolicy: %v", err)
	}
	assertQuotaMicros(t, policy.DailyTokenLimitCanonical, quotaMicros(0))
	assertQuotaMicros(t, policy.MonthlyTokenLimitCanonical, quotaMicros(200))
	if policy.RPMLimitCanonical == nil || *policy.RPMLimitCanonical != 30 {
		t.Fatalf("RPM canonical=%v, want 30", policy.RPMLimitCanonical)
	}
	if policy.ConcurrencyLimitCanonical == nil || *policy.ConcurrencyLimitCanonical != 4 {
		t.Fatalf("concurrency canonical=%v, want 4", policy.ConcurrencyLimitCanonical)
	}
	if policy.QuotaTimezone != "UTC" {
		t.Fatalf("timezone=%q, want UTC", policy.QuotaTimezone)
	}
}

func TestNormalizeQuotaPolicyRejectsInvalidCanonicalLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*QuotaPolicy)
	}{
		{name: "negative token", mutate: func(p *QuotaPolicy) { p.DailyTokenLimitCanonical = quotaMicros(-1) }},
		{name: "token overflow", mutate: func(p *QuotaPolicy) { p.DailyTokenLimitCanonical = quotaMicros(MaxQuotaTokenLimit + 1) }},
		{name: "token block conflict", mutate: func(p *QuotaPolicy) {
			p.DailyTokenLimitCanonical = quotaMicros(0)
			p.DailyTokenBlocked = true
		}},
		{name: "negative RPM", mutate: func(p *QuotaPolicy) { p.RPMLimitCanonical = quotaInt(-1) }},
		{name: "RPM block conflict", mutate: func(p *QuotaPolicy) {
			p.RPMLimitCanonical = quotaInt(0)
			p.RPMBlocked = true
		}},
		{name: "invalid timezone", mutate: func(p *QuotaPolicy) { p.QuotaTimezone = "Mars/Olympus" }},
		{name: "empty timezone", mutate: func(p *QuotaPolicy) { p.QuotaTimezone = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &QuotaPolicy{
				DailyTokenCanonical:    true,
				MonthlyTokenCanonical:  true,
				RPMCanonical:           true,
				ConcurrencyCanonical:   true,
				DailyBudgetCanonical:   true,
				MonthlyBudgetCanonical: true,
				QuotaTimezone:          DefaultQuotaTimezone,
				QuotaTimezoneCanonical: true,
			}
			tt.mutate(policy)
			err := NormalizeQuotaPolicy(policy)
			if !errors.Is(err, ErrInvalidQuotaLimit) {
				t.Fatalf("error=%v, want ErrInvalidQuotaLimit", err)
			}
		})
	}
}

func TestNormalizeQuotaPolicyIsAtomicAcrossDimensions(t *testing.T) {
	policy := &QuotaPolicy{
		DailyBudgetLimit:           1,
		DailyTokenLimit:            10,
		MonthlyTokenCanonical:      true,
		MonthlyTokenLimitCanonical: quotaMicros(-1),
	}
	err := NormalizeQuotaPolicy(policy)
	if !errors.Is(err, ErrInvalidQuotaLimit) {
		t.Fatalf("error=%v, want ErrInvalidQuotaLimit", err)
	}
	if policy.DailyBudgetCanonical || policy.DailyBudgetMicros != nil ||
		policy.DailyTokenCanonical || policy.DailyTokenLimitCanonical != nil {
		t.Fatalf("policy was partially normalized: %+v", policy)
	}
}
