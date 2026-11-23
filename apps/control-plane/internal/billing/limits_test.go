package billing

import (
	"errors"
	"testing"
	"time"
)

func TestUsageTotalTokensIncludesPromptAndOutput(t *testing.T) {
	total, err := UsageTotalTokens(Usage{PromptTokens: 40, CachedInputTokens: 10, CacheWriteInputTokens: 5, OutputTokens: 9})
	if err != nil || total != 49 {
		t.Fatalf("total=%d err=%v, want 49 and nil", total, err)
	}
	if _, err := UsageTotalTokens(Usage{PromptTokens: 2, CachedInputTokens: 3}); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("invalid cache usage err=%v, want ErrInvalidUsage", err)
	}
}

func TestLimitWouldExceedCombinesSettledAndReserved(t *testing.T) {
	counter := usageLimitCounter{SettledAmountMicros: 60, ReservedAmountMicros: 15, SettledTokens: 80, ReservedTokens: 10}
	exceeded, err := limitWouldExceed(counter, 25, 5, 100, 100)
	if err != nil || exceeded {
		t.Fatalf("at exact limits exceeded=%v err=%v", exceeded, err)
	}
	exceeded, err = limitWouldExceed(counter, 26, 5, 100, 100)
	if err != nil || !exceeded {
		t.Fatalf("amount cap exceeded=%v err=%v", exceeded, err)
	}
	exceeded, err = limitWouldExceed(counter, 1, 11, 0, 100)
	if err != nil || !exceeded {
		t.Fatalf("token cap exceeded=%v err=%v", exceeded, err)
	}
}

func TestCustomerRequestLimitErrorDistinguishesRPMAndConcurrency(t *testing.T) {
	if err := customerRequestLimitError(1, 0, CustomerLimits{RPMLimit: 1}); !errors.Is(err, ErrCustomerRPMLimitExceeded) {
		t.Fatalf("rpm limit error = %v, want ErrCustomerRPMLimitExceeded", err)
	}
	if err := customerRequestLimitError(0, 1, CustomerLimits{ConcurrencyLimit: 1}); !errors.Is(err, ErrCustomerConcurrencyLimitExceeded) {
		t.Fatalf("concurrency limit error = %v, want ErrCustomerConcurrencyLimitExceeded", err)
	}
	if err := customerRequestLimitError(999, 999, CustomerLimits{}); err != nil {
		t.Fatalf("zero limits must be unlimited, got %v", err)
	}
}

func TestBillingPeriodDatesUseChinaBusinessDay(t *testing.T) {
	daily, monthly := billingPeriodDates(time.Date(2026, 8, 4, 18, 0, 0, 0, time.UTC))
	if daily != "2026-08-05" || monthly != "2026-08-01" {
		t.Fatalf("periods daily=%q monthly=%q", daily, monthly)
	}
}

func TestRedemptionCodeNormalizationIsFormatTolerant(t *testing.T) {
	a := redemptionHash("ENF-0123-ABCD")
	b := redemptionHash(" enf 0123 abcd ")
	if a != b {
		t.Fatalf("hashes differ for equivalent code")
	}
}
