package repository

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxQuotaTokenLimit   = MaxQuotaBudgetMicros
	MaxQuotaIntLimit     = int(1<<31 - 1)
	DefaultQuotaTimezone = "Asia/Shanghai"
)

var ErrInvalidQuotaLimit = errors.New("invalid quota limit")

type normalizedInt64QuotaLimit struct {
	canonical *int64
	blocked   bool
	legacy    int64
}

type normalizedIntQuotaLimit struct {
	canonical *int
	blocked   bool
	legacy    int
}

// NormalizeQuotaPolicy validates every canonical quota dimension atomically.
func NormalizeQuotaPolicy(policy *QuotaPolicy) error {
	if policy == nil {
		return fmt.Errorf("%w: nil policy", ErrInvalidQuotaLimit)
	}
	normalized := *policy
	if err := NormalizeQuotaPolicyMoney(&normalized); err != nil {
		return err
	}
	if err := normalizeQuotaPolicyLimits(&normalized); err != nil {
		return err
	}
	*policy = normalized
	return nil
}

func normalizeQuotaPolicyLimits(policy *QuotaPolicy) error {
	daily, err := normalizeInt64QuotaLimit(
		"daily token",
		policy.DailyTokenCanonical,
		policy.DailyTokenLimitCanonical,
		policy.DailyTokenBlocked,
		policy.DailyTokenLimit,
		MaxQuotaTokenLimit,
	)
	if err != nil {
		return err
	}
	monthly, err := normalizeInt64QuotaLimit(
		"monthly token",
		policy.MonthlyTokenCanonical,
		policy.MonthlyTokenLimitCanonical,
		policy.MonthlyTokenBlocked,
		policy.MonthlyTokenLimit,
		MaxQuotaTokenLimit,
	)
	if err != nil {
		return err
	}
	rpm, err := normalizeIntQuotaLimit(
		"RPM",
		policy.RPMCanonical,
		policy.RPMLimitCanonical,
		policy.RPMBlocked,
		policy.RPMLimit,
	)
	if err != nil {
		return err
	}
	concurrency, err := normalizeIntQuotaLimit(
		"concurrency",
		policy.ConcurrencyCanonical,
		policy.ConcurrencyLimitCanonical,
		policy.ConcurrencyBlocked,
		policy.ConcurrencyLimit,
	)
	if err != nil {
		return err
	}

	timezone := strings.TrimSpace(policy.QuotaTimezone)
	if !policy.QuotaTimezoneCanonical {
		timezone = DefaultQuotaTimezone
	} else if timezone == "" {
		return fmt.Errorf("%w: quota timezone must not be empty", ErrInvalidQuotaLimit)
	}
	if len(timezone) > 64 {
		return fmt.Errorf("%w: quota timezone exceeds 64 characters", ErrInvalidQuotaLimit)
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return fmt.Errorf("%w: invalid quota timezone %q", ErrInvalidQuotaLimit, timezone)
	}
	policy.DailyTokenLimitCanonical = daily.canonical
	policy.DailyTokenBlocked = daily.blocked
	policy.DailyTokenLimit = daily.legacy
	policy.DailyTokenCanonical = true
	policy.MonthlyTokenLimitCanonical = monthly.canonical
	policy.MonthlyTokenBlocked = monthly.blocked
	policy.MonthlyTokenLimit = monthly.legacy
	policy.MonthlyTokenCanonical = true
	policy.RPMLimitCanonical = rpm.canonical
	policy.RPMBlocked = rpm.blocked
	policy.RPMLimit = rpm.legacy
	policy.RPMCanonical = true
	policy.ConcurrencyLimitCanonical = concurrency.canonical
	policy.ConcurrencyBlocked = concurrency.blocked
	policy.ConcurrencyLimit = concurrency.legacy
	policy.ConcurrencyCanonical = true
	policy.QuotaTimezone = timezone
	policy.QuotaTimezoneCanonical = true
	return nil
}

func normalizeInt64QuotaLimit(
	field string,
	present bool,
	canonical *int64,
	blocked bool,
	legacy int64,
	max int64,
) (normalizedInt64QuotaLimit, error) {
	if !present {
		if legacy < 0 || legacy > max {
			return normalizedInt64QuotaLimit{}, invalidQuotaLimitRange(field, max)
		}
		value := legacy
		return normalizedInt64QuotaLimit{canonical: &value, legacy: legacy}, nil
	}
	if blocked {
		if canonical != nil {
			return normalizedInt64QuotaLimit{}, invalidBlockedQuotaLimit(field)
		}
		return normalizedInt64QuotaLimit{blocked: true}, nil
	}
	if canonical == nil {
		return normalizedInt64QuotaLimit{}, nil
	}
	if *canonical < 0 || *canonical > max {
		return normalizedInt64QuotaLimit{}, invalidQuotaLimitRange(field, max)
	}
	return normalizedInt64QuotaLimit{canonical: canonical, legacy: *canonical}, nil
}

func normalizeIntQuotaLimit(
	field string,
	present bool,
	canonical *int,
	blocked bool,
	legacy int,
) (normalizedIntQuotaLimit, error) {
	if !present {
		if legacy < 0 || legacy > MaxQuotaIntLimit {
			return normalizedIntQuotaLimit{}, invalidQuotaLimitRange(field, int64(MaxQuotaIntLimit))
		}
		value := legacy
		return normalizedIntQuotaLimit{canonical: &value, legacy: legacy}, nil
	}
	if blocked {
		if canonical != nil {
			return normalizedIntQuotaLimit{}, invalidBlockedQuotaLimit(field)
		}
		return normalizedIntQuotaLimit{blocked: true}, nil
	}
	if canonical == nil {
		return normalizedIntQuotaLimit{}, nil
	}
	if *canonical < 0 || *canonical > MaxQuotaIntLimit {
		return normalizedIntQuotaLimit{}, invalidQuotaLimitRange(field, int64(MaxQuotaIntLimit))
	}
	return normalizedIntQuotaLimit{canonical: canonical, legacy: *canonical}, nil
}

func invalidQuotaLimitRange(field string, max int64) error {
	return fmt.Errorf("%w: %s limit must be between 0 and %d", ErrInvalidQuotaLimit, field, max)
}

func invalidBlockedQuotaLimit(field string) error {
	return fmt.Errorf("%w: %s limit cannot be blocked and have a value", ErrInvalidQuotaLimit, field)
}
