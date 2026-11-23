package repository

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
)

const (
	// MaxQuotaBudgetMicros is the largest integer that remains exact in
	// Redis Lua numbers and JavaScript clients.
	MaxQuotaBudgetMicros int64 = 1<<53 - 1
	quotaMicrosPerCNY          = int64(1_000_000)
)

var ErrInvalidQuotaBudget = errors.New("invalid quota budget")

type normalizedQuotaBudget struct {
	micros  *int64
	blocked bool
	legacy  float64
}

// NormalizeQuotaPolicyMoney converts legacy CNY fields to the canonical
// integer-micros representation and keeps the legacy columns synchronized.
func NormalizeQuotaPolicyMoney(policy *QuotaPolicy) error {
	if policy == nil {
		return fmt.Errorf("%w: nil policy", ErrInvalidQuotaBudget)
	}

	daily, err := normalizeQuotaBudget(
		"daily",
		policy.DailyBudgetCanonical,
		policy.DailyBudgetMicros,
		policy.DailyBudgetBlocked,
		policy.DailyBudgetLimit,
	)
	if err != nil {
		return err
	}
	monthly, err := normalizeQuotaBudget(
		"monthly",
		policy.MonthlyBudgetCanonical,
		policy.MonthlyBudgetMicros,
		policy.MonthlyBudgetBlocked,
		policy.MonthlyBudgetLimit,
	)
	if err != nil {
		return err
	}

	policy.DailyBudgetMicros = daily.micros
	policy.DailyBudgetBlocked = daily.blocked
	policy.DailyBudgetLimit = daily.legacy
	policy.DailyBudgetCanonical = true
	policy.MonthlyBudgetMicros = monthly.micros
	policy.MonthlyBudgetBlocked = monthly.blocked
	policy.MonthlyBudgetLimit = monthly.legacy
	policy.MonthlyBudgetCanonical = true
	return nil
}

func normalizeQuotaBudget(
	field string,
	canonical bool,
	micros *int64,
	blocked bool,
	legacyCNY float64,
) (normalizedQuotaBudget, error) {
	if !canonical {
		converted, err := quotaBudgetMicrosFromLegacy(legacyCNY)
		if err != nil {
			return normalizedQuotaBudget{}, fmt.Errorf("%w: %s budget: %v", ErrInvalidQuotaBudget, field, err)
		}
		return normalizedQuotaBudget{
			micros:  &converted,
			blocked: false,
			legacy:  float64(converted) / float64(quotaMicrosPerCNY),
		}, nil
	}

	if blocked {
		if micros != nil {
			return normalizedQuotaBudget{}, fmt.Errorf(
				"%w: %s budget cannot be blocked and have a micros value",
				ErrInvalidQuotaBudget,
				field,
			)
		}
		return normalizedQuotaBudget{blocked: true}, nil
	}
	if micros == nil {
		return normalizedQuotaBudget{}, nil
	}
	if *micros < 0 || *micros > MaxQuotaBudgetMicros {
		return normalizedQuotaBudget{}, fmt.Errorf(
			"%w: %s budget micros must be between 0 and %d",
			ErrInvalidQuotaBudget,
			field,
			MaxQuotaBudgetMicros,
		)
	}
	return normalizedQuotaBudget{
		micros: micros,
		legacy: float64(*micros) / float64(quotaMicrosPerCNY),
	}, nil
}

func quotaBudgetMicrosFromLegacy(cny float64) (int64, error) {
	if math.IsNaN(cny) || math.IsInf(cny, 0) {
		return 0, errors.New("CNY value must be finite")
	}
	if cny < 0 {
		return 0, errors.New("CNY value must not be negative")
	}

	decimal := strconv.FormatFloat(cny, 'f', -1, 64)
	amount, ok := new(big.Rat).SetString(decimal)
	if !ok {
		return 0, errors.New("CNY value is not a decimal number")
	}
	amount.Mul(amount, big.NewRat(quotaMicrosPerCNY, 1))
	if !amount.IsInt() {
		return 0, errors.New("CNY value has precision below one micro")
	}
	max := new(big.Int).SetInt64(MaxQuotaBudgetMicros)
	if amount.Num().Cmp(max) > 0 {
		return 0, fmt.Errorf("CNY value exceeds %d micros", MaxQuotaBudgetMicros)
	}
	return amount.Num().Int64(), nil
}
