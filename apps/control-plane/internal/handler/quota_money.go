package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

const maxQuotaPolicyConfigRequestBytes int64 = 16 << 10

type quotaMoneyRequest struct {
	dailyMicros      *int64
	monthlyMicros    *int64
	dailyBlocked     bool
	monthlyBlocked   bool
	dailyCanonical   bool
	monthlyCanonical bool
	timezonePresent  bool
}

func decodeQuotaPolicyRequest(w http.ResponseWriter, r *http.Request) (types.QuotaPolicyRequest, quotaMoneyRequest, error) {
	var req types.QuotaPolicyRequest
	var money quotaMoneyRequest

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxQuotaPolicyConfigRequestBytes))
	if err != nil {
		return req, money, fmt.Errorf("read request body: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, money, fmt.Errorf("decode request: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return req, money, fmt.Errorf("request body must contain one JSON value")
		}
		return req, money, fmt.Errorf("decode trailing data: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return req, money, fmt.Errorf("decode request fields: %w", err)
	}
	_, money.timezonePresent = raw["quota_timezone"]

	money.dailyMicros, money.dailyBlocked, money.dailyCanonical, err = resolveQuotaMoneyRequest(
		raw,
		"daily_budget_micros",
		"daily_budget_blocked",
		"daily_budget_limit",
		req.DailyBudgetMicros,
		req.DailyBudgetBlocked,
	)
	if err != nil {
		return req, money, fmt.Errorf("daily budget: %w", err)
	}
	money.monthlyMicros, money.monthlyBlocked, money.monthlyCanonical, err = resolveQuotaMoneyRequest(
		raw,
		"monthly_budget_micros",
		"monthly_budget_blocked",
		"monthly_budget_limit",
		req.MonthlyBudgetMicros,
		req.MonthlyBudgetBlocked,
	)
	if err != nil {
		return req, money, fmt.Errorf("monthly budget: %w", err)
	}
	return req, money, nil
}

func resolveQuotaMoneyRequest(
	raw map[string]json.RawMessage,
	microsKey string,
	blockedKey string,
	legacyKey string,
	micros *int64,
	blocked bool,
) (*int64, bool, bool, error) {
	_, microsPresent := raw[microsKey]
	_, blockedPresent := raw[blockedKey]
	legacyRaw, legacyPresent := raw[legacyKey]
	canonical := microsPresent || (blockedPresent && blocked)

	if micros != nil && (*micros < 0 || *micros > repository.MaxQuotaBudgetMicros) {
		return nil, false, canonical, fmt.Errorf("%s must be between 0 and %d", microsKey, repository.MaxQuotaBudgetMicros)
	}
	if blocked && micros != nil {
		return nil, false, canonical, fmt.Errorf("%s requires %s to be null", blockedKey, microsKey)
	}

	legacyMicros, legacyNull, err := parseLegacyBudgetMicros(legacyRaw, legacyPresent)
	if err != nil {
		return nil, false, canonical, fmt.Errorf("%s: %w", legacyKey, err)
	}

	if canonical {
		if legacyPresent && (blocked || !optionalInt64Equal(micros, legacyMicros)) {
			return nil, false, canonical, fmt.Errorf("%s conflicts with canonical money fields", legacyKey)
		}
		return micros, blocked, true, nil
	}
	if legacyNull {
		// A legacy database NULL meant unset. Preserve that state instead of
		// letting the repository's legacy zero-value compatibility path run.
		return nil, false, true, nil
	}
	if legacyPresent {
		return legacyMicros, false, false, nil
	}
	return nil, false, false, nil
}

func parseLegacyBudgetMicros(raw json.RawMessage, present bool) (*int64, bool, error) {
	if !present {
		return nil, false, nil
	}
	value := strings.TrimSpace(string(raw))
	if value == "null" {
		return nil, true, nil
	}
	rat, ok := new(big.Rat).SetString(value)
	if !ok {
		return nil, false, fmt.Errorf("must be a finite decimal number")
	}
	if rat.Sign() < 0 {
		return nil, false, fmt.Errorf("must be non-negative")
	}
	scaled := new(big.Rat).Mul(rat, big.NewRat(1_000_000, 1))
	if !scaled.IsInt() {
		return nil, false, fmt.Errorf("supports at most six decimal places")
	}
	max := big.NewInt(repository.MaxQuotaBudgetMicros)
	if scaled.Num().Cmp(max) > 0 {
		return nil, false, fmt.Errorf("exceeds maximum %d micros", repository.MaxQuotaBudgetMicros)
	}
	result := scaled.Num().Int64()
	return &result, false, nil
}

func optionalInt64Equal(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validateQuotaCountRequest(req types.QuotaPolicyRequest) error {
	if err := validateInt64QuotaState("daily_token_limit", req.DailyTokenLimit, req.DailyTokenBlocked); err != nil {
		return err
	}
	if err := validateInt64QuotaState("monthly_token_limit", req.MonthlyTokenLimit, req.MonthlyTokenBlocked); err != nil {
		return err
	}
	if err := validateIntQuotaState("rpm_limit", req.RPMLimit, req.RPMBlocked); err != nil {
		return err
	}
	if err := validateInt64QuotaState("tpm_limit", req.TPMLimit, req.TPMBlocked); err != nil {
		return err
	}
	if err := validateIntQuotaState("concurrency_limit", req.ConcurrencyLimit, req.ConcurrencyBlocked); err != nil {
		return err
	}
	return nil
}

func validateInt64QuotaState(name string, limit *int64, blocked bool) error {
	if limit != nil && (*limit < 0 || *limit > repository.MaxQuotaBudgetMicros) {
		return fmt.Errorf("%s must be between 0 and %d", name, repository.MaxQuotaBudgetMicros)
	}
	if blocked && limit != nil {
		return fmt.Errorf("%s_blocked requires %s to be null", strings.TrimSuffix(name, "_limit"), name)
	}
	return nil
}

func validateIntQuotaState(name string, limit *int, blocked bool) error {
	if limit != nil && *limit < 0 {
		return fmt.Errorf("%s must be non-negative", name)
	}
	if blocked && limit != nil {
		return fmt.Errorf("%s_blocked requires %s to be null", strings.TrimSuffix(name, "_limit"), name)
	}
	return nil
}

func normalizeQuotaTimezone(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Asia/Shanghai", nil
	}
	if len(value) > 64 || value == "Local" || strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") || strings.Contains(value, "..") {
		return "", fmt.Errorf("quota_timezone must be an IANA timezone")
	}
	if _, err := time.LoadLocation(value); err != nil {
		return "", fmt.Errorf("quota_timezone must be an IANA timezone")
	}
	return value, nil
}

func int64Value(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
