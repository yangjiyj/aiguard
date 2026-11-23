package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// tier1ThresholdRepo answers Get only; the validator reads nothing else.
type tier1ThresholdRepo struct {
	SystemRepo
	values map[string]string
}

func (r tier1ThresholdRepo) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	if value, ok := r.values[key]; ok {
		return &repository.SystemSetting{Key: key, Value: value}, nil
	}
	return nil, nil
}

// The generic settings route used to store anything strconv.ParseFloat accepts,
// and to compare against the previously stored value when a threshold was
// cleared. The engine is stricter (finite Python float, low < high), and refuses
// the whole managed semantic configuration on a violation.
func TestGenericSettingsTier1ThresholdsMatchTheEngineContract(t *testing.T) {
	stored := map[string]string{"tier1_low_threshold": "0.2", "tier1_high_threshold": "0.95"}
	cases := []struct {
		name     string
		stored   map[string]string
		settings map[string]string
		wantErr  string
	}{
		{name: "plain pair", settings: map[string]string{"tier1_low_threshold": "0.2", "tier1_high_threshold": "0.8"}},
		// 2026-09-17: {"tier1_low_threshold": "0.0"} written through this very route
		// disabled the tier-1 cascade for weeks; nobody read the audit warning.
		{name: "zero disables the cascade", settings: map[string]string{"tier1_low_threshold": "0.0"}, wantErr: "disables the tier-1 cascade"},
		{name: "zero as an integer", settings: map[string]string{"tier1_low_threshold": "0"}, wantErr: "disables the tier-1 cascade"},
		{name: "just below the cut-off", settings: map[string]string{"tier1_low_threshold": "0.04999"}, wantErr: "disables the tier-1 cascade"},
		{name: "at the cut-off", settings: map[string]string{"tier1_low_threshold": "0.05"}},
		{
			// Only a request that sets the lower bound is judged on it: an operator has to be
			// able to fix the upper bound while an old 0.0 is still stored.
			name:     "fixing high while a low of 0.0 is already stored",
			stored:   map[string]string{"tier1_low_threshold": "0.0", "tier1_high_threshold": "0.95"},
			settings: map[string]string{"tier1_high_threshold": "0.8"},
		},
		{name: "exponent form", settings: map[string]string{"tier1_low_threshold": "1e-1"}},
		{name: "clear low", settings: map[string]string{"tier1_low_threshold": ""}},
		{name: "NaN", settings: map[string]string{"tier1_low_threshold": "NaN"}, wantErr: "must be a number"},
		{name: "Inf", settings: map[string]string{"tier1_high_threshold": "Inf"}, wantErr: "must be a number"},
		{name: "hex float", settings: map[string]string{"tier1_low_threshold": "0x1p-2"}, wantErr: "must be a number"},
		{name: "underscore", settings: map[string]string{"tier1_low_threshold": "0_5"}, wantErr: "must be a number"},
		{name: "text", settings: map[string]string{"tier1_low_threshold": "abc"}, wantErr: "must be a number"},
		{name: "out of range", settings: map[string]string{"tier1_high_threshold": "1.5"}, wantErr: "between 0 and 1"},
		{name: "negative", settings: map[string]string{"tier1_low_threshold": "-0.1"}, wantErr: "between 0 and 1"},
		{name: "equal values", settings: map[string]string{"tier1_low_threshold": "0.5", "tier1_high_threshold": "0.5"}, wantErr: "lower than"},
		{name: "low above high", settings: map[string]string{"tier1_low_threshold": "0.9", "tier1_high_threshold": "0.4"}, wantErr: "lower than"},
		{
			// Clearing high falls back to the deployed default 0.70, not to the stored 0.95,
			// so a low of 0.8 would end up above the high the engine actually uses.
			name:     "low above the default high after clearing high",
			stored:   stored,
			settings: map[string]string{"tier1_low_threshold": "0.8", "tier1_high_threshold": ""},
			wantErr:  "lower than",
		},
		{
			name:     "low below the stored high",
			stored:   stored,
			settings: map[string]string{"tier1_low_threshold": "0.8"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := &Dependencies{SystemRepo: tier1ThresholdRepo{values: tc.stored}}
			err := validateTier1ThresholdSettings(context.Background(), deps, tc.settings)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
