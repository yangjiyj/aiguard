package main

import (
	"errors"
	"testing"
)

func TestValidateBudgetBootstrapFailsClosedUnlessGovernorKillSwitchIsExplicit(t *testing.T) {
	bootstrapErr := errors.New("database unavailable")
	if err := validateBudgetBootstrap(false, bootstrapErr); !errors.Is(err, bootstrapErr) {
		t.Fatalf("enabled governor accepted empty bootstrap: %v", err)
	}
	if err := validateBudgetBootstrap(true, bootstrapErr); err != nil {
		t.Fatalf("explicit governor kill switch did not bypass bootstrap: %v", err)
	}
	if err := validateBudgetBootstrap(false, nil); err != nil {
		t.Fatalf("successful bootstrap rejected: %v", err)
	}
}
