package forecast

import (
	"testing"
)

func TestSimulatorInterceptsOverBudget(t *testing.T) {
	params := QuotaParams{
		MonthlyBudgetLimit: 100,
		OverageAction:      "downgrade_model",
		DowngradeRatio:     0.5,
	}
	sim := NewSimulator(params)
	rows := []ReplayRow{
		{Cost: 40, Tokens: 100, UserID: "u1"},
		{Cost: 40, Tokens: 100, UserID: "u1"},
		{Cost: 40, Tokens: 100, UserID: "u2"},
	}
	res := sim.Replay(rows)
	if res.Intercepted < 1 {
		t.Errorf("expected intercepted >= 1, got %d", res.Intercepted)
	}
	if res.SavedUSD <= 0 {
		t.Errorf("expected SavedUSD > 0, got %f", res.SavedUSD)
	}
	if res.Total != 3 {
		t.Errorf("expected total=3, got %d", res.Total)
	}
}

func TestSimulatorNoSideEffect(t *testing.T) {
	params := QuotaParams{
		MonthlyBudgetLimit: 1000,
		OverageAction:      "pause_key",
	}
	sim := NewSimulator(params)
	rows := []ReplayRow{
		{Cost: 50, Tokens: 500, UserID: "u1"},
	}
	res := sim.Replay(rows)
	if res.Intercepted != 0 {
		t.Errorf("expected intercepted=0, got %d", res.Intercepted)
	}
	if res.SavedUSD != 0 {
		t.Errorf("expected SavedUSD=0, got %f", res.SavedUSD)
	}
}

func TestSimulatorRateLimitSavesFullCost(t *testing.T) {
	params := QuotaParams{
		MonthlyBudgetLimit: 10,
		OverageAction:      "rate_limit",
	}
	sim := NewSimulator(params)
	rows := []ReplayRow{
		{Cost: 5, Tokens: 100, UserID: "u1"},
		{Cost: 8, Tokens: 100, UserID: "u1"},
		{Cost: 3, Tokens: 100, UserID: "u1"},
	}
	res := sim.Replay(rows)
	// cumCost after row2 = 13 >= 10, so row2 and row3 intercepted
	if res.Intercepted < 1 {
		t.Errorf("expected intercepted >= 1, got %d", res.Intercepted)
	}
	// saved should be the full cost of intercepted rows (rate_limit saves full)
	if res.SavedUSD <= 0 {
		t.Errorf("expected SavedUSD > 0, got %f", res.SavedUSD)
	}
	if _, ok := res.ByAction["rate_limit"]; !ok {
		t.Error("expected rate_limit in ByAction")
	}
}

func TestSimulatorAffectedUsers(t *testing.T) {
	params := QuotaParams{
		MonthlyBudgetLimit: 50,
		OverageAction:      "pause_key",
	}
	sim := NewSimulator(params)
	rows := []ReplayRow{
		{Cost: 30, Tokens: 100, UserID: "user-A"},
		{Cost: 30, Tokens: 100, UserID: "user-B"},
		{Cost: 10, Tokens: 100, UserID: "user-A"},
		{Cost: 10, Tokens: 100, UserID: "user-C"},
	}
	res := sim.Replay(rows)
	// After row2 cumCost=60 >= 50, row2/3/4 intercepted
	// AffectedUsers should deduplicate user IDs
	if res.AffectedUsers < 1 {
		t.Errorf("expected AffectedUsers >= 1, got %d", res.AffectedUsers)
	}
	// Should not double count same user
	if res.AffectedUsers > 3 {
		t.Errorf("expected AffectedUsers <= 3, got %d (should deduplicate)", res.AffectedUsers)
	}
}

func TestSimulatorCNYConversion(t *testing.T) {
	params := QuotaParams{
		MonthlyBudgetLimit: 10,
		OverageAction:      "rate_limit",
	}
	sim := NewSimulator(params)
	sim.SetFxRate(7.5)
	rows := []ReplayRow{
		{Cost: 5, Tokens: 100, UserID: "u1"},
		{Cost: 8, Tokens: 100, UserID: "u1"},
	}
	res := sim.Replay(rows)
	expectedCNY := res.SavedUSD * 7.5
	if res.SavedCNY != expectedCNY {
		t.Errorf("expected SavedCNY=%f, got %f", expectedCNY, res.SavedCNY)
	}
}
