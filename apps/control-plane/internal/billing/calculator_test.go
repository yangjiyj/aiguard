package billing

import (
	"errors"
	"math"
	"testing"
)

func TestCalculateDirectChargeSeparatesPromptCacheUsage(t *testing.T) {
	usage := Usage{
		PromptTokens:          1_000_000,
		CachedInputTokens:     200_000,
		CacheWriteInputTokens: 100_000,
		OutputTokens:          400_000,
		ReasoningTokens:       50_000,
	}
	price := DirectPrice{
		InputPerMillionMicros:       2_000_000,
		CachedInputPerMillionMicros: 200_000,
		CacheWritePerMillionMicros:  2_500_000,
		OutputPerMillionMicros:      8_000_000,
		HasCachedInputPrice:         true,
		HasCacheWritePrice:          true,
	}

	got, err := CalculateDirectCharge(usage, price)
	if err != nil {
		t.Fatalf("calculate direct charge: %v", err)
	}
	if got.UncachedInputTokens != 700_000 {
		t.Fatalf("uncached input tokens = %d, want 700000", got.UncachedInputTokens)
	}
	if got.InputMicros != 1_400_000 || got.CachedInputMicros != 40_000 || got.CacheWriteMicros != 250_000 || got.OutputMicros != 3_200_000 {
		t.Fatalf("unexpected breakdown: %#v", got)
	}
	if got.TotalMicros != 4_890_000 {
		t.Fatalf("total = %d, want 4890000", got.TotalMicros)
	}
}

func TestApplyCustomerGroupRatioScalesEveryExplicitModelRate(t *testing.T) {
	got, err := ApplyCustomerGroupRatio(DirectPrice{
		InputPerMillionMicros:       2_000_000,
		CachedInputPerMillionMicros: 200_000,
		CacheWritePerMillionMicros:  2_500_000,
		OutputPerMillionMicros:      8_000_000,
		HasCachedInputPrice:         true,
		HasCacheWritePrice:          true,
	}, 800_000)
	if err != nil {
		t.Fatalf("apply customer group ratio: %v", err)
	}
	if got.InputPerMillionMicros != 1_600_000 || got.CachedInputPerMillionMicros != 160_000 ||
		got.CacheWritePerMillionMicros != 2_000_000 || got.OutputPerMillionMicros != 6_400_000 {
		t.Fatalf("customer group rates = %#v", got)
	}
	if !got.HasCachedInputPrice || !got.HasCacheWritePrice {
		t.Fatalf("customer group ratio dropped explicit cache prices: %#v", got)
	}
}

func TestApplyPriceRatiosCombinesCustomerAndTimeBandWithoutDoubleRounding(t *testing.T) {
	got, err := ApplyPriceRatios(DirectPrice{
		InputPerMillionMicros:  1,
		OutputPerMillionMicros: 1_000_000,
	}, 500_000, 1_500_000)
	if err != nil {
		t.Fatalf("apply combined price ratios: %v", err)
	}
	if got.InputPerMillionMicros != 1 {
		t.Fatalf("combined input rate = %d, want 1 (single final rounding)", got.InputPerMillionMicros)
	}
	if got.OutputPerMillionMicros != 750_000 {
		t.Fatalf("combined output rate = %d, want 750000", got.OutputPerMillionMicros)
	}
}

func TestCalculateDirectChargeFallsBackToInputPriceForCacheTokens(t *testing.T) {
	got, err := CalculateDirectCharge(Usage{
		PromptTokens:          100,
		CachedInputTokens:     20,
		CacheWriteInputTokens: 10,
	}, DirectPrice{InputPerMillionMicros: 1_000_000})
	if err != nil {
		t.Fatalf("calculate direct charge: %v", err)
	}
	if got.InputMicros != 70 || got.CachedInputMicros != 20 || got.CacheWriteMicros != 10 || got.TotalMicros != 100 {
		t.Fatalf("cache fallback breakdown: %#v", got)
	}
}

func TestCalculateDirectChargeRejectsImpossibleUsage(t *testing.T) {
	_, err := CalculateDirectCharge(Usage{
		PromptTokens:          10,
		CachedInputTokens:     8,
		CacheWriteInputTokens: 3,
	}, DirectPrice{InputPerMillionMicros: 1})
	if !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("error = %v, want ErrInvalidUsage", err)
	}
}

func TestCalculateDirectChargeUsesOneMicroMinimumForNonZeroComponent(t *testing.T) {
	got, err := CalculateDirectCharge(Usage{PromptTokens: 1}, DirectPrice{InputPerMillionMicros: 1})
	if err != nil {
		t.Fatalf("calculate direct charge: %v", err)
	}
	if got.TotalMicros != 1 {
		t.Fatalf("total = %d, want one micro", got.TotalMicros)
	}
}

func TestNormalizeNewAPIRatioPrice(t *testing.T) {
	got, err := NormalizeNewAPIRatioPrice(RatioPrice{
		BaseInputPerMillionMicros: 2_000_000,
		ModelRatioPPM:             1_500_000,
		CompletionRatioPPM:        2_000_000,
		GroupRatioPPM:             800_000,
		CachedInputRatioPPM:       250_000,
		CacheWriteRatioPPM:        1_250_000,
	})
	if err != nil {
		t.Fatalf("normalize ratio price: %v", err)
	}
	if got.InputPerMillionMicros != 2_400_000 {
		t.Fatalf("input price = %d, want 2400000", got.InputPerMillionMicros)
	}
	if got.OutputPerMillionMicros != 4_800_000 {
		t.Fatalf("output price = %d, want 4800000", got.OutputPerMillionMicros)
	}
	if got.CachedInputPerMillionMicros != 600_000 {
		t.Fatalf("cached input price = %d, want 600000", got.CachedInputPerMillionMicros)
	}
	if got.CacheWritePerMillionMicros != 3_000_000 {
		t.Fatalf("cache write price = %d, want 3000000", got.CacheWritePerMillionMicros)
	}
	if !got.HasCachedInputPrice || !got.HasCacheWritePrice {
		t.Fatalf("normalized cache prices must be explicit: %#v", got)
	}
}

func TestNormalizeNewAPIRatioPriceDefaultsOptionalRatios(t *testing.T) {
	got, err := NormalizeNewAPIRatioPrice(RatioPrice{
		BaseInputPerMillionMicros: 3_000_000,
		ModelRatioPPM:             1_000_000,
		CompletionRatioPPM:        1_000_000,
		GroupRatioPPM:             1_000_000,
	})
	if err != nil {
		t.Fatalf("normalize ratio price: %v", err)
	}
	if got.InputPerMillionMicros != 3_000_000 || got.OutputPerMillionMicros != 3_000_000 {
		t.Fatalf("default normalized price: %#v", got)
	}
	if got.HasCachedInputPrice || got.HasCacheWritePrice {
		t.Fatalf("absent cache ratios must retain input-price fallback: %#v", got)
	}
}

func TestNormalizeNewAPIRatioPricePreservesExplicitZeroRatio(t *testing.T) {
	got, err := NormalizeNewAPIRatioPrice(RatioPrice{
		BaseInputPerMillionMicros: 3_000_000,
		ModelRatioPPM:             0,
		CompletionRatioPPM:        1_000_000,
		GroupRatioPPM:             1_000_000,
	})
	if err != nil {
		t.Fatalf("normalize free ratio: %v", err)
	}
	if got.InputPerMillionMicros != 0 || got.OutputPerMillionMicros != 0 {
		t.Fatalf("explicit zero ratio was not preserved: %#v", got)
	}
}

func TestNormalizeNewAPIRatioPriceRoundsCombinedRatiosOnce(t *testing.T) {
	got, err := NormalizeNewAPIRatioPrice(RatioPrice{
		BaseInputPerMillionMicros: 10,
		ModelRatioPPM:             510_000,
		GroupRatioPPM:             510_000,
	})
	if err != nil {
		t.Fatalf("normalize ratio price: %v", err)
	}
	if got.InputPerMillionMicros != 3 {
		t.Fatalf("input price = %d, want 3 after one final rounding", got.InputPerMillionMicros)
	}
}

func TestNormalizeNewAPIRatioPriceDoesNotReuseRoundedInputForOutput(t *testing.T) {
	got, err := NormalizeNewAPIRatioPrice(RatioPrice{
		BaseInputPerMillionMicros: 2,
		ModelRatioPPM:             510_000,
		GroupRatioPPM:             990_000,
		CompletionRatioPPM:        510_000,
	})
	if err != nil {
		t.Fatalf("normalize ratio price: %v", err)
	}
	if got.InputPerMillionMicros != 2 || got.OutputPerMillionMicros != 1 {
		t.Fatalf("normalized prices = input:%d output:%d, want 2/1", got.InputPerMillionMicros, got.OutputPerMillionMicros)
	}
}

func TestNormalizeNewAPIRatioPriceSupportsExplicitFreeCacheRead(t *testing.T) {
	got, err := NormalizeNewAPIRatioPrice(RatioPrice{
		BaseInputPerMillionMicros: 2_000_000,
		ModelRatioPPM:             1_000_000,
		HasCachedInputRatio:       true,
		CachedInputRatioPPM:       0,
	})
	if err != nil {
		t.Fatalf("normalize ratio price: %v", err)
	}
	if !got.HasCachedInputPrice || got.CachedInputPerMillionMicros != 0 {
		t.Fatalf("explicit free cache read was not preserved: %#v", got)
	}
}

func TestWalletStateReserveFailsClosedWhenAvailableWouldUnderflow(t *testing.T) {
	state := WalletState{BalanceMicros: Micros(math.MinInt64 + 1), ReservedMicros: 5}
	_, err := state.Reserve(1)
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("error = %v, want ErrInsufficientBalance", err)
	}
}

func TestWalletStateReserveSettleAndRelease(t *testing.T) {
	state := WalletState{BalanceMicros: 10_000_000}
	reserved, err := state.Reserve(3_000_000)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if reserved.AvailableMicros() != 7_000_000 {
		t.Fatalf("available after reserve = %d", reserved.AvailableMicros())
	}
	settled, err := reserved.Settle(3_000_000, 3_500_000)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if settled.BalanceMicros != 6_500_000 || settled.ReservedMicros != 0 {
		t.Fatalf("settled state: %#v", settled)
	}

	reserved, err = settled.Reserve(1_000_000)
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	released, err := reserved.Release(1_000_000)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released != settled {
		t.Fatalf("released state = %#v, want %#v", released, settled)
	}
}

func TestWalletStateReserveFailsClosed(t *testing.T) {
	state := WalletState{BalanceMicros: 10, ReservedMicros: 8}
	_, err := state.Reserve(3)
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("error = %v, want ErrInsufficientBalance", err)
	}
}

// D5: the upstream cost is already incurred, so settlement books the actual
// amount even when it overdraws the wallet; the ledger marks it overdraft.
func TestWalletStateSettleBooksActualAmountWhenOverdrawn(t *testing.T) {
	before := WalletState{BalanceMicros: 100, ReservedMicros: 90}
	after, err := before.Settle(60, 80)
	if err != nil {
		t.Fatalf("overdrawing settlement must book the actual amount: %v", err)
	}
	if after.BalanceMicros != 20 || after.ReservedMicros != 30 || after.AvailableMicros() != -10 || !after.Overdrawn() {
		t.Fatalf("settled state = %#v, want balance 20 reserved 30 available -10", after)
	}
	meta := OverdraftLedgerMetadata(before, after)
	if meta["overdraft"] != true || meta["available_before_micros"] != int64(10) || meta["available_after_micros"] != int64(-10) {
		t.Fatalf("overdraft metadata = %#v", meta)
	}

	negative, err := (WalletState{BalanceMicros: 50, ReservedMicros: 50}).Settle(50, 70)
	if err != nil || negative.BalanceMicros != -20 || negative.ReservedMicros != 0 {
		t.Fatalf("settlement below zero = %#v err=%v, want balance -20", negative, err)
	}
	covered, err := (WalletState{BalanceMicros: 100, ReservedMicros: 50}).Settle(50, 40)
	if err != nil || covered.Overdrawn() || OverdraftLedgerMetadata(WalletState{BalanceMicros: 100, ReservedMicros: 50}, covered) != nil {
		t.Fatalf("covered settlement flagged overdraft: %#v err=%v", covered, err)
	}
}

// D5: once the balance is zero or negative, the next admission is refused
// (402) and there is no overdraft credit line.
func TestWalletStateReserveRefusesEmptyOrOverdrawnWallet(t *testing.T) {
	for _, state := range []WalletState{{BalanceMicros: 0}, {BalanceMicros: -1}, {BalanceMicros: -500, ReservedMicros: 0}} {
		if _, err := state.Reserve(1); !errors.Is(err, ErrInsufficientBalance) {
			t.Fatalf("reserve on %#v error = %v, want ErrInsufficientBalance", state, err)
		}
	}
	if _, err := (WalletState{BalanceMicros: 1}).Reserve(1); err != nil {
		t.Fatalf("fully covered reserve: %v", err)
	}
}

func TestAddMicrosRejectsNegativeUnderflow(t *testing.T) {
	if _, err := addMicros(Micros(math.MinInt64), -1); !errors.Is(err, ErrAmountOverflow) {
		t.Fatalf("underflow error = %v, want ErrAmountOverflow", err)
	}
}
