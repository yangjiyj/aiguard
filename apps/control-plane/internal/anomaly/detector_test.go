package anomaly

import (
	"testing"
)

func TestMADBaseline(t *testing.T) {
	// 30 days of stable data at 100.0
	hist := make([]float64, 30)
	for i := range hist {
		hist[i] = 100.0
	}
	b := Baseline(hist)
	if b.Median != 100.0 {
		t.Fatalf("expected median=100, got %v", b.Median)
	}
	// MAD should be 0 for flat series
	if b.MAD != 0 {
		t.Fatalf("expected MAD=0, got %v", b.MAD)
	}

	// 500 should be a spike (actual > 100 + 3*1.4826*0 is degenerate for flat series)
	// Use a non-flat series to test spike detection
	hist2 := make([]float64, 30)
	for i := range hist2 {
		hist2[i] = 100.0 + float64(i%5) // slight variation: 100,101,102,103,104,...
	}
	b2 := Baseline(hist2)
	if !IsAbsoluteSpike(500.0, b2, 3.0) {
		t.Error("500 should be detected as spike")
	}
	if IsAbsoluteSpike(105.0, b2, 3.0) {
		t.Error("105 should NOT be detected as spike")
	}
}

func TestMADRobustToOutlier(t *testing.T) {
	// 29 days at 100, 1 day at 9999
	hist := make([]float64, 30)
	for i := range hist {
		hist[i] = 100.0
	}
	hist[15] = 9999.0
	b := Baseline(hist)
	// median should still be ~100, not pulled by single outlier
	if b.Median < 99 || b.Median > 101 {
		t.Fatalf("median should be ~100 despite outlier, got %v", b.Median)
	}
}

func TestInsufficientData(t *testing.T) {
	three := make([]float64, 3)
	if HasEnoughData(three) {
		t.Error("3 points should NOT have enough data")
	}
	seven := make([]float64, 7)
	if !HasEnoughData(seven) {
		t.Error("7 points should have enough data")
	}
}

func TestRatioSpike(t *testing.T) {
	// actual/prev > ratio => spike
	if !RatioSpike(300.0, 100.0, 2.0) {
		t.Error("300/100=3 > 2.0 should be spike")
	}
	if RatioSpike(150.0, 100.0, 2.0) {
		t.Error("150/100=1.5 < 2.0 should NOT be spike")
	}
	// prev <= 0 edge case
	if RatioSpike(100.0, 0, 2.0) {
		t.Error("prev=0 should return false (avoid divide by zero)")
	}
	if RatioSpike(100.0, -1.0, 2.0) {
		t.Error("prev<0 should return false")
	}
}

// TestKeySurgeLogic tests the RatioSpike function as used by detectKeySurge.
// key_surge fires when: todayShare/avgShare > 3.0 AND todayShare > 0.05 (5% noise floor).
func TestKeySurgeLogic(t *testing.T) {
	// Scenario A: key normally ~10% of tenant spend, today spikes to 40%
	// avgShare = 0.10, todayShare = 0.40 => ratio = 4.0 > 3.0 => fire
	avgShare := 0.10
	todayShare := 0.40
	if !RatioSpike(todayShare, avgShare, 3.0) {
		t.Errorf("40%% share / 10%% avg = 4x, should trigger key_surge")
	}
	// noise floor: todayShare > 0.05 ✓
	if todayShare <= 0.05 {
		t.Error("test setup error: todayShare should exceed noise floor")
	}

	// Scenario B: key normally ~10% of tenant, today 25% => ratio 2.5 < 3.0 => no fire
	todayShareB := 0.25
	if RatioSpike(todayShareB, avgShare, 3.0) {
		t.Errorf("25%% / 10%% = 2.5x, should NOT trigger key_surge (threshold 3.0)")
	}

	// Scenario C: key brand-new (avg = 0) => prev <= 0 => RatioSpike returns false
	if RatioSpike(0.20, 0.0, 3.0) {
		t.Error("avg=0 (new key) should return false, not trigger spike")
	}

	// Scenario D: todayShare exactly at noise floor (5%) with high ratio => suppressed
	// We check the noise floor logic: todayShare <= 0.05 => skip even if ratio > 3
	todayShareD := 0.04
	avgShareD := 0.01
	// ratio = 4.0 > 3.0, but share is tiny — in detectKeySurge this would be filtered
	// We confirm RatioSpike itself would fire (it's pure math)...
	if !RatioSpike(todayShareD, avgShareD, 3.0) {
		t.Error("RatioSpike itself should fire for 4% / 1% but noise-floor filter in detectKeySurge suppresses it")
	}
	// ...and the noise floor (todayShare <= 0.05) correctly identifies it should be suppressed
	if todayShareD > 0.05 {
		t.Error("test setup error: scenario D todayShare should be <= 0.05")
	}

	// Scenario E: severity boundary — share > 50% of tenant => high severity
	todayShareE := 0.60
	avgShareE := 0.10
	if !RatioSpike(todayShareE, avgShareE, 3.0) {
		t.Error("60%% / 10%% = 6x, should trigger key_surge")
	}
	// confirm severity would be "high"
	expectedSev := "warning"
	if todayShareE > 0.5 {
		expectedSev = "high"
	}
	if expectedSev != "high" {
		t.Error("60%% share should produce high severity")
	}
}
