package modelrouter

import (
	"fmt"
	"testing"
)

func TestCanaryHitStable(t *testing.T) {
	key := "tenant-abc:req-123"
	// Call multiple times — must be deterministic
	first := CanaryHit(key, 50)
	for i := 0; i < 100; i++ {
		if CanaryHit(key, 50) != first {
			t.Errorf("CanaryHit not stable: iteration %d returned different result", i)
		}
	}
}

func TestCanaryRatioZero(t *testing.T) {
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key-%d", i)
		if CanaryHit(key, 0) {
			t.Errorf("ratio=0: expected false for key %s", key)
		}
	}
}

func TestCanaryRatioHundred(t *testing.T) {
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key-%d", i)
		if !CanaryHit(key, 100) {
			t.Errorf("ratio=100: expected true for key %s", key)
		}
	}
}

func TestCanaryRatioDistribution(t *testing.T) {
	ratio := 10
	total := 10000
	hits := 0
	for i := 0; i < total; i++ {
		key := fmt.Sprintf("request-%d", i)
		if CanaryHit(key, ratio) {
			hits++
		}
	}
	pct := float64(hits) / float64(total) * 100
	// Expect 8%–12%
	if pct < 8.0 || pct > 12.0 {
		t.Errorf("ratio=10 distribution: got %.2f%% hits (expected 8%%–12%%)", pct)
	}
}
