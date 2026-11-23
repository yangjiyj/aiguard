package backoff

import (
	"testing"
	"time"
)

func fixed(v float64) func() float64 { return func() float64 { return v } }

func TestNextGrowsExponentiallyAndCaps(t *testing.T) {
	b := New(2*time.Second, 30*time.Second)
	b.rand = fixed(0) // 无抖动：恰好等于理论值
	want := []time.Duration{2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if got := b.Next(); got != w*time.Second {
			t.Fatalf("attempt %d: got %s want %s", i, got, w*time.Second)
		}
	}
	if b.Failures() != len(want) {
		t.Fatalf("failures=%d", b.Failures())
	}
}

func TestJitterStaysWithinBand(t *testing.T) {
	b := New(10*time.Second, time.Minute)
	b.rand = fixed(1) // 抖动取最大
	got := b.Next()
	lo := time.Duration(float64(10*time.Second) * (1 - DefaultJitter))
	if got != lo {
		t.Fatalf("max jitter delay=%s want %s", got, lo)
	}
	b.Reset()
	b.rand = fixed(0.5)
	got = b.Next()
	if got <= lo || got >= 10*time.Second {
		t.Fatalf("mid jitter delay=%s not inside (%s,%s)", got, lo, 10*time.Second)
	}
}

func TestRealRandomJitterNeverExceedsCapOrDropsBelowHalf(t *testing.T) {
	b := New(time.Second, 8*time.Second)
	for i := 0; i < 200; i++ {
		d := b.Next()
		if d > 8*time.Second || d < 500*time.Millisecond {
			t.Fatalf("attempt %d delay %s outside [0.5s, 8s]", i, d)
		}
	}
}

func TestResetStartsOver(t *testing.T) {
	b := New(time.Second, time.Minute)
	b.rand = fixed(0)
	b.Next()
	b.Next()
	b.Next()
	b.Reset()
	if b.Failures() != 0 {
		t.Fatalf("failures after reset=%d", b.Failures())
	}
	if got := b.Next(); got != time.Second {
		t.Fatalf("after reset got %s", got)
	}
}

func TestHugeFailureCountDoesNotOverflow(t *testing.T) {
	b := New(time.Second, 5*time.Minute)
	b.rand = fixed(0)
	var last time.Duration
	for i := 0; i < 5000; i++ {
		last = b.Next()
	}
	if last != 5*time.Minute {
		t.Fatalf("saturated delay=%s", last)
	}
}

func TestInvalidParametersFallBackToSafeDefaults(t *testing.T) {
	b := New(0, 0)
	b.rand = fixed(0)
	if got := b.Next(); got <= 0 {
		t.Fatalf("non-positive delay %s", got)
	}
	b = New(time.Minute, time.Second) // max < base
	b.rand = fixed(0)
	if got := b.Next(); got != time.Minute {
		t.Fatalf("max<base should clamp to base, got %s", got)
	}
}
