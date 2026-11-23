package security

import (
	"context"
	"net/http"
	"strconv"
	"sync"
)

// Advisory per-message-segment fingerprint counters sent to security-engine
// with a /check-input/batch call. The gateway is the only component that knows
// which history/tool segments were served from the scanfp cache; the engine
// uses these numbers for /metrics only. They never change a detection
// decision, and a missing or malformed header is a no-op on both sides.
const (
	FingerprintChecksHeader = "X-JJD-FP-Checks"
	FingerprintHitsHeader   = "X-JJD-FP-Hits"
	maxFingerprintStat      = 10000
)

// FingerprintStats counts one lookup per candidate message segment; Hits is
// the subset answered from the fingerprint cache (scan_mode=fingerprint_reuse).
type FingerprintStats struct {
	Checks int
	Hits   int
}

type fingerprintStatsRef struct {
	once  sync.Once
	stats FingerprintStats
}

type fingerprintStatsKey struct{}

// WithFingerprintStats attaches advisory stats for exactly one logical batch.
// CheckInputBatch may split a large batch into several HTTP chunks; the stats
// must be reported once, not once per chunk.
func WithFingerprintStats(ctx context.Context, stats FingerprintStats) context.Context {
	if stats.Checks < 0 {
		stats.Checks = 0
	}
	if stats.Hits < 0 {
		stats.Hits = 0
	}
	if stats.Checks > maxFingerprintStat {
		stats.Checks = maxFingerprintStat
	}
	if stats.Hits > stats.Checks {
		stats.Hits = stats.Checks
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, fingerprintStatsKey{}, &fingerprintStatsRef{stats: stats})
}

func fingerprintStatsRefFromContext(ctx context.Context) *fingerprintStatsRef {
	if ctx == nil {
		return nil
	}
	ref, _ := ctx.Value(fingerprintStatsKey{}).(*fingerprintStatsRef)
	return ref
}

func applyFingerprintStatsHeaders(ctx context.Context, req *http.Request) {
	ref := fingerprintStatsRefFromContext(ctx)
	if ref == nil || req == nil {
		return
	}
	ref.once.Do(func() {
		if ref.stats.Checks <= 0 {
			return
		}
		req.Header.Set(FingerprintChecksHeader, strconv.Itoa(ref.stats.Checks))
		req.Header.Set(FingerprintHitsHeader, strconv.Itoa(ref.stats.Hits))
	})
}
