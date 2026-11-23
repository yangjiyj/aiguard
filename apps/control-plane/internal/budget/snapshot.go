package budget

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ScopeUsage holds the aggregated usage counters for a single scope.
// Money is integer micros (1 CNY = 1_000_000); no float is involved.
//
// Cost quality is tracked per period because the gateway's settlement Lua
// increments cost_estimated_requests / cost_unpriced_requests on the month and
// day hash independently, and a request settling across a UTC or timezone
// boundary lands in two different periods. A month-level quality figure
// therefore cannot be reused for the day view, and the two are reported
// separately rather than merged.
type ScopeUsage struct {
	MonthTokens     int64
	MonthCostMicros int64
	MonthRequests   int64
	DayTokens       int64
	DayCostMicros   int64
	DayRequests     int64
	Rpm             int64
	Concurrency     int64
	MonthBucket     string
	DayBucket       string

	// Cost-quality counters written by the gateway settlement script
	// (atomic_admission_money_lua.go): one increment per settled request whose
	// cost was an estimate, or which had no price at all. Month and day are
	// separate counters on separate keys.
	MonthCostEstimatedRequests int64
	MonthCostUnpricedRequests  int64
	DayCostEstimatedRequests   int64
	DayCostUnpricedRequests    int64
	MonthFields                map[string]bool
	DayFields                  map[string]bool
}

// CostQuality classifies how much of a window's settled money is a real price.
//
// The gateway's settle script increments cost_micros unconditionally, so that
// total blends actual, estimated and unpriced money, while the quality counters
// say how many settled requests fell short of an actual price.
//
// There is deliberately NO "actual" label. Proving every request in a bucket
// was really priced would need a per-bucket count of settled requests to compare
// the degraded counters against, and no such total exists on the budget hash:
// `requests` is written by a different writer (the usage Aggregator) than the one
// that writes cost_estimated_requests / cost_unpriced_requests (admission
// settle), so the two cannot be reconciled. Absence of the counters is not proof
// either — a bucket written before the gateway began recording them has none, and
// a bucket whose only traffic predates them is indistinguishable. So a bucket with
// no positive counter is unknown, never actual: only a positive counter is real
// evidence of degradation, and the observed money is reported beside it untouched.
type CostQuality string

const (
	// CostQualityUnknown means no evidence either way: no money, or money with
	// no recorded quality counters to vouch for it. It is never upgraded to a
	// clean "actual".
	CostQualityUnknown CostQuality = "unknown"
	// CostQualityEstimated means at least one request was billed from an
	// estimate rather than a final price.
	CostQualityEstimated CostQuality = "estimated"
	// CostQualityUnpriced means at least one request had neither an actual
	// price nor an estimate, so the total understates real spend. It outranks
	// estimated: those requests contributed no billable figure at all.
	CostQualityUnpriced CostQuality = "unpriced"
)

// ClassifyCostQuality labels one window from its quality counters. Only a
// positive counter is evidence; see CostQuality for why "actual" is unreachable.
// The observed total never influences the label and is never adjusted by it.
func ClassifyCostQuality(totalMicros, estimatedRequests, unpricedRequests int64) CostQuality {
	_ = totalMicros // kept in the signature: the caller reports money beside the label
	switch {
	case unpricedRequests > 0:
		return CostQualityUnpriced
	case estimatedRequests > 0:
		return CostQualityEstimated
	default:
		return CostQualityUnknown
	}
}

// SnapshotScope identifies one scope to read. Timezone is the scope's policy
// quota_timezone; empty means DefaultQuotaTimezone, the bucket
// AtomicAdmission uses for scopes that only have accounting (no policy).
type SnapshotScope struct {
	Scope    string
	ID       string
	Timezone string
}

// SnapshotReader reads live usage snapshots from Redis in a single pipeline.
// It reads the keys gateway-core AtomicAdmission writes: budget hash field
// cost_micros in the timezone-suffixed bucket, the orgquota rpm STRING for the
// current minute, and the orgquota concurrency ZSET of unexpired leases.
type SnapshotReader struct {
	rdb *redis.Client
}

// NewSnapshotReader creates a new SnapshotReader.
func NewSnapshotReader(rdb *redis.Client) *SnapshotReader {
	return &SnapshotReader{rdb: rdb}
}

// Get returns current usage for each scope using a single pipelined round-trip.
// Keys in the returned map follow the pattern "scope:id" (e.g. "project:pj1").
// Periods and the rpm minute use Redis server time, like the writer.
func (s *SnapshotReader) Get(ctx context.Context, tenantID string, scopes []SnapshotScope) (map[string]ScopeUsage, error) {
	type entry struct {
		scope, id  string
		monthKey   string
		dayKey     string
		month, day *redis.MapStringStringCmd
		rpm        *redis.StringCmd
		conc       *redis.IntCmd
	}
	now, err := s.rdb.Time(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("budget snapshot redis time: %w", err)
	}

	pipe := s.rdb.Pipeline()
	cmds := make([]entry, 0, len(scopes))
	for _, sk := range scopes {
		if sk.ID == "" {
			continue
		}
		timezone := NormalizedQuotaTimezone(sk.Timezone)
		location, err := time.LoadLocation(timezone)
		if err != nil {
			return nil, fmt.Errorf("budget snapshot %s: invalid quota timezone %q: %w", sk.Scope, timezone, err)
		}
		local := now.In(location)
		monthBucket := QuotaPeriodBucket(timezone, local.Format("2006-01"))
		dayBucket := QuotaPeriodBucket(timezone, local.Format("2006-01-02"))
		cmds = append(cmds, entry{
			scope:    sk.Scope,
			id:       sk.ID,
			monthKey: monthBucket,
			dayKey:   dayBucket,
			month:    pipe.HGetAll(ctx, BudgetKey(sk.Scope, sk.ID, monthBucket)),
			day:      pipe.HGetAll(ctx, BudgetKeyDay(sk.Scope, sk.ID, dayBucket)),
			rpm:      pipe.Get(ctx, RpmKey(tenantID, sk.Scope, sk.ID, now.Unix()/60)),
			conc:     pipe.ZCount(ctx, ConcurrencyKey(tenantID, sk.Scope, sk.ID), "("+strconv.FormatInt(now.UnixMilli(), 10), "+inf"),
		})
	}
	if len(cmds) == 0 {
		return map[string]ScopeUsage{}, nil
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, fmt.Errorf("budget snapshot redis pipeline: %w", err)
	}

	out := make(map[string]ScopeUsage, len(cmds))
	for _, c := range cmds {
		u := ScopeUsage{MonthBucket: c.monthKey, DayBucket: c.dayKey}
		if m, err := c.month.Result(); err == nil {
			u.MonthFields = usagePresence(m)
			if err := validatePresentUsage(m, c.scope); err != nil {
				return nil, err
			}
			if u.MonthTokens, err = parseUsageInt(m["tokens"], c.scope, "month tokens"); err != nil {
				return nil, err
			}
			if u.MonthCostMicros, err = parseUsageInt(m["cost_micros"], c.scope, "month cost_micros"); err != nil {
				return nil, err
			}
			if u.MonthRequests, err = parseUsageInt(m["requests"], c.scope, "month requests"); err != nil {
				return nil, err
			}
			// Cost-quality counters: absent on buckets written before the
			// gateway started recording them, which parseUsageInt reports as 0
			// (no evidence, not a measured zero).
			if u.MonthCostEstimatedRequests, err = parseUsageInt(m["cost_estimated_requests"], c.scope, "month cost_estimated_requests"); err != nil {
				return nil, err
			}
			if u.MonthCostUnpricedRequests, err = parseUsageInt(m["cost_unpriced_requests"], c.scope, "month cost_unpriced_requests"); err != nil {
				return nil, err
			}
		} else if err != redis.Nil {
			return nil, fmt.Errorf("budget snapshot %s month: %w", c.scope, err)
		}
		if d, err := c.day.Result(); err == nil {
			u.DayFields = usagePresence(d)
			if err := validatePresentUsage(d, c.scope); err != nil {
				return nil, err
			}
			if u.DayTokens, err = parseUsageInt(d["tokens"], c.scope, "day tokens"); err != nil {
				return nil, err
			}
			if u.DayCostMicros, err = parseUsageInt(d["cost_micros"], c.scope, "day cost_micros"); err != nil {
				return nil, err
			}
			if u.DayRequests, err = parseUsageInt(d["requests"], c.scope, "day requests"); err != nil {
				return nil, err
			}
			if u.DayCostEstimatedRequests, err = parseUsageInt(d["cost_estimated_requests"], c.scope, "day cost_estimated_requests"); err != nil {
				return nil, err
			}
			if u.DayCostUnpricedRequests, err = parseUsageInt(d["cost_unpriced_requests"], c.scope, "day cost_unpriced_requests"); err != nil {
				return nil, err
			}
		} else if err != redis.Nil {
			return nil, fmt.Errorf("budget snapshot %s day: %w", c.scope, err)
		}
		if rv, err := c.rpm.Result(); err == nil {
			if u.Rpm, err = parseUsageInt(rv, c.scope, "rpm"); err != nil {
				return nil, err
			}
		} else if err != redis.Nil {
			return nil, fmt.Errorf("budget snapshot %s rpm: %w", c.scope, err)
		}
		conc, err := c.conc.Result()
		if err != nil && err != redis.Nil {
			return nil, fmt.Errorf("budget snapshot %s concurrency: %w", c.scope, err)
		}
		u.Concurrency = conc
		out[c.scope+":"+c.id] = u
	}
	return out, nil
}

func validatePresentUsage(values map[string]string, scope string) error {
	for _, field := range []string{"tokens", "requests", "cost_micros", "cost_estimated_requests", "cost_unpriced_requests"} {
		if value, ok := values[field]; ok && value == "" {
			return fmt.Errorf("budget snapshot %s %s: empty counter", scope, field)
		}
	}
	return nil
}

func usagePresence(values map[string]string) map[string]bool {
	presence := make(map[string]bool, 5)
	for _, field := range []string{"tokens", "requests", "cost_micros", "cost_estimated_requests", "cost_unpriced_requests"} {
		_, presence[field] = values[field]
	}
	return presence
}

func parseUsageInt(value, scope, field string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("budget snapshot %s %s: %w", scope, field, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("budget snapshot %s %s: negative counter", scope, field)
	}
	return parsed, nil
}

// FormatMicrosCNY renders integer micros as an exact decimal string with six
// fraction digits trimmed of trailing zeros (e.g. 3234567 -> "3.234567").
func FormatMicrosCNY(micros int64) string {
	negative := micros < 0
	magnitude := uint64(micros)
	if negative {
		magnitude = uint64(-(micros + 1)) + 1
	}
	whole := magnitude / 1_000_000
	frac := magnitude % 1_000_000
	text := strconv.FormatUint(whole, 10)
	if frac != 0 {
		fraction := fmt.Sprintf("%06d", frac)
		for len(fraction) > 0 && fraction[len(fraction)-1] == '0' {
			fraction = fraction[:len(fraction)-1]
		}
		text += "." + fraction
	}
	if negative {
		text = "-" + text
	}
	return text
}
