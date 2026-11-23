package providers

import (
	"context"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
)

// SnapshotReader reads live usage snapshots from Redis in a single pipeline.
// It reads exactly the keys AtomicAdmission writes:
//   - budget:<scope>:<id>:<bucket> hash field cost_micros (int64 micros) and tokens,
//     where <bucket> carries the policy's quota_timezone suffix (see quotaPeriodBucket);
//   - orgquota:{tenant}:rpm:<scope>:<b64 id>:<minute> (STRING counter);
//   - orgquota:{tenant}:concurrency:<scope>:<b64 id> (ZSET, score = lease expiry ms).
//
// rpm/concurrency counters only exist for scopes whose policy sets the
// corresponding limit; other scopes report 0 because nothing is tracked.
type SnapshotReader struct {
	rdb *redis.Client
}

type snapshotScope struct {
	scope    string
	id       string
	timezone string
}

func snapshotScopes(ref governor.ScopeRef) []snapshotScope {
	return []snapshotScope{
		{"tenant", ref.TenantID, ""},
		{"team", ref.TeamID, ""},
		{"project", ref.ProjectID, ""},
		{"user", ref.UserID, ""},
		{"key", ref.KeyID, ""},
	}
}

// NewSnapshotReader creates a new SnapshotReader.
func NewSnapshotReader(rdb *redis.Client) *SnapshotReader {
	return &SnapshotReader{rdb: rdb}
}

// GetMulti returns the current usage snapshot for all non-empty scopes
// in the ScopeRef, reading monthly and daily buckets in one pipeline round-trip.
// Scopes without a policy are accounted in the Asia/Shanghai bucket.
// The returned map key is "scope:id" (e.g. "project:pj1").
func (s *SnapshotReader) GetMulti(ctx context.Context, ref governor.ScopeRef) (map[string]governor.Snapshot, error) {
	return s.getScopes(ctx, ref.TenantID, snapshotScopes(ref))
}

// GetScoped includes every policy/accounting scope returned by QuotaCache,
// including application-team ancestors that are not representable by ScopeRef.TeamID.
// A scope governed by a policy is read from that policy's quota_timezone bucket,
// matching AtomicAdmission (the last policy for a scope wins, as in atomicAdmissionScopes).
func (s *SnapshotReader) GetScoped(ctx context.Context, ref governor.ScopeRef, quotas []governor.ScopedQuota) (map[string]governor.Snapshot, error) {
	timezones := make(map[string]string, len(quotas))
	pairs := make([]snapshotScope, 0, len(quotas)+5)
	for _, quota := range quotas {
		pairs = append(pairs, snapshotScope{scope: quota.Scope, id: quota.ID})
		timezones[quota.Scope+"\x00"+quota.ID] = quota.Limits.QuotaTimezone
	}
	pairs = append(pairs, snapshotScopes(ref)...)
	for index := range pairs {
		pairs[index].timezone = timezones[pairs[index].scope+"\x00"+pairs[index].id]
	}
	return s.getScopes(ctx, ref.TenantID, pairs)
}

func (s *SnapshotReader) getScopes(ctx context.Context, tenantID string, pairs []snapshotScope) (map[string]governor.Snapshot, error) {
	type entry struct {
		scope, id  string
		month, day *redis.MapStringStringCmd
		rpm        *redis.StringCmd
		conc       *redis.IntCmd
	}

	candidates := make([]snapshotScope, 0, len(pairs))
	seen := make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		if pair.id == "" {
			continue
		}
		key := pair.scope + "\x00" + pair.id
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, pair)
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	// Minute buckets and lease expiry scores are written with Redis server time.
	now, err := s.rdb.Time(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("quota snapshot redis time: %w", err)
	}

	pipe := s.rdb.Pipeline()
	cmds := make([]entry, 0, len(candidates))
	for _, pair := range candidates {
		month, day, _, _, periodErr := admissionPeriodsForTimezone(now, pair.timezone)
		if periodErr != nil {
			return nil, fmt.Errorf("quota snapshot %s: %w", pair.scope, periodErr)
		}
		scope := governor.AdmissionScope{Scope: pair.scope, ID: pair.id}
		cmds = append(cmds, entry{
			scope: pair.scope,
			id:    pair.id,
			month: pipe.HGetAll(ctx, BudgetKey(pair.scope, pair.id, quotaPeriodBucket(pair.timezone, month))),
			day:   pipe.HGetAll(ctx, BudgetKeyDay(pair.scope, pair.id, quotaPeriodBucket(pair.timezone, day))),
			rpm:   pipe.Get(ctx, atomicRPMKey(tenantID, scope, now.Unix()/60)),
			conc:  pipe.ZCount(ctx, atomicConcurrencyKey(tenantID, scope), "("+strconv.FormatInt(now.UnixMilli(), 10), "+inf"),
		})
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, fmt.Errorf("quota snapshot redis pipeline: %w", err)
	}

	out := make(map[string]governor.Snapshot, len(cmds))
	for _, c := range cmds {
		var snap governor.Snapshot

		if m, err := c.month.Result(); err == nil {
			if snap.MonthTokens, err = parseSnapshotInt(m["tokens"], c.scope, "month tokens"); err != nil {
				return nil, err
			}
			if snap.MonthCostMicros, err = parseSnapshotInt(m["cost_micros"], c.scope, "month cost_micros"); err != nil {
				return nil, err
			}
		} else if err != redis.Nil {
			return nil, fmt.Errorf("quota snapshot %s month: %w", c.scope, err)
		}
		if d, err := c.day.Result(); err == nil {
			if snap.DayTokens, err = parseSnapshotInt(d["tokens"], c.scope, "day tokens"); err != nil {
				return nil, err
			}
			if snap.DayCostMicros, err = parseSnapshotInt(d["cost_micros"], c.scope, "day cost_micros"); err != nil {
				return nil, err
			}
		} else if err != redis.Nil {
			return nil, fmt.Errorf("quota snapshot %s day: %w", c.scope, err)
		}
		if rv, err := c.rpm.Result(); err == nil {
			if snap.Rpm, err = parseSnapshotInt(rv, c.scope, "rpm"); err != nil {
				return nil, err
			}
		} else if err != redis.Nil {
			return nil, fmt.Errorf("quota snapshot %s rpm: %w", c.scope, err)
		}
		conc, err := c.conc.Result()
		if err != nil && err != redis.Nil {
			return nil, fmt.Errorf("quota snapshot %s concurrency: %w", c.scope, err)
		}
		snap.Concurrency = conc

		out[c.scope+":"+c.id] = snap
	}
	return out, nil
}

func parseSnapshotInt(value, scope, field string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("quota snapshot %s %s: %w", scope, field, err)
	}
	return parsed, nil
}
