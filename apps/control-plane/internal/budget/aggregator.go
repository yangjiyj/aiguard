package budget

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// incrAllLua atomically increments tokens, cost, and requests for all
// provided scope keys (both monthly and daily) in a single round-trip.
const incrAllLua = `
local scopes_count = tonumber(ARGV[1])
local tokens = ARGV[2]
local cost = ARGV[3]
local requests = ARGV[4]
for i = 0, scopes_count*2 - 1 do
  local key = KEYS[i+1]
  redis.call('HINCRBY', key, 'tokens', tokens)
  redis.call('HINCRBYFLOAT', key, 'cost', cost)
  redis.call('HINCRBY', key, 'requests', requests)
end
return 'OK'
`

var incrScript = redis.NewScript(incrAllLua)

// ScopeKey identifies a single budget scope.
type ScopeKey struct {
	Scope string // tenant | team | project | user | key
	ID    string
}

// IncrementArgs holds the values for one usage event to fan out across scopes.
type IncrementArgs struct {
	Scopes   []ScopeKey
	Tokens   int64
	Cost     float64
	Requests int64
	YYYYMM   string // monthly bucket, e.g. "2026-05"
	YYYYMMDD string // daily bucket,   e.g. "2026-05-29"
}

// Aggregator writes usage increments to Redis for all relevant budget scopes.
type Aggregator struct {
	rdb *redis.Client
}

// NewAggregator creates a new Aggregator backed by the given Redis client.
func NewAggregator(rdb *redis.Client) *Aggregator {
	return &Aggregator{rdb: rdb}
}

// IncrementAllScopes fans out a usage event to monthly and daily hash keys for
// every non-empty scope in args using a single Lua script execution.
func (a *Aggregator) IncrementAllScopes(ctx context.Context, args IncrementArgs) error {
	keys := make([]string, 0, len(args.Scopes)*2)
	validScopes := 0
	for _, s := range args.Scopes {
		if s.ID == "" {
			continue
		}
		keys = append(keys, BudgetKey(s.Scope, s.ID, args.YYYYMM))
		keys = append(keys, BudgetKeyDay(s.Scope, s.ID, args.YYYYMMDD))
		validScopes++
	}
	if validScopes == 0 {
		return nil
	}
	err := incrScript.Run(ctx, a.rdb, keys, validScopes, args.Tokens, args.Cost, args.Requests).Err()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("budget.IncrementAllScopes: %w", err)
	}
	return nil
}
