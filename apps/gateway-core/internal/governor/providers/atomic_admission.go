package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/redis/go-redis/v9"
)

const atomicAdmissionLua = `
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local bucket_ttl_ms = tonumber(ARGV[2])
local lease_ttl_ms = tonumber(ARGV[3])
local request_id = ARGV[4]
local estimated = tonumber(ARGV[5])
local scope_count = tonumber(ARGV[6])
local lease_payload = ARGV[7]
local month_reservation_ttl_ms = tonumber(ARGV[8])
local day_reservation_ttl_ms = tonumber(ARGV[9])
local day_retry_seconds = tonumber(ARGV[10])
local month_retry_seconds = tonumber(ARGV[11])
local lease_owner = cjson.decode(lease_payload)
local existing = redis.call('GET', KEYS[1])
if existing then
  return {2, existing}
end

local observation = nil
for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 10
  local arg_offset = 12 + i * 8
  local rpm_limit = tonumber(ARGV[arg_offset])
  local tpm_limit = tonumber(ARGV[arg_offset + 1])
  local concurrency_limit = tonumber(ARGV[arg_offset + 2])
  local month_limit = tonumber(ARGV[arg_offset + 3])
  local day_limit = tonumber(ARGV[arg_offset + 4])
  local realtime_enforce = tonumber(ARGV[arg_offset + 5])
  local token_enforce = tonumber(ARGV[arg_offset + 6])
  local overage_action = ARGV[arg_offset + 7]
  local expired = redis.call('ZRANGEBYSCORE', KEYS[key_offset + 8], '-inf', now_ms)
	for _, expired_lease_id in ipairs(expired) do
    local raw_detail = redis.call('HGET', KEYS[key_offset + 9], expired_lease_id)
    if raw_detail then
      local detail = cjson.decode(raw_detail)
      local active = false
      if detail.lease_key and detail.lease_key ~= '' then
        local raw_active_lease = redis.call('GET', detail.lease_key)
        local active_ttl = redis.call('PTTL', detail.lease_key)
        if raw_active_lease and active_ttl > 0 then
          local decoded_ok, active_lease = pcall(cjson.decode, raw_active_lease)
          if decoded_ok and active_lease.state == 'acquired' and active_lease.fingerprint == detail.fingerprint then
			active = true
			redis.call('ZADD', KEYS[key_offset + 8], now_ms + active_ttl, expired_lease_id)
			if detail.concurrency_key and detail.concurrency_key ~= '' then
				redis.call('ZADD', detail.concurrency_key, now_ms + active_ttl, expired_lease_id)
			end
          end
        end
      end
      if not active then
        for _, counter_key in ipairs({detail.tpm_key, detail.month_key, detail.day_key}) do
          if counter_key and counter_key ~= '' then
            local raw_counter = redis.call('GET', counter_key)
            if raw_counter then
              redis.call('SET', counter_key, math.max(0, tonumber(raw_counter) - tonumber(detail.amount)), 'KEEPTTL')
            end
          end
        end
        if detail.concurrency_key and detail.concurrency_key ~= '' then
          redis.call('ZREM', detail.concurrency_key, expired_lease_id)
        end
        redis.call('HDEL', KEYS[key_offset + 9], expired_lease_id)
        redis.call('ZREM', KEYS[key_offset + 8], expired_lease_id)
      end
    else
      redis.call('ZREM', KEYS[key_offset + 8], expired_lease_id)
		end
	end
	redis.call('ZREMRANGEBYSCORE', KEYS[key_offset + 3], '-inf', now_ms)
	local rpm_used = tonumber(redis.call('GET', KEYS[key_offset]) or '0')
  local tpm_used = tonumber(redis.call('GET', KEYS[key_offset + 1]) or '0')
  local tpm_reserved = tonumber(redis.call('GET', KEYS[key_offset + 2]) or '0')
  local concurrency_used = tonumber(redis.call('ZCOUNT', KEYS[key_offset + 3], '(' .. now_ms, '+inf'))
  local month_used = tonumber(redis.call('HGET', KEYS[key_offset + 4], 'tokens') or '0')
  local day_used = tonumber(redis.call('HGET', KEYS[key_offset + 5], 'tokens') or '0')
  local month_reserved = tonumber(redis.call('GET', KEYS[key_offset + 6]) or '0')
  local day_reserved = tonumber(redis.call('GET', KEYS[key_offset + 7]) or '0')
  local retry_seconds = math.max(1, math.ceil(bucket_ttl_ms / 1000) - 60)
  if rpm_limit > 0 and rpm_used >= rpm_limit then
    if realtime_enforce == 1 then
      return {0, 'rpm', i + 1, rpm_limit, rpm_used, 0, 1, retry_seconds}
    elseif not observation then
      observation = {'rpm', i + 1, rpm_limit, rpm_used, 0, 1, retry_seconds}
    end
  end
  if tpm_limit > 0 and tpm_used + tpm_reserved + estimated > tpm_limit then
    if realtime_enforce == 1 then
      return {0, 'tpm', i + 1, tpm_limit, tpm_used, tpm_reserved, estimated, retry_seconds}
    elseif not observation then
      observation = {'tpm', i + 1, tpm_limit, tpm_used, tpm_reserved, estimated, retry_seconds}
    end
  end
  if concurrency_limit > 0 and concurrency_used >= concurrency_limit then
    local first = redis.call('ZRANGE', KEYS[key_offset + 3], 0, 0, 'WITHSCORES')
    local retry = 1
    if #first >= 2 then
      retry = math.max(1, math.ceil((tonumber(first[2]) - now_ms) / 1000))
    end
    if realtime_enforce == 1 then
      return {0, 'concurrency', i + 1, concurrency_limit, concurrency_used, 0, 1, retry}
    elseif not observation then
      observation = {'concurrency', i + 1, concurrency_limit, concurrency_used, 0, 1, retry}
    end
  end
  if day_limit > 0 and day_used + day_reserved + estimated > day_limit then
    if token_enforce == 1 then
      return {0, 'day_tokens', i + 1, day_limit, day_used, day_reserved, estimated, day_retry_seconds, overage_action}
    elseif not observation then
      observation = {'day_tokens', i + 1, day_limit, day_used, day_reserved, estimated, day_retry_seconds}
    end
  end
  if month_limit > 0 and month_used + month_reserved + estimated > month_limit then
    if token_enforce == 1 then
      return {0, 'month_tokens', i + 1, month_limit, month_used, month_reserved, estimated, month_retry_seconds, overage_action}
    elseif not observation then
      observation = {'month_tokens', i + 1, month_limit, month_used, month_reserved, estimated, month_retry_seconds}
    end
  end
end

for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 10
  local arg_offset = 12 + i * 8
  local rpm_limit = tonumber(ARGV[arg_offset])
  local tpm_limit = tonumber(ARGV[arg_offset + 1])
  local concurrency_limit = tonumber(ARGV[arg_offset + 2])
  local month_limit = tonumber(ARGV[arg_offset + 3])
  local day_limit = tonumber(ARGV[arg_offset + 4])
  if rpm_limit > 0 then
    redis.call('INCR', KEYS[key_offset])
    redis.call('PEXPIRE', KEYS[key_offset], bucket_ttl_ms)
  end
  if tpm_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 2], estimated)
    redis.call('PEXPIRE', KEYS[key_offset + 2], bucket_ttl_ms)
  end
  if concurrency_limit > 0 then
    redis.call('ZADD', KEYS[key_offset + 3], now_ms + lease_ttl_ms, request_id)
    redis.call('PEXPIRE', KEYS[key_offset + 3], lease_ttl_ms * 2)
  end
  if month_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 6], estimated)
    redis.call('PEXPIRE', KEYS[key_offset + 6], month_reservation_ttl_ms)
  end
  if day_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 7], estimated)
    redis.call('PEXPIRE', KEYS[key_offset + 7], day_reservation_ttl_ms)
  end
  if tpm_limit > 0 or month_limit > 0 or day_limit > 0 or concurrency_limit > 0 then
    local detail = cjson.encode({
      amount = estimated,
      tpm_key = tpm_limit > 0 and KEYS[key_offset + 2] or '',
      month_key = month_limit > 0 and KEYS[key_offset + 6] or '',
      day_key = day_limit > 0 and KEYS[key_offset + 7] or '',
      concurrency_key = concurrency_limit > 0 and KEYS[key_offset + 3] or '',
      lease_key = KEYS[1],
      fingerprint = lease_owner.fingerprint
    })
    redis.call('ZADD', KEYS[key_offset + 8], now_ms + lease_ttl_ms, request_id)
    redis.call('HSET', KEYS[key_offset + 9], request_id, detail)
    redis.call('PEXPIRE', KEYS[key_offset + 8], month_reservation_ttl_ms)
    redis.call('PEXPIRE', KEYS[key_offset + 9], month_reservation_ttl_ms)
  end
end
redis.call('SET', KEYS[1], lease_payload, 'PX', lease_ttl_ms)
if observation then
  return {1, 'acquired', observation[1], observation[2], observation[3], observation[4], observation[5], observation[6], observation[7]}
end
return {1, 'acquired', '', 0, 0, 0, 0, 0, 0}
`

const settleAdmissionLua = `
local existing = redis.call('GET', KEYS[1])
if not existing then
  return {0, 'expired'}
end
local decoded = cjson.decode(existing)
if decoded.fingerprint ~= ARGV[7] then
  return {3, decoded.state}
end
if decoded.state ~= 'acquired' then
  return {2, decoded.state}
end
local estimated = tonumber(ARGV[1])
local actual = tonumber(ARGV[2])
local request_id = ARGV[3]
local finalized_ttl_ms = tonumber(ARGV[4])
local scope_count = tonumber(ARGV[5])
for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 9
  local arg_offset = 8 + i * 4
  local tpm_limit = tonumber(ARGV[arg_offset])
  local concurrency_limit = tonumber(ARGV[arg_offset + 1])
  local month_limit = tonumber(ARGV[arg_offset + 2])
  local day_limit = tonumber(ARGV[arg_offset + 3])
  if tpm_limit > 0 then
    local raw_reserved = redis.call('GET', KEYS[key_offset + 1])
    if raw_reserved then
      local ttl = redis.call('PTTL', KEYS[key_offset + 1])
      redis.call('INCRBY', KEYS[key_offset], actual)
      if ttl > 0 then redis.call('PEXPIRE', KEYS[key_offset], ttl) end
      redis.call('SET', KEYS[key_offset + 1], math.max(0, tonumber(raw_reserved) - estimated), 'KEEPTTL')
    end
  end
  if concurrency_limit > 0 then
    redis.call('ZREM', KEYS[key_offset + 2], request_id)
  end
  redis.call('HINCRBY', KEYS[key_offset + 3], 'tokens', actual)
  redis.call('HINCRBY', KEYS[key_offset + 4], 'tokens', actual)
  if month_limit > 0 then
    local raw_current = redis.call('GET', KEYS[key_offset + 5])
    if raw_current then redis.call('SET', KEYS[key_offset + 5], math.max(0, tonumber(raw_current) - estimated), 'KEEPTTL') end
  end
  if day_limit > 0 then
    local raw_current = redis.call('GET', KEYS[key_offset + 6])
    if raw_current then redis.call('SET', KEYS[key_offset + 6], math.max(0, tonumber(raw_current) - estimated), 'KEEPTTL') end
  end
  redis.call('ZREM', KEYS[key_offset + 7], request_id)
  redis.call('HDEL', KEYS[key_offset + 8], request_id)
end
redis.call('SET', KEYS[1], ARGV[6], 'PX', finalized_ttl_ms)
return {1, 'settled'}
`

const releaseAdmissionLua = `
local existing = redis.call('GET', KEYS[1])
if not existing then
  return {0, 'expired'}
end
local decoded = cjson.decode(existing)
if decoded.fingerprint ~= ARGV[7] then
  return {3, decoded.state}
end
if decoded.state ~= 'acquired' then
  return {2, decoded.state}
end
local estimated = tonumber(ARGV[1])
local actual = tonumber(ARGV[2])
local request_id = ARGV[3]
local finalized_ttl_ms = tonumber(ARGV[4])
local scope_count = tonumber(ARGV[5])
for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 9
  local arg_offset = 8 + i * 4
  local tpm_limit = tonumber(ARGV[arg_offset])
  local concurrency_limit = tonumber(ARGV[arg_offset + 1])
  local month_limit = tonumber(ARGV[arg_offset + 2])
  local day_limit = tonumber(ARGV[arg_offset + 3])
  if tpm_limit > 0 then
    local raw_reserved = redis.call('GET', KEYS[key_offset + 1])
    if raw_reserved then
      local ttl = redis.call('PTTL', KEYS[key_offset + 1])
      redis.call('INCRBY', KEYS[key_offset], actual)
      if ttl > 0 then redis.call('PEXPIRE', KEYS[key_offset], ttl) end
      redis.call('SET', KEYS[key_offset + 1], math.max(0, tonumber(raw_reserved) - estimated), 'KEEPTTL')
    end
  end
  if concurrency_limit > 0 then
    redis.call('ZREM', KEYS[key_offset + 2], request_id)
  end
  redis.call('HINCRBY', KEYS[key_offset + 3], 'tokens', actual)
  redis.call('HINCRBY', KEYS[key_offset + 4], 'tokens', actual)
  if month_limit > 0 then
    local raw_current = redis.call('GET', KEYS[key_offset + 5])
    if raw_current then redis.call('SET', KEYS[key_offset + 5], math.max(0, tonumber(raw_current) - estimated), 'KEEPTTL') end
  end
  if day_limit > 0 then
    local raw_current = redis.call('GET', KEYS[key_offset + 6])
    if raw_current then redis.call('SET', KEYS[key_offset + 6], math.max(0, tonumber(raw_current) - estimated), 'KEEPTTL') end
  end
  redis.call('ZREM', KEYS[key_offset + 7], request_id)
  redis.call('HDEL', KEYS[key_offset + 8], request_id)
end
redis.call('SET', KEYS[1], ARGV[6], 'PX', finalized_ttl_ms)
return {1, 'released'}
`

const heartbeatAdmissionLua = `
local existing = redis.call('GET', KEYS[1])
if not existing then
  return {0, 'expired'}
end
local decoded = cjson.decode(existing)
if decoded.fingerprint ~= ARGV[6] then
  return {3, decoded.state}
end
if decoded.state ~= 'acquired' then
  return {2, decoded.state}
end
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local lease_ttl_ms = tonumber(ARGV[2])
local request_id = ARGV[3]
local scope_count = tonumber(ARGV[4])
redis.call('PEXPIRE', KEYS[1], lease_ttl_ms)
for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 2
  local arg_offset = 7 + i * 2
  local concurrency_limit = tonumber(ARGV[arg_offset])
  local has_lease_detail = tonumber(ARGV[arg_offset + 1])
  if concurrency_limit > 0 then
    redis.call('ZADD', KEYS[key_offset], now_ms + lease_ttl_ms, request_id)
    redis.call('PEXPIRE', KEYS[key_offset], lease_ttl_ms * 2)
  end
  if has_lease_detail > 0 then
    redis.call('ZADD', KEYS[key_offset + 1], now_ms + lease_ttl_ms, request_id)
  end
end
redis.call('SET', KEYS[1], ARGV[5], 'PX', lease_ttl_ms)
return {1, 'acquired'}
`

var (
	atomicAdmissionScript    = redis.NewScript(atomicAdmissionMoneyLua)
	settleAdmissionScript    = redis.NewScript(settleAdmissionMoneyLua)
	releaseAdmissionScript   = redis.NewScript(releaseAdmissionMoneyLua)
	heartbeatAdmissionScript = redis.NewScript(heartbeatAdmissionLua)
)

type AtomicAdmission struct {
	rdb          *redis.Client
	quota        governor.ScopedQuotaProvider
	leaseTTL     time.Duration
	finalizedTTL time.Duration
	now          func() time.Time
	// underflows counts reserved counters that settle/release had to clamp
	// at zero. Any non-zero value means a reservation was subtracted twice.
	underflows atomic.Uint64
}

// ReservationUnderflows reports how many reserved-counter underflows the
// finalize scripts have clamped since start-up (anomaly metric, 7.9).
func (a *AtomicAdmission) ReservationUnderflows() uint64 {
	if a == nil {
		return 0
	}
	return a.underflows.Load()
}

// recordReservationUnderflows raises an anomaly for every clamped counter
// returned by the settle/release scripts as {key, deficit, key, deficit, ...}.
func (a *AtomicAdmission) recordReservationUnderflows(result []interface{}, requestID, operation string) {
	if len(result) < 3 {
		return
	}
	pairs, ok := result[2].([]interface{})
	if !ok {
		return
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		deficit, err := redisInt64(pairs, i+1)
		if err != nil || deficit <= 0 {
			continue
		}
		a.underflows.Add(1)
		log.Printf("[quota.admission] ALERT reserved counter underflow op=%s request=%s key=%v deficit=%d (clamped to 0; reservation subtracted twice?)",
			operation, requestID, pairs[i], deficit)
	}
}

const (
	defaultAdmissionLeaseTTL = 35 * time.Minute
	admissionLeaseMargin     = 5 * time.Minute
	maxExactAdmissionTokens  = int64(1<<53 - 1)
)

// NewAtomicAdmission requires a single-node Redis client. The admission Lua
// touches existing budget keys plus tenant-tagged lease keys atomically; Redis
// Cluster is not supported until all budget keys share the same hash slot.
func NewAtomicAdmission(rdb *redis.Client, quota governor.ScopedQuotaProvider) *AtomicAdmission {
	return &AtomicAdmission{
		rdb: rdb, quota: quota,
		leaseTTL: defaultAdmissionLeaseTTL, finalizedTTL: 24 * time.Hour,
		now: time.Now,
	}
}

// SetMaxRequestDuration keeps a logical lease alive for every request the
// gateway itself permits, even if all heartbeats fail for the whole request.
func (a *AtomicAdmission) SetMaxRequestDuration(maxRequestDuration time.Duration) {
	if a == nil || maxRequestDuration <= 0 {
		return
	}
	leaseTTL := maxRequestDuration
	if leaseTTL <= time.Duration(1<<63-1)-admissionLeaseMargin {
		leaseTTL += admissionLeaseMargin
	}
	if leaseTTL > a.leaseTTL {
		a.leaseTTL = leaseTTL
	}
}

func (a *AtomicAdmission) Admit(ctx context.Context, request governor.AdmissionRequest) (*governor.AdmissionLease, error) {
	request.RequestID = strings.TrimSpace(request.RequestID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.IdempotencyKey == "" {
		request.IdempotencyKey = request.RequestID
	}
	request.Ref.TenantID = strings.TrimSpace(request.Ref.TenantID)
	if request.RequestID == "" || request.Ref.TenantID == "" {
		return nil, runtimeAdmissionError(request.RequestID, errors.New("tenant and request id are required"))
	}
	if a == nil || a.quota == nil {
		return nil, runtimeAdmissionError(request.RequestID, errors.New("quota admission is unavailable"))
	}
	if request.EstimatedTokens < 1 {
		request.EstimatedTokens = 1
	} else if request.EstimatedTokens > maxExactAdmissionTokens {
		request.EstimatedTokens = maxExactAdmissionTokens
	}
	if request.EstimatedCostMicros < 0 {
		return nil, runtimeAdmissionError(request.RequestID, errors.New("estimated cost must be non-negative"))
	}
	if request.EstimatedCostMicros > maxExactAdmissionTokens {
		request.EstimatedCostMicros = maxExactAdmissionTokens
	}
	quotas, err := a.quota.ScopedQuotas(ctx, request.Ref)
	if err != nil {
		return nil, runtimeAdmissionError(request.RequestID, fmt.Errorf("load scoped quotas: %w", err))
	}
	policyScopes := atomicAdmissionScopes(request.Ref, quotas)
	cutoff := true
	policyScopes = applyBudgetCutoffToScopes(policyScopes)
	if request.CostEstimateMissingPrice {
		for i := range policyScopes {
			policyScopes[i].DailyCostLimitMicros = 0
			policyScopes[i].MonthlyCostLimitMicros = 0
			policyScopes[i].DailyCostBlocked = false
			policyScopes[i].MonthlyCostBlocked = false
		}
	}
	scopeNames := scopeDisplayNames(quotas)
	scopes := addAdmissionAccountingScopes(request.Ref, policyScopes)
	now := a.now()
	if a.rdb != nil {
		redisNow, timeErr := a.rdb.Time(ctx).Result()
		if timeErr != nil {
			if hasEnforcingAdmissionScope(scopes) {
				return nil, cutoffRuntimeError(cutoff, scopes, request.RequestID, fmt.Errorf("read quota Redis time: %w", timeErr))
			}
		} else {
			now = redisNow
		}
	}
	monthBucket, dayBucket, _, _ := admissionPeriods(now)
	for index := range scopes {
		month, day, _, _, periodErr := admissionPeriodsForTimezone(now, scopes[index].QuotaTimezone)
		if periodErr != nil {
			return nil, runtimeAdmissionError(request.RequestID, periodErr)
		}
		scopes[index].QuotaTimezone = normalizedQuotaTimezone(scopes[index].QuotaTimezone)
		scopes[index].MonthBucket = quotaPeriodBucket(scopes[index].QuotaTimezone, month)
		scopes[index].DayBucket = quotaPeriodBucket(scopes[index].QuotaTimezone, day)
	}
	lease := &governor.AdmissionLease{
		TenantID: request.Ref.TenantID, RequestID: request.RequestID, LeaseID: request.IdempotencyKey,
		EstimatedTokens: request.EstimatedTokens, EstimatedCostMicros: request.EstimatedCostMicros,
		CostEstimateAvailable: request.CostEstimateAvailable, MinuteBucket: now.Unix() / 60,
		MonthBucket: monthBucket, DayBucket: dayBucket,
		ExpiresAt: now.Add(a.leaseTTL), LeaseTTLMillis: a.leaseTTL.Milliseconds(), State: "bypass", Scopes: scopes,
	}
	if len(scopes) == 0 {
		return lease, nil
	}
	for _, scope := range scopes {
		blocked := []struct {
			active    bool
			metric    string
			requested int64
		}{
			{scope.RPMBlocked, "rpm", 1},
			{scope.TPMBlocked, "tpm", request.EstimatedTokens},
			{scope.ConcurrencyBlocked, "concurrency", 1},
			{scope.DailyTokenBlocked, "day_tokens", request.EstimatedTokens},
			{scope.MonthlyTokenBlocked, "month_tokens", request.EstimatedTokens},
			{scope.DailyCostBlocked, "day_cost_micros", request.EstimatedCostMicros},
			{scope.MonthlyCostBlocked, "month_cost_micros", request.EstimatedCostMicros},
		}
		for _, item := range blocked {
			if !item.active {
				continue
			}
			fact := governor.AdmissionObservation{Metric: item.metric, Scope: scope.Scope, Limit: 0, Used: 0, Reserved: 0, Requested: item.requested}
			if scope.EnforcementMode == "enforce" && (scope.OverageAction != "notify" || item.metric == "rpm" || item.metric == "tpm" || item.metric == "concurrency") {
				return nil, &governor.AdmissionLimitError{
					Metric: fact.Metric, Scope: fact.Scope, ScopeID: scope.ID,
					Limit: fact.Limit, Used: fact.Used, Reserved: fact.Reserved, Requested: fact.Requested,
					RequestID: request.RequestID,
				}
			}
			lease.Observations = append(lease.Observations, fact)
		}
		needsCost := scope.DailyCostLimitMicros > 0 || scope.MonthlyCostLimitMicros > 0
		if needsCost && !request.CostEstimateAvailable {
			if scope.EnforcementMode == "enforce" && scope.OverageAction != "notify" {
				return nil, cutoffRuntimeError(cutoff, scopes, request.RequestID, errors.New("billable amount estimate is unavailable for an enforced money quota"))
			}
			lease.Observations = append(lease.Observations, governor.AdmissionObservation{
				Metric: "cost_estimate_unavailable", Scope: scope.Scope,
			})
		}
	}
	lease.State = "acquired"
	lease.Fingerprint = admissionLeaseFingerprint(lease)
	leasePayload, err := json.Marshal(lease)
	if err != nil {
		return nil, runtimeAdmissionError(request.RequestID, fmt.Errorf("encode admission lease: %w", err))
	}
	if a.rdb == nil {
		if hasEnforcingAdmissionScope(scopes) {
			return nil, cutoffRuntimeError(cutoff, scopes, request.RequestID, errors.New("quota Redis is unavailable"))
		}
		lease.State = "observation_unavailable"
		return lease, nil
	}
	keys := []string{atomicLeaseKey(request.Ref.TenantID, request.IdempotencyKey)}
	args := []interface{}{
		now.UnixMilli(), minuteBucketTTL(now).Milliseconds(), a.leaseTTL.Milliseconds(),
		request.IdempotencyKey, request.EstimatedTokens, request.EstimatedCostMicros,
		len(scopes), string(leasePayload),
	}
	for _, scope := range scopes {
		_, _, monthTTL, dayTTL, periodErr := admissionPeriodsForTimezone(now, scope.QuotaTimezone)
		if periodErr != nil {
			return nil, runtimeAdmissionError(request.RequestID, periodErr)
		}
		keys = append(keys,
			atomicRPMKey(request.Ref.TenantID, scope, lease.MinuteBucket),
			atomicTPMKey(request.Ref.TenantID, scope, lease.MinuteBucket),
			atomicTPMReservationKey(request.Ref.TenantID, scope, lease.MinuteBucket),
			atomicConcurrencyKey(request.Ref.TenantID, scope),
			BudgetKey(scope.Scope, scope.ID, scope.MonthBucket),
			BudgetKeyDay(scope.Scope, scope.ID, scope.DayBucket),
			atomicMonthReservationKey(request.Ref.TenantID, scope, scope.MonthBucket),
			atomicDayReservationKey(request.Ref.TenantID, scope, scope.DayBucket),
			atomicMonthCostReservationKey(request.Ref.TenantID, scope, scope.MonthBucket),
			atomicDayCostReservationKey(request.Ref.TenantID, scope, scope.DayBucket),
			atomicReservationExpiryKey(request.Ref.TenantID, scope),
			atomicReservationDetailKey(request.Ref.TenantID, scope),
		)
		realtimeEnforce := 0
		if scope.EnforcementMode == "enforce" {
			realtimeEnforce = 1
		}
		tokenCostEnforce := 0
		if realtimeEnforce == 1 && scope.OverageAction != "notify" {
			tokenCostEnforce = 1
		}
		args = append(args, scope.RPMLimit, scope.TPMLimit, scope.ConcurrencyLimit,
			scope.MonthlyTokenLimit, scope.DailyTokenLimit,
			scope.MonthlyCostLimitMicros, scope.DailyCostLimitMicros,
			realtimeEnforce, tokenCostEnforce, scope.OverageAction,
			monthTTL.Milliseconds(), dayTTL.Milliseconds(),
			maxInt64(1, int64((dayTTL-24*time.Hour).Seconds())),
			maxInt64(1, int64((monthTTL-24*time.Hour).Seconds())),
		)
	}
	values, err := atomicAdmissionScript.Run(ctx, a.rdb, keys, args...).Slice()
	if err != nil {
		if !hasEnforcingAdmissionScope(scopes) {
			lease.State = "observation_unavailable"
			return lease, nil
		}
		return nil, cutoffRuntimeError(cutoff, scopes, request.RequestID, fmt.Errorf("redis atomic admission: %w", err))
	}
	code, err := redisInt64(values, 0)
	if err != nil {
		return nil, runtimeAdmissionError(request.RequestID, err)
	}
	if code == 2 {
		if len(values) < 2 {
			return nil, runtimeAdmissionError(request.RequestID, errors.New("stored admission lease is missing"))
		}
		stored, err := decodeAdmissionLease(values[1])
		if err != nil {
			return nil, runtimeAdmissionError(request.RequestID, err)
		}
		if stored.RequestID != request.RequestID {
			return nil, &governor.AdmissionIdempotencyError{RequestID: request.RequestID, State: stored.State, Reason: "idempotency key belongs to another request"}
		}
		if stored.Fingerprint != lease.Fingerprint {
			return nil, &governor.AdmissionIdempotencyError{RequestID: request.RequestID, State: stored.State, Reason: "request parameters changed"}
		}
		if stored.State != "acquired" {
			return nil, &governor.AdmissionIdempotencyError{RequestID: request.RequestID, State: stored.State, Reason: "request already finalized"}
		}
		return stored, nil
	}
	if code == 1 {
		if len(values) >= 9 && fmt.Sprint(values[2]) != "" {
			observation, err := admissionObservationFromRedis(values[2:], scopes)
			if err != nil {
				return nil, runtimeAdmissionError(request.RequestID, err)
			}
			lease.Observations = append(lease.Observations, observation)
		}
		return lease, nil
	}
	if code != 0 || len(values) < 8 {
		return nil, runtimeAdmissionError(request.RequestID, fmt.Errorf("invalid redis admission response"))
	}
	scopeIndex, err := redisInt64(values, 2)
	if err != nil || scopeIndex < 1 || int(scopeIndex) > len(scopes) {
		return nil, runtimeAdmissionError(request.RequestID, fmt.Errorf("invalid redis admission scope"))
	}
	scope := scopes[scopeIndex-1]
	limit, _ := redisInt64(values, 3)
	used, _ := redisInt64(values, 4)
	reserved, _ := redisInt64(values, 5)
	requested, _ := redisInt64(values, 6)
	retryAfter, _ := redisInt64(values, 7)
	configuredAction := ""
	if len(values) > 8 {
		configuredAction = fmt.Sprint(values[8])
	}
	limitErr := &governor.AdmissionLimitError{
		Metric: fmt.Sprint(values[1]), Scope: scope.Scope, ScopeID: scope.ID,
		Limit: limit, Used: used, Reserved: reserved, Requested: requested, RetryAfter: retryAfter,
		RequestID: request.RequestID, ConfiguredAction: configuredAction,
		Currency: request.CostCurrency,
	}
	if cutoff && isMoneyMetric(limitErr.Metric) {
		limitErr.BudgetCutoff = true
		limitErr.ScopeName = scopeNames[scope.Scope+"\x00"+scope.ID]
		limitErr.ResetAt = admissionResetAt(now, scope.QuotaTimezone, limitErr.Metric)
	}
	return nil, limitErr
}

func (a *AtomicAdmission) Settle(ctx context.Context, lease *governor.AdmissionLease, actualTokens, actualCostMicros int64, actualCostAvailable bool) error {
	if lease == nil || lease.State == "bypass" || lease.State == "observation_unavailable" {
		return nil
	}
	if actualTokens < 0 {
		actualTokens = 0
	}
	if actualCostMicros < 0 {
		actualCostMicros = 0
	} else if actualCostMicros > maxExactAdmissionTokens {
		actualCostMicros = maxExactAdmissionTokens
	}
	costState := "actual"
	if !actualCostAvailable {
		costState = "estimated"
		if !lease.CostEstimateAvailable {
			costState = "unpriced"
		}
	}
	keys, args := a.finalizeKeysAndArgs(lease)
	settled := *lease
	settled.State = "settled"
	payload, err := json.Marshal(&settled)
	if err != nil {
		return runtimeAdmissionError(lease.RequestID, err)
	}
	args = append([]interface{}{
		lease.EstimatedTokens, actualTokens, lease.EstimatedCostMicros, actualCostMicros,
		costState, lease.LeaseID, a.finalizedTTL.Milliseconds(), len(lease.Scopes),
		string(payload), lease.Fingerprint,
	}, args...)
	result, err := a.runFinalizeScript(ctx, settleAdmissionScript, keys, args...)
	if err != nil {
		return runtimeAdmissionError(lease.RequestID, fmt.Errorf("redis settle admission: %w", err))
	}
	if err := validateFinalizeResult(result, lease.RequestID, "settled"); err != nil {
		return err
	}
	a.recordReservationUnderflows(result, lease.RequestID, "settle")
	lease.State = "settled"
	if actualTokens > lease.EstimatedTokens {
		return &governor.AdmissionOverrunError{RequestID: lease.RequestID, EstimatedTokens: lease.EstimatedTokens, ActualTokens: actualTokens}
	}
	if actualCostMicros > lease.EstimatedCostMicros && lease.CostEstimateAvailable {
		return &governor.AdmissionCostOverrunError{RequestID: lease.RequestID, EstimatedMicros: lease.EstimatedCostMicros, ActualMicros: actualCostMicros}
	}
	return nil
}

func (a *AtomicAdmission) Release(ctx context.Context, lease *governor.AdmissionLease, actualTokens, actualCostMicros int64) error {
	if lease == nil || lease.State == "bypass" || lease.State == "observation_unavailable" {
		return nil
	}
	if actualTokens < 0 {
		actualTokens = 0
	}
	if actualCostMicros < 0 {
		actualCostMicros = 0
	} else if actualCostMicros > maxExactAdmissionTokens {
		actualCostMicros = maxExactAdmissionTokens
	}
	keys, args := a.finalizeKeysAndArgs(lease)
	released := *lease
	released.State = "released"
	payload, err := json.Marshal(&released)
	if err != nil {
		return runtimeAdmissionError(lease.RequestID, err)
	}
	args = append([]interface{}{
		lease.EstimatedTokens, actualTokens, lease.EstimatedCostMicros, actualCostMicros,
		"estimated", lease.LeaseID, a.finalizedTTL.Milliseconds(), len(lease.Scopes),
		string(payload), lease.Fingerprint,
	}, args...)
	result, err := a.runFinalizeScript(ctx, releaseAdmissionScript, keys, args...)
	if err != nil {
		return runtimeAdmissionError(lease.RequestID, fmt.Errorf("redis release admission: %w", err))
	}
	if err := validateFinalizeResult(result, lease.RequestID, "released"); err != nil {
		return err
	}
	a.recordReservationUnderflows(result, lease.RequestID, "release")
	lease.State = "released"
	return nil
}

func (a *AtomicAdmission) Heartbeat(ctx context.Context, lease *governor.AdmissionLease) error {
	if lease == nil || lease.State == "bypass" || lease.State == "observation_unavailable" {
		return nil
	}
	now := a.now()
	updated := *lease
	updated.ExpiresAt = now.Add(a.leaseTTL)
	payload, err := json.Marshal(&updated)
	if err != nil {
		return runtimeAdmissionError(lease.RequestID, err)
	}
	keys := []string{atomicLeaseKey(lease.TenantID, lease.LeaseID)}
	args := []interface{}{now.UnixMilli(), a.leaseTTL.Milliseconds(), lease.LeaseID, len(lease.Scopes), string(payload), lease.Fingerprint}
	for _, scope := range lease.Scopes {
		keys = append(keys, atomicConcurrencyKey(lease.TenantID, scope), atomicReservationExpiryKey(lease.TenantID, scope))
		hasLeaseDetail := 0
		if scope.ConcurrencyLimit > 0 || scope.TPMLimit > 0 || scope.MonthlyTokenLimit > 0 || scope.DailyTokenLimit > 0 ||
			scope.MonthlyCostLimitMicros > 0 || scope.DailyCostLimitMicros > 0 {
			hasLeaseDetail = 1
		}
		args = append(args, scope.ConcurrencyLimit, hasLeaseDetail)
	}
	result, err := heartbeatAdmissionScript.Run(ctx, a.rdb, keys, args...).Slice()
	if err != nil {
		return runtimeAdmissionError(lease.RequestID, fmt.Errorf("redis heartbeat admission: %w", err))
	}
	if err := validateFinalizeResult(result, lease.RequestID, "acquired"); err != nil {
		return err
	}
	return nil
}

func (a *AtomicAdmission) runFinalizeScript(
	ctx context.Context,
	script *redis.Script,
	keys []string,
	args ...interface{},
) ([]interface{}, error) {
	if a == nil || a.rdb == nil {
		return nil, errors.New("quota Redis is unavailable")
	}
	finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
	defer cancel()
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		attemptCtx, attemptCancel := context.WithTimeout(finalizeCtx, 2*time.Second)
		result, err := script.Run(attemptCtx, a.rdb, keys, args...).Slice()
		attemptCancel()
		if err == nil {
			return result, nil
		}
		lastErr = err
		if attempt == 4 || finalizeCtx.Err() != nil {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * 150 * time.Millisecond)
		select {
		case <-finalizeCtx.Done():
			timer.Stop()
			return nil, finalizeCtx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func (a *AtomicAdmission) finalizeKeysAndArgs(lease *governor.AdmissionLease) ([]string, []interface{}) {
	keys := []string{atomicLeaseKey(lease.TenantID, lease.LeaseID)}
	args := make([]interface{}, 0, len(lease.Scopes)*6)
	for _, scope := range lease.Scopes {
		monthBucket := scope.MonthBucket
		if monthBucket == "" {
			monthBucket = lease.MonthBucket
		}
		dayBucket := scope.DayBucket
		if dayBucket == "" {
			dayBucket = lease.DayBucket
		}
		keys = append(keys,
			atomicTPMKey(lease.TenantID, scope, lease.MinuteBucket),
			atomicTPMReservationKey(lease.TenantID, scope, lease.MinuteBucket),
			atomicConcurrencyKey(lease.TenantID, scope),
			BudgetKey(scope.Scope, scope.ID, monthBucket),
			BudgetKeyDay(scope.Scope, scope.ID, dayBucket),
			atomicMonthReservationKey(lease.TenantID, scope, monthBucket),
			atomicDayReservationKey(lease.TenantID, scope, dayBucket),
			atomicMonthCostReservationKey(lease.TenantID, scope, monthBucket),
			atomicDayCostReservationKey(lease.TenantID, scope, dayBucket),
			atomicReservationExpiryKey(lease.TenantID, scope),
			atomicReservationDetailKey(lease.TenantID, scope),
		)
		args = append(args, scope.TPMLimit, scope.ConcurrencyLimit,
			scope.MonthlyTokenLimit, scope.DailyTokenLimit,
			scope.MonthlyCostLimitMicros, scope.DailyCostLimitMicros)
	}
	return keys, args
}

func atomicAdmissionScopes(ref governor.ScopeRef, quotas []governor.ScopedQuota) []governor.AdmissionScope {
	byKey := make(map[string]governor.AdmissionScope)
	for _, quota := range quotas {
		mode := quota.EnforcementMode
		if mode == "bypass" {
			mode = "accounting"
		}
		if mode != "enforce" && mode != "soft" && mode != "accounting" {
			continue
		}
		expected := admissionScopeID(ref, quota.Scope)
		if quota.Scope == "team" && ref.TeamID != "" {
			expected = quota.ID
		}
		if expected == "" || quota.ID != expected {
			continue
		}
		incoming := governor.AdmissionScope{
			Scope: quota.Scope, ID: quota.ID,
			EnforcementMode: mode,
			RPMLimit:        quota.Limits.RPMLimit, RPMBlocked: quota.Limits.RPMBlocked,
			TPMLimit:               quota.Limits.TPMLimit,
			TPMConfigured:          quota.Limits.TPMConfigured || quota.Limits.TPMLimit > 0,
			TPMBlocked:             quota.Limits.TPMBlocked,
			ConcurrencyLimit:       quota.Limits.ConcurrencyLimit,
			ConcurrencyBlocked:     quota.Limits.ConcurrencyBlocked,
			DailyTokenLimit:        quota.Limits.DailyTokenLimit,
			DailyTokenBlocked:      quota.Limits.DailyTokenBlocked,
			MonthlyTokenLimit:      quota.Limits.MonthlyTokenLimit,
			MonthlyTokenBlocked:    quota.Limits.MonthlyTokenBlocked,
			DailyCostLimitMicros:   quota.Limits.DailyBudgetMicros,
			DailyCostBlocked:       quota.Limits.DailyBudgetBlocked,
			MonthlyCostLimitMicros: quota.Limits.MonthlyBudgetMicros,
			MonthlyCostBlocked:     quota.Limits.MonthlyBudgetBlocked,
			QuotaTimezone:          normalizedQuotaTimezone(quota.Limits.QuotaTimezone),
			OverageAction:          quota.Limits.OverageAction,
		}
		key := incoming.Scope + "\x00" + incoming.ID
		if current, ok := byKey[key]; ok {
			if current.EnforcementMode == "enforce" {
				incoming.EnforcementMode = "enforce"
			}
			incoming.RPMLimit = minimumPositive(current.RPMLimit, incoming.RPMLimit)
			incoming.RPMBlocked = current.RPMBlocked || incoming.RPMBlocked
			incoming.TPMLimit = minimumPositive(current.TPMLimit, incoming.TPMLimit)
			incoming.TPMConfigured = current.TPMConfigured || incoming.TPMConfigured
			incoming.TPMBlocked = current.TPMBlocked || incoming.TPMBlocked
			incoming.ConcurrencyLimit = minimumPositive(current.ConcurrencyLimit, incoming.ConcurrencyLimit)
			incoming.ConcurrencyBlocked = current.ConcurrencyBlocked || incoming.ConcurrencyBlocked
			incoming.DailyTokenLimit = minimumPositive(current.DailyTokenLimit, incoming.DailyTokenLimit)
			incoming.DailyTokenBlocked = current.DailyTokenBlocked || incoming.DailyTokenBlocked
			incoming.MonthlyTokenLimit = minimumPositive(current.MonthlyTokenLimit, incoming.MonthlyTokenLimit)
			incoming.MonthlyTokenBlocked = current.MonthlyTokenBlocked || incoming.MonthlyTokenBlocked
			incoming.DailyCostLimitMicros = minimumPositive(current.DailyCostLimitMicros, incoming.DailyCostLimitMicros)
			incoming.DailyCostBlocked = current.DailyCostBlocked || incoming.DailyCostBlocked
			incoming.MonthlyCostLimitMicros = minimumPositive(current.MonthlyCostLimitMicros, incoming.MonthlyCostLimitMicros)
			incoming.MonthlyCostBlocked = current.MonthlyCostBlocked || incoming.MonthlyCostBlocked
		}
		if incoming.EnforcementMode == "accounting" || incoming.RPMLimit > 0 || incoming.RPMBlocked ||
			incoming.TPMLimit > 0 || incoming.TPMBlocked || incoming.ConcurrencyLimit > 0 || incoming.ConcurrencyBlocked ||
			incoming.DailyTokenLimit > 0 || incoming.DailyTokenBlocked || incoming.MonthlyTokenLimit > 0 || incoming.MonthlyTokenBlocked ||
			incoming.DailyCostLimitMicros > 0 || incoming.DailyCostBlocked ||
			incoming.MonthlyCostLimitMicros > 0 || incoming.MonthlyCostBlocked {
			byKey[key] = incoming
		}
	}
	out := make([]governor.AdmissionScope, 0, len(byKey))
	for _, scope := range byKey {
		out = append(out, scope)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := admissionScopeRank(out[i].Scope), admissionScopeRank(out[j].Scope)
		if left == right {
			return out[i].ID < out[j].ID
		}
		return left < right
	})
	return out
}

func addAdmissionAccountingScopes(ref governor.ScopeRef, scopes []governor.AdmissionScope) []governor.AdmissionScope {
	byKey := make(map[string]governor.AdmissionScope, len(scopes)+5)
	for _, scope := range scopes {
		byKey[scope.Scope+"\x00"+scope.ID] = scope
	}
	for _, candidate := range []governor.AdmissionScope{
		{Scope: "tenant", ID: ref.TenantID, EnforcementMode: "accounting", QuotaTimezone: "Asia/Shanghai"},
		{Scope: "team", ID: ref.TeamID, EnforcementMode: "accounting", QuotaTimezone: "Asia/Shanghai"},
		{Scope: "project", ID: ref.ProjectID, EnforcementMode: "accounting", QuotaTimezone: "Asia/Shanghai"},
		{Scope: "user", ID: ref.UserID, EnforcementMode: "accounting", QuotaTimezone: "Asia/Shanghai"},
		{Scope: "key", ID: ref.KeyID, EnforcementMode: "accounting", QuotaTimezone: "Asia/Shanghai"},
	} {
		if candidate.ID == "" {
			continue
		}
		key := candidate.Scope + "\x00" + candidate.ID
		if _, exists := byKey[key]; !exists {
			byKey[key] = candidate
		}
	}
	out := make([]governor.AdmissionScope, 0, len(byKey))
	for _, scope := range byKey {
		out = append(out, scope)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := admissionScopeRank(out[i].Scope), admissionScopeRank(out[j].Scope)
		if left == right {
			return out[i].ID < out[j].ID
		}
		return left < right
	})
	return out
}

func admissionScopeID(ref governor.ScopeRef, scope string) string {
	switch scope {
	case "tenant":
		return ref.TenantID
	case "team":
		return ref.TeamID
	case "project":
		return ref.ProjectID
	case "user":
		// UserID must be an independently verified actor. Key ownership is not an actor claim.
		return ref.UserID
	case "key":
		return ref.KeyID
	default:
		return ""
	}
}

func admissionScopeRank(scope string) int {
	switch scope {
	case "tenant":
		return 0
	case "team":
		return 1
	case "project":
		return 2
	case "user":
		return 3
	case "key":
		return 4
	default:
		return 5
	}
}

func minimumPositive(left, right int64) int64 {
	if left <= 0 {
		return right
	}
	if right <= 0 || left < right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func minuteBucketTTL(now time.Time) time.Duration {
	next := time.Unix((now.Unix()/60+1)*60, 0)
	return next.Sub(now) + time.Minute
}

func admissionPeriods(now time.Time) (month, day string, monthTTL, dayTTL time.Duration) {
	month, day, monthTTL, dayTTL, _ = admissionPeriodsForTimezone(now, "Asia/Shanghai")
	return month, day, monthTTL, dayTTL
}

func normalizedQuotaTimezone(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Asia/Shanghai"
	}
	return value
}

func quotaPeriodBucket(timezone, period string) string {
	timezone = normalizedQuotaTimezone(timezone)
	if timezone == "Asia/Shanghai" {
		return period
	}
	digest := sha256.Sum256([]byte(timezone))
	return period + "@" + hex.EncodeToString(digest[:6])
}

func admissionPeriodsForTimezone(now time.Time, timezone string) (month, day string, monthTTL, dayTTL time.Duration, err error) {
	timezone = normalizedQuotaTimezone(timezone)
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("invalid quota timezone %q: %w", timezone, err)
	}
	localized := now.In(location)
	dayStart := time.Date(localized.Year(), localized.Month(), localized.Day(), 0, 0, 0, 0, location)
	nextDay := dayStart.AddDate(0, 0, 1)
	monthStart := time.Date(localized.Year(), localized.Month(), 1, 0, 0, 0, 0, location)
	nextMonth := monthStart.AddDate(0, 1, 0)
	return localized.Format("2006-01"), localized.Format("2006-01-02"),
		nextMonth.Sub(localized) + 24*time.Hour, nextDay.Sub(localized) + 24*time.Hour, nil
}

func atomicKeyPrefix(tenantID string) string {
	digest := sha256.Sum256([]byte(tenantID))
	return "orgquota:{" + hex.EncodeToString(digest[:8]) + "}:"
}

func encodedAdmissionPart(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func atomicLeaseKey(tenantID, requestID string) string {
	return atomicKeyPrefix(tenantID) + "lease:" + encodedAdmissionPart(requestID)
}

func atomicRPMKey(tenantID string, scope governor.AdmissionScope, minute int64) string {
	return fmt.Sprintf("%srpm:%s:%s:%d", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), minute)
}

func atomicTPMKey(tenantID string, scope governor.AdmissionScope, minute int64) string {
	return fmt.Sprintf("%stpm:%s:%s:%d", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), minute)
}

func atomicTPMReservationKey(tenantID string, scope governor.AdmissionScope, minute int64) string {
	return fmt.Sprintf("%sreserved:tpm:%s:%s:%d", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), minute)
}

func atomicConcurrencyKey(tenantID string, scope governor.AdmissionScope) string {
	return fmt.Sprintf("%sconcurrency:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID))
}

func atomicMonthReservationKey(tenantID string, scope governor.AdmissionScope, month string) string {
	return fmt.Sprintf("%sreserved:month:%s:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), month)
}

func atomicDayReservationKey(tenantID string, scope governor.AdmissionScope, day string) string {
	return fmt.Sprintf("%sreserved:day:%s:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), day)
}

func atomicMonthCostReservationKey(tenantID string, scope governor.AdmissionScope, month string) string {
	return fmt.Sprintf("%sreserved:cost:month:%s:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), month)
}

func atomicDayCostReservationKey(tenantID string, scope governor.AdmissionScope, day string) string {
	return fmt.Sprintf("%sreserved:cost:day:%s:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID), day)
}

func atomicReservationExpiryKey(tenantID string, scope governor.AdmissionScope) string {
	return fmt.Sprintf("%sreserved:leases:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID))
}

func atomicReservationDetailKey(tenantID string, scope governor.AdmissionScope) string {
	return fmt.Sprintf("%sreserved:details:%s:%s", atomicKeyPrefix(tenantID), scope.Scope, encodedAdmissionPart(scope.ID))
}

func runtimeAdmissionError(requestID string, err error) error {
	return &governor.AdmissionRuntimeError{Metric: "runtime_fault", RequestID: requestID, Err: err}
}

func validateFinalizeResult(values []interface{}, requestID, targetState string) error {
	code, err := redisInt64(values, 0)
	if err != nil {
		return runtimeAdmissionError(requestID, err)
	}
	if code == 0 {
		return runtimeAdmissionError(requestID, errors.New("quota admission lease expired"))
	}
	state := ""
	if len(values) > 1 {
		state = fmt.Sprint(values[1])
	}
	if code == 2 && state != targetState {
		return &governor.AdmissionIdempotencyError{RequestID: requestID, State: state, Reason: "conflicting terminal operation"}
	}
	if code == 3 {
		return &governor.AdmissionIdempotencyError{RequestID: requestID, State: state, Reason: "lease fingerprint changed"}
	}
	return nil
}

func hasEnforcingAdmissionScope(scopes []governor.AdmissionScope) bool {
	for _, scope := range scopes {
		if scope.EnforcementMode != "enforce" {
			continue
		}
		if scope.RPMLimit > 0 || scope.RPMBlocked || scope.TPMConfigured || scope.TPMBlocked || scope.ConcurrencyLimit > 0 || scope.ConcurrencyBlocked {
			return true
		}
		if scope.OverageAction != "notify" && (scope.DailyTokenLimit > 0 || scope.DailyTokenBlocked || scope.MonthlyTokenLimit > 0 || scope.MonthlyTokenBlocked || scope.DailyCostLimitMicros > 0 || scope.DailyCostBlocked || scope.MonthlyCostLimitMicros > 0 || scope.MonthlyCostBlocked) {
			return true
		}
	}
	return false
}

func admissionLeaseFingerprint(lease *governor.AdmissionLease) string {
	canonical := struct {
		TenantID              string
		RequestID             string
		LeaseID               string
		EstimatedTokens       int64
		EstimatedCostMicros   int64
		CostEstimateAvailable bool
		Scopes                []governor.AdmissionScope
	}{
		lease.TenantID, lease.RequestID, lease.LeaseID, lease.EstimatedTokens,
		lease.EstimatedCostMicros, lease.CostEstimateAvailable, lease.Scopes,
	}
	raw, _ := json.Marshal(canonical)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func decodeAdmissionLease(value interface{}) (*governor.AdmissionLease, error) {
	var raw []byte
	switch typed := value.(type) {
	case string:
		raw = []byte(typed)
	case []byte:
		raw = typed
	default:
		return nil, fmt.Errorf("invalid stored admission lease type %T", value)
	}
	var lease governor.AdmissionLease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return nil, fmt.Errorf("decode stored admission lease: %w", err)
	}
	if lease.RequestID == "" || lease.LeaseID == "" || lease.Fingerprint == "" {
		return nil, errors.New("stored admission lease is incomplete")
	}
	return &lease, nil
}

func admissionObservationFromRedis(values []interface{}, scopes []governor.AdmissionScope) (governor.AdmissionObservation, error) {
	if len(values) < 7 {
		return governor.AdmissionObservation{}, errors.New("invalid soft quota observation")
	}
	index, err := redisInt64(values, 1)
	if err != nil || index < 1 || int(index) > len(scopes) {
		return governor.AdmissionObservation{}, errors.New("invalid soft quota observation scope")
	}
	limit, _ := redisInt64(values, 2)
	used, _ := redisInt64(values, 3)
	reserved, _ := redisInt64(values, 4)
	requested, _ := redisInt64(values, 5)
	retryAfter, _ := redisInt64(values, 6)
	return governor.AdmissionObservation{
		Metric: fmt.Sprint(values[0]), Scope: scopes[index-1].Scope,
		Limit: limit, Used: used, Reserved: reserved, Requested: requested, RetryAfter: retryAfter,
	}, nil
}

func redisInt64(values []interface{}, index int) (int64, error) {
	if index < 0 || index >= len(values) {
		return 0, fmt.Errorf("redis admission response index %d is missing", index)
	}
	value := values[index]
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		var parsed int64
		if _, err := fmt.Sscan(typed, &parsed); err != nil {
			return 0, err
		}
		return parsed, nil
	case []byte:
		return redisInt64([]interface{}{string(typed)}, 0)
	default:
		return 0, fmt.Errorf("invalid redis integer type %T", value)
	}
}

// 不受策略行 enforcement_mode=soft 和 overage_action=notify 影响。没有金额预算的作用域保持原样，
// 因此 token/RPM 等限额的语义不变。入参不会被修改。
func applyBudgetCutoffToScopes(scopes []governor.AdmissionScope) []governor.AdmissionScope {
	out := make([]governor.AdmissionScope, len(scopes))
	copy(out, scopes)
	for index := range out {
		scope := &out[index]
		hasMoneyBudget := scope.DailyCostLimitMicros > 0 || scope.MonthlyCostLimitMicros > 0 || scope.DailyCostBlocked || scope.MonthlyCostBlocked
		if !hasMoneyBudget || scope.EnforcementMode == "accounting" || scope.EnforcementMode == "soft" || scope.OverageAction == "notify" {
			continue
		}
		scope.EnforcementMode = "enforce"
		if scope.OverageAction == "" {
			scope.OverageAction = "rate_limit"
		}
	}
	return out
}

func hasMoneyBudgetScope(scopes []governor.AdmissionScope) bool {
	for _, scope := range scopes {
		if scope.EnforcementMode != "enforce" || scope.OverageAction == "notify" {
			continue
		}
		if scope.DailyCostLimitMicros > 0 || scope.MonthlyCostLimitMicros > 0 || scope.DailyCostBlocked || scope.MonthlyCostBlocked {
			return true
		}
	}
	return false
}

// cutoffRuntimeError 在断流开启且存在金额预算时，把运行时故障标成“断流 fail-closed”，让 HTTP 层给出
// 中文 503；其余情况与原有 runtimeAdmissionError 完全一致。
func cutoffRuntimeError(cutoff bool, scopes []governor.AdmissionScope, requestID string, err error) error {
	runtime := &governor.AdmissionRuntimeError{Metric: "runtime_fault", RequestID: requestID, Err: err}
	runtime.BudgetCutoff = cutoff && hasMoneyBudgetScope(scopes)
	return runtime
}

func isMoneyMetric(metric string) bool {
	return metric == "day_cost_micros" || metric == "month_cost_micros"
}

func scopeDisplayNames(quotas []governor.ScopedQuota) map[string]string {
	names := make(map[string]string, len(quotas))
	for _, quota := range quotas {
		if quota.Name != "" {
			names[quota.Scope+"\x00"+quota.ID] = quota.Name
		}
	}
	return names
}

// admissionResetAt 返回额度周期的下一次重置时间：日预算为次日 0 点，月预算为下月 1 日 0 点（按策略时区）。
func admissionResetAt(now time.Time, timezone, metric string) time.Time {
	location, err := time.LoadLocation(normalizedQuotaTimezone(timezone))
	if err != nil {
		return time.Time{}
	}
	local := now.In(location)
	if metric == "day_cost_micros" {
		return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location).AddDate(0, 0, 1)
	}
	return time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, location).AddDate(0, 1, 0)
}
