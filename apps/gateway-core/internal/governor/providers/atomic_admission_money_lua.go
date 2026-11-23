package providers

const atomicAdmissionMoneyLua = `
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local minute_ttl_ms = tonumber(ARGV[2])
local lease_ttl_ms = tonumber(ARGV[3])
local request_id = ARGV[4]
local estimated_tokens = tonumber(ARGV[5])
local estimated_cost = tonumber(ARGV[6])
local scope_count = tonumber(ARGV[7])
local lease_payload = ARGV[8]
local lease_owner = cjson.decode(lease_payload)
local existing = redis.call('GET', KEYS[1])
if existing then
  return {2, existing}
end

local function subtract_counter(key, amount)
  if not key or key == '' or amount <= 0 then return end
  local raw = redis.call('GET', key)
  if raw then
    redis.call('SET', key, math.max(0, tonumber(raw) - amount), 'KEEPTTL')
  end
end

local observation = nil
for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 12
  local arg_offset = 9 + i * 14
  local rpm_limit = tonumber(ARGV[arg_offset])
  local tpm_limit = tonumber(ARGV[arg_offset + 1])
  local concurrency_limit = tonumber(ARGV[arg_offset + 2])
  local month_token_limit = tonumber(ARGV[arg_offset + 3])
  local day_token_limit = tonumber(ARGV[arg_offset + 4])
  local month_cost_limit = tonumber(ARGV[arg_offset + 5])
  local day_cost_limit = tonumber(ARGV[arg_offset + 6])
  local realtime_enforce = tonumber(ARGV[arg_offset + 7])
  local token_cost_enforce = tonumber(ARGV[arg_offset + 8])
  local overage_action = ARGV[arg_offset + 9]
  local month_reservation_ttl_ms = tonumber(ARGV[arg_offset + 10])
  local day_reservation_ttl_ms = tonumber(ARGV[arg_offset + 11])
  local day_retry_seconds = tonumber(ARGV[arg_offset + 12])
  local month_retry_seconds = tonumber(ARGV[arg_offset + 13])

  local expired = redis.call('ZRANGEBYSCORE', KEYS[key_offset + 10], '-inf', now_ms)
  for _, expired_lease_id in ipairs(expired) do
    local raw_detail = redis.call('HGET', KEYS[key_offset + 11], expired_lease_id)
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
            redis.call('ZADD', KEYS[key_offset + 10], now_ms + active_ttl, expired_lease_id)
            if detail.concurrency_key and detail.concurrency_key ~= '' then
              redis.call('ZADD', detail.concurrency_key, now_ms + active_ttl, expired_lease_id)
            end
          end
        end
      end
      if not active then
        local token_amount = tonumber(detail.token_amount or detail.amount or 0)
        local cost_amount = tonumber(detail.cost_amount or 0)
        subtract_counter(detail.tpm_key, token_amount)
        subtract_counter(detail.month_token_key or detail.month_key, token_amount)
        subtract_counter(detail.day_token_key or detail.day_key, token_amount)
        subtract_counter(detail.month_cost_key, cost_amount)
        subtract_counter(detail.day_cost_key, cost_amount)
        if detail.concurrency_key and detail.concurrency_key ~= '' then
          redis.call('ZREM', detail.concurrency_key, expired_lease_id)
        end
        redis.call('HDEL', KEYS[key_offset + 11], expired_lease_id)
        redis.call('ZREM', KEYS[key_offset + 10], expired_lease_id)
      end
    else
      redis.call('ZREM', KEYS[key_offset + 10], expired_lease_id)
    end
  end

  redis.call('ZREMRANGEBYSCORE', KEYS[key_offset + 3], '-inf', now_ms)
  local rpm_used = tonumber(redis.call('GET', KEYS[key_offset]) or '0')
  local tpm_used = tonumber(redis.call('GET', KEYS[key_offset + 1]) or '0')
  local tpm_reserved = tonumber(redis.call('GET', KEYS[key_offset + 2]) or '0')
  local concurrency_used = tonumber(redis.call('ZCOUNT', KEYS[key_offset + 3], '(' .. now_ms, '+inf'))
  local month_token_used = tonumber(redis.call('HGET', KEYS[key_offset + 4], 'tokens') or '0')
  local day_token_used = tonumber(redis.call('HGET', KEYS[key_offset + 5], 'tokens') or '0')
  local month_cost_used = tonumber(redis.call('HGET', KEYS[key_offset + 4], 'cost_micros') or '0')
  local day_cost_used = tonumber(redis.call('HGET', KEYS[key_offset + 5], 'cost_micros') or '0')
  local month_cost_unpriced = tonumber(redis.call('HGET', KEYS[key_offset + 4], 'cost_unpriced_requests') or '0')
  local day_cost_unpriced = tonumber(redis.call('HGET', KEYS[key_offset + 5], 'cost_unpriced_requests') or '0')
  local month_token_reserved = tonumber(redis.call('GET', KEYS[key_offset + 6]) or '0')
  local day_token_reserved = tonumber(redis.call('GET', KEYS[key_offset + 7]) or '0')
  local month_cost_reserved = tonumber(redis.call('GET', KEYS[key_offset + 8]) or '0')
  local day_cost_reserved = tonumber(redis.call('GET', KEYS[key_offset + 9]) or '0')
  local minute_retry = math.max(1, math.ceil(minute_ttl_ms / 1000) - 60)

  local function reject_or_observe(metric, limit, used, reserved, requested, retry, enforce, include_action)
    if enforce == 1 then
      if include_action then
        return {0, metric, i + 1, limit, used, reserved, requested, retry, overage_action}
      end
      return {0, metric, i + 1, limit, used, reserved, requested, retry}
    end
    if not observation then
      observation = {metric, i + 1, limit, used, reserved, requested, retry}
    end
    return nil
  end

  if rpm_limit > 0 and rpm_used >= rpm_limit then
    local rejected = reject_or_observe('rpm', rpm_limit, rpm_used, 0, 1, minute_retry, realtime_enforce, false)
    if rejected then return rejected end
  end
  if tpm_limit > 0 and tpm_used + tpm_reserved + estimated_tokens > tpm_limit then
    local rejected = reject_or_observe('tpm', tpm_limit, tpm_used, tpm_reserved, estimated_tokens, minute_retry, realtime_enforce, false)
    if rejected then return rejected end
  end
  if concurrency_limit > 0 and concurrency_used >= concurrency_limit then
    local first = redis.call('ZRANGE', KEYS[key_offset + 3], 0, 0, 'WITHSCORES')
    local retry = 1
    if #first >= 2 then retry = math.max(1, math.ceil((tonumber(first[2]) - now_ms) / 1000)) end
    local rejected = reject_or_observe('concurrency', concurrency_limit, concurrency_used, 0, 1, retry, realtime_enforce, false)
    if rejected then return rejected end
  end
  if day_token_limit > 0 and day_token_used + day_token_reserved + estimated_tokens > day_token_limit then
    local rejected = reject_or_observe('day_tokens', day_token_limit, day_token_used, day_token_reserved, estimated_tokens, day_retry_seconds, token_cost_enforce, true)
    if rejected then return rejected end
  end
  if month_token_limit > 0 and month_token_used + month_token_reserved + estimated_tokens > month_token_limit then
    local rejected = reject_or_observe('month_tokens', month_token_limit, month_token_used, month_token_reserved, estimated_tokens, month_retry_seconds, token_cost_enforce, true)
    if rejected then return rejected end
  end
  if day_cost_limit > 0 and day_cost_unpriced > 0 then
    if not observation then observation = {'day_cost_usage_incomplete', i + 1, day_cost_limit, day_cost_used, day_cost_reserved, estimated_cost, day_retry_seconds} end
  end
  if month_cost_limit > 0 and month_cost_unpriced > 0 then
    if not observation then observation = {'month_cost_usage_incomplete', i + 1, month_cost_limit, month_cost_used, month_cost_reserved, estimated_cost, month_retry_seconds} end
  end
  if day_cost_limit > 0 and day_cost_used + day_cost_reserved + estimated_cost > day_cost_limit then
    local rejected = reject_or_observe('day_cost_micros', day_cost_limit, day_cost_used, day_cost_reserved, estimated_cost, day_retry_seconds, token_cost_enforce, true)
    if rejected then return rejected end
  end
  if month_cost_limit > 0 and month_cost_used + month_cost_reserved + estimated_cost > month_cost_limit then
    local rejected = reject_or_observe('month_cost_micros', month_cost_limit, month_cost_used, month_cost_reserved, estimated_cost, month_retry_seconds, token_cost_enforce, true)
    if rejected then return rejected end
  end
end

for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 12
  local arg_offset = 9 + i * 14
  local rpm_limit = tonumber(ARGV[arg_offset])
  local tpm_limit = tonumber(ARGV[arg_offset + 1])
  local concurrency_limit = tonumber(ARGV[arg_offset + 2])
  local month_token_limit = tonumber(ARGV[arg_offset + 3])
  local day_token_limit = tonumber(ARGV[arg_offset + 4])
  local month_cost_limit = tonumber(ARGV[arg_offset + 5])
  local day_cost_limit = tonumber(ARGV[arg_offset + 6])
  local month_reservation_ttl_ms = tonumber(ARGV[arg_offset + 10])
  local day_reservation_ttl_ms = tonumber(ARGV[arg_offset + 11])

  if rpm_limit > 0 then
    redis.call('INCR', KEYS[key_offset])
    redis.call('PEXPIRE', KEYS[key_offset], minute_ttl_ms)
  end
  if tpm_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 2], estimated_tokens)
    redis.call('PEXPIRE', KEYS[key_offset + 2], minute_ttl_ms)
  end
  if concurrency_limit > 0 then
    redis.call('ZADD', KEYS[key_offset + 3], now_ms + lease_ttl_ms, request_id)
    redis.call('PEXPIRE', KEYS[key_offset + 3], lease_ttl_ms * 2)
  end
  if month_token_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 6], estimated_tokens)
    redis.call('PEXPIRE', KEYS[key_offset + 6], month_reservation_ttl_ms)
  end
  if day_token_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 7], estimated_tokens)
    redis.call('PEXPIRE', KEYS[key_offset + 7], day_reservation_ttl_ms)
  end
  if month_cost_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 8], estimated_cost)
    redis.call('PEXPIRE', KEYS[key_offset + 8], month_reservation_ttl_ms)
  end
  if day_cost_limit > 0 then
    redis.call('INCRBY', KEYS[key_offset + 9], estimated_cost)
    redis.call('PEXPIRE', KEYS[key_offset + 9], day_reservation_ttl_ms)
  end
  if tpm_limit > 0 or concurrency_limit > 0 or month_token_limit > 0 or day_token_limit > 0 or month_cost_limit > 0 or day_cost_limit > 0 then
    local detail = cjson.encode({
      token_amount = estimated_tokens,
      cost_amount = estimated_cost,
      tpm_key = tpm_limit > 0 and KEYS[key_offset + 2] or '',
      month_token_key = month_token_limit > 0 and KEYS[key_offset + 6] or '',
      day_token_key = day_token_limit > 0 and KEYS[key_offset + 7] or '',
      month_cost_key = month_cost_limit > 0 and KEYS[key_offset + 8] or '',
      day_cost_key = day_cost_limit > 0 and KEYS[key_offset + 9] or '',
      concurrency_key = concurrency_limit > 0 and KEYS[key_offset + 3] or '',
      lease_key = KEYS[1],
      fingerprint = lease_owner.fingerprint
    })
    redis.call('ZADD', KEYS[key_offset + 10], now_ms + lease_ttl_ms, request_id)
    redis.call('HSET', KEYS[key_offset + 11], request_id, detail)
    local detail_ttl = math.max(month_reservation_ttl_ms, day_reservation_ttl_ms, lease_ttl_ms * 2)
    redis.call('PEXPIRE', KEYS[key_offset + 10], detail_ttl)
    redis.call('PEXPIRE', KEYS[key_offset + 11], detail_ttl)
  end
end
redis.call('SET', KEYS[1], lease_payload, 'PX', lease_ttl_ms)
if observation then
  return {1, 'acquired', observation[1], observation[2], observation[3], observation[4], observation[5], observation[6], observation[7]}
end
return {1, 'acquired', '', 0, 0, 0, 0, 0, 0}
`

const settleAdmissionMoneyLua = `
local existing = redis.call('GET', KEYS[1])
if not existing then return {0, 'expired'} end
local decoded = cjson.decode(existing)
if decoded.fingerprint ~= ARGV[10] then return {3, decoded.state} end
if decoded.state ~= 'acquired' then return {2, decoded.state} end
local estimated_tokens = tonumber(ARGV[1])
local actual_tokens = tonumber(ARGV[2])
local estimated_cost = tonumber(ARGV[3])
local actual_cost = tonumber(ARGV[4])
local cost_state = ARGV[5]
local request_id = ARGV[6]
local finalized_ttl_ms = tonumber(ARGV[7])
local scope_count = tonumber(ARGV[8])

-- A reserved counter going below zero means this lease was already
-- subtracted (duplicate settle/release or expiry reclaim racing a finalize).
-- The counter still clamps at 0, but the deficit is reported back so the
-- gateway can raise an anomaly instead of silently masking it.
local underflows = {}
local function subtract_counter(key, amount)
  local raw = redis.call('GET', key)
  if raw then
    local remaining = tonumber(raw) - amount
    if remaining < 0 then
      table.insert(underflows, key)
      table.insert(underflows, tostring(-remaining))
      remaining = 0
    end
    redis.call('SET', key, remaining, 'KEEPTTL')
  end
end

for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 11
  local arg_offset = 11 + i * 6
  local tpm_limit = tonumber(ARGV[arg_offset])
  local concurrency_limit = tonumber(ARGV[arg_offset + 1])
  local month_token_limit = tonumber(ARGV[arg_offset + 2])
  local day_token_limit = tonumber(ARGV[arg_offset + 3])
  local month_cost_limit = tonumber(ARGV[arg_offset + 4])
  local day_cost_limit = tonumber(ARGV[arg_offset + 5])
  if tpm_limit > 0 then
    local ttl = redis.call('PTTL', KEYS[key_offset + 1])
    redis.call('INCRBY', KEYS[key_offset], actual_tokens)
    if ttl > 0 then redis.call('PEXPIRE', KEYS[key_offset], ttl) end
    subtract_counter(KEYS[key_offset + 1], estimated_tokens)
  end
  if concurrency_limit > 0 then redis.call('ZREM', KEYS[key_offset + 2], request_id) end
  redis.call('HINCRBY', KEYS[key_offset + 3], 'tokens', actual_tokens)
  redis.call('HINCRBY', KEYS[key_offset + 4], 'tokens', actual_tokens)
  redis.call('HINCRBY', KEYS[key_offset + 3], 'cost_micros', actual_cost)
  redis.call('HINCRBY', KEYS[key_offset + 4], 'cost_micros', actual_cost)
  if cost_state == 'estimated' then
    redis.call('HINCRBY', KEYS[key_offset + 3], 'cost_estimated_requests', 1)
    redis.call('HINCRBY', KEYS[key_offset + 4], 'cost_estimated_requests', 1)
  elseif cost_state == 'unpriced' then
    redis.call('HINCRBY', KEYS[key_offset + 3], 'cost_unpriced_requests', 1)
    redis.call('HINCRBY', KEYS[key_offset + 4], 'cost_unpriced_requests', 1)
  end
  if month_token_limit > 0 then subtract_counter(KEYS[key_offset + 5], estimated_tokens) end
  if day_token_limit > 0 then subtract_counter(KEYS[key_offset + 6], estimated_tokens) end
  if month_cost_limit > 0 then subtract_counter(KEYS[key_offset + 7], estimated_cost) end
  if day_cost_limit > 0 then subtract_counter(KEYS[key_offset + 8], estimated_cost) end
  redis.call('ZREM', KEYS[key_offset + 9], request_id)
  redis.call('HDEL', KEYS[key_offset + 10], request_id)
end
redis.call('SET', KEYS[1], ARGV[9], 'PX', finalized_ttl_ms)
return {1, 'settled', underflows}
`

const releaseAdmissionMoneyLua = `
local existing = redis.call('GET', KEYS[1])
if not existing then return {0, 'expired'} end
local decoded = cjson.decode(existing)
if decoded.fingerprint ~= ARGV[10] then return {3, decoded.state} end
if decoded.state ~= 'acquired' then return {2, decoded.state} end
local estimated_tokens = tonumber(ARGV[1])
local actual_tokens = tonumber(ARGV[2])
local estimated_cost = tonumber(ARGV[3])
local actual_cost = tonumber(ARGV[4])
local cost_state = ARGV[5]
local request_id = ARGV[6]
local finalized_ttl_ms = tonumber(ARGV[7])
local scope_count = tonumber(ARGV[8])

-- A reserved counter going below zero means this lease was already
-- subtracted (duplicate settle/release or expiry reclaim racing a finalize).
-- The counter still clamps at 0, but the deficit is reported back so the
-- gateway can raise an anomaly instead of silently masking it.
local underflows = {}
local function subtract_counter(key, amount)
  local raw = redis.call('GET', key)
  if raw then
    local remaining = tonumber(raw) - amount
    if remaining < 0 then
      table.insert(underflows, key)
      table.insert(underflows, tostring(-remaining))
      remaining = 0
    end
    redis.call('SET', key, remaining, 'KEEPTTL')
  end
end

for i = 0, scope_count - 1 do
  local key_offset = 2 + i * 11
  local arg_offset = 11 + i * 6
  local tpm_limit = tonumber(ARGV[arg_offset])
  local concurrency_limit = tonumber(ARGV[arg_offset + 1])
  local month_token_limit = tonumber(ARGV[arg_offset + 2])
  local day_token_limit = tonumber(ARGV[arg_offset + 3])
  local month_cost_limit = tonumber(ARGV[arg_offset + 4])
  local day_cost_limit = tonumber(ARGV[arg_offset + 5])
  if tpm_limit > 0 then
    local ttl = redis.call('PTTL', KEYS[key_offset + 1])
    redis.call('INCRBY', KEYS[key_offset], actual_tokens)
    if ttl > 0 then redis.call('PEXPIRE', KEYS[key_offset], ttl) end
    subtract_counter(KEYS[key_offset + 1], estimated_tokens)
  end
  if concurrency_limit > 0 then redis.call('ZREM', KEYS[key_offset + 2], request_id) end
  redis.call('HINCRBY', KEYS[key_offset + 3], 'tokens', actual_tokens)
  redis.call('HINCRBY', KEYS[key_offset + 4], 'tokens', actual_tokens)
  if actual_cost > 0 then
    redis.call('HINCRBY', KEYS[key_offset + 3], 'cost_micros', actual_cost)
    redis.call('HINCRBY', KEYS[key_offset + 4], 'cost_micros', actual_cost)
  end
  if cost_state == 'estimated' and actual_cost > 0 then
    redis.call('HINCRBY', KEYS[key_offset + 3], 'cost_estimated_requests', 1)
    redis.call('HINCRBY', KEYS[key_offset + 4], 'cost_estimated_requests', 1)
  end
  if month_token_limit > 0 then subtract_counter(KEYS[key_offset + 5], estimated_tokens) end
  if day_token_limit > 0 then subtract_counter(KEYS[key_offset + 6], estimated_tokens) end
  if month_cost_limit > 0 then subtract_counter(KEYS[key_offset + 7], estimated_cost) end
  if day_cost_limit > 0 then subtract_counter(KEYS[key_offset + 8], estimated_cost) end
  redis.call('ZREM', KEYS[key_offset + 9], request_id)
  redis.call('HDEL', KEYS[key_offset + 10], request_id)
end
redis.call('SET', KEYS[1], ARGV[9], 'PX', finalized_ttl_ms)
return {1, 'released', underflows}
`
