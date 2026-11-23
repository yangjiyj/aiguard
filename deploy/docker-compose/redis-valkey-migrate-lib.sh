#!/usr/bin/env bash
# Redis 7.4 -> Valkey 8.1 logical migration used by upgrade-bundle.sh and upgrade.sh.
#
# Valkey 8.x cannot load the RDB v12 files Redis 7.4 writes, and DUMP/RESTORE or
# REPLICAOF cannot cross that boundary either, so the upgrade copies the keys that
# must survive at command level:
#   pause:*          key pause state; lives only in Redis (losing it re-enables paused keys)
#   budget:*         spend counters (rebuilt from PostgreSQL on gateway start, copied anyway)
#   daily_tokens:* monthly_tokens:*   token counters, never rebuilt
# Everything else (session:*, auth:captcha:*, orgquota:*, rpm:*, concurrency:*) is
# short-lived or recomputed and is intentionally not copied; the log states how many.
#
# All container IO goes through rvm_cli so tests can replace it. Values travel as
# x-prefixed hex, so arbitrary bytes, spaces and newlines survive. The password is
# read inside the container (REDIS_PASSWORD) and never appears in a host argv.

RVM_PREFIXES=("pause:*" "budget:*" "daily_tokens:*" "monthly_tokens:*")

# shellcheck disable=SC2016
RVM_EXPORT_LUA='
local out, seen = {}, {}
local function hex(s)
  return "x" .. (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end
for _, pat in ipairs(ARGV) do
  local cursor = "0"
  repeat
    local r = redis.call("SCAN", cursor, "MATCH", pat, "COUNT", 1000)
    cursor = r[1]
    for _, k in ipairs(r[2]) do
      if not seen[k] then
        seen[k] = true
        local t = redis.call("TYPE", k)["ok"]
        local ttl = redis.call("PTTL", k)
        if ttl ~= -2 then
          if t == "string" then
            out[#out + 1] = "S " .. ttl .. " " .. hex(k) .. " " .. hex(redis.call("GET", k))
          elseif t == "hash" then
            local h, fv = redis.call("HGETALL", k), {}
            for i = 1, #h, 2 do fv[#fv + 1] = hex(h[i]) .. " " .. hex(h[i + 1]) end
            table.sort(fv)
            out[#out + 1] = "H " .. ttl .. " " .. hex(k) .. " " .. table.concat(fv, " ")
          else
            out[#out + 1] = "E " .. t .. " " .. hex(k)
          end
        end
      end
    end
  until cursor == "0"
end
out[#out + 1] = "N " .. redis.call("DBSIZE")
return out
'

# ARGV[1..n-1] = prefixes to resync, ARGV[n] = export dump (appended by -x from stdin).
# shellcheck disable=SC2016
RVM_IMPORT_LUA='
local function unhex(s)
  return (string.gsub(string.sub(s, 2), "%x%x", function(h) return string.char(tonumber(h, 16)) end))
end
local dump, n = ARGV[#ARGV], 0
for i = 1, #ARGV - 1 do
  local cursor = "0"
  repeat
    local r = redis.call("SCAN", cursor, "MATCH", ARGV[i], "COUNT", 1000)
    cursor = r[1]
    for _, k in ipairs(r[2]) do redis.call("DEL", k) end
  until cursor == "0"
end
for line in string.gmatch(dump, "[^\n]+") do
  local f = {}
  for w in string.gmatch(line, "%S+") do f[#f + 1] = w end
  local kind, ttl = f[1], tonumber(f[2])
  if kind == "S" or kind == "H" then
    local key = unhex(f[3])
    if kind == "S" then
      redis.call("SET", key, unhex(f[4]))
    else
      local args = {}
      for j = 4, #f do
        args[#args + 1] = unhex(f[j])
        if #args == 400 then redis.call("HSET", key, unpack(args)); args = {} end
      end
      if #args > 0 then redis.call("HSET", key, unpack(args)) end
    end
    if ttl and ttl > 0 then redis.call("PEXPIRE", key, ttl) end
    n = n + 1
  end
end
return n
'

rvm_log() { printf '%s\n' "[redis->valkey] $*" >&2; }

# rvm_cli <container> <cli args...>   (stdin is forwarded for -x)
rvm_cli() {
  local container="$1"; shift
  REDISCLI_AUTH="${REDIS_PASSWORD:-}" docker exec -i -e REDISCLI_AUTH "$container" sh -c '
    c="$(command -v valkey-cli || command -v redis-cli)" || exit 127
    REDISCLI_AUTH="${REDISCLI_AUTH:-${REDIS_PASSWORD:-}}"; export REDISCLI_AUTH
    exec "$c" --raw "$@"' rvm "$@"
}

# Prints redis | valkey | unknown.
rvm_flavor() {
  local info
  info="$(rvm_cli "$1" INFO server </dev/null 2>/dev/null)" || { echo unknown; return 0; }
  if grep -q '^valkey_version:' <<<"$info"; then echo valkey
  elif grep -q '^redis_version:' <<<"$info"; then echo redis
  else echo unknown; fi
}

# rvm_export <container> <out-file>: must-keep keys only; fails on unexpected types.
rvm_export() {
  local container="$1" out="$2"
  rvm_cli "$container" EVAL "$RVM_EXPORT_LUA" 0 "${RVM_PREFIXES[@]}" </dev/null >"$out.tmp" || return 1
  if grep -qvE '^(S -?[0-9]+ x[0-9a-f]* x[0-9a-f]*|H -?[0-9]+ x[0-9a-f]*( x[0-9a-f]* x[0-9a-f]*)+|E [a-z]+ x[0-9a-f]*|N [0-9]+)$' "$out.tmp"; then
    rvm_log "export returned unexpected output"; return 1
  fi
  grep -q '^N [0-9]*$' "$out.tmp" || { rvm_log "export output is incomplete"; return 1; }
  if grep -q '^E ' "$out.tmp"; then
    rvm_log "must-keep prefix holds an unsupported key type: $(grep -c '^E ' "$out.tmp") key(s)"; return 1
  fi
  mv -f "$out.tmp" "$out"
}

# rvm_import <container> <dump-file>: resyncs the must-keep prefixes (deletes then
# writes), so re-running after a rolled-back attempt converges on the source.
rvm_import() {
  local container="$1" dump="$2" out
  out="$(rvm_cli "$container" -x EVAL "$RVM_IMPORT_LUA" 0 "${RVM_PREFIXES[@]}" <"$dump")" || return 1
  [[ "$out" =~ ^[0-9]+$ ]] || { rvm_log "import returned unexpected output"; return 1; }
  printf '%s\n' "$out"
}

# Normalized view for comparison: TTL reduced to P(ersistent) / T(expiring).
rvm_normalize() {
  awk '$1 == "S" || $1 == "H" { $2 = ($2 == "-1") ? "P" : "T"; print }' "$1" | LC_ALL=C sort
}

rvm_verify() {
  local container="$1" dump="$2" check="$2.verify"
  rvm_export "$container" "$check" || return 1
  if ! cmp -s <(rvm_normalize "$dump") <(rvm_normalize "$check"); then
    rvm_log "verification failed: must-keep keys differ after import"
    rm -f -- "$check"
    return 1
  fi
  rm -f -- "$check"
}

rvm_wait_ready() {
  local container="$1" i
  for ((i = 0; i < ${RVM_READY_TRIES:-60}; i++)); do
    [[ "$(rvm_cli "$container" PING </dev/null 2>/dev/null)" == PONG ]] && return 0
    sleep "${RVM_READY_INTERVAL:-1}"
  done
  rvm_log "new redis service did not answer PING"
  return 1
}

# Upgrade step. Callers define the four hooks below for their Compose layout:
#   rvm_hook_old_container  prints the running old `redis` container id, or nothing
#   rvm_hook_stop_old       stops the old `redis` container (redis-data stays as is)
#   rvm_hook_start_new      starts `redis` from the new Compose (Valkey on valkey-data)
#   rvm_hook_new_container  prints the new `redis` container id
# The export is taken after the application writers are stopped, so it is final.
# Returns 0 when there is nothing to do: no old service, or it already runs Valkey.
# On failure after the old container was stopped the caller must run its normal
# rollback, which recreates the old `redis` on the untouched redis-data volume.
migrate_redis_to_valkey() {
  local dir="$1" old flavor new dump copied total
  old="$(rvm_hook_old_container)" || old=""
  if [[ -z "$old" ]]; then
    rvm_log "redis service is not running; nothing to migrate"
    return 0
  fi
  flavor="$(rvm_flavor "$old")"
  case "$flavor" in
    valkey) rvm_log "redis service already runs Valkey; no migration needed"; return 0 ;;
    redis) ;;
    *) rvm_log "cannot query the running redis service (auth or connectivity)"; return 1 ;;
  esac
  dump="$dir/redis-valkey-export.$$.txt"
  rvm_export "$old" "$dump" || { rm -f -- "$dump" "$dump.tmp"; return 1; }
  total="$(sed -n 's/^N //p' "$dump")"
  rvm_hook_stop_old || { rvm_log "stopping the old redis container failed"; rm -f -- "$dump"; return 1; }
  rvm_hook_start_new || { rvm_log "starting Valkey failed"; rm -f -- "$dump"; return 1; }
  new="$(rvm_hook_new_container)" || new=""
  [[ -n "$new" && "$new" != "$old" ]] || { rvm_log "new redis container not found"; rm -f -- "$dump"; return 1; }
  rvm_wait_ready "$new" || { rm -f -- "$dump"; return 1; }
  [[ "$(rvm_flavor "$new")" == valkey ]] || { rvm_log "new redis service is not Valkey"; rm -f -- "$dump"; return 1; }
  copied="$(rvm_import "$new" "$dump")" || { rm -f -- "$dump"; return 1; }
  rvm_verify "$new" "$dump" || { rm -f -- "$dump"; return 1; }
  rm -f -- "$dump"
  rvm_log "copied $copied must-keep key(s) (pause/budget/daily_tokens/monthly_tokens) of $total in total;" \
    "session, captcha, quota and rate-limit keys are not copied by design"
  rvm_log "the old redis-data volume is left untouched as the rollback anchor"
}
