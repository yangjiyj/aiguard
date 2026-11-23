#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

default_seconds() {
  local file="$1" key="$2" value
  value=$(awk -v key="$key" 'index($0, key "=${" key ":-") {value=$0; sub(/^.*:-/, "", value); sub(/s}.*$/, "", value); print value}' "$file")
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$value"
}

for compose in docker-compose.offline.yml docker-compose.yml; do
  file="$root/deploy/docker-compose/$compose"
  gateway=$(default_seconds "$file" GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT)
  engine=$(default_seconds "$file" SECURITY_ENGINE_TIMEOUT)
  (( engine >= 40 && gateway > engine && gateway < 75 )) || {
    echo "$compose does not leave enough time for the bundled CPU judge and the strict upgrade probe" >&2
    exit 1
  }
done

example="$root/deploy/docker-compose/.env.example"
grep -Fxq 'GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT=45s' "$example"
grep -Fxq 'SECURITY_ENGINE_TIMEOUT=40s' "$example"
grep -Fq 'curl --config - -sS --connect-timeout 5 -m 75' "$root/deploy/docker-compose/upgrade-bundle.sh"
grep -Fq "se.matched_summary->>'category'='ssh_private_key'" "$root/deploy/docker-compose/upgrade-bundle.sh"
echo 'upgrade security probe budget: PASS'
