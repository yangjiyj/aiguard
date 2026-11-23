#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/mcp_real_e2e/claude_output.sh
source "$SCRIPT_DIR/claude_output.sh"

fixture="$(mktemp)"
trap 'rm -f "$fixture"' EXIT

assert_connection_state() {
  local label="$1"
  local expected="$2"
  local output="$3"
  local actual=false
  printf '%s\n' "$output" >"$fixture"
  if claude_mcp_output_connected "$fixture"; then
    actual=true
  fi
  if [[ "$actual" != "$expected" ]]; then
    printf 'FAIL %s: expected %s, got %s\n' "$label" "$expected" "$actual" >&2
    return 1
  fi
}

assert_connection_state \
  "plain connected" true \
  $'jjdguard-real-e2e:\n  Status: Connected\n  Type: http'
assert_connection_state \
  "unicode check connected" true \
  $'jjdguard-real-e2e:\n  Status: \u2713 Connected\n  Type: http'
assert_connection_state \
  "lowercase connected" true \
  $'jjdguard-real-e2e:\n  status: connected\n  type: http'
assert_connection_state \
  "not connected" false \
  $'jjdguard-real-e2e:\n  Status: Not connected\n  Type: http'
assert_connection_state \
  "disconnected" false \
  $'jjdguard-real-e2e:\n  Status: Disconnected\n  Type: http'
assert_connection_state \
  "connection failed" false \
  $'jjdguard-real-e2e:\n  Status: Failed to connect\n  Error: HTTP 401'
assert_connection_state \
  "generic error" false \
  $'jjdguard-real-e2e:\n  Error: MCP server unavailable'

printf 'Claude MCP output fixtures: OK\n'
