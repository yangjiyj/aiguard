#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/mcp_real_e2e/log_sanitize.sh
source "$SCRIPT_DIR/log_sanitize.sh"

input="$(mktemp)"
output="$(mktemp)"
trap 'rm -f "$input" "$output"' EXIT

printf '%s\n' \
  'TOKEN=top-secret-token' \
  'PASSWORD=top-secret-password' \
  'Authorization: Bearer top-secret-bearer' \
  'ordinary build failure' >"$input"

sanitize_mcp_e2e_log "$input" "$output"

grep -Fq 'TOKEN=[REDACTED]' "$output"
grep -Fq 'PASSWORD=[REDACTED]' "$output"
grep -Fq 'Authorization: Bearer [REDACTED]' "$output"
grep -q 'ordinary build failure' "$output"
if grep -q 'top-secret' "$output"; then
  printf 'FAIL: sanitized log retained secret material\n' >&2
  exit 1
fi

printf 'MCP E2E log sanitization fixtures: OK\n'
