#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_executable() {
  [[ -x "$1" ]] || fail "not executable: $1"
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  [[ "$haystack" == *"$needle"* ]] || fail "expected output to contain: $needle"
}

assert_file scripts/harness/preflight.sh
assert_file scripts/harness/scope-check.sh
assert_file scripts/harness/evidence.sh
assert_file scripts/harness/verify.sh

assert_executable scripts/harness/preflight.sh
assert_executable scripts/harness/scope-check.sh
assert_executable scripts/harness/evidence.sh
assert_executable scripts/harness/verify.sh

bash -n scripts/harness/preflight.sh
bash -n scripts/harness/scope-check.sh
bash -n scripts/harness/evidence.sh
bash -n scripts/harness/verify.sh

verify_list="$(scripts/harness/verify.sh --list)"
assert_contains "$verify_list" "harness"
assert_contains "$verify_list" "gateway-core"
assert_contains "$verify_list" "control-plane"

goal_file="$(mktemp)"
cat > "$goal_file" <<'GOAL'
# Test Goal

## 允许修改

- docs/harness/**
- scripts/harness/**
- .gitignore
- docs/superpowers/plans/**
GOAL

scripts/harness/scope-check.sh --goal "$goal_file"
rm -f "$goal_file"

loop_id="test-harness-script"
rm -rf ".harness/runs/$loop_id"
evidence_dir="$(scripts/harness/evidence.sh "$loop_id")"
[[ "$evidence_dir" == *".harness/runs/$loop_id" ]] || fail "unexpected evidence dir: $evidence_dir"
assert_file ".harness/runs/$loop_id/status.txt"
assert_file ".harness/runs/$loop_id/diff-stat.txt"
rm -rf ".harness/runs/$loop_id"
