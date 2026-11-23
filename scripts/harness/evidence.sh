#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/harness/evidence.sh <loop-id>

Collect lightweight Loop evidence into .harness/runs/<loop-id>/.
The output path is printed on stdout.
USAGE
}

fail() {
  echo "evidence: $*" >&2
  exit 1
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

loop_id="${1:-}"
[[ -n "$loop_id" ]] || fail "missing loop id"
[[ "$loop_id" != *"/"* ]] || fail "loop id must not contain '/'"
[[ "$loop_id" != *".."* ]] || fail "loop id must not contain '..'"

repo_root="${HARNESS_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null)}"
[[ -n "$repo_root" ]] || fail "not inside a git repository"
cd "$repo_root"

run_dir="$repo_root/.harness/runs/$loop_id"
mkdir -p "$run_dir"

{
  echo "LOOP_ID=$loop_id"
  echo "REPO_ROOT=$repo_root"
  echo "CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "HEAD=$(git rev-parse --short HEAD 2>/dev/null || true)"
} > "$run_dir/metadata.env"

git status --short > "$run_dir/status.txt"
git diff --stat > "$run_dir/diff-stat.txt"
git diff --name-only > "$run_dir/diff-name-only.txt"
git diff --cached --stat > "$run_dir/diff-cached-stat.txt"
git diff --cached --name-only > "$run_dir/diff-cached-name-only.txt"

echo "$run_dir"
