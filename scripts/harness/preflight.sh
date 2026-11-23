#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/harness/preflight.sh --goal <goal-contract>

Run conservative checks before starting a Loop.

Environment:
  HARNESS_REPO_ROOT       Override git repository root, mainly for tests.
  HARNESS_REQUIRE_HOME    Set to 0 to skip the canonical JJDGuard lineage check.
  HARNESS_CANONICAL_ROOT  Override canonical source root (default /home/dev/jjdguard-src).
USAGE
}

fail() {
  echo "preflight: $*" >&2
  exit 1
}

goal=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --goal)
      goal="${2:-}"
      [[ -n "$goal" ]] || fail "--goal requires a file"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$goal" ]] || fail "missing --goal <goal-contract>"

repo_root="${HARNESS_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null)}"
[[ -n "$repo_root" ]] || fail "not inside a git repository"
repo_root="$(cd "$repo_root" && pwd -P)"
cd "$repo_root"

require_home="${HARNESS_REQUIRE_HOME:-1}"
canonical_root="${HARNESS_CANONICAL_ROOT:-/home/dev/jjdguard-src}"
if [[ "$require_home" != "0" ]]; then
  [[ -d "$canonical_root" ]] || fail "canonical JJDGuard source root is missing: $canonical_root"
  current_common="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || fail "cannot resolve git common dir for $repo_root"
  canonical_common="$(git -C "$canonical_root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || fail "cannot resolve git common dir for $canonical_root"
  current_common="$(cd "$current_common" && pwd -P)"
  canonical_common="$(cd "$canonical_common" && pwd -P)"
  [[ "$current_common" == "$canonical_common" ]] || fail "repository is not a worktree of canonical JJDGuard source: $repo_root"
fi

if [[ "$goal" != /* ]]; then
  goal="$repo_root/$goal"
fi
[[ -f "$goal" ]] || fail "goal contract not found: $goal"

echo "preflight: repo=$repo_root"
echo "preflight: goal=$goal"
echo "preflight: head=$(git rev-parse --short HEAD)"
echo "preflight: status"
git status --short

untracked_count="$(git ls-files --others --exclude-standard | wc -l | tr -d ' ')"
if [[ "$untracked_count" != "0" ]]; then
  echo "preflight: note: $untracked_count untracked file(s) exist; they will not be modified automatically" >&2
fi

echo "preflight: ok"
