#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/harness/scope-check.sh --goal <goal-contract>

Check staged and tracked diff files against allowed paths in a goal contract.
Untracked files are reported as notes but are not treated as failures by default.
USAGE
}

fail() {
  echo "scope-check: $*" >&2
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
cd "$repo_root"

if [[ "$goal" != /* ]]; then
  goal="$repo_root/$goal"
fi
[[ -f "$goal" ]] || fail "goal contract not found: $goal"

mapfile -t allowed < <(
  awk '
    /^##[[:space:]]+(允许修改|Allowed paths)/ { in_allowed = 1; next }
    /^##[[:space:]]+/ && in_allowed { exit }
    in_allowed && /^[[:space:]]*-/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      gsub(/`/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$goal"
)

[[ "${#allowed[@]}" -gt 0 ]] || fail "no allowed paths found in $goal"

mapfile -t changed < <(
  {
    git diff --name-only
    git diff --cached --name-only
  } | sort -u
)

path_allowed() {
  local file="$1"
  local rule prefix
  for rule in "${allowed[@]}"; do
    rule="${rule#./}"
    case "$rule" in
      */**)
        prefix="${rule%/**}/"
        [[ "$file" == "$prefix"* ]] && return 0
        ;;
      */*)
        [[ "$file" == "$rule" ]] && return 0
        [[ "$file" == "$rule/"* ]] && return 0
        ;;
      *)
        [[ "$file" == "$rule" ]] && return 0
        ;;
    esac
  done
  return 1
}

violations=()
for file in "${changed[@]}"; do
  [[ -n "$file" ]] || continue
  if ! path_allowed "$file"; then
    violations+=("$file")
  fi
done

if [[ "${#violations[@]}" -gt 0 ]]; then
  echo "scope-check: files outside allowed paths:" >&2
  printf '  %s\n' "${violations[@]}" >&2
  echo "scope-check: allowed paths:" >&2
  printf '  %s\n' "${allowed[@]}" >&2
  exit 1
fi

untracked_count="$(git ls-files --others --exclude-standard | wc -l | tr -d ' ')"
if [[ "$untracked_count" != "0" ]]; then
  echo "scope-check: note: $untracked_count untracked file(s) exist; not treated as scope violations" >&2
fi

echo "scope-check: ok"
