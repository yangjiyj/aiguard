#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() {
  printf '[task3-stage] %s\n' "$*" >&2
  exit 1
}

contains_path() {
  local want=$1 item
  shift
  for item in "$@"; do
    [[ "$item" == "$want" ]] && return 0
  done
  return 1
}

stage_candidate() {
  local repo=$1 contract=$2 verifier=$3 candidate_tree record status path
  local -a allowed cached
  [[ -d "$repo/.git" || -f "$repo/.git" ]] || die "not a git worktree: $repo"
  [[ -r "$contract" ]] || die "trusted contract is not readable: $contract"
  [[ -x "$verifier" ]] || die "trusted verifier is not executable: $verifier"

  mapfile -t allowed < <(
    awk -F '\t' '$1 == "task" && $2 == "03" && $4 == "required" {print $5}' "$contract" |
      LC_ALL=C sort -u
  )
  ((${#allowed[@]} > 0)) || die 'Task03 required path set is empty'
  for path in "${allowed[@]}"; do
    [[ -e "$repo/$path" ]] || die "required Task03 path is missing: $path"
  done

  while IFS= read -r -d '' record; do
    status=${record:0:2}
    path=${record:3}
    [[ "$status" != *R* && "$status" != *C* ]] ||
      die "rename/copy status is forbidden while staging Task03: $path"
    contains_path "$path" "${allowed[@]}" ||
      die "change outside Task03 contract: $status $path"
  done < <(git -C "$repo" status --porcelain=v1 -z --untracked-files=all)

  git -C "$repo" add -- "${allowed[@]}"
  git -C "$repo" diff --check
  git -C "$repo" diff --cached --check
  git -C "$repo" diff --quiet ||
    die 'tracked worktree differs from the reviewed Task03 index'
  mapfile -t cached < <(git -C "$repo" diff --cached --name-only | LC_ALL=C sort -u)
  [[ "$(printf '%s\n' "${cached[@]}")" == "$(printf '%s\n' "${allowed[@]}")" ]] ||
    die 'staged path set does not exactly equal Task03 required paths'
  [[ -z "$(git -C "$repo" ls-files --others --exclude-standard)" ]] ||
    die 'untracked file remains after Task03 staging'

  candidate_tree=$(git -C "$repo" write-tree)
  [[ "$candidate_tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid candidate tree'
  (cd "$repo"; bash "$verifier" --trusted-contract "$contract"     --verify-index --task 03 --candidate-tree "$candidate_tree")
  [[ "$(git -C "$repo" write-tree)" == "$candidate_tree" ]] ||
    die 'candidate tree changed during trusted verification'
  printf '%s\n' "$candidate_tree"
}

write_fixture_contract() {
  printf '%s\n'     $'record\ttask\tsubject\tkind\tpath\tpredicate'     $'task\t03\tfixture\trequired\ta.txt\t-'     $'task\t03\tfixture\trequired\tb.txt\t-' >"$1"
  chmod 0600 "$1"
}

write_fixture_verifier() {
  printf '%s\n'     '#!/usr/bin/env bash' 'set -Eeuo pipefail' 'candidate= task='     'while (($#)); do case "$1" in'     '  --candidate-tree) candidate=$2; shift 2 ;;'     '  --trusted-contract) shift 2 ;;'     '  --task) task=$2; shift 2 ;;'     '  --verify-index) shift ;;'     '  *) exit 64 ;; esac; done'     'test "$task" = 03'     'test -n "$candidate"' 'test "$(git write-tree)" = "$candidate"' >"$1"
  chmod 0500 "$1"
}

new_fixture_repo() {
  git init -q "$1"
  git -C "$1" config user.name task3-fixture
  git -C "$1" config user.email task3-fixture@example.invalid
  printf 'old-a\n' >"$1/a.txt"
  printf 'old-b\n' >"$1/b.txt"
  printf 'old-c\n' >"$1/c.txt"
  git -C "$1" add -- a.txt b.txt c.txt
  git -C "$1" commit -qm base
  printf 'new-a\n' >"$1/a.txt"
  printf 'new-b\n' >"$1/b.txt"
}

expect_reject() {
  local label=$1
  shift
  ( "$@" ) >/dev/null 2>&1 && die "self-test expected rejection: $label"
  return 0
}

self_test() {
  local tmp contract verifier repo tree
  tmp=$(mktemp -d)
  chmod 0700 "$tmp"
  trap "rm -rf -- '$tmp'" EXIT
  contract="$tmp/contract.tsv"
  verifier="$tmp/verifier"
  write_fixture_contract "$contract"
  write_fixture_verifier "$verifier"

  repo="$tmp/valid"; new_fixture_repo "$repo"
  tree=$(stage_candidate "$repo" "$contract" "$verifier")
  [[ "$tree" == "$(git -C "$repo" write-tree)" ]] || die 'valid tree mismatch'

  repo="$tmp/untracked"; new_fixture_repo "$repo"
  printf 'extra\n' >"$repo/extra.txt"
  expect_reject 'untracked extra' stage_candidate "$repo" "$contract" "$verifier"

  repo="$tmp/outside-staged"; new_fixture_repo "$repo"
  printf 'new-c\n' >"$repo/c.txt"; git -C "$repo" add -- c.txt
  expect_reject 'task-external staged path' stage_candidate "$repo" "$contract" "$verifier"

  repo="$tmp/missing"; new_fixture_repo "$repo"; rm "$repo/b.txt"
  expect_reject 'missing required path' stage_candidate "$repo" "$contract" "$verifier"

  repo="$tmp/rename"; new_fixture_repo "$repo"; git -C "$repo" mv a.txt renamed.txt
  expect_reject 'rename in candidate' stage_candidate "$repo" "$contract" "$verifier"
  printf '[task3-stage] self-test PASS\n'
}

repo= contract= verifier= mode=stage
while (($#)); do
  case "$1" in
    --self-test) mode=self-test; shift ;;
    --repo) repo=$2; shift 2 ;;
    --trusted-contract) contract=$2; shift 2 ;;
    --trusted-verifier) verifier=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$mode" == self-test ]] && { self_test; exit 0; }

repo=${repo:-$(git rev-parse --show-toplevel)}
if [[ -z "$contract" || -z "$verifier" ]]; then
  tmp=$(mktemp -d); chmod 0700 "$tmp"; trap 'rm -rf "$tmp"' EXIT
  contract="$tmp/contract.tsv"; verifier="$tmp/verifier"
  git -C "$repo" show refs/jjdguard-task-checkpoints/naming-integration-r4/start:scripts/tests/fixtures/jjdguard-naming-task-contract-r4.tsv >"$contract"
  git -C "$repo" show refs/jjdguard-task-checkpoints/naming-integration-r4/start:scripts/tests/verify_jjdguard_naming_worktree_provenance_r4.sh >"$verifier"
  chmod 0400 "$contract"; chmod 0500 "$verifier"
fi
stage_candidate "$repo" "$contract" "$verifier"
