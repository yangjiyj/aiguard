#!/usr/bin/env bash
set -Eeuo pipefail
export GIT_NO_REPLACE_OBJECTS=1

readonly PROD_REPO=/home/dev/jjdguard-src
readonly PROD_WORKTREE=/home/dev/.config/superpowers/worktrees/jjdguard/naming-integration-r4
readonly PROD_COMMON=/home/dev/jjdguard-src/.git
readonly EXPECTED_ORIGIN=git@github.com:yangjiyj/aiguard.git
readonly EXPECTED_BRANCH=feat/jjdguard-naming-integration-r4
readonly CHECKPOINT_ROOT=refs/jjdguard-task-checkpoints/naming-integration-r4
readonly START_REF="$CHECKPOINT_ROOT/start"
readonly ZERO=0000000000000000000000000000000000000000
readonly BOOTSTRAP_BASE=f98f1baa95426ad23747dfd4cce40c821f22009f
readonly BOOTSTRAP_SUBJECT='chore(构建): 固化 JJDGuard 命名任务验证器 r4'
readonly VERIFIER_PATH=scripts/tests/verify_jjdguard_naming_worktree_provenance_r4.sh
readonly TEST_PATH=scripts/tests/test_jjdguard_naming_worktree_provenance_r4.sh
readonly CONTRACT_PATH=scripts/tests/fixtures/jjdguard-naming-task-contract-r4.tsv

die() { printf 'provenance: %s\n' "$*" >&2; exit 1; }
usage() {
  cat >&2 <<'EOF'
usage:
  verifier --trusted-contract FILE --verify-index --task NN [--candidate-tree OID]
  verifier --trusted-contract FILE --commit-and-record NN --message SUBJECT --candidate-tree OID
  verifier --trusted-contract FILE --verify-resume --expected-completed N
fixture only: prefix with JJDGUARD_PROVENANCE_FIXTURE=1 and add --repo TEMP_WORKTREE
EOF
  exit 2
}

fixture=${JJDGUARD_PROVENANCE_FIXTURE:-0}
repo_arg=
contract=
mode=
task=
message=
candidate_tree=
expected_completed=
while (($#)); do
  case "$1" in
    --repo) (($# >= 2)) || usage; repo_arg=$2; shift 2 ;;
    --trusted-contract) (($# >= 2)) || usage; contract=$2; shift 2 ;;
    --verify-index) [[ -z "$mode" ]] || usage; mode=verify-index; shift ;;
    --commit-and-record) [[ -z "$mode" ]] || usage; (($# >= 2)) || usage; mode=commit-and-record; task=$2; shift 2 ;;
    --verify-resume) [[ -z "$mode" ]] || usage; mode=verify-resume; shift ;;
    --task) (($# >= 2)) || usage; task=$2; shift 2 ;;
    --message) (($# >= 2)) || usage; message=$2; shift 2 ;;
    --candidate-tree) (($# >= 2)) || usage; candidate_tree=$2; shift 2 ;;
    --expected-completed) (($# >= 2)) || usage; expected_completed=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$contract" && -n "$mode" ]] || usage

if [[ "$fixture" == 1 ]]; then
  [[ -n "$repo_arg" ]] || die 'fixture mode requires --repo'
  worktree=$(realpath -e -- "$repo_arg") || die 'fixture repo does not exist'
else
  [[ "$fixture" == 0 ]] || die 'invalid JJDGUARD_PROVENANCE_FIXTURE value'
  [[ -z "$repo_arg" ]] || die 'production mode rejects --repo'
  worktree=$PROD_WORKTREE
fi
git -C "$worktree" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die 'not a git worktree'
top=$(git -C "$worktree" rev-parse --show-toplevel)
top=$(realpath -e -- "$top")
[[ "$top" == "$worktree" ]] || die 'repo must name the worktree root'
common=$(git -C "$worktree" rev-parse --path-format=absolute --git-common-dir)
common=$(realpath -e -- "$common")
[[ -z $(git -C "$worktree" for-each-ref --format='%(refname)' refs/replace/) ]] || die 'replace refs are forbidden'
grafts=$(git -C "$worktree" rev-parse --path-format=absolute --git-path info/grafts)
[[ ! -s "$grafts" ]] || die 'non-empty graft file is forbidden'
[[ $(git -C "$worktree" rev-parse --is-shallow-repository) == false ]] || die 'shallow repositories are forbidden'
require_direct_ref() {
  local ref=$1 label=$2
  if git -C "$worktree" symbolic-ref -q "$ref" >/dev/null 2>&1; then
    die "$label must be a direct ref"
  fi
  git -C "$worktree" show-ref --verify --quiet "$ref" || die "missing $label"
}
branch_ref=refs/heads/$EXPECTED_BRANCH
require_direct_ref "$branch_ref" 'expected branch'


if [[ "$fixture" == 1 ]]; then
  [[ "$common" != "$PROD_COMMON" ]] || die 'fixture mode refuses production common-dir'
  while IFS= read -r line; do
    [[ "$line" != "worktree $PROD_WORKTREE" ]] || die 'fixture repo maps production worktree'
  done < <(git -C "$worktree" worktree list --porcelain)
else
  [[ "$worktree" == "$PROD_WORKTREE" ]] || die 'wrong production worktree'
  [[ "$common" == "$PROD_COMMON" ]] || die 'wrong production common-dir'
  [[ $(realpath -e -- "$PROD_REPO") == "$PROD_REPO" ]] || die 'production repo missing'
fi
[[ $(git -C "$worktree" remote get-url origin 2>/dev/null) == "$EXPECTED_ORIGIN" ]] || die 'unexpected origin URL'
[[ $(git -C "$worktree" branch --show-current) == "$EXPECTED_BRANCH" ]] || die 'unexpected branch'

mapfile -t mapped < <(git -C "$worktree" worktree list --porcelain | awk -v b="refs/heads/$EXPECTED_BRANCH" '
  $1 == "worktree" { p=$2 }
  $1 == "branch" && $2 == b { print p }
')
[[ ${#mapped[@]} -eq 1 ]] || die 'branch must map to exactly one worktree'
[[ $(realpath -e -- "${mapped[0]}") == "$worktree" ]] || die 'branch maps another worktree'

contract=$(realpath -e -- "$contract") || die 'trusted contract missing'
[[ -f "$contract" ]] || die 'trusted contract is not a file'
[[ $(tail -c 1 "$contract" | od -An -tuC | tr -d ' ') == 10 ]] || die 'contract must end with LF'
LC_ALL=C grep -n $'\r' "$contract" >/dev/null 2>&1 && die 'contract contains CR'
[[ $(head -n 1 "$contract") == $'record\ttask\tsubject\tkind\tpath\tpredicate' ]] || die 'invalid contract header'
awk -F '\t' 'NR > 1 && NF != 6 { exit 1 }' "$contract" || die 'contract rows must have six fields'

declare -A subjects=() kinds=() predicates=() required=() known=() seen_row=() meta=()
while IFS=$'\t' read -r record row_task subject kind path predicate; do
  if [[ "$record" == meta ]]; then
    [[ "$row_task" == '-' && "$subject" == '-' && "$path" == '-' ]] || die 'invalid metadata row'
    case "$kind" in
      bootstrap-base|bootstrap-subject|bootstrap-test-blob|origin-url|branch|checkpoint-root) ;;
      bootstrap-path)
        [[ "$predicate" == "$VERIFIER_PATH" || "$predicate" == "$TEST_PATH" || "$predicate" == "$CONTRACT_PATH" ]] || die 'unknown bootstrap path'
        ;;
      *) die "unknown metadata key: $kind" ;;
    esac
    key="$kind:$predicate"
    [[ -z ${seen_row[$key]+x} ]] || die 'duplicate metadata row'
    seen_row[$key]=1
    if [[ "$kind" != bootstrap-path ]]; then
      [[ -z ${meta[$kind]+x} ]] || die 'duplicate metadata key'
      meta[$kind]=$predicate
    fi
    continue
  fi
  [[ "$record" == task ]] || die 'unknown contract record'
  [[ "$row_task" =~ ^0[1-6]$ ]] || die 'invalid task number'
  [[ -n "$subject" && -n "$path" ]] || die 'empty task field'
  [[ "$path" != /* && "$path" != . && "$path" != ../* && "$path" != */../* && "$path" != */.. ]] || die 'unsafe contract path'
  case "$path" in "$VERIFIER_PATH"|"$TEST_PATH"|"$CONTRACT_PATH") die 'task may not modify bootstrap trust files' ;; esac
  case "$kind" in
    required|allowed) [[ "$predicate" == '-' ]] || die "$kind path has predicate" ;;
    conditional)
      [[ "$path" == go.work.sum && "$predicate" == changed-by-go-work-sync ]] || die 'unknown conditional predicate'
      ;;
    *) die "unknown path kind: $kind" ;;
  esac
  if [[ -n ${subjects[$row_task]+x} ]]; then
    [[ ${subjects[$row_task]} == "$subject" ]] || die 'task has multiple subjects'
  else
    subjects[$row_task]=$subject
  fi
  key="$row_task:$path"
  [[ -z ${known[$key]+x} ]] || die 'duplicate task path'
  known[$key]=1; kinds[$key]=$kind; predicates[$key]=$predicate
  [[ "$kind" != required ]] || required[$key]=1
done < <(tail -n +2 "$contract")

[[ ${meta[bootstrap-base]:-} == "$BOOTSTRAP_BASE" ]] || die 'contract bootstrap base mismatch'
[[ ${meta[bootstrap-subject]:-} == "$BOOTSTRAP_SUBJECT" ]] || die 'contract bootstrap subject mismatch'
[[ ${meta[bootstrap-test-blob]:-} =~ ^[0-9a-f]{40}$ ]] || die 'contract bootstrap test blob is invalid'
[[ ${meta[origin-url]:-} == "$EXPECTED_ORIGIN" ]] || die 'contract origin mismatch'
[[ ${meta[branch]:-} == "$EXPECTED_BRANCH" ]] || die 'contract branch mismatch'
[[ ${meta[checkpoint-root]:-} == "$CHECKPOINT_ROOT" ]] || die 'contract checkpoint root mismatch'
for n in 01 02 03 04 05 06; do
  [[ -n ${subjects[$n]+x} ]] || die "contract missing task $n"
done
for p in "$VERIFIER_PATH" "$TEST_PATH" "$CONTRACT_PATH"; do
  [[ -n ${seen_row["bootstrap-path:$p"]+x} ]] || die "contract missing bootstrap path $p"
done

raw_commit_parents() {
  local oid=$1
  GIT_NO_REPLACE_OBJECTS=1 git -C "$worktree" cat-file -e "$oid^{commit}" 2>/dev/null || die "not a commit: $oid"
  GIT_NO_REPLACE_OBJECTS=1 git -C "$worktree" cat-file -p "$oid" | sed -n 's/^parent //p; /^$/q'
}

require_direct_ref "$START_REF" 'immutable start ref'
start=$(git -C "$worktree" rev-parse "$START_REF")
mapfile -t start_parents < <(raw_commit_parents "$start")
[[ ${#start_parents[@]} -eq 1 && ${start_parents[0]} == "$BOOTSTRAP_BASE" ]] || die 'bootstrap start must have exact single parent'
start_parent=${start_parents[0]}
[[ $(git -C "$worktree" show -s --format=%s "$start") == "$BOOTSTRAP_SUBJECT" ]] || die 'bootstrap subject mismatch'
mapfile -d '' -t bootstrap_paths < <(git -C "$worktree" diff-tree --no-commit-id --name-only -r -z "$start_parent" "$start")
expected_bootstrap=("$CONTRACT_PATH" "$TEST_PATH" "$VERIFIER_PATH")
mapfile -t bootstrap_sorted < <(printf '%s\n' "${bootstrap_paths[@]}" | LC_ALL=C sort)
[[ $(printf '%s\n' "${bootstrap_sorted[@]}") == $(printf '%s\n' "${expected_bootstrap[@]}") ]] || die 'bootstrap commit changed unexpected paths'
[[ $(git -C "$worktree" hash-object "$contract") == $(git -C "$worktree" rev-parse "$start:$CONTRACT_PATH") ]] || die 'trusted contract does not match immutable start'
script_abs=$(realpath -e -- "${BASH_SOURCE[0]}")
[[ $(git -C "$worktree" hash-object "$script_abs") == $(git -C "$worktree" rev-parse "$start:$VERIFIER_PATH") ]] || die 'running verifier does not match immutable start'
[[ ${meta[bootstrap-test-blob]} == $(git -C "$worktree" rev-parse "$start:$TEST_PATH") ]] || die 'bootstrap fixture blob mismatch'

task_refs=()
mapfile -t checkpoint_refs < <(git -C "$worktree" for-each-ref --sort=refname --format='%(refname)' "$CHECKPOINT_ROOT/")
for ref in "${checkpoint_refs[@]}"; do
  [[ "$ref" == "$START_REF" ]] && continue
  [[ "$ref" =~ ^$CHECKPOINT_ROOT/task-[0-9][0-9]$ ]] || die "unexpected checkpoint ref: $ref"
  require_direct_ref "$ref" 'task checkpoint'
  task_refs+=("$ref")
done

check_paths() {
  local t=$1 source_kind=$2 left=$3 right=${4:-}
  local -a actual=()
  if [[ "$source_kind" == index ]]; then
    mapfile -d '' -t actual < <(git -C "$worktree" diff --cached --name-only -z "$left")
  else
    mapfile -d '' -t actual < <(git -C "$worktree" diff-tree --no-commit-id --name-only -r -z "$left" "$right")
  fi
  local -A present=()
  local p key
  for p in "${actual[@]}"; do
    key="$t:$p"
    [[ -n ${known[$key]+x} ]] || die "task $t contains forbidden path: $p"
    present[$key]=1
  done
  for key in "${!required[@]}"; do
    [[ "$key" == "$t:"* ]] || continue
    [[ -n ${present[$key]+x} ]] || die "task $t misses required path: ${key#*:}"
  done
}

verify_chain() {
  local expected=$1
  [[ "$expected" =~ ^[0-6]$ ]] || die 'invalid completed count'
  [[ ${#task_refs[@]} -eq "$expected" ]] || die 'checkpoint count mismatch'
  local previous=$start i ref oid t
  for ((i=1; i<=expected; i++)); do
    printf -v t '%02d' "$i"
    ref="$CHECKPOINT_ROOT/task-$t"
    [[ ${task_refs[$((i-1))]} == "$ref" ]] || die 'checkpoint gap or unexpected ref'
    oid=$(git -C "$worktree" rev-parse "$ref")
    mapfile -t task_parents < <(raw_commit_parents "$oid")
    [[ ${#task_parents[@]} -eq 1 && ${task_parents[0]} == "$previous" ]] || die "task $t is not the unique direct child"
    [[ $(git -C "$worktree" show -s --format=%s "$oid") == "${subjects[$t]}" ]] || die "task $t subject mismatch"
    check_paths "$t" commit "$previous" "$oid"
    previous=$oid
  done
  VERIFIED_TIP=$previous
}

verify_position_for_next() {
  local t=$1 n
  [[ "$t" =~ ^0[1-6]$ ]] || die 'invalid task'
  n=$((10#$t))
  verify_chain "$((n-1))"
  require_direct_ref "$branch_ref" 'expected branch'
  [[ $(git -C "$worktree" rev-parse "refs/heads/$EXPECTED_BRANCH") == "$VERIFIED_TIP" ]] || die 'branch/checkpoint mismatch'
  [[ $(git -C "$worktree" rev-parse HEAD) == "$VERIFIED_TIP" ]] || die 'HEAD/checkpoint mismatch'
  git -C "$worktree" diff --quiet || die 'unstaged tracked changes are forbidden'
  [[ -z $(git -C "$worktree" ls-files --others --exclude-standard) ]] || die 'untracked files are forbidden'
}

case "$mode" in
  verify-index)
    [[ -n "$task" && -z "$message" && -z "$expected_completed" ]] || usage
    verify_position_for_next "$task"
    git -C "$worktree" diff --cached --quiet && die 'empty staged task'
    check_paths "$task" index "$VERIFIED_TIP"
    tree=$(git -C "$worktree" write-tree)
    if [[ -n "$candidate_tree" ]]; then
      [[ "$candidate_tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid candidate tree'
      [[ "$candidate_tree" == "$tree" ]] || die 'candidate tree differs from index'
    fi
    ;;
  commit-and-record)
    [[ -n "$task" && -n "$message" && -n "$candidate_tree" && -z "$expected_completed" ]] || usage
    [[ "$candidate_tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid candidate tree'
    [[ "$message" == "${subjects[$task]:-}" ]] || die 'message does not match task contract'
    verify_position_for_next "$task"
    git -C "$worktree" diff --cached --quiet && die 'empty staged task'
    current_tree=$(git -C "$worktree" write-tree)
    [[ "$current_tree" == "$candidate_tree" ]] || die 'candidate tree changed after review'
    check_paths "$task" index "$VERIFIED_TIP"
    new_commit=$(printf '%s\n' "$message" | git -C "$worktree" commit-tree "$candidate_tree" -p "$VERIFIED_TIP")
    checkpoint="$CHECKPOINT_ROOT/task-$task"
    if [[ -n ${JJDGUARD_PROVENANCE_FAILPOINT:-} && "$fixture" != 1 ]]; then
      die 'failpoints are fixture-only'
    fi
    require_direct_ref "$branch_ref" 'expected branch'
    require_direct_ref "$START_REF" 'immutable start ref'
    for ref in "${task_refs[@]}"; do
      require_direct_ref "$ref" 'task checkpoint'
    done
    if [[ ${JJDGUARD_PROVENANCE_FAILPOINT:-} == before-prepare ]]; then
      die 'fixture failpoint before prepare'
    fi
    tx=$(mktemp)
    trap 'rm -f "$tx"' EXIT
    {
      printf 'start\n'
      printf 'option no-deref\n'
      printf 'verify %s %s\n' "$START_REF" "$start"
      for ref in "${task_refs[@]}"; do
        printf 'option no-deref\n'
        printf 'verify %s %s\n' "$ref" "$(git -C "$worktree" rev-parse "$ref")"
      done
      printf 'option no-deref\n'
      printf 'update refs/heads/%s %s %s\n' "$EXPECTED_BRANCH" "$new_commit" "$VERIFIED_TIP"
      printf 'option no-deref\n'
      printf 'create %s %s\n' "$checkpoint" "$new_commit"
      printf 'prepare\ncommit\n'
    } >"$tx"
    git -C "$worktree" update-ref --stdin <"$tx"
    if [[ ${JJDGUARD_PROVENANCE_FAILPOINT:-} == after-commit ]]; then
      die 'fixture failpoint after commit'
    fi
    [[ $(git -C "$worktree" rev-parse HEAD) == "$new_commit" ]] || die 'HEAD did not advance atomically'
    [[ $(git -C "$worktree" rev-parse "$checkpoint") == "$new_commit" ]] || die 'checkpoint did not advance atomically'
    ;;
  verify-resume)
    [[ -z "$task" && -z "$message" && -z "$candidate_tree" && -n "$expected_completed" ]] || usage
    verify_chain "$expected_completed"
    [[ $(git -C "$worktree" rev-parse "refs/heads/$EXPECTED_BRANCH") == "$VERIFIED_TIP" ]] || die 'branch/checkpoint mismatch'
    [[ $(git -C "$worktree" rev-parse HEAD) == "$VERIFIED_TIP" ]] || die 'HEAD/checkpoint mismatch'
    [[ -z $(git -C "$worktree" status --porcelain) ]] || die 'resume requires clean worktree and index'
    ;;
  *) usage ;;
esac
