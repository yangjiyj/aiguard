#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

verifier_path=scripts/tests/verify_jjdguard_naming_worktree_provenance_r4.sh
test_path=scripts/tests/test_jjdguard_naming_worktree_provenance_r4.sh
contract_path=scripts/tests/fixtures/jjdguard-naming-task-contract-r4.tsv
base=f98f1baa95426ad23747dfd4cce40c821f22009f
subject='chore(构建): 固化 JJDGuard 命名任务验证器 r4'
origin=git@github.com:yangjiyj/aiguard.git
branch=feat/jjdguard-naming-integration-r4
root=refs/jjdguard-task-checkpoints/naming-integration-r4

production_ref_snapshot() {
  LC_ALL=C git -C "$repo_root" for-each-ref --sort=refname \
    --format='%(refname)%00%(objectname)%00' "$root/" | sha256sum | awk '{print $1}'
}
production_refs_before=$(production_ref_snapshot)

for path in "$verifier_path" "$test_path" "$contract_path"; do
  [[ -f "$path" ]] || { printf 'missing fixture input: %s\n' "$path" >&2; exit 1; }
done
bash -n "$verifier_path" "$test_path"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
template=$tmp/template.git
git init -q --bare "$template"
git -C "$template" fetch -q "$repo_root" "$base:refs/heads/base"
index=$tmp/bootstrap.index
rm -f "$index"
GIT_DIR="$template" GIT_WORK_TREE="$repo_root" GIT_INDEX_FILE="$index" git read-tree "$base"
GIT_DIR="$template" GIT_WORK_TREE="$repo_root" GIT_INDEX_FILE="$index" git add -- "$verifier_path" "$test_path" "$contract_path"
bootstrap_tree=$(GIT_DIR="$template" GIT_INDEX_FILE="$index" git write-tree)
bootstrap=$(printf '%s\n' "$subject" | \
  GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
  git --git-dir="$template" commit-tree "$bootstrap_tree" -p "$base")
git -C "$template" update-ref refs/heads/bootstrap "$bootstrap"
git -C "$template" symbolic-ref HEAD refs/heads/bootstrap

pass=0
fail=0
ok() { pass=$((pass+1)); printf 'ok %d - %s\n' "$pass" "$1"; }
expect_fail() {
  local name=$1; shift
  if "$@" >"$tmp/out" 2>"$tmp/err"; then
    printf 'not ok - %s unexpectedly succeeded\n' "$name" >&2
    fail=$((fail+1)); return 1
  fi
  ok "$name"
}
expect_ok() {
  local name=$1; shift
  if ! "$@" >"$tmp/out" 2>"$tmp/err"; then
    printf 'not ok - %s failed\n' "$name" >&2
    sed -n '1,80p' "$tmp/err" >&2
    fail=$((fail+1)); return 1
  fi
  ok "$name"
}

fixture_no=0
new_fixture() {
  fixture_no=$((fixture_no+1))
  bare=$tmp/repo-$fixture_no.git
  wt=$tmp/worktree-$fixture_no
  trusted=$tmp/trusted-$fixture_no
  git clone -q --bare "$template" "$bare"
  git clone -q -b bootstrap "$bare" "$wt"
  git -C "$wt" branch -m "$branch"
  git -C "$wt" remote set-url origin "$origin"
  git -C "$wt" config user.name fixture
  git -C "$wt" config user.email fixture@example.invalid
  git -C "$wt" update-ref "$root/start" "$bootstrap"
  mkdir -p "$trusted"
  git -C "$wt" --no-replace-objects show "$root/start:$verifier_path" >"$trusted/verifier"
  git -C "$wt" --no-replace-objects show "$root/start:$contract_path" >"$trusted/contract.tsv"
  chmod 0500 "$trusted/verifier"
}
run_v() {
  JJDGUARD_PROVENANCE_FIXTURE=1 bash "$trusted/verifier" --repo "$wt" --trusted-contract "$trusted/contract.tsv" "$@"
}
required_paths() {
  local task=$1
  awk -F '\t' -v task="$task" '$1=="task" && $2==task && $4=="required" { print $5 }' "$trusted/contract.tsv"
}
stage_task() {
  local task=$1 path
  while IFS= read -r path; do
    mkdir -p "$wt/$(dirname "$path")"
    printf '\nfixture-task-%s\n' "$task" >>"$wt/$path"
    git -C "$wt" add -- "$path"
  done < <(required_paths "$task")
}
commit_task() {
  local task=$1 reviewed_tree=${2:-} task_subject
  if [[ -z "$reviewed_tree" ]]; then
    reviewed_tree=$(git -C "$wt" write-tree)
    run_v --verify-index --task "$task" --candidate-tree "$reviewed_tree"
  fi
  task_subject=$(awk -F '\t' -v task="$task" '$1=="task" && $2==task { print $3; exit }' "$trusted/contract.tsv")
  run_v --commit-and-record "$task" --message "$task_subject" \
    --candidate-tree "$reviewed_tree"
}

# The fixture escape hatch must never point at the production common-dir.
expect_fail 'fixture mode rejects the production common-dir' env JJDGUARD_PROVENANCE_FIXTURE=1 \
  bash "$repo_root/$verifier_path" --repo "$repo_root" --trusted-contract "$repo_root/$contract_path" \
  --verify-resume --expected-completed 0
expect_fail 'production mode rejects --repo' bash "$repo_root/$verifier_path" --repo "$repo_root" \
  --trusted-contract "$repo_root/$contract_path" --verify-resume --expected-completed 0

new_fixture
stage_task 01
reviewed_tree=$(git -C "$wt" write-tree)
expect_ok 'valid Task01 index is accepted' run_v --verify-index --task 01 --candidate-tree "$reviewed_tree"
expect_fail 'candidate tree mismatch is rejected' run_v --verify-index --task 01 --candidate-tree "$base"
expect_fail 'wrong task subject is rejected' run_v --commit-and-record 01 --message 'wrong subject' --candidate-tree "$reviewed_tree"
missing=$(required_paths 01 | sed -n 1p)
git -C "$wt" reset -q HEAD -- "$missing"; rm -f "$wt/$missing"
expect_fail 'missing required path is rejected' run_v --verify-index --task 01
stage_task 01
printf 'extra\n' >"$wt/unplanned.txt"; git -C "$wt" add -- unplanned.txt
expect_fail 'extra staged path is rejected' run_v --verify-index --task 01
git -C "$wt" reset -q HEAD -- unplanned.txt; rm -f "$wt/unplanned.txt"
odd=$'line\nbreak.go'; printf 'odd\n' >"$wt/$odd"; git -C "$wt" add -- "$odd"
expect_fail 'newline path is rejected without line parsing ambiguity' run_v --verify-index --task 01
git -C "$wt" reset -q HEAD -- "$odd"; rm -f "$wt/$odd"
printf 'untracked\n' >"$wt/untracked"
expect_fail 'untracked worktree content is rejected' run_v --verify-index --task 01
rm -f "$wt/untracked"
first_required=$(awk -F '\t' '$1=="task" && $2=="01" && $4=="required" { print $5; exit }' "$trusted/contract.tsv")
printf 'dirty\n' >>"$wt/$first_required"
expect_fail 'unstaged tracked content is rejected' run_v --verify-index --task 01
git -C "$wt" checkout -- "$first_required"

# A worktree copy cannot replace either immutable trusted input.
printf '#!/usr/bin/env bash\nexit 0\n' >"$wt/$verifier_path"; git -C "$wt" add -- "$verifier_path"
expect_fail 'approve-all worktree verifier is rejected by trusted verifier' run_v --verify-index --task 01
git -C "$wt" reset -q HEAD -- "$verifier_path"; git -C "$wt" checkout -- "$verifier_path"
printf '\nstaged-contract-tamper\n' >>"$wt/$contract_path"; git -C "$wt" add -- "$contract_path"
expect_fail 'staged bootstrap contract modification is rejected by trusted verifier' run_v --verify-index --task 01
git -C "$wt" reset -q HEAD -- "$contract_path"; git -C "$wt" checkout -- "$contract_path"
cp "$trusted/contract.tsv" "$tmp/tampered-contract.tsv"; printf '\n' >>"$tmp/tampered-contract.tsv"
expect_fail 'modified trusted contract is rejected' env JJDGUARD_PROVENANCE_FIXTURE=1 \
  bash "$trusted/verifier" --repo "$wt" --trusted-contract "$tmp/tampered-contract.tsv" --verify-index --task 01

# A start ref with the wrong approval subject or blob set cannot establish trust.
wrong_subject=$(printf 'wrong bootstrap subject\n' | \
  GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
  git -C "$wt" commit-tree "$bootstrap_tree" -p "$base")
git -C "$wt" update-ref "$root/start" "$wrong_subject" "$bootstrap"
expect_fail 'bootstrap subject mismatch is rejected' run_v --verify-index --task 01
git -C "$wt" update-ref "$root/start" "$bootstrap" "$wrong_subject"

wrong_parent=$(printf '%s\n' "$subject" | \
  GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
  git -C "$wt" commit-tree "$bootstrap_tree" -p "$bootstrap")
git -C "$wt" update-ref "$root/start" "$wrong_parent" "$bootstrap"
expect_fail 'bootstrap parent mismatch is rejected' run_v --verify-index --task 01
git -C "$wt" update-ref "$root/start" "$bootstrap" "$wrong_parent"

blob_index=$tmp/wrong-blob.index
rm -f "$blob_index"
GIT_INDEX_FILE="$blob_index" git -C "$wt" read-tree "$bootstrap"
cp "$wt/$test_path" "$tmp/test.original"
printf '\nwrong-bootstrap-blob\n' >>"$wt/$test_path"
GIT_INDEX_FILE="$blob_index" git -C "$wt" add -- "$test_path"
wrong_blob_tree=$(GIT_INDEX_FILE="$blob_index" git -C "$wt" write-tree)
mv "$tmp/test.original" "$wt/$test_path"
wrong_blob=$(printf '%s\n' "$subject" | \
  GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
  git -C "$wt" commit-tree "$wrong_blob_tree" -p "$base")
git -C "$wt" update-ref "$root/start" "$wrong_blob" "$bootstrap"
expect_fail 'bootstrap blob set mismatch is rejected' run_v --verify-index --task 01
git -C "$wt" update-ref "$root/start" "$bootstrap" "$wrong_blob"

replacement=$(printf '%s\n' "$subject" | \
  GIT_AUTHOR_NAME=replacement GIT_AUTHOR_EMAIL=replacement@example.invalid \
  GIT_COMMITTER_NAME=replacement GIT_COMMITTER_EMAIL=replacement@example.invalid \
  git -C "$wt" commit-tree "$bootstrap_tree" -p "$base")
git -C "$wt" replace "$bootstrap" "$replacement"
[[ $(git -C "$wt" show -s --format=%an "$root/start") == replacement ]]
[[ $(git -C "$wt" --no-replace-objects show -s --format=%an "$root/start") == fixture ]]
expect_fail 'replace ref attack is rejected even when tree parent and subject look valid' run_v --verify-index --task 01
git -C "$wt" replace -d "$bootstrap" >/dev/null

replace_index=$tmp/replace-blob.index
rm -f "$replace_index"
GIT_INDEX_FILE="$replace_index" git -C "$wt" read-tree "$bootstrap"
cp "$wt/$verifier_path" "$tmp/verifier.original"
printf '#!/usr/bin/env bash\nexit 0\n' >"$wt/$verifier_path"
GIT_INDEX_FILE="$replace_index" git -C "$wt" add -- "$verifier_path"
malicious_tree=$(GIT_INDEX_FILE="$replace_index" git -C "$wt" write-tree)
mv "$tmp/verifier.original" "$wt/$verifier_path"
malicious_replace=$(printf '%s\n' "$subject" | \
  GIT_AUTHOR_NAME=replacement GIT_AUTHOR_EMAIL=replacement@example.invalid \
  GIT_COMMITTER_NAME=replacement GIT_COMMITTER_EMAIL=replacement@example.invalid \
  git -C "$wt" commit-tree "$malicious_tree" -p "$base")
git -C "$wt" replace "$bootstrap" "$malicious_replace"
normal_extract=$(git -C "$wt" show "$root/start:$verifier_path" | git -C "$wt" hash-object --stdin)
signed_extract=$(git -C "$wt" --no-replace-objects show "$root/start:$verifier_path" | git -C "$wt" hash-object --stdin)
[[ "$normal_extract" != "$signed_extract" ]]
[[ "$signed_extract" == $(git -C "$wt" --no-replace-objects rev-parse "$root/start:$verifier_path") ]]
git -C "$wt" replace -d "$bootstrap" >/dev/null
ok 'no-replace extraction returns the signed start blob under replacement attack'

grafted_merge=$(printf '%s\n' "$subject" | \
  GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
  git -C "$wt" commit-tree "$bootstrap_tree" -p "$base" -p "$bootstrap")
git -C "$wt" update-ref "$root/start" "$grafted_merge" "$bootstrap"
git -C "$wt" update-ref "refs/heads/$branch" "$grafted_merge" "$bootstrap"
grafts=$(git -C "$wt" rev-parse --path-format=absolute --git-path info/grafts)
mkdir -p "$(dirname "$grafts")"
printf '%s %s\n' "$grafted_merge" "$base" >"$grafts"
read -r grafted_oid grafted_parent grafted_extra < <(git -C "$wt" rev-list --parents -n 1 "$grafted_merge")
[[ "$grafted_oid" == "$grafted_merge" && "$grafted_parent" == "$base" && -z ${grafted_extra:-} ]]
mapfile -t raw_grafted_parents < <(git -C "$wt" --no-replace-objects cat-file -p "$grafted_merge" | sed -n 's/^parent //p')
[[ ${#raw_grafted_parents[@]} -eq 2 ]]
expect_fail 'graft-hidden bootstrap merge is rejected' run_v --verify-index --task 01
rm -f "$grafts"
git -C "$wt" update-ref "refs/heads/$branch" "$bootstrap" "$grafted_merge"
git -C "$wt" update-ref "$root/start" "$bootstrap" "$grafted_merge"
shallow_file=$(git -C "$wt" rev-parse --path-format=absolute --git-path shallow)
printf '%s\n' "$base" >"$shallow_file"
[[ $(git -C "$wt" rev-parse --is-shallow-repository) == true ]]
expect_fail 'shallow repository is rejected' run_v --verify-index --task 01
rm -f "$shallow_file"
[[ $(git -C "$wt" rev-parse --is-shallow-repository) == false ]]

# Origin and branch/worktree identity are checked on every invocation.
git -C "$wt" remote set-url origin ssh://attacker.invalid/repo.git
expect_fail 'origin spoof is rejected' run_v --verify-index --task 01
git -C "$wt" remote set-url origin "$origin"
git -C "$wt" checkout -q --detach
expect_fail 'branch ref without current worktree ownership is rejected' run_v --verify-index --task 01
git -C "$wt" checkout -q "$branch"

new_fixture
other=$tmp/other-worktree
git -C "$wt" checkout -q --detach
git -C "$wt" worktree add -q "$other" "$branch"
expect_fail 'same-name branch mapped to another worktree is rejected' run_v --verify-resume --expected-completed 0

unrelated=$tmp/unrelated
git init -q "$unrelated"
git -C "$unrelated" config user.name fixture
git -C "$unrelated" config user.email fixture@example.invalid
printf 'unrelated\n' >"$unrelated/file"
git -C "$unrelated" add file
git -C "$unrelated" commit -qm unrelated
git -C "$unrelated" branch -m "$branch"
git -C "$unrelated" remote add origin "$origin"
expect_fail 'unrelated repo with spoofed origin and no trusted start is rejected' env JJDGUARD_PROVENANCE_FIXTURE=1 \
  bash "$trusted/verifier" --repo "$unrelated" --trusted-contract "$trusted/contract.tsv" \
  --verify-resume --expected-completed 0

# The committed tree must be the exact tree that passed review.
new_fixture
stage_task 01
reviewed_tree=$(git -C "$wt" write-tree)
expect_ok 'Task01 reviewed tree is accepted before commit' run_v --verify-index --task 01 \
  --candidate-tree "$reviewed_tree"
git -C "$wt" update-ref refs/heads/review-victim "$bootstrap"
review_branch_before=$(git -C "$wt" rev-parse "refs/heads/$branch")
review_start_before=$(git -C "$wt" rev-parse "$root/start")
review_checkpoints_before=$(git -C "$wt" for-each-ref --sort=refname \
  --format='%(refname)%00%(objectname)%00' "$root/" | sha256sum | awk '{print $1}')
review_victim_before=$(git -C "$wt" rev-parse refs/heads/review-victim)
reviewed_path=$(required_paths 01 | sed -n 1p)
printf '\nfixture-post-review-change\n' >>"$wt/$reviewed_path"
git -C "$wt" add -- "$reviewed_path"
[[ $(git -C "$wt" write-tree) != "$reviewed_tree" ]]
expect_fail 'stale reviewed tree is rejected before commit' run_v --commit-and-record 01 \
  --message 'feat(协议): 增加 JJDGuard Header 双读与冲突拒绝' --candidate-tree "$reviewed_tree"
grep -Fq 'candidate tree changed after review' "$tmp/err"
[[ $(git -C "$wt" rev-parse "refs/heads/$branch") == "$review_branch_before" ]]
[[ $(git -C "$wt" rev-parse "$root/start") == "$review_start_before" ]]
[[ $(git -C "$wt" for-each-ref --sort=refname --format='%(refname)%00%(objectname)%00' \
  "$root/" | sha256sum | awk '{print $1}') == "$review_checkpoints_before" ]]
[[ $(git -C "$wt" rev-parse refs/heads/review-victim) == "$review_victim_before" ]]
! git -C "$wt" show-ref --verify --quiet "$root/task-01"
ok 'stale reviewed tree leaves branch start checkpoints and victim unchanged'

new_fixture
stage_task 01
reviewed_tree=$(git -C "$wt" write-tree)
expect_ok 'Task01 tree is reviewed before candidate validation' run_v --verify-index --task 01 \
  --candidate-tree "$reviewed_tree"
candidate_branch_before=$(git -C "$wt" rev-parse "refs/heads/$branch")
candidate_refs_before=$(git -C "$wt" for-each-ref --sort=refname \
  --format='%(refname)%00%(objectname)%00' "$root/" | sha256sum | awk '{print $1}')
expect_fail 'commit-and-record requires a reviewed candidate tree' run_v --commit-and-record 01 \
  --message 'feat(协议): 增加 JJDGuard Header 双读与冲突拒绝'
expect_fail 'commit-and-record rejects a non-OID candidate tree' run_v --commit-and-record 01 \
  --message 'feat(协议): 增加 JJDGuard Header 双读与冲突拒绝' --candidate-tree not-a-tree
[[ $(git -C "$wt" rev-parse "refs/heads/$branch") == "$candidate_branch_before" ]]
[[ $(git -C "$wt" for-each-ref --sort=refname --format='%(refname)%00%(objectname)%00' \
  "$root/" | sha256sum | awk '{print $1}') == "$candidate_refs_before" ]]
! git -C "$wt" show-ref --verify --quiet "$root/task-01"
ok 'missing and invalid candidate trees leave branch and checkpoints unchanged'

# A symbolic-ref swap at transaction time must not move its victim.
new_fixture
stage_task 01; commit_task 01
git -C "$wt" update-ref refs/heads/race-victim "$(git -C "$wt" rev-parse HEAD)"
victim_before=$(git -C "$wt" rev-parse refs/heads/race-victim)
start_before=$(git -C "$wt" rev-parse "$root/start")
checkpoint_before=$(git -C "$wt" rev-parse "$root/task-01")
stage_task 02
race_bin=$tmp/race-bin
mkdir -p "$race_bin"
real_git=$(command -v git)
cat >"$race_bin/git" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ " $* " == *" update-ref --stdin "* ]]; then
  "$REAL_GIT" -C "$RACE_WORKTREE" symbolic-ref "refs/heads/$RACE_BRANCH" "refs/heads/$RACE_VICTIM"
fi
exec "$REAL_GIT" "$@"
EOF
chmod 0500 "$race_bin/git"
race_subject=$(awk -F '\t' '$1=="task" && $2=="02" {print $3; exit}' "$trusted/contract.tsv")
race_reviewed_tree=$(git -C "$wt" write-tree)
run_v --verify-index --task 02 --candidate-tree "$race_reviewed_tree"
symref_race_commit() {
  env PATH="$race_bin:$PATH" REAL_GIT="$real_git" RACE_WORKTREE="$wt" \
    RACE_BRANCH="$branch" RACE_VICTIM=race-victim JJDGUARD_PROVENANCE_FIXTURE=1 \
    bash "$trusted/verifier" --repo "$wt" --trusted-contract "$trusted/contract.tsv" \
    --commit-and-record 02 --message "$race_subject" --candidate-tree "$race_reviewed_tree"
  if [[ $(git -C "$wt" rev-parse refs/heads/race-victim) != "$victim_before" ]]; then
    return 1
  fi
  if [[ $(git -C "$wt" rev-parse "$root/start") != "$start_before" ]]; then
    return 1
  fi
  if [[ $(git -C "$wt" rev-parse "$root/task-01") != "$checkpoint_before" ]]; then
    return 1
  fi
  if git -C "$wt" symbolic-ref -q "refs/heads/$branch" >/dev/null; then
    return 1
  fi
  if [[ $(git -C "$wt" rev-parse "refs/heads/$branch") != $(git -C "$wt" rev-parse "$root/task-02") ]]; then
    return 1
  fi
}
expect_ok 'no-deref transaction preserves symref victim and prior checkpoints' symref_race_commit

new_fixture
git -C "$wt" update-ref refs/heads/direct-victim "$bootstrap"
git -C "$wt" symbolic-ref "refs/heads/$branch" refs/heads/direct-victim
expect_fail 'symbolic expected branch is rejected' run_v --verify-resume --expected-completed 0

new_fixture
git -C "$wt" symbolic-ref "$root/start" "refs/heads/$branch"
expect_fail 'symbolic start checkpoint is rejected' run_v --verify-resume --expected-completed 0

new_fixture
stage_task 01
commit_task 01
git -C "$wt" symbolic-ref "$root/task-01" "refs/heads/$branch"
expect_fail 'symbolic completed task checkpoint is rejected' run_v --verify-resume --expected-completed 1

# Review is read-only: only the later record operation may advance both refs.
new_fixture
stage_task 01
reviewed_tree=$(git -C "$wt" write-tree)
review_branch_before=$(git -C "$wt" rev-parse "refs/heads/$branch")
review_refs_before=$(git -C "$wt" for-each-ref --sort=refname --format='%(refname)%00%(objectname)%00' \
  "$root/" | sha256sum | awk '{print $1}')
expect_ok 'verify-index review accepts candidate without moving refs' run_v --verify-index --task 01 --candidate-tree "$reviewed_tree"
[[ $(git -C "$wt" rev-parse "refs/heads/$branch") == "$review_branch_before" ]]
[[ $(git -C "$wt" for-each-ref --sort=refname --format='%(refname)%00%(objectname)%00' \
  "$root/" | sha256sum | awk '{print $1}') == "$review_refs_before" ]]
! git -C "$wt" show-ref --verify --quiet "$root/task-01"
ok 'verify-index review leaves branch and checkpoints unchanged'
expect_ok 'commit-and-record advances the reviewed task atomically' commit_task 01 "$reviewed_tree"
[[ $(git -C "$wt" rev-parse "refs/heads/$branch") != "$review_branch_before" ]]
[[ $(git -C "$wt" rev-parse "refs/heads/$branch") == $(git -C "$wt" rev-parse "$root/task-01") ]]
ok 'commit-and-record advances branch and checkpoint together'

# Transaction failpoints prove both refs remain together.
new_fixture
stage_task 01
reviewed_tree=$(git -C "$wt" write-tree)
run_v --verify-index --task 01 --candidate-tree "$reviewed_tree"
expect_fail 'failure before prepare moves neither ref' env JJDGUARD_PROVENANCE_FIXTURE=1 JJDGUARD_PROVENANCE_FAILPOINT=before-prepare \
  bash "$trusted/verifier" --repo "$wt" --trusted-contract "$trusted/contract.tsv" \
  --commit-and-record 01 --message 'feat(协议): 增加 JJDGuard Header 双读与冲突拒绝' --candidate-tree "$reviewed_tree"
[[ $(git -C "$wt" rev-parse HEAD) == "$bootstrap" ]]
! git -C "$wt" show-ref --verify --quiet "$root/task-01"
expect_ok 'retry after pre-prepare failure commits normally' commit_task 01 "$reviewed_tree"
expect_ok 'clean resume after retry is valid' run_v --verify-resume --expected-completed 1

new_fixture
stage_task 01
reviewed_tree=$(git -C "$wt" write-tree)
run_v --verify-index --task 01 --candidate-tree "$reviewed_tree"
expect_fail 'failure after transaction commit reports failure' env JJDGUARD_PROVENANCE_FIXTURE=1 JJDGUARD_PROVENANCE_FAILPOINT=after-commit \
  bash "$trusted/verifier" --repo "$wt" --trusted-contract "$trusted/contract.tsv" \
  --commit-and-record 01 --message 'feat(协议): 增加 JJDGuard Header 双读与冲突拒绝' --candidate-tree "$reviewed_tree"
[[ $(git -C "$wt" rev-parse HEAD) == $(git -C "$wt" rev-parse "$root/task-01") ]]
expect_ok 'post-commit failure resumes with both refs present' run_v --verify-resume --expected-completed 1

# Build the full legal chain from the immutable start.
new_fixture
for task in 01 02 03 04 05 06; do
  stage_task "$task"
  reviewed_tree=$(git -C "$wt" write-tree)
  expect_ok "Task$task index matches exact contract" run_v --verify-index --task "$task" --candidate-tree "$reviewed_tree"
  expect_ok "Task$task atomically commits and records" commit_task "$task" "$reviewed_tree"
done
expect_ok 'legal six-task chain resumes cleanly' run_v --verify-resume --expected-completed 6
expect_fail 'wrong completed count is rejected' run_v --verify-resume --expected-completed 5

# Corruptions are tested on isolated repositories so no test repairs a bad state.
new_fixture
stage_task 01; commit_task 01
tail_commit=$(printf 'tail\n' | git -C "$wt" commit-tree "$(git -C "$wt" rev-parse HEAD^{tree})" -p "$(git -C "$wt" rev-parse HEAD)")
git -C "$wt" update-ref "refs/heads/$branch" "$tail_commit" "$(git -C "$wt" rev-parse HEAD)"
expect_fail 'uncheckpointed branch tail is rejected' run_v --verify-resume --expected-completed 1

new_fixture
stage_task 01; commit_task 01
git -C "$wt" update-ref "$root/task-01" "$bootstrap"
expect_fail 'checkpoint-only movement is rejected' run_v --verify-resume --expected-completed 1

new_fixture
stage_task 01
wrong_task_subject=$(printf 'wrong task subject\n' | git -C "$wt" commit-tree "$(git -C "$wt" write-tree)" -p "$bootstrap")
git -C "$wt" update-ref "refs/heads/$branch" "$wrong_task_subject" "$bootstrap"
git -C "$wt" update-ref "$root/task-01" "$wrong_task_subject"
expect_fail 'wrong task subject in checkpoint chain is rejected' run_v --verify-resume --expected-completed 1

new_fixture
git -C "$wt" update-ref "$root/task-03" "$bootstrap"
expect_fail 'checkpoint gap is rejected' run_v --verify-resume --expected-completed 1

new_fixture
stage_task 01
tree=$(git -C "$wt" write-tree)
merge=$(printf 'feat(协议): 增加 JJDGuard Header 双读与冲突拒绝\n' | \
  git -C "$wt" commit-tree "$tree" -p "$bootstrap" -p "$base")
git -C "$wt" update-ref "refs/heads/$branch" "$merge" "$bootstrap"
git -C "$wt" update-ref "$root/task-01" "$merge"
expect_fail 'merge task commit is rejected' run_v --verify-resume --expected-completed 1

[[ $(production_ref_snapshot) == "$production_refs_before" ]]
ok 'fixture leaves production checkpoint namespace byte-for-byte unchanged'

if ((fail)); then
  printf '%d fixture checks failed\n' "$fail" >&2
  exit 1
fi
printf 'PASS: %d provenance fixture checks\n' "$pass"
