#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT_DIR/deploy/docker-compose/release-source-gate.sh"
BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
PACKAGE_SCRIPT="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
REAL_GIT="$(command -v git)"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() {
  echo "[fail] $*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE_ROOT/$label.stdout" 2>"$FIXTURE_ROOT/$label.stderr"; then
    fail "$label was accepted"
  fi
}

expect_success() {
  local label="$1"
  shift
  if ! "$@" >"$FIXTURE_ROOT/$label.stdout" 2>"$FIXTURE_ROOT/$label.stderr"; then
    cat "$FIXTURE_ROOT/$label.stderr" >&2
    fail "$label was rejected"
  fi
}

configure_repo() {
  "$REAL_GIT" -C "$1" config user.name 'Release Test'
  "$REAL_GIT" -C "$1" config user.email release-test@example.invalid
}

new_clone() {
  local name="$1"
  local destination="$FIXTURE_ROOT/$name"
  "$REAL_GIT" clone -q "$REMOTE" "$destination"
  configure_repo "$destination"
  printf '%s\n' "$destination"
}

make_fake_git() {
  local directory="$FIXTURE_ROOT/fake-bin"
  mkdir -p "$directory"
  cat >"$directory/git" <<'EOF'
#!/bin/sh
set -eu

printf '%s\n' invoked >>"$FAKE_GIT_MARKER"
case "${FAKE_GIT_MODE:-}:$*" in
  non40:*' rev-parse --verify HEAD')
    printf '%s\n' deadbeef
    exit 0
    ;;
  tree-mismatch:*' rev-parse --verify HEAD^{tree}')
    printf '%040d\n' 1
    exit 0
    ;;
  remote-forward:*' ls-remote origin refs/heads/main')
    printf '%040d\trefs/heads/main\n' 2
    exit 0
    ;;
esac

exec "$REAL_GIT" "$@"
EOF
  chmod +x "$directory/git"
  printf '%s\n' "$directory"
}

[[ -f "$GATE" ]] || fail "release source gate is missing: $GATE"
[[ -f "$BUILDER" ]] || fail "architecture builder is missing: $BUILDER"
grep -Fq "sh \"\$SOURCE_GATE\" \"\$PROJECT_ROOT\" \"\$SOURCE_ATTESTATION_FILE\" \"\$SOURCE_GATE_EXPECTED_REMOTE\"" "$BUILDER" ||
  fail "architecture builder does not invoke the release source gate with sh"
grep -Fq "SOURCE_GATE_EXPECTED_REMOTE='git@github.com:yangjiyj/aiguard.git'" "$PACKAGE_SCRIPT" ||
  fail 'packager does not pin the Gitee source remote'
grep -Fq 'sh "$SOURCE_GATE" "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$SOURCE_GATE_EXPECTED_REMOTE"' "$PACKAGE_SCRIPT" ||
  fail 'packager does not invoke the release source gate'
grep -Fq 'cp "$SOURCE_ATTESTATION_FILE" "$BUNDLE_DIR/release-source.json"' "$PACKAGE_SCRIPT" ||
  fail 'packager does not copy the source attestation into the bundle'

gate_line="$(grep -nF 'sh "$SOURCE_GATE" "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$SOURCE_GATE_EXPECTED_REMOTE"' "$PACKAGE_SCRIPT" | head -1 | cut -d: -f1)"
output_line="$(grep -nF 'mkdir -p "$OUTPUT_DIR_INPUT"' "$PACKAGE_SCRIPT" | head -1 | cut -d: -f1)"
image_line="$(grep -nF 'check_images' "$PACKAGE_SCRIPT" | tail -1 | cut -d: -f1)"
[[ -n "$gate_line" && -n "$output_line" && -n "$image_line" ]] ||
  fail 'unable to locate source gate, output creation, or image check'
[[ "$gate_line" -lt "$output_line" && "$gate_line" -lt "$image_line" ]] ||
  fail 'source gate must run before output creation and image checks'

REMOTE="$FIXTURE_ROOT/origin.git"
SEED="$FIXTURE_ROOT/seed"
"$REAL_GIT" init -q --bare "$REMOTE"
"$REAL_GIT" init -q "$SEED"
configure_repo "$SEED"
printf '%s\n' 'release-source-fixture' >"$SEED/tracked.txt"
"$REAL_GIT" -C "$SEED" add tracked.txt
"$REAL_GIT" -C "$SEED" commit -q -m initial
"$REAL_GIT" -C "$SEED" branch -M main
"$REAL_GIT" -C "$SEED" remote add origin "$REMOTE"
"$REAL_GIT" -C "$SEED" push -q -u origin main
"$REAL_GIT" -C "$REMOTE" symbolic-ref HEAD refs/heads/main

clean="$(new_clone clean)"
clean_json="$FIXTURE_ROOT/clean.json"
sh "$GATE" "$clean" "$clean_json" "$REMOTE"
revision="$("$REAL_GIT" -C "$clean" rev-parse HEAD)"
tree="$("$REAL_GIT" -C "$clean" rev-parse 'HEAD^{tree}')"
python3 - "$clean_json" "$REMOTE" "$revision" "$tree" <<'PY'
import json
import pathlib
import sys

path, remote, revision, tree = sys.argv[1:]
data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected = {
    "schema": "jjdguard-release-source/v1",
    "remote": remote,
    "source_revision": revision,
    "source_tree": tree,
}
if data != expected:
    raise SystemExit(f"unexpected release source attestation: {data!r}")
PY

dirty="$(new_clone dirty)"
printf '%s\n' changed >>"$dirty/tracked.txt"
expect_failure dirty sh "$GATE" "$dirty" "$FIXTURE_ROOT/dirty.json" "$REMOTE"

untracked="$(new_clone untracked)"
printf '%s\n' untracked >"$untracked/untracked.txt"
expect_failure untracked sh "$GATE" "$untracked" "$FIXTURE_ROOT/untracked.json" "$REMOTE"

diverged="$(new_clone diverged)"
printf '%s\n' local >>"$diverged/tracked.txt"
"$REAL_GIT" -C "$diverged" add tracked.txt
"$REAL_GIT" -C "$diverged" commit -q -m local-only
expect_failure diverged sh "$GATE" "$diverged" "$FIXTURE_ROOT/diverged.json" "$REMOTE"

expect_failure wrong-remote sh "$GATE" "$clean" "$FIXTURE_ROOT/wrong-remote.json" "$FIXTURE_ROOT/not-origin.git"

fake_bin="$(make_fake_git)"
fake_git_marker="$FIXTURE_ROOT/fake-git-invoked"
expect_success hostile-git-environment env \
  PATH="$fake_bin:$PATH" \
  GIT_DIR="$FIXTURE_ROOT/nonexistent-git-dir" \
  GIT_WORK_TREE="$FIXTURE_ROOT/nonexistent-work-tree" \
  GIT_CONFIG_GLOBAL="$FIXTURE_ROOT/nonexistent-global-config" \
  REAL_GIT="$REAL_GIT" \
  FAKE_GIT_MARKER="$fake_git_marker" \
  sh "$GATE" "$clean" "$FIXTURE_ROOT/hostile-git-environment.json" "$REMOTE"
[[ ! -e "$fake_git_marker" ]] ||
  fail 'release source gate executed a PATH-injected Git shim'

replaced="$(new_clone replaced)"
replacement="$(
  printf '%s\n' replacement |
    "$REAL_GIT" -C "$replaced" commit-tree "$("$REAL_GIT" -C "$replaced" rev-parse 'HEAD^{tree}')" -p HEAD
)"
"$REAL_GIT" -C "$replaced" replace HEAD "$replacement"
expect_failure replace-ref sh "$GATE" "$replaced" "$FIXTURE_ROOT/replace-ref.json" "$REMOTE"
grep -Fq 'replace refs are not allowed' "$FIXTURE_ROOT/replace-ref.stderr" ||
  fail 'replace ref rejection did not report the expected boundary'

stale="$(new_clone stale)"
printf '%s\n' remote-ahead >>"$SEED/tracked.txt"
"$REAL_GIT" -C "$SEED" add tracked.txt
"$REAL_GIT" -C "$SEED" commit -q -m remote-ahead
"$REAL_GIT" -C "$SEED" push -q origin main
expect_failure remote-ahead sh "$GATE" "$stale" "$FIXTURE_ROOT/remote-ahead.json" "$REMOTE"

echo '[ok] release source gate binds a clean checkout to live origin/main'
