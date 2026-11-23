#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GATE="$ROOT_DIR/deploy/docker-compose/release-candidate-source-gate.sh"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() { echo "[fail] $*" >&2; exit 1; }
expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE_ROOT/$label.stdout" 2>"$FIXTURE_ROOT/$label.stderr"; then
    fail "$label was accepted"
  fi
}

REMOTE="$FIXTURE_ROOT/origin.git"
SEED="$FIXTURE_ROOT/seed"
OUTPUT="$FIXTURE_ROOT/evidence/release-source.json"
mkdir -p "$(dirname "$OUTPUT")"
git init -q --bare "$REMOTE"
git init -q "$SEED"
git -C "$SEED" config user.name 'Release Candidate Fixture'
git -C "$SEED" config user.email release-candidate@example.invalid
printf '%s\n' base >"$SEED/README.md"
git -C "$SEED" add README.md
git -C "$SEED" commit -q -m base
git -C "$SEED" branch -M main
git -C "$SEED" remote add origin "$REMOTE"
git -C "$SEED" push -q -u origin main
git -C "$REMOTE" symbolic-ref HEAD refs/heads/main

git -C "$SEED" switch -q -c release/test
printf '%s\n' candidate >"$SEED/candidate.txt"
git -C "$SEED" add candidate.txt
git -C "$SEED" commit -q -m candidate
"$GATE" "$SEED" "$OUTPUT" "$REMOTE"
python3 - "$OUTPUT" "$REMOTE" "$SEED" <<'PY'
import json
import pathlib
import subprocess
import sys
path, remote, repo = sys.argv[1:]
data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
assert set(data) == {"schema", "remote", "source_revision", "source_tree"}
assert data["schema"] == "jjdguard-release-source/v1"
assert data["remote"] == remote
assert data["source_revision"] == subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
assert data["source_tree"] == subprocess.check_output(
    ["git", "-C", repo, "rev-parse", "HEAD^{tree}"], text=True).strip()
PY

printf '%s\n' dirty >>"$SEED/candidate.txt"
expect_failure dirty-worktree "$GATE" "$SEED" "$OUTPUT" "$REMOTE"
git -C "$SEED" reset -q --hard HEAD
git -C "$SEED" switch -q -c feature/not-release
expect_failure non-release-branch "$GATE" "$SEED" "$OUTPUT" "$REMOTE"

git -C "$SEED" switch -q release/test
git -C "$SEED" switch -q main
printf '%s\n' advanced >>"$SEED/README.md"
git -C "$SEED" add README.md
git -C "$SEED" commit -q -m advanced-main
git -C "$SEED" push -q origin main
git -C "$SEED" switch -q release/test
expect_failure stale-main-base "$GATE" "$SEED" "$OUTPUT" "$REMOTE"

echo '[ok] release candidate source gate binds clean release branches to live main'
