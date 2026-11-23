#!/bin/sh
set -eu

fail() {
  echo "[error] release source gate failed: $1" >&2
  exit 1
}

GIT_BIN=/usr/bin/git
PYTHON_BIN=/usr/bin/python3
ENV_BIN=/usr/bin/env
GREP_BIN=/usr/bin/grep
SED_BIN=/usr/bin/sed
AWK_BIN=/usr/bin/awk
DIRNAME_BIN=/usr/bin/dirname

for binary in \
  "$GIT_BIN" "$PYTHON_BIN" "$ENV_BIN" "$GREP_BIN" \
  "$SED_BIN" "$AWK_BIN" "$DIRNAME_BIN" /usr/bin/ssh; do
  [ -x "$binary" ] || fail "required system tool is unavailable: $binary"
done

git_clean() {
  if [ -n "${SSH_AUTH_SOCK:-}" ]; then
    "$ENV_BIN" -i \
      PATH=/usr/bin:/bin \
      HOME="${HOME:-/nonexistent}" \
      LC_ALL=C \
      SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_NO_REPLACE_OBJECTS=1 \
      GIT_SSH_COMMAND=/usr/bin/ssh \
      "$GIT_BIN" "$@"
  else
    "$ENV_BIN" -i \
      PATH=/usr/bin:/bin \
      HOME="${HOME:-/nonexistent}" \
      LC_ALL=C \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_NO_REPLACE_OBJECTS=1 \
      GIT_SSH_COMMAND=/usr/bin/ssh \
      "$GIT_BIN" "$@"
  fi
}

reject_replace_refs() {
  replace_refs="$(git_clean -C "$repository" for-each-ref --format='%(refname)' refs/replace/)" ||
    fail 'unable to inspect replace refs'
  [ -z "$replace_refs" ] || fail 'replace refs are not allowed'
}

is_sha1() {
  printf '%s\n' "$1" | "$GREP_BIN" -Eq '^[0-9a-f]{40}$'
}

[ "$#" -eq 3 ] || fail 'expected repository, output file, and remote'
repository="$1"
output_file="$2"
expected_remote="$3"
output_parent="$("$DIRNAME_BIN" "$output_file")"

[ -d "$repository" ] && [ ! -L "$repository" ] || fail 'repository is not a real directory'
[ -d "$output_parent" ] && [ ! -L "$output_parent" ] || fail 'output parent is not a real directory'
[ ! -L "$output_file" ] || fail 'output file is a symbolic link'
if [ -e "$output_file" ] && [ ! -f "$output_file" ]; then
  fail 'output path is not a regular file'
fi
reject_replace_refs
[ "$(git_clean -C "$repository" rev-parse --is-inside-work-tree 2>/dev/null)" = true ] ||
  fail 'repository is not a Git worktree'
status="$(git_clean -C "$repository" status --porcelain --untracked-files=all)" ||
  fail 'unable to read worktree status'
[ -z "$status" ] || fail 'worktree is not clean'

source_revision="$(git_clean -C "$repository" rev-parse --verify HEAD)" ||
  fail 'unable to resolve HEAD'
source_tree="$(git_clean -C "$repository" rev-parse --verify 'HEAD^{tree}')" ||
  fail 'unable to resolve HEAD tree'
is_sha1 "$source_revision" || fail 'HEAD is not a 40-hex revision'
is_sha1 "$source_tree" || fail 'HEAD tree is not a 40-hex object'
[ "$(git_clean -C "$repository" cat-file -t "$source_revision" 2>/dev/null)" = commit ] ||
  fail 'HEAD is not a commit object'
commit_tree="$(git_clean -C "$repository" cat-file -p "$source_revision" |
  "$SED_BIN" -n '1s/^tree \([0-9a-f]\{40\}\)$/\1/p')"
[ "$commit_tree" = "$source_tree" ] || fail 'HEAD tree does not match the commit object'

source_remote="$(git_clean -C "$repository" remote get-url origin)" ||
  fail 'origin remote is unavailable'
[ "$source_remote" = "$expected_remote" ] || fail 'origin remote does not match the release remote'

git_clean -C "$repository" fetch --quiet --no-tags origin main ||
  fail 'unable to fetch origin/main'
origin_revision="$(git_clean -C "$repository" rev-parse --verify refs/remotes/origin/main)" ||
  fail 'unable to resolve fetched origin/main'
is_sha1 "$origin_revision" || fail 'origin/main is not a 40-hex revision'
[ "$source_revision" = "$origin_revision" ] ||
  fail 'HEAD does not match fetched origin/main'

remote_line="$(git_clean -C "$repository" ls-remote origin refs/heads/main)" ||
  fail 'unable to query live origin/main'
remote_count="$(printf '%s\n' "$remote_line" | "$AWK_BIN" 'NF { count++ } END { print count + 0 }')"
[ "$remote_count" -eq 1 ] || fail 'live origin/main response is not unique'
remote_revision="$(printf '%s\n' "$remote_line" |
  "$AWK_BIN" '$2 == "refs/heads/main" && NF == 2 { print $1 }')"
is_sha1 "$remote_revision" || fail 'live origin/main is not a 40-hex revision'
[ "$source_revision" = "$remote_revision" ] ||
  fail 'live origin/main moved after fetch'

origin_tree="$(git_clean -C "$repository" rev-parse --verify "$origin_revision^{tree}")" ||
  fail 'unable to resolve origin/main tree'
[ "$source_tree" = "$origin_tree" ] || fail 'source tree does not match origin/main'

final_status="$(git_clean -C "$repository" status --porcelain --untracked-files=all)" ||
  fail 'unable to recheck worktree status'
final_revision="$(git_clean -C "$repository" rev-parse --verify HEAD)" ||
  fail 'unable to recheck HEAD'
final_tree="$(git_clean -C "$repository" rev-parse --verify 'HEAD^{tree}')" ||
  fail 'unable to recheck HEAD tree'
[ -z "$final_status" ] || fail 'worktree changed during source verification'
[ "$final_revision" = "$source_revision" ] || fail 'HEAD changed during source verification'
[ "$final_tree" = "$source_tree" ] || fail 'HEAD tree changed during source verification'
reject_replace_refs

"$PYTHON_BIN" - "$output_file" "$source_remote" "$source_revision" "$source_tree" <<'PY'
import json
import os
import pathlib
import tempfile
import sys

output = pathlib.Path(sys.argv[1])
payload = {
    "schema": "jjdguard-release-source/v1",
    "remote": sys.argv[2],
    "source_revision": sys.argv[3],
    "source_tree": sys.argv[4],
}
temporary = None
try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f".{output.name}.",
        dir=output.parent,
        delete=False,
    ) as handle:
        temporary = pathlib.Path(handle.name)
        json.dump(payload, handle, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o444)
    os.replace(temporary, output)
    temporary = None
finally:
    if temporary is not None:
        temporary.unlink(missing_ok=True)
PY

echo '[ok] release source matches live origin/main'
