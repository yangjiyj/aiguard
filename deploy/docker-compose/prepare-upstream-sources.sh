#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
LOCK_FILE="$SCRIPT_DIR/release-toolchain.lock"
UPSTREAM_REMOTE=https://github.com/ggerganov/llama.cpp.git
UPSTREAM_REVISION="$(sed -n 's/^llama_cpp_revision=//p' "$LOCK_FILE")"
CACHE_DIR="/home/dev/tool-cache/llama.cpp-$UPSTREAM_REVISION"
WORK_DIR=
VERIFY_ARCHIVE=

cleanup() {
  if [ -n "$VERIFY_ARCHIVE" ]; then
    rm -f -- "$VERIFY_ARCHIVE"
  fi
  if [ -n "$WORK_DIR" ]; then
    rm -rf -- "$WORK_DIR"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "[error] upstream source verification failed: $1" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

verify_cache() {
  cache="$1"
  remote="$2"
  revision="$3"
  repository="$cache/repo.git"
  archive="$cache/llama.cpp.tar"
  receipt="$cache/receipt.json"

  [ -d "$cache" ] && [ ! -L "$cache" ] || fail "cache is missing or a symbolic link: $cache"
  [ -d "$repository" ] && [ ! -L "$repository" ] || fail "cached Git repository is invalid: $repository"
  for file in "$archive" "$receipt"; do
    [ -f "$file" ] && [ ! -L "$file" ] || fail "cached source file is invalid: $file"
  done

  receipt_fields="$(python3 - "$receipt" "$archive" "$remote" "$revision" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import tarfile

receipt_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
expected_remote = sys.argv[3]
expected_revision = sys.argv[4]
data = json.loads(receipt_path.read_text(encoding="utf-8"))
expected_keys = {
    "schema",
    "component",
    "remote",
    "revision",
    "tree",
    "commit_count",
    "archive_file",
    "archive_sha256",
    "archive_size",
}
if set(data) != expected_keys:
    raise SystemExit("receipt fields do not match the schema")
if data["schema"] != "jjdguard-upstream-source/v1" or data["component"] != "llama.cpp":
    raise SystemExit("receipt identity is invalid")
if data["remote"] != expected_remote or data["revision"] != expected_revision:
    raise SystemExit("receipt remote or revision does not match")
if not isinstance(data["tree"], str) or not re.fullmatch(r"[0-9a-f]{40}", data["tree"]):
    raise SystemExit("receipt tree is invalid")
if not isinstance(data["commit_count"], int) or data["commit_count"] < 1:
    raise SystemExit("receipt commit count is invalid")
if data["archive_file"] != "llama.cpp.tar":
    raise SystemExit("receipt archive name is invalid")
if not isinstance(data["archive_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["archive_sha256"]):
    raise SystemExit("receipt archive digest is invalid")
if not isinstance(data["archive_size"], int) or data["archive_size"] < 1:
    raise SystemExit("receipt archive size is invalid")
if archive_path.stat().st_size != data["archive_size"]:
    raise SystemExit("source archive size does not match the receipt")
digest = hashlib.sha256()
with archive_path.open("rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
if digest.hexdigest() != data["archive_sha256"]:
    raise SystemExit("source archive digest does not match the receipt")

file_count = 0
with tarfile.open(archive_path, mode="r:") as archive:
    for member in archive:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit("source archive contains an unsafe path")
        if not path.parts or path.parts[0] != "llama.cpp":
            raise SystemExit("source archive member is outside llama.cpp/")
        if not (member.isdir() or member.isfile()):
            raise SystemExit("source archive contains links or special files")
        if member.isfile():
            file_count += 1
if file_count == 0:
    raise SystemExit("source archive contains no regular files")

print(data["tree"])
print(data["commit_count"])
print(data["archive_sha256"])
PY
  )" || fail 'cached source receipt or archive is invalid'
  receipt_tree="$(printf '%s\n' "$receipt_fields" | sed -n '1p')"
  receipt_count="$(printf '%s\n' "$receipt_fields" | sed -n '2p')"
  receipt_archive_sha="$(printf '%s\n' "$receipt_fields" | sed -n '3p')"

  [ "$(git --git-dir="$repository" remote get-url origin 2>/dev/null)" = "$remote" ] ||
    fail 'cached Git remote does not match'
  actual_revision="$(GIT_NO_LAZY_FETCH=1 git --git-dir="$repository" rev-parse --verify "$revision^{commit}")" ||
    fail 'cached Git repository does not contain the fixed revision'
  [ "$actual_revision" = "$revision" ] || fail 'cached Git commit does not match'
  actual_tree="$(GIT_NO_LAZY_FETCH=1 git --git-dir="$repository" rev-parse --verify "$revision^{tree}")" ||
    fail 'unable to resolve the cached Git tree'
  [ "$actual_tree" = "$receipt_tree" ] || fail 'cached Git tree does not match the receipt'
  actual_count="$(GIT_NO_LAZY_FETCH=1 git --git-dir="$repository" rev-list --count "$revision")" ||
    fail 'unable to count cached Git commits'
  [ "$actual_count" = "$receipt_count" ] || fail 'cached Git commit count does not match the receipt'

  VERIFY_ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/jjdguard-llama-verify.XXXXXX")"
  if ! GIT_NO_LAZY_FETCH=1 git --git-dir="$repository" archive \
    --format=tar --prefix=llama.cpp/ "$revision" >"$VERIFY_ARCHIVE"; then
    fail 'cached Git objects cannot reproduce the source archive without network'
  fi
  [ "$(sha256_file "$VERIFY_ARCHIVE")" = "$receipt_archive_sha" ] ||
    fail 'cached Git objects reproduce a different archive'
  cmp -s "$VERIFY_ARCHIVE" "$archive" || fail 'cached source archive is not byte reproducible'
  rm -f -- "$VERIFY_ARCHIVE"
  VERIFY_ARCHIVE=
}

mode="${1:-}"
shift || true
case "$mode" in
  prepare|verify) ;;
  *) fail 'expected prepare or verify mode' ;;
esac

if [ "$#" -gt 0 ]; then
  [ "${JJDGUARD_UPSTREAM_SOURCE_TESTING:-0}" = 1 ] ||
    fail 'custom upstream arguments are test-only'
  [ "$#" -eq 6 ] ||
    fail 'test mode expects --remote, --revision, and --cache'
  [ "$1" = --remote ] && [ "$3" = --revision ] && [ "$5" = --cache ] ||
    fail 'invalid test-mode arguments'
  UPSTREAM_REMOTE="$2"
  UPSTREAM_REVISION="$4"
  CACHE_DIR="$6"
fi

printf '%s\n' "$UPSTREAM_REVISION" | grep -Eq '^[0-9a-f]{40}$' ||
  fail 'upstream revision is not 40-hex'
case "$CACHE_DIR" in
  /*) ;;
  *) fail 'cache path must be absolute' ;;
esac
command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
command -v cmp >/dev/null 2>&1 || fail 'cmp is unavailable'

if [ "$mode" = verify ]; then
  verify_cache "$CACHE_DIR" "$UPSTREAM_REMOTE" "$UPSTREAM_REVISION"
  echo '[ok] fixed llama.cpp source cache verified without network'
  exit 0
fi

if [ -e "$CACHE_DIR" ]; then
  verify_cache "$CACHE_DIR" "$UPSTREAM_REMOTE" "$UPSTREAM_REVISION"
  echo '[ok] existing fixed llama.cpp source cache is valid'
  exit 0
fi

cache_parent="$(dirname "$CACHE_DIR")"
mkdir -p "$cache_parent"
[ -d "$cache_parent" ] && [ ! -L "$cache_parent" ] ||
  fail 'cache parent is not a real directory'
WORK_DIR="$(mktemp -d "$cache_parent/.llama-source.XXXXXX")"
repository="$WORK_DIR/repo.git"
archive="$WORK_DIR/llama.cpp.tar"

git clone --quiet --bare --filter=blob:none "$UPSTREAM_REMOTE" "$repository" ||
  fail 'unable to clone the fixed upstream repository'
actual_revision="$(git --git-dir="$repository" rev-parse --verify "$UPSTREAM_REVISION^{commit}")" ||
  fail 'fixed upstream revision is unavailable'
[ "$actual_revision" = "$UPSTREAM_REVISION" ] || fail 'cloned upstream revision does not match'
source_tree="$(git --git-dir="$repository" rev-parse --verify "$UPSTREAM_REVISION^{tree}")" ||
  fail 'unable to resolve upstream tree'
commit_count="$(git --git-dir="$repository" rev-list --count "$UPSTREAM_REVISION")" ||
  fail 'unable to count upstream commits'
git --git-dir="$repository" archive --format=tar --prefix=llama.cpp/ \
  "$UPSTREAM_REVISION" >"$archive" ||
  fail 'unable to create the fixed upstream archive'
archive_sha256="$(sha256_file "$archive")"
archive_size="$(stat -c '%s' "$archive")"

python3 - "$WORK_DIR/receipt.json" "$UPSTREAM_REMOTE" "$UPSTREAM_REVISION" \
  "$source_tree" "$commit_count" "$archive_sha256" "$archive_size" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "schema": "jjdguard-upstream-source/v1",
    "component": "llama.cpp",
    "remote": sys.argv[2],
    "revision": sys.argv[3],
    "tree": sys.argv[4],
    "commit_count": int(sys.argv[5]),
    "archive_file": "llama.cpp.tar",
    "archive_sha256": sys.argv[6],
    "archive_size": int(sys.argv[7]),
}
with path.open("x", encoding="utf-8", newline="\n") as handle:
    json.dump(payload, handle, ensure_ascii=True, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
chmod 0444 "$archive" "$WORK_DIR/receipt.json"

verify_cache "$WORK_DIR" "$UPSTREAM_REMOTE" "$UPSTREAM_REVISION"
[ ! -e "$CACHE_DIR" ] || fail 'cache path appeared during preparation'
mv "$WORK_DIR" "$CACHE_DIR"
WORK_DIR=
verify_cache "$CACHE_DIR" "$UPSTREAM_REMOTE" "$UPSTREAM_REVISION"
echo '[ok] fixed llama.cpp source cache prepared and verified'
