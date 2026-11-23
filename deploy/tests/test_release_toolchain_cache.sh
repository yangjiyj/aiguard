#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREPARER="$ROOT_DIR/deploy/docker-compose/prepare-release-toolchain.sh"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

fail() {
  printf '[toolchain-cache] %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

expect_failure() {
  local label=$1
  shift
  if "$@" >"$TMP_ROOT/$label.stdout" 2>"$TMP_ROOT/$label.stderr"; then
    fail "$label was accepted"
  fi
}

[[ -x "$PREPARER" ]] || fail "missing executable preparer: $PREPARER"

source_dir="$TMP_ROOT/source"
cache_dir="$TMP_ROOT/cache"
mkdir -p "$source_dir"
printf 'docker-static-amd64-fixture\n' >"$source_dir/docker-static.tgz"
printf 'docker-compose-amd64-fixture\n' >"$source_dir/docker-compose"
printf 'docker-static-arm64-fixture\n' >"$source_dir/docker-static-arm64.tgz"
printf 'docker-compose-arm64-fixture\n' >"$source_dir/docker-compose-arm64"
chmod 0700 "$source_dir/docker-compose"

lock="$TMP_ROOT/release-toolchain.lock"
cat >"$lock" <<EOF
syft_version=1.44.0
syft_binary_sha256=23d4e25a32026ab27351c3c044a40bcc51311c00b8bb990aa204bec4b0bb19cd
syft_archive_sha256=0e91737aee2b5baf1d255b959630194a302335d848ff97bb07921eb6205b5f5a
docker_static_amd64_sha256=$(sha256_file "$source_dir/docker-static.tgz")
docker_compose_amd64_sha256=$(sha256_file "$source_dir/docker-compose")
docker_static_arm64_sha256=$(sha256_file "$source_dir/docker-static-arm64.tgz")
docker_compose_arm64_sha256=$(sha256_file "$source_dir/docker-compose-arm64")
llama_cpp_revision=3653e6d6d547ec763317d9ecd0ace334a7e21359
judge_gguf_sha256=3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597
judge_gguf_size=2497281120
EOF

sources="$TMP_ROOT/release-toolchain.sources.json"
python3 - "$sources" "$source_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
source = pathlib.Path(sys.argv[2])
assets = []
for name, arch, filename, fixture_filename, url in (
    ("docker-static-amd64", "amd64", "docker-static.tgz", "docker-static.tgz", "https://fixture.invalid/docker-static.tgz"),
    ("docker-compose-amd64", "amd64", "docker-compose", "docker-compose", "https://fixture.invalid/docker-compose-linux-x86_64"),
    ("docker-static-arm64", "arm64", "docker-static.tgz", "docker-static-arm64.tgz", "https://fixture.invalid/docker-static-arm64.tgz"),
    ("docker-compose-arm64", "arm64", "docker-compose", "docker-compose-arm64", "https://fixture.invalid/docker-compose-linux-aarch64"),
):
    payload = source / fixture_filename
    assets.append(
        {
            "name": name,
            "arch": arch,
            "file": filename,
            "version": "fixture",
            "url": url,
            "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
        }
    )
target.write_text(
    json.dumps({"schema": "jjdguard-release-toolchain-sources/v1", "assets": assets}, sort_keys=True)
    + "\n",
    encoding="utf-8",
)
PY

fake_curl="$TMP_ROOT/fake-curl"
cat >"$fake_curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${FAKE_CURL_BLOCK:-0}" != 1 ]] || exit 91
output=
url=
while (($#)); do
  case "$1" in
    --output|-o) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
[[ -n "$output" ]] || exit 92
case "$url" in
  https://fixture.invalid/docker-static.tgz) source="$FAKE_TOOLCHAIN_SOURCE/docker-static.tgz" ;;
  https://fixture.invalid/docker-compose-linux-x86_64) source="$FAKE_TOOLCHAIN_SOURCE/docker-compose" ;;
  https://fixture.invalid/docker-static-arm64.tgz) source="$FAKE_TOOLCHAIN_SOURCE/docker-static-arm64.tgz" ;;
  https://fixture.invalid/docker-compose-linux-aarch64) source="$FAKE_TOOLCHAIN_SOURCE/docker-compose-arm64" ;;
  *) exit 93 ;;
esac
cp "$source" "$output"
if [[ -n "${FAKE_CURL_RACE_CACHE_DIR:-}" && ! -e "$FAKE_CURL_RACE_CACHE_DIR/.competing-publisher" ]]; then
  mkdir -p "$FAKE_CURL_RACE_CACHE_DIR"
  : >"$FAKE_CURL_RACE_CACHE_DIR/.competing-publisher"
fi
printf '%s\n' "$url" >>"$FAKE_CURL_LOG"
EOF
chmod 0700 "$fake_curl"

run_preparer() {
  JJDGUARD_RELEASE_TOOLCHAIN_TESTING=1 \
  JJDGUARD_RELEASE_TOOLCHAIN_CURL="$fake_curl" \
  FAKE_TOOLCHAIN_SOURCE="$source_dir" \
  FAKE_CURL_LOG="$TMP_ROOT/curl.log" \
  FAKE_CURL_RACE_CACHE_DIR="${FAKE_CURL_RACE_CACHE_DIR:-}" \
  OFFLINE_TARGET_ARCH=${TEST_TARGET_ARCH:-amd64} \
    "$PREPARER" "$@" --sources "$sources" --lock "$lock" --cache-dir "$cache_dir"
}

run_preparer prepare
for file in docker-static.tgz docker-compose receipt.json; do
  [[ -f "$cache_dir/$file" && ! -L "$cache_dir/$file" ]] || fail "prepared cache is missing $file"
done
cmp -s "$source_dir/docker-static.tgz" "$cache_dir/docker-static.tgz" || fail 'Docker payload changed during prepare'
cmp -s "$source_dir/docker-compose" "$cache_dir/docker-compose" || fail 'Compose payload changed during prepare'
[[ "$(wc -l <"$TMP_ROOT/curl.log" | tr -d ' ')" == 2 ]] || fail 'prepare did not fetch exactly the two locked assets'

run_preparer prepare
[[ "$(wc -l <"$TMP_ROOT/curl.log" | tr -d ' ')" == 2 ]] || fail 'valid cache was downloaded again'

FAKE_CURL_BLOCK=1 run_preparer verify

cache_dir="$TMP_ROOT/arm-cache"
TEST_TARGET_ARCH=arm64 run_preparer prepare
for file in docker-static.tgz docker-compose receipt.json; do
  [[ -f "$cache_dir/$file" && ! -L "$cache_dir/$file" ]] || fail "ARM64 prepared cache is missing $file"
done
cmp -s "$source_dir/docker-static-arm64.tgz" "$cache_dir/docker-static.tgz" || fail 'ARM64 Docker payload changed during prepare'
cmp -s "$source_dir/docker-compose-arm64" "$cache_dir/docker-compose" || fail 'ARM64 Compose payload changed during prepare'
[[ "$(wc -l <"$TMP_ROOT/curl.log" | tr -d ' ')" == 4 ]] || fail 'ARM64 prepare did not fetch exactly its two locked assets'
TEST_TARGET_ARCH=arm64 FAKE_CURL_BLOCK=1 run_preparer verify
cache_dir="$TMP_ROOT/cache"

printf 'tampered\n' >>"$cache_dir/docker-compose"
expect_failure tampered-cache run_preparer verify
expect_failure invalid-cache-reprepare run_preparer prepare

rm -rf -- "$cache_dir"
run_preparer prepare
mv "$cache_dir/docker-static.tgz" "$cache_dir/docker-static.saved"
ln -s docker-static.saved "$cache_dir/docker-static.tgz"
expect_failure symlink-cache run_preparer verify

rm -rf -- "$cache_dir"
mkdir "$cache_dir.lock"
expect_failure concurrent-lock-holder run_preparer prepare
[[ -d "$cache_dir.lock" ]] || fail 'prepare without lock ownership removed the active cache lock'
rmdir "$cache_dir.lock"

FAKE_CURL_RACE_CACHE_DIR="$cache_dir" \
  expect_failure concurrent-cache-publisher run_preparer prepare
[[ -f "$cache_dir/.competing-publisher" ]] || fail 'concurrent publisher fixture was not created'
if find "$cache_dir" -mindepth 1 -type d -name '.release-toolchain.*' -print -quit | grep -q .; then
  fail 'concurrent prepare nested an unpublished cache directory into the target cache'
fi
[[ ! -e "$cache_dir.lock" && ! -L "$cache_dir.lock" ]] ||
  fail 'concurrent prepare left its cache lock behind'

printf '[toolchain-cache] PASS\n'
