#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK_FILE="$ROOT_DIR/deploy/docker-compose/release-toolchain.lock"
OWNED_JUDGE_LOCK="$ROOT_DIR/deploy/docker-compose/owned-judge-model.lock.json"
VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-release-toolchain.sh"
TOOLCHAIN_CACHE_DIR="$ROOT_DIR/deploy/docker-compose/release-toolchain-cache-dir.sh"
TOOLCHAIN_PREPARER="$ROOT_DIR/deploy/docker-compose/prepare-release-toolchain.sh"
TOOLCHAIN_SOURCES="$ROOT_DIR/deploy/docker-compose/release-toolchain.sources.json"
OWNED_JUDGE_VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-owned-judge-model.py"
SBOM_GENERATOR="$ROOT_DIR/deploy/docker-compose/generate-release-sbom.sh"
BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
PACKAGER="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() {
  echo "[fail] $*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE_ROOT/$label.stdout" 2>"$FIXTURE_ROOT/$label.stderr"; then
    fail "$label was accepted"
  fi
}

write_syft() {
  local path="$1" version="$2"
  cat >"$path" <<EOF
#!/bin/sh
printf '%s\n' 'Application: syft' 'Version: $version' 'Platform: linux/amd64'
EOF
  chmod +x "$path"
}

write_fixture_lock() {
  local root="$1" lock="$2" judge_size
  judge_size="$(stat -c '%s' "$root/judge.gguf")"
  cat >"$lock" <<EOF
syft_version=1.44.0
syft_binary_sha256=$(sha256_file "$root/syft")
syft_archive_sha256=$(sha256_file "$root/syft-archive")
docker_static_amd64_sha256=$(sha256_file "$root/docker-static.tgz")
docker_compose_amd64_sha256=$(sha256_file "$root/docker-compose")
docker_static_arm64_sha256=$(sha256_file "$root/docker-static.tgz")
docker_compose_arm64_sha256=$(sha256_file "$root/docker-compose")
llama_cpp_revision=3653e6d6d547ec763317d9ecd0ace334a7e21359
judge_gguf_sha256=$(sha256_file "$root/judge.gguf")
judge_gguf_size=$judge_size
EOF
}

run_fixture_verifier() {
  local root="$1" lock="$2"
  JJDGUARD_RELEASE_TOOLCHAIN_TESTING=1 \
    sh "$VERIFIER" amd64 --fixture-root "$root" --lock "$lock"
}

[[ -f "$LOCK_FILE" ]] || fail "release toolchain lock is missing: $LOCK_FILE"
[[ -f "$OWNED_JUDGE_LOCK" ]] || fail "owned Judge model lock is missing: $OWNED_JUDGE_LOCK"
[[ -f "$VERIFIER" ]] || fail "release toolchain verifier is missing: $VERIFIER"
[[ -x "$TOOLCHAIN_CACHE_DIR" ]] || fail "release toolchain cache locator is missing or not executable: $TOOLCHAIN_CACHE_DIR"
[[ -x "$TOOLCHAIN_PREPARER" ]] || fail "release toolchain preparer is missing or not executable: $TOOLCHAIN_PREPARER"
[[ -f "$TOOLCHAIN_SOURCES" && ! -L "$TOOLCHAIN_SOURCES" ]] ||
  fail "release toolchain source manifest is missing or unsafe: $TOOLCHAIN_SOURCES"
[[ -x "$OWNED_JUDGE_VERIFIER" ]] || fail "owned Judge model verifier is missing or not executable: $OWNED_JUDGE_VERIFIER"

for line in \
  'syft_version=1.44.0' \
  'syft_binary_sha256=23d4e25a32026ab27351c3c044a40bcc51311c00b8bb990aa204bec4b0bb19cd' \
  'syft_archive_sha256=0e91737aee2b5baf1d255b959630194a302335d848ff97bb07921eb6205b5f5a' \
  'docker_static_amd64_sha256=6d81a5be56232d9cc047e60b7110a087793536ae5a8b465719cd303f05fc56ec' \
  'docker_compose_amd64_sha256=fffb010206c952ee5e45d0cd05dc88d3ca063c4634d40eaad6b72677c4c7bbf0' \
  'docker_static_arm64_sha256=d1d9cb857c32c596ea96a9ca6b25d13621a97c83511e667868a33a320b2a707f' \
  'docker_compose_arm64_sha256=ba0d9f5ce70086b3830448ce2f8a6405513c996065fe45d2f7c144a1f0d99398' \
  'llama_cpp_revision=3653e6d6d547ec763317d9ecd0ace334a7e21359' \
  'judge_gguf_sha256=60638ee75d32a530108f08ce5dd50fd8bf69769ae4268add786dfbc3cbd5bc7b' \
  'judge_gguf_size=2497278752'; do
  grep -Fqx "$line" "$LOCK_FILE" || fail "toolchain lock is missing exact entry: $line"
done
[[ "$(wc -l <"$LOCK_FILE" | tr -d ' ')" == 10 ]] ||
  fail 'toolchain lock must contain exactly the reviewed entries'

# The installer checks the GGUF against the toolchain lock while the builder checks
# the model lock; both must describe the same bundled Judge file.
OWNED_JUDGE_LOCK="$ROOT_DIR/deploy/docker-compose/owned-judge-model.lock.json"
python3 - "$OWNED_JUDGE_LOCK" "$LOCK_FILE" <<'PY_LOCKS' || fail 'model lock and toolchain lock disagree on the bundled Judge'
import json, sys
model = json.load(open(sys.argv[1], encoding="utf-8"))
tool = dict(line.strip().split("=", 1) for line in open(sys.argv[2], encoding="utf-8") if "=" in line)
assert tool["judge_gguf_sha256"] == model["sha256"], "sha256 differs"
assert int(tool["judge_gguf_size"]) == model["size"], "size differs"
PY_LOCKS

grep -Fq 'SYFT_BIN=/home/dev/tool-cache/syft-1.44.0/syft' "$VERIFIER" ||
  fail 'production verifier does not use the fixed Syft path'
grep -Fq 'release-toolchain-cache-dir.sh' "$VERIFIER" ||
  fail 'production verifier does not use the locked Docker and Compose cache locator'
grep -Fq 'prepare-release-toolchain.sh" verify' "$VERIFIER" ||
  fail 'production verifier does not require an offline cache verification pass'
grep -Fq '"$SCRIPT_DIR/verify-release-toolchain.sh" "$TARGET_ARCH"' "$BUILDER" ||
  fail 'architecture builder does not enforce the toolchain lock'
grep -Fq 'release-toolchain-cache-dir.sh' "$BUILDER" ||
  fail 'architecture builder does not use the locked Docker and Compose cache locator'
grep -Fq 'prepare-release-toolchain.sh' "$BUILDER" ||
  fail 'architecture builder does not prepare or verify the locked Docker and Compose cache'
grep -Fq 'sh "$TOOLCHAIN_VERIFIER" "$TARGET_ARCH"' "$PACKAGER" ||
  fail 'packager does not enforce the toolchain lock'
grep -Fq 'release-toolchain-cache-dir.sh' "$PACKAGER" ||
  fail 'packager does not use the locked Docker and Compose cache locator'
grep -Fq 'cp "$TOOLCHAIN_LOCK" "$BUNDLE_DIR/deploy/docker-compose/release-toolchain.lock"' "$PACKAGER" ||
  fail 'full bundle does not stage the Judge lock beside deploy-offline.sh'
grep -Fq 'test_judge_model_integrity.sh' "$PACKAGER" ||
  fail 'candidate packaging does not run the Judge model integrity regression'
[[ -x "$SBOM_GENERATOR" ]] || fail 'fixed Syft SBOM generator is missing'
grep -Fq 'SYFT_BIN=/home/dev/tool-cache/syft-1.44.0/syft' "$SBOM_GENERATOR" ||
  fail 'SBOM generator does not use the fixed Syft path'
grep -Fq '"$SYFT_BIN" scan' "$SBOM_GENERATOR" ||
  fail 'SBOM generator does not invoke the fixed Syft binary'
grep -Fq 'JUDGE_OWNED_MODEL_INPUT="${JUDGE_OWNED_MODEL_INPUT:-}"' "$PACKAGER" ||
  fail 'packager does not require the caller-supplied owned Judge model input'
grep -Fq 'JUDGE_OWNED_MODEL_INPUT="${JUDGE_OWNED_MODEL_INPUT:-}"' "$BUILDER" ||
  fail 'architecture builder does not require the caller-supplied owned Judge model input'
grep -Fq -- '--input "$JUDGE_OWNED_MODEL_INPUT"' "$PACKAGER" ||
  fail 'packager does not validate the owned Judge model input'
grep -Fq -- '--input "$JUDGE_OWNED_MODEL_INPUT"' "$BUILDER" ||
  fail 'architecture builder does not validate the owned Judge model input'
if grep -Fq 'vendor/$TARGET_ARCH' "$BUILDER" "$PACKAGER" ||
   grep -Fq '$SCRIPT_DIR/vendor/amd64' "$VERIFIER"; then
  fail 'formal release tooling must not depend on ignored source-tree vendor assets'
fi
if grep -Eq 'reuse host Compose|download Compose|download Docker' "$BUILDER"; then
  fail 'production builder still has a host or network tool fallback'
fi
if grep -Eq 'command -v syft|SYFT_BIN=.*\$\{' "$VERIFIER" "$PACKAGER" "$SBOM_GENERATOR"; then
  fail 'production toolchain may fall back to an environment or PATH Syft'
fi
if grep -Eq 'JUDGE_GGUF_SRC=/home/dev/local-llm|DOCKER_(STATIC_TGZ|COMPOSE_BINARY)=.*\$\{' "$PACKAGER"; then
  fail 'production package assets may be overridden by the environment'
fi

fixture="$FIXTURE_ROOT/valid"
mkdir -p "$fixture"
write_syft "$fixture/syft" 1.44.0
printf '%s\n' archive >"$fixture/syft-archive"
printf '%s\n' docker-static >"$fixture/docker-static.tgz"
printf '%s\n' '#!/bin/sh' 'echo Docker Compose version v5.3.0' >"$fixture/docker-compose"
chmod +x "$fixture/docker-compose"
printf '%s\n' judge-model >"$fixture/judge.gguf"
fixture_lock="$FIXTURE_ROOT/fixture.lock"
write_fixture_lock "$fixture" "$fixture_lock"
run_fixture_verifier "$fixture" "$fixture_lock" >/dev/null

mv "$fixture/docker-static.tgz" "$fixture/docker-static.saved"
expect_failure missing-file run_fixture_verifier "$fixture" "$fixture_lock"
mv "$fixture/docker-static.saved" "$fixture/docker-static.tgz"

printf '%s\n' changed >>"$fixture/docker-compose"
expect_failure checksum-mismatch run_fixture_verifier "$fixture" "$fixture_lock"
printf '%s\n' '#!/bin/sh' 'echo Docker Compose version v5.3.0' >"$fixture/docker-compose"
chmod +x "$fixture/docker-compose"

version_lock="$FIXTURE_ROOT/version.lock"
write_syft "$fixture/syft" 1.45.0
write_fixture_lock "$fixture" "$version_lock"
expect_failure version-mismatch run_fixture_verifier "$fixture" "$version_lock"
write_syft "$fixture/syft" 1.44.0

size_lock="$FIXTURE_ROOT/size.lock"
write_fixture_lock "$fixture" "$size_lock"
sed -i 's/^judge_gguf_size=.*/judge_gguf_size=999999/' "$size_lock"
expect_failure size-mismatch run_fixture_verifier "$fixture" "$size_lock"

symlink_root="$FIXTURE_ROOT/symlink"
cp -a "$fixture" "$symlink_root"
rm "$symlink_root/syft-archive"
ln -s "$fixture/syft-archive" "$symlink_root/syft-archive"
symlink_lock="$FIXTURE_ROOT/symlink.lock"
write_fixture_lock "$fixture" "$symlink_lock"
expect_failure symlink-asset run_fixture_verifier "$symlink_root" "$symlink_lock"

ln -s "$fixture_lock" "$FIXTURE_ROOT/linked.lock"
expect_failure symlink-lock run_fixture_verifier "$fixture" "$FIXTURE_ROOT/linked.lock"
expect_failure missing-lock run_fixture_verifier "$fixture" "$FIXTURE_ROOT/missing.lock"

fallback_root="$FIXTURE_ROOT/fallback"
cp -a "$fixture" "$fallback_root"
rm "$fallback_root/syft"
mkdir -p "$FIXTURE_ROOT/fallback-bin"
write_syft "$FIXTURE_ROOT/fallback-bin/syft" 1.44.0
expect_failure path-fallback env PATH="$FIXTURE_ROOT/fallback-bin:$PATH" \
  JJDGUARD_RELEASE_TOOLCHAIN_TESTING=1 \
  sh "$VERIFIER" amd64 --fixture-root "$fallback_root" --lock "$fixture_lock"

duplicate_lock="$FIXTURE_ROOT/duplicate.lock"
cp "$fixture_lock" "$duplicate_lock"
printf '%s\n' 'syft_version=1.44.0' >>"$duplicate_lock"
expect_failure duplicate-key run_fixture_verifier "$fixture" "$duplicate_lock"

JUDGE_OWNED_MODEL_INPUT=/home/dev/local-llm/models/jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf \
  sh "$VERIFIER" amd64

echo '[ok] release toolchain and model inputs match the reviewed lock'
