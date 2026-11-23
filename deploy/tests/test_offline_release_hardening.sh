#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_SCRIPT="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
ACCEPTANCE_GATE="$ROOT_DIR/deploy/lib/acceptance-gate.sh"
ARCHIVE_VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-jjdguard-offline-archive.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
assert_file_contains() {
  local file="$1" needle="$2"
  grep -Fq -- "$needle" "$file" || fail "expected $file to contain: $needle"
}

assert_file_has_line() {
  local file="$1" line="$2"
  grep -Fqx -- "$line" "$file" || fail "expected $file to contain exact line: $line"
}

function_body() {
  local name="$1" file="${2:-$PACKAGE_SCRIPT}"
  awk -v signature="${name}() {" '
    $0 == signature { found = 1 }
    found { print }
    found && /^}$/ { exit }
  ' "$file"
}

assert_function_contains() {
  local name="$1" needle="$2" body
  body="$(function_body "$name")" || fail "cannot read function $name"
  grep -Fq -- "$needle" <<<"$body" ||
    fail "expected function $name to contain: $needle"
}

assert_function_not_contains() {
  local name="$1" needle="$2" body
  body="$(function_body "$name")" || fail "cannot read function $name"
  if grep -Fq -- "$needle" <<<"$body"; then
    fail "expected function $name not to contain: $needle"
  fi
}

assert_function_has_line() {
  local file="$1" name="$2" line="$3" body
  body="$(function_body "$name" "$file")"
  grep -Fqx -- "$line" <<<"$body" ||
    fail "expected function $name in $file to contain exact line: $line"
}

assert_function_not_contains_file() {
  local file="$1" name="$2" needle="$3" body
  body="$(function_body "$name" "$file")" || fail "cannot read function $name in $file"
  if grep -Fq -- "$needle" <<<"$body"; then
    fail "expected function $name in $file not to contain: $needle"
  fi
}

# Read the complete producer output before matching. Under pipefail, grep -q
# can close early and turn a present literal into SIGPIPE, or hide a forbidden
# literal in a negative assertion. Exercise both directions above pipe size.
assertion_fixture="$(mktemp)"
{
  printf '%s\n' 'copy_payload() {' '  # TARGET_NEEDLE'
  awk 'BEGIN { for (i = 0; i < 20000; i++) print "  : # safe filler" }'
  printf '%s\n' '}'
} >"$assertion_fixture"
if ! (PACKAGE_SCRIPT="$assertion_fixture"; assert_function_contains copy_payload TARGET_NEEDLE) >/dev/null 2>&1; then
  fail 'large-body positive literal assertion rejected a present needle'
fi
if (PACKAGE_SCRIPT="$assertion_fixture"; assert_function_contains copy_payload MISSING_NEEDLE) >/dev/null 2>&1; then
  fail 'large-body positive literal assertion accepted a missing needle'
fi
if (PACKAGE_SCRIPT="$assertion_fixture"; assert_function_not_contains copy_payload TARGET_NEEDLE) >/dev/null 2>&1; then
  fail 'large-body negative literal assertion missed a forbidden needle'
fi
if ! (PACKAGE_SCRIPT="$assertion_fixture"; assert_function_not_contains copy_payload MISSING_NEEDLE) >/dev/null 2>&1; then
  fail 'large-body negative literal assertion rejected an absent needle'
fi
if (assert_function_not_contains_file "$assertion_fixture" copy_payload TARGET_NEEDLE) >/dev/null 2>&1; then
  fail 'large-body file assertion missed a forbidden needle'
fi
if ! (assert_function_not_contains_file "$assertion_fixture" copy_payload MISSING_NEEDLE) >/dev/null 2>&1; then
  fail 'large-body file assertion rejected an absent needle'
fi
rm -f -- "$assertion_fixture"

assert_file_contains "$PACKAGE_SCRIPT" 'OFFLINE_MANIFEST_SIGNING_KEY_FILE'
assert_file_contains "$PACKAGE_SCRIPT" 'SYFT_BIN=/home/dev/tool-cache/syft-1.44.0/syft'
assert_file_contains "$PACKAGE_SCRIPT" 'OFFLINE_REQUIRE_CLEAN_TREE'
assert_file_contains "$PACKAGE_SCRIPT" 'OFFLINE_TARGET_ARCH'
assert_file_contains "$PACKAGE_SCRIPT" 'run_n_minus_one_gate'
assert_file_contains "$ACCEPTANCE_GATE" 'captcha_login_json'
assert_file_contains "$ROOT_DIR/deploy/docker-compose/smoke-test.sh" 'captcha_login_json'
assert_function_contains copy_payload 'deploy/lib/captcha-login.sh'
assert_function_contains copy_payload 'deploy/lib/jjd-env.sh'
assert_file_contains "$PACKAGE_SCRIPT" '"product": "jjdguard-enterprise"'
assert_file_contains "$PACKAGE_SCRIPT" 'write_offline_inventory'
assert_file_contains "$PACKAGE_SCRIPT" 'write_archive_handoff'
assert_file_contains "$PACKAGE_SCRIPT" 'jjdguard-offline-manifest/v2'
assert_file_contains "$PACKAGE_SCRIPT" 'jjdguard-offline-handoff/v2'
assert_file_contains "$PACKAGE_SCRIPT" 'openssl pkeyutl -sign -rawin'
assert_file_contains "$DEPLOY_SCRIPT" 'verify_manifest_signature'
assert_file_contains "$DEPLOY_SCRIPT" 'target_arch'
assert_file_has_line "$DEPLOY_SCRIPT" 'wait_service_ready() {'
assert_file_has_line "$DEPLOY_SCRIPT" 'wait_active_services() {'
assert_function_has_line "$DEPLOY_SCRIPT" wait_active_services '    wait_service_ready "$service"'
assert_function_not_contains_file "$DEPLOY_SCRIPT" write_result 'BOOTSTRAP_ADMIN_PASSWORD='
assert_file_contains "$DEPLOY_SCRIPT" 'ADMIN_CREDENTIALS_FILE=$ENV_FILE'
wait_active_services_call_count="$(grep -Fxc -- 'wait_active_services' "$DEPLOY_SCRIPT" || true)"
[ "$wait_active_services_call_count" -eq 1 ] ||
  fail "expected exactly one top-level wait_active_services call in $DEPLOY_SCRIPT, found: $wait_active_services_call_count"
assert_file_contains "$ACCEPTANCE_GATE" 'bad "成品安装脚本退出码=$INSTALL_RC"'
assert_file_contains "$ACCEPTANCE_GATE" '离线镜像引用检查'
assert_file_contains "$ACCEPTANCE_GATE" 'RepoTags'

n1_body="$(function_body run_n_minus_one_gate)"
previous_line=0
for test_name in \
  test_rule_runtime_type_migration.sh \
  test_bundle_upgrade_contract.sh \
  test_bundle_upgrade_discovery.sh \
  test_bundle_upgrade_switch.sh \
  test_upgrade_min_data_version.sh \
  test_upgrade_script.sh; do
  line="$(printf '%s\n' "$n1_body" | grep -nF "$test_name" | head -1 | cut -d: -f1)"
  [ -n "$line" ] || fail "N-1 gate does not run $test_name"
  [ "$line" -gt "$previous_line" ] || fail "N-1 gate test order is incorrect at $test_name"
  previous_line="$line"
done

assert_function_contains copy_compose_binary '[error] Docker Compose fallback binary not found'
assert_function_contains copy_compose_binary '[ -s "$BUNDLE_DIR/deploy/docker-compose/bin/docker-compose" ]'
assert_function_contains copy_compose_binary '[ -x "$BUNDLE_DIR/deploy/docker-compose/bin/docker-compose" ]'

assert_function_not_contains copy_docker_engine 'curl '
assert_function_contains copy_docker_engine '[error] Docker engine static tarball not found'
assert_function_contains copy_docker_engine 'tar -tzf'
assert_function_contains copy_docker_engine 'dockerd'
assert_function_contains copy_payload 'ensure-user-profile-department.py'
assert_function_contains copy_payload 'rm -f "$BUNDLE_DIR/deploy/docker-compose/chat/ensure-user-profile-department.py"'
! grep -Fq 'python3' "$ROOT_DIR/deploy/docker-compose/judge-benchmark.sh" ||
  fail 'customer judge benchmark must not require host Python'

fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

run_copy_docker_engine() {
  local tgz="$1" bundle="$2" runner="$fixture_root/run-copy-engine.sh"
  {
    printf '%s\n' '#!/bin/sh' 'set -eu'
    function_body normalize_arch
    function_body validate_target_elf
    function_body copy_docker_engine
    printf '%s\n' 'TARGET_ARCH=amd64' 'DOCKER_STATIC_TGZ="$1"' \
      'BUNDLE_DIR="$2"' 'copy_docker_engine'
  } >"$runner"
  sh "$runner" "$tgz" "$bundle" >/dev/null 2>&1
}

run_copy_compose() {
  local binary="$1" bundle="$2" runner="$fixture_root/run-copy-compose.sh"
  {
    printf '%s\n' '#!/bin/sh' 'set -eu' 'COMPOSE_FIXTURE="$1"' 'BUNDLE_DIR="$2"' \
      'COMPOSE_FIXTURE_CASE="$3"' 'export COMPOSE_FIXTURE_CASE'
    printf '%s\n' 'find_compose_binary() { printf "%s\\n" "$COMPOSE_FIXTURE"; }'
    function_body validate_target_elf
    function_body copy_compose_binary
    printf '%s\n' 'TARGET_ARCH=amd64' 'copy_compose_binary'
  } >"$runner"
  sh "$runner" "$binary" "$bundle" "$(basename "$binary")" >/dev/null 2>&1
}

validate_static_compose_fixture() {
  local binary="$1" runner="$fixture_root/run-validate-compose.sh"
  {
    printf '%s\n' '#!/bin/sh' 'set -eu'
    function_body validate_target_elf
    printf '%s\n' 'TARGET_ARCH=amd64' 'validate_target_elf "$1" "Compose fixture" 1'
  } >"$runner"
  sh "$runner" "$binary" >/dev/null 2>&1 ||
    fail 'fake-version fixture did not pass the static amd64 ELF gate'
}

expect_compose_success() {
  local name="$1" binary="$2"
  run_copy_compose "$binary" "$fixture_root/compose-bundle-$name" ||
    fail "valid Compose fixture rejected: $name"
}

expect_compose_failure() {
  local name="$1" binary="$2"
  if run_copy_compose "$binary" "$fixture_root/compose-bundle-$name"; then
    fail "invalid Compose fixture accepted: $name"
  fi
}

system_compose="/usr/libexec/docker/cli-plugins/docker-compose"
[ -x "$system_compose" ] || system_compose="$(command -v docker-compose)"
# 发行版自带的 Compose 插件可能是动态链接的（如 Ubuntu 24.04 的 docker-compose-v2），
# 那不是随包交付的二进制；此时改用发布工具链缓存里校验过的静态 Compose 作为合法样本。
case "$(file -Lb "$system_compose" 2>/dev/null)" in
  *"statically linked"*|*"static-pie linked"*) ;;
  *)
    toolchain_compose="$(bash "$ROOT_DIR/deploy/docker-compose/release-toolchain-cache-dir.sh" amd64 2>/dev/null)/docker-compose"
    [ -x "$toolchain_compose" ] && system_compose="$toolchain_compose"
    ;;
esac
expect_compose_success system "$system_compose"
cp "$system_compose" "$fixture_root/docker-compose-copy"
expect_compose_success copied "$fixture_root/docker-compose-copy"
printf '%s\n' '#!/bin/sh' 'echo fake compose' >"$fixture_root/compose-text"
chmod +x "$fixture_root/compose-text"
expect_compose_failure text "$fixture_root/compose-text"
cp /bin/true "$fixture_root/compose-aarch64"
printf '\267\000' | dd of="$fixture_root/compose-aarch64" bs=1 seek=18 conv=notrunc 2>/dev/null
expect_compose_failure aarch64 "$fixture_root/compose-aarch64"
cp /bin/true "$fixture_root/compose-not-executable"
chmod -x "$fixture_root/compose-not-executable"
expect_compose_failure not-executable "$fixture_root/compose-not-executable"
printf '%s\n' \
  'package main' \
  'import ("fmt"; "os")' \
  'func main() {' \
  '  switch os.Getenv("COMPOSE_FIXTURE_CASE") {' \
  '  case "compose-bad-prerelease": fmt.Println("Docker Compose version v1.2.3-..")' \
  '  case "compose-leading-zero": fmt.Println("Docker Compose version v1.2.3-01")' \
  '  case "compose-multiline": fmt.Println("Docker Compose version v1.2.3"); fmt.Println("unexpected")' \
  '  case "compose-trailing-blank": fmt.Print("Docker Compose version v1.2.3\n\n")' \
  '  default: fmt.Println("Docker Compose version v1.2.3-alpha.1+build.5")' \
  '  case "compose-build-hyphen": fmt.Println("Docker Compose version 1.2.3+build-01")' \
  '  }' \
  '}' \
  >"$fixture_root/fake-compose-version.go"
CGO_ENABLED=0 /usr/local/go/bin/go build -o "$fixture_root/compose-version-fixture" \
  "$fixture_root/fake-compose-version.go"
for compose_case in compose-bad-prerelease compose-leading-zero compose-multiline compose-trailing-blank compose-build-hyphen compose-valid-semver; do
  cp "$fixture_root/compose-version-fixture" "$fixture_root/$compose_case"
done
validate_static_compose_fixture "$fixture_root/compose-bad-prerelease"
[ "$(COMPOSE_FIXTURE_CASE=compose-bad-prerelease "$fixture_root/compose-bad-prerelease" version)" = 'Docker Compose version v1.2.3-..' ] ||
  fail 'fake-version fixture did not return its malformed version string'
expect_compose_failure fake-version "$fixture_root/compose-bad-prerelease"
expect_compose_failure leading-zero "$fixture_root/compose-leading-zero"
expect_compose_failure multiline "$fixture_root/compose-multiline"
expect_compose_failure trailing-blank "$fixture_root/compose-trailing-blank"
expect_compose_success valid-semver "$fixture_root/compose-valid-semver"
cp /bin/true "$fixture_root/compose-dynamic"
chmod +x "$fixture_root/compose-dynamic"
expect_compose_failure dynamic "$fixture_root/compose-dynamic"
head -c 64 /bin/true >"$fixture_root/compose-corrupt"
chmod +x "$fixture_root/compose-corrupt"
expect_compose_failure corrupt "$fixture_root/compose-corrupt"
expect_compose_success build-hyphen "$fixture_root/compose-build-hyphen"

expect_engine_success() {
  local name="$1" tgz="$2"
  local bundle="$fixture_root/bundle-$name"
  run_copy_docker_engine "$tgz" "$bundle" || fail "valid amd64 engine fixture rejected: $name"
  [ -s "$bundle/deploy/docker-compose/docker-engine/docker-static.tgz" ] ||
    fail "validated engine fixture was not copied: $name"
}

expect_engine_failure() {
  local name="$1" tgz="$2"
  if run_copy_docker_engine "$tgz" "$fixture_root/bundle-$name"; then
    fail "invalid engine fixture accepted: $name"
  fi
}

engine_files='dockerd docker-init ctr docker-proxy containerd-shim-runc-v2 docker containerd runc'
mkdir -p "$fixture_root/valid/docker"
for engine_file in $engine_files; do cp "$fixture_root/compose-version-fixture" "$fixture_root/valid/docker/$engine_file"; done
tar -czf "$fixture_root/valid.tgz" -C "$fixture_root/valid" docker
expect_engine_success valid "$fixture_root/valid.tgz"

cp -a "$fixture_root/valid" "$fixture_root/text"
printf '%s\n' '#!/bin/sh' 'echo fake dockerd' >"$fixture_root/text/docker/dockerd"
tar -czf "$fixture_root/text.tgz" -C "$fixture_root/text" docker
expect_engine_failure text-dockerd "$fixture_root/text.tgz"

cp -a "$fixture_root/valid" "$fixture_root/text-member"
printf '%s\n' '#!/bin/sh' 'echo fake runc' >"$fixture_root/text-member/docker/runc"
chmod +x "$fixture_root/text-member/docker/runc"
tar -czf "$fixture_root/text-member.tgz" -C "$fixture_root/text-member" docker
expect_engine_failure text-non-dockerd "$fixture_root/text-member.tgz"
cp -a "$fixture_root/valid" "$fixture_root/dynamic-member"
cp /bin/true "$fixture_root/dynamic-member/docker/ctr"
tar -czf "$fixture_root/dynamic-member.tgz" -C "$fixture_root/dynamic-member" docker
expect_engine_failure dynamic-member "$fixture_root/dynamic-member.tgz"


cp -a "$fixture_root/valid" "$fixture_root/wrong-arch-member"
printf '\267\000' | dd of="$fixture_root/wrong-arch-member/docker/containerd" bs=1 seek=18 conv=notrunc 2>/dev/null
tar -czf "$fixture_root/wrong-arch-member.tgz" -C "$fixture_root/wrong-arch-member" docker
expect_engine_failure wrong-arch-non-dockerd "$fixture_root/wrong-arch-member.tgz"

cp -a "$fixture_root/valid" "$fixture_root/non-amd64"
printf '\267\000' | dd of="$fixture_root/non-amd64/docker/dockerd" bs=1 seek=18 conv=notrunc 2>/dev/null
tar -czf "$fixture_root/non-amd64.tgz" -C "$fixture_root/non-amd64" docker
expect_engine_failure non-amd64 "$fixture_root/non-amd64.tgz"

cp -a "$fixture_root/valid" "$fixture_root/missing"
rm "$fixture_root/missing/docker/dockerd"
tar -czf "$fixture_root/missing.tgz" -C "$fixture_root/missing" docker
expect_engine_failure missing-dockerd "$fixture_root/missing.tgz"

tar -cf "$fixture_root/duplicate.tar" -C "$fixture_root/valid" docker
tar -rf "$fixture_root/duplicate.tar" -C "$fixture_root/valid" docker/dockerd
gzip -c "$fixture_root/duplicate.tar" >"$fixture_root/duplicate.tgz"
expect_engine_failure duplicate-dockerd "$fixture_root/duplicate.tgz"

tar -cf "$fixture_root/ambiguous.tar" -C "$fixture_root/valid" docker
tar -rf "$fixture_root/ambiguous.tar" -C "$fixture_root/valid" ./docker/dockerd
gzip -c "$fixture_root/ambiguous.tar" >"$fixture_root/ambiguous.tgz"
expect_engine_failure ambiguous-dockerd "$fixture_root/ambiguous.tgz"

cp -a "$fixture_root/valid" "$fixture_root/extra"
printf 'unexpected\n' >"$fixture_root/extra/docker/evil"
tar -czf "$fixture_root/extra.tgz" -C "$fixture_root/extra" docker
expect_engine_failure extra-member "$fixture_root/extra.tgz"

cp -a "$fixture_root/valid" "$fixture_root/symlink"
rm "$fixture_root/symlink/docker/runc"
ln -s dockerd "$fixture_root/symlink/docker/runc"
tar -czf "$fixture_root/symlink.tgz" -C "$fixture_root/symlink" docker
expect_engine_failure symlink "$fixture_root/symlink.tgz"

cp -a "$fixture_root/valid" "$fixture_root/hardlink"
rm "$fixture_root/hardlink/docker/runc"
ln "$fixture_root/hardlink/docker/dockerd" "$fixture_root/hardlink/docker/runc"
tar -czf "$fixture_root/hardlink.tgz" -C "$fixture_root/hardlink" docker
expect_engine_failure hardlink "$fixture_root/hardlink.tgz"

cp -a "$fixture_root/valid" "$fixture_root/fifo"
rm "$fixture_root/fifo/docker/runc"
mkfifo "$fixture_root/fifo/docker/runc"
tar -czf "$fixture_root/fifo.tgz" -C "$fixture_root/fifo" docker
expect_engine_failure fifo "$fixture_root/fifo.tgz"

printf 'escape\n' >"$fixture_root/escape"
tar -cf "$fixture_root/traversal.tar" -C "$fixture_root/valid" docker
tar -rf "$fixture_root/traversal.tar" --transform='s|^escape$|../escape|' -C "$fixture_root" escape
gzip -c "$fixture_root/traversal.tar" >"$fixture_root/traversal.tgz"
expect_engine_failure traversal "$fixture_root/traversal.tgz"

tar -cf "$fixture_root/absolute.tar" -C "$fixture_root/valid" docker
tar -P -rf "$fixture_root/absolute.tar" --transform='s|^escape$|/escape|' -C "$fixture_root" escape
gzip -c "$fixture_root/absolute.tar" >"$fixture_root/absolute.tgz"
expect_engine_failure absolute-path "$fixture_root/absolute.tgz"
toolchain_dir="$("$ROOT_DIR/deploy/docker-compose/release-toolchain-cache-dir.sh" amd64)"
toolchain_tgz="$toolchain_dir/docker-static.tgz"
[ -f "$toolchain_tgz" ] || fail 'locked Docker tgz not found in the release toolchain cache'
tar -xOzf "$toolchain_tgz" docker/runc >"$fixture_root/vendor-runc"
chmod +x "$fixture_root/vendor-runc"
file -Lb "$fixture_root/vendor-runc" | grep -Fq 'static-pie linked' || fail 'vendor runc is not static-pie linked'
validate_static_compose_fixture "$fixture_root/vendor-runc"


expect_engine_success vendor "$toolchain_tgz"

assert_file_contains "$DEPLOY_SCRIPT" 'verify_offline_verification_stamp'
assert_file_contains "$DEPLOY_SCRIPT" 'OFFLINE_ALLOW_UNVERIFIED_ARCHIVE'
assert_file_contains "$ARCHIVE_VERIFIER" 'manifest signature verification failed against external trust key'
for hook in check_release_inputs sign_manifest write_sbom run_n_minus_one_gate write_offline_inventory pack_bundle write_archive_handoff; do
  grep -Fqx "$hook" "$PACKAGE_SCRIPT" || fail "release hook is defined but not invoked: $hook"
done

echo '[ok] gateway offline release hardening hooks are present'
! grep -Fq 'manifest.pub' "$DEPLOY_SCRIPT" || fail 'deploy script must not trust a public key bundled beside the archive'
