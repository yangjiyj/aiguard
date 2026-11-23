#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HEADER="$ROOT/deploy/offline-installer/self-extracting-header.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[[ -f "$HEADER" ]] || fail "missing installer header: $HEADER"
for required in \
  '__JJDGUARD_ARCHIVE_BELOW__' \
  '__EMBEDDED_PUBLIC_KEY__' \
  '__EMBEDDED_HEADER_SIGNATURE__' \
  'jjdguard-offline-run-manifest/v2' \
  'verify_outer' \
  'verify_inner' \
  'write_verification_stamp'; do
  grep -Fq -- "$required" "$HEADER" || fail "header missing: $required"
done
if grep -Eq 'python3|pkeyutl' "$HEADER"; then
  fail 'customer self-extracting header must not require Python or OpenSSL'
fi
bash -n "$HEADER"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
root_name=jjdguard-fixture
bundle="$tmp/$root_name"
mkdir -p "$bundle/deploy/docker-compose" "$bundle/sbom"
mkdir -p "$bundle/docs"
printf '%s\n' '中文说明文件' >"$bundle/docs/中文说明.txt"
source_revision=0123456789abcdef0123456789abcdef01234567
source_tree=89abcdef0123456789abcdef0123456789abcdef

printf '%s\n' "{\"schema\":\"jjdguard-release-source/v1\",\"remote\":\"git@github.com:yangjiyj/aiguard.git\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\"}" >"$bundle/release-source.json"
printf '%s\n' '{"images":[]}' >"$bundle/image-provenance.json"
printf '%s\n' '{"schema":"jjdguard-release-sbom-index/v1","images":[]}' >"$bundle/sbom/index.json"
provenance_sha="$(sha "$bundle/image-provenance.json")"
sbom_sha="$(sha "$bundle/sbom/index.json")"
manifest="{\"schema\":\"offline-manifest/v2\",\"product\":\"jjdguard-enterprise\",\"version\":\"fixture\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"target_arch\":\"amd64\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"min_data_version\":\"077_request_logs_proxy_access_type_resolved.sql\",\"manifest_signature\":\"sha256-only\",\"built_at\":\"2026-09-07T00:00:00Z\",\"bundle\":\"$root_name\"}"
printf '%s\n' "$manifest" >"$bundle/manifest.json"
printf '%s\n' "$manifest" >"$bundle/deploy/docker-compose/manifest.json"
printf '%s\n' '077_request_logs_proxy_access_type_resolved.sql' >"$bundle/deploy/docker-compose/upgrade-min-data-version"
printf '%s\n' '137_enterprise_identity_department.sql' >"$bundle/deploy/docker-compose/upgrade-bridge-target-version"
(cd "$bundle" && sha256sum manifest.json >manifest.sig)
printf '%s\n' '#!/bin/sh' 'set -eu' \
  'test -f "$(dirname "$0")/.jjdguard-offline-verified.tsv"' \
  "echo 'fixture install: stamp ok'" >"$bundle/install.sh"
chmod 0755 "$bundle/install.sh"

encoded_install="$(printf '%s' install.sh | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
{
  printf 'schema\tjjdguard-offline-inventory/v1\n'
  printf 'file\t%s\t%s\t%s\n' "$encoded_install" "$(stat -c '%s' "$bundle/install.sh")" "$(sha "$bundle/install.sh")"
} >"$bundle/offline-inventory.tsv"
chmod 0444 "$bundle/offline-inventory.tsv"

runtime_bin="$tmp/runtime-bin"
mkdir "$runtime_bin"
for command_name in awk bash base64 cat chmod cmp date dd df dirname find grep gzip head id mkdir mktemp mv od printf rm sed sha256sum sort stat tail tar test tr uname wc; do
  command_path="$(command -v "$command_name" || true)"
  [[ -n "$command_path" ]] || fail "test host is missing: $command_name"
  ln -s "$command_path" "$runtime_bin/$command_name"
done
rm "$runtime_bin/id"
printf '%s\n' '#!/bin/sh' 'if [ "$1" = -u ]; then echo 0; else exec /usr/bin/id "$@"; fi' >"$runtime_bin/id"
chmod 0755 "$runtime_bin/id"

make_run() {
  local output="$1" outer="$2" payload run_manifest
  payload="$tmp/payload.tar.gz"
  tar -C "$tmp" -czf "$payload" "$root_name"
  payload_sha="$(sha "$payload")"
  payload_size="$(stat -c '%s' "$payload")"
  run_manifest="$tmp/run-manifest.json"
  printf '%s\n' "{\"schema\":\"jjdguard-offline-run-manifest/v2\",\"product\":\"JJDGuard\",\"version\":\"fixture\",\"target_arch\":\"amd64\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"payload_sha256\":\"$payload_sha\",\"payload_size\":$payload_size,\"built_at\":\"2026-09-07T00:00:00Z\"}" >"$run_manifest"
  (cd "$tmp" && sha256sum run-manifest.json >run-manifest.sig)
  tar -C "$tmp" -cf "$outer" payload.tar.gz run-manifest.json run-manifest.sig
  cp "$HEADER" "$output"
  cat "$outer" >>"$output"
  chmod 0755 "$output"
}

run_isolated() {
  "$runtime_bin/env" -i PATH="$runtime_bin" "$runtime_bin/bash" "$1" "$2"
}

for command_name in env; do
  command_path="$(command -v "$command_name" || true)"
  [[ -n "$command_path" ]] || fail "test host is missing: $command_name"
  ln -s "$command_path" "$runtime_bin/$command_name"
done
printf '%s\n' '#!/bin/sh' 'set -eu' '[ "$1" = -n ] && shift || true' 'exec "$@"' >"$runtime_bin/sudo"
chmod 0755 "$runtime_bin/sudo"

run="$tmp/fixture.run"
make_run "$run" "$tmp/outer.tar"
verify_output="$(run_isolated "$run" --verify-only)" || fail 'shell-only verifier rejected a valid fixture'
[[ "$verify_output" == *'完整性及内容校验通过'* ]] || fail "unexpected verify output: $verify_output"
list_output="$(run_isolated "$run" --list)" || fail 'shell-only list mode failed'
[[ "$list_output" == *'版本：fixture'* && "$list_output" == *'架构：amd64'* ]] || fail "unexpected list output: $list_output"

install_output="$(run_isolated "$run" install 2>&1)" ||
  fail "shell-only install path failed: $install_output"
[[ "$install_output" == *'fixture install: stamp ok'* ]] || fail "install stamp was not consumed: $install_output"

flip="$tmp/flip.run"
cp "$run" "$flip"
run_size="$(stat -c '%s' "$flip")"
printf '\001' >"$tmp/one-byte"
dd if="$tmp/one-byte" of="$flip" bs=1 seek=$((run_size - 1)) conv=notrunc status=none
set +e
flip_output="$(run_isolated "$flip" --verify-only 2>&1)"
flip_status=$?
set -e
[[ "$flip_status" -ne 0 && -n "$flip_output" ]] || fail 'outer tar final-byte tamper was accepted'

appended="$tmp/appended.run"
cp "$run" "$appended"
printf X >>"$appended"
set +e
appended_status="$(run_isolated "$appended" --verify-only >/dev/null 2>&1; echo $?)"
set -e
[[ "$appended_status" -ne 0 ]] || fail 'outer tar appended data was accepted'

printf '%s\n' flood >"$tmp/flood"
flood_outer="$tmp/flood.outer.tar"
tar -C "$tmp" -cf "$flood_outer" payload.tar.gz run-manifest.json run-manifest.sig flood
flood_run="$tmp/flood.run"
cp "$HEADER" "$flood_run"
cat "$flood_outer" >>"$flood_run"
chmod 0755 "$flood_run"
set +e
flood_output="$(run_isolated "$flood_run" --verify-only 2>&1)"
flood_status=$?
set -e
[[ "$flood_status" -ne 0 && "$flood_output" == *'too many members'* ]] ||
  fail "outer member flood was not rejected: $flood_output"

echo '[ok] shell-only self-extracting installer works without customer Python/OpenSSL'
