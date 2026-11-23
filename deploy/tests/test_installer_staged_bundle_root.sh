#!/usr/bin/env bash
# Regression: a staged release must keep the signed bundle's safe root name.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"
VERIFIER="$ROOT/deploy/docker-compose/verify-release-manifest-chain.py"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"
DEPLOY="$ROOT/deploy/docker-compose/deploy-offline.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[[ -f "$INSTALLER" ]] || fail "missing installer: $INSTALLER"
[[ -f "$VERIFIER" ]] || fail "missing verifier: $VERIFIER"
[[ -f "$PACKAGER" ]] || fail "missing packager: $PACKAGER"
[[ -f "$DEPLOY" ]] || fail "missing deployment script: $DEPLOY"

candidate_gate="$(sed -n '/^run_candidate_static_gates()/,/^}/p' "$PACKAGER")"
[[ "$candidate_gate" == *'test_installer_staged_bundle_root.sh'* ]] || fail 'candidate package gate must run the staged bundle root regression'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bundle_name='jjdguard-2.0-offline-full-chat-amd64-20260811T000000Z'
bundle="$tmp/$bundle_name"
mkdir -p "$bundle/deploy/offline-installer" "$bundle/deploy/docker-compose" "$bundle/sbom"
printf '#!/usr/bin/env bash\nexit 0\n' >"$bundle/deploy/offline-installer/jjdctl"
chmod 755 "$bundle/deploy/offline-installer/jjdctl"
printf '%s\n' '077_request_logs_proxy_access_type_resolved.sql' \
  >"$bundle/deploy/docker-compose/upgrade-min-data-version"

printf '{"fixture":"image-provenance"}\n' >"$bundle/image-provenance.json"
printf '{"fixture":"sbom"}\n' >"$bundle/sbom/index.json"
image_sha="$(sha "$bundle/image-provenance.json")"
sbom_sha="$(sha "$bundle/sbom/index.json")"
revision='1111111111111111111111111111111111111111'
tree='2222222222222222222222222222222222222222'

manifest="$(printf '{"schema":"offline-manifest/v2","product":"jjdguard-enterprise","version":"2.0","source_revision":"%s","source_tree":"%s","image_provenance_sha256":"%s","sbom_index_sha256":"%s","target_arch":"amd64","bundle_profile":"full","include_chat":"1","artifact_stage":"candidate","min_data_version":"077_request_logs_proxy_access_type_resolved.sql","manifest_signature":"ed25519-domain-v2","built_at":"2026-08-11T00:00:00Z","bundle":"%s"}\n' "$revision" "$tree" "$image_sha" "$sbom_sha" "$bundle_name")"
printf '%s' "$manifest" >"$bundle/manifest.json"
printf '%s' "$manifest" >"$bundle/deploy/docker-compose/manifest.json"
printf '{"schema":"jjdguard-release-source/v1","remote":"git@github.com:yangjiyj/aiguard.git","source_revision":"%s","source_tree":"%s"}\n' "$revision" "$tree" >"$bundle/release-source.json"

stage_bundle() {
  local source_bundle="$1" release_root="$tmp/releases" active_version=''
  if (( $# > 1 )); then release_root="$2"; fi
  if (( $# > 2 )); then active_version="$3"; fi
  JJD_INSTALLER_LIB_ONLY=1 JJD_PAYLOAD_ROOT="$source_bundle" \
    bash -s -- "$INSTALLER" "$release_root" "$tmp/etc" "$tmp/backups" "$tmp/log" "$active_version" <<'BASH'
set -Eeuo pipefail
installer="$1"
release_root="$2"
etc_root="$3"
backup_root="$4"
log_root="$5"
active_version="$6"

source "$installer"
RELEASES="$release_root"
ETC_ROOT="$etc_root"
BACKUP_ROOT="$backup_root"
LOG_ROOT="$log_root"
stage_release "$active_version"
BASH
}

staged="$(stage_bundle "$bundle")"

expected="$tmp/releases/$bundle_name"
[[ "$staged" == "$expected" ]] || fail "stage_release must retain the signed bundle root, got: $(basename "$staged")"
python3 "$VERIFIER" --bundle "$staged" >/dev/null || fail 'staged release must pass the same manifest-chain verifier as the unpacked bundle'

platform_name='agent-platform-1.0-offline-full-chat-amd64-20260811T000000Z'
platform_bundle="$tmp/platform-source/$platform_name"
mkdir -p "$(dirname "$platform_bundle")"
cp -a "$bundle" "$platform_bundle"
mkdir -p "$platform_bundle/deploy/docker-compose/agent-kit"
printf 'agent kit fixture\n' >"$platform_bundle/deploy/docker-compose/agent-kit/install.sh"
platform_kit_sha="$(python3 - "$platform_bundle/deploy/docker-compose/agent-kit" <<'PY'
import hashlib
import pathlib
import sys
path = pathlib.Path(sys.argv[1]) / "install.sh"
relative = b"install.sh"
print(hashlib.sha256(len(relative).to_bytes(4, "big") + relative + hashlib.sha256(path.read_bytes()).digest()).hexdigest())
PY
)"
python3 - "$platform_bundle" "$platform_name" "$platform_kit_sha" <<'PY'
import json
import pathlib
import sys
bundle, name, kit_sha = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
for path in (bundle / "manifest.json", bundle / "deploy/docker-compose/manifest.json"):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest.update(product="agent-platform", bundle=name, product_profile="agent-platform",
                    product_name="JJDGuard Agent Platform", product_version="1.0.0",
                    product_slug="agent-platform", agent_kit_sha256=kit_sha)
    path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
PY
platform_staged="$(stage_bundle "$platform_bundle" "$tmp/platform-releases")"
[[ "$platform_staged" == "$tmp/platform-releases/$platform_name" ]] || fail 'platform stage must preserve signed root'
python3 "$VERIFIER" --bundle "$platform_staged" >/dev/null || fail 'platform staged release must pass manifest chain verifier'

# Run only the real deploy script's env writers; never start Docker or run installation.
platform_env="$tmp/platform.env"
platform_manifest="$platform_staged/manifest.json"
platform_env_writer="$(sed -n '/^append_env_if_missing() {/,/^}/p; /^manifest_value() {/,/^}/p; /^ensure_platform_defaults() {/,/^}/p' "$DEPLOY")"
[[ "$platform_env_writer" == *'ensure_platform_defaults() {'* ]] || fail 'platform env writer is missing'
check_platform_env() {
  local fixture_env="$1" fixture_manifest="$2"
  ENV_FILE="$fixture_env" MANIFEST_FILE="$fixture_manifest" bash -s <<BASH
set -eu
$platform_env_writer
ensure_platform_defaults
BASH
}
: >"$platform_env"
check_platform_env "$platform_env" "$platform_manifest" || fail 'platform env writer rejected signed brand'
[[ "$(bash -c 'set -a; . "$1"; printf "%s|%s|%s|%s" "$PRODUCT_PROFILE" "$PRODUCT_NAME" "$PRODUCT_VERSION" "$PRODUCT_SLUG"' -- "$platform_env")" == 'agent-platform|JJDGuard Agent Platform|1.0.0|agent-platform' ]] || fail 'platform env values failed shell sourcing'
platform_env_before="$(sha "$platform_env")"
check_platform_env "$platform_env" "$platform_manifest" || fail 'platform env reapply failed'
[[ "$(sha "$platform_env")" == "$platform_env_before" ]] || fail 'reapplying platform env must not change existing values'
conflicting_env="$tmp/conflicting.env"
printf 'PRODUCT_PROFILE=gateway\n' >"$conflicting_env"
if check_platform_env "$conflicting_env" "$platform_manifest" >"$tmp/conflict.log" 2>&1; then
  fail 'existing gateway profile must reject signed platform package'
fi
[[ "$(cat "$conflicting_env")" == 'PRODUCT_PROFILE=gateway' ]] || fail 'profile conflict must not mutate existing env'
gateway_env="$tmp/gateway.env"
: >"$gateway_env"
check_platform_env "$gateway_env" "$staged/manifest.json" || fail 'gateway default env writer failed'
[[ ! -s "$gateway_env" ]] || fail 'gateway package must leave env bytes unchanged'

reused="$(stage_bundle "$bundle")"
[[ "$reused" == "$expected" ]] || fail "reinstalling the same bundle must reuse the signed root, got: $(basename "$reused")"
[[ "$(find "$tmp/releases" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ]] || fail 'reinstalling the same bundle must not create a timestamped release copy'

conflict_parent="$tmp/conflict"
mkdir -p "$conflict_parent"
cp -a "$bundle" "$conflict_parent/"
conflicting_bundle="$conflict_parent/$bundle_name"
conflicting_revision='3333333333333333333333333333333333333333'
sed -i "s/$revision/$conflicting_revision/g" \
  "$conflicting_bundle/manifest.json" \
  "$conflicting_bundle/deploy/docker-compose/manifest.json" \
  "$conflicting_bundle/release-source.json"

if conflict_output="$(stage_bundle "$conflicting_bundle" 2>&1)"; then
  fail 'same version and architecture with a different manifest must be rejected'
fi
[[ "$conflict_output" == *'暂存目录已存在，但 manifest 与当前安装包不一致'* ]] || fail "manifest collision must fail closed, got: $conflict_output"

version_collision_parent="$tmp/version-arch-conflict"
mkdir -p "$version_collision_parent"
version_collision_name='jjdguard-2.0-offline-full-chat-amd64-20260811T010000Z'
version_collision_bundle="$version_collision_parent/$version_collision_name"
cp -a "$bundle" "$version_collision_bundle"
version_collision_revision='4444444444444444444444444444444444444444'
sed -i \
  -e "s/$revision/$version_collision_revision/g" \
  -e "s/$bundle_name/$version_collision_name/g" \
  "$version_collision_bundle/manifest.json" \
  "$version_collision_bundle/deploy/docker-compose/manifest.json" \
  "$version_collision_bundle/release-source.json"

if version_collision_output="$(stage_bundle "$version_collision_bundle" 2>&1)"; then
  fail 'same version and architecture with a different signed root must be rejected'
fi
[[ "$version_collision_output" == *'暂存目录已有相同版本和架构但 manifest 不一致'* ]] || fail "version and architecture collision must fail closed, got: $version_collision_output"

retry_staged="$(stage_bundle "$version_collision_bundle" "$tmp/releases" "1.9")"
[[ "$retry_staged" == "$tmp/releases/$version_collision_name" ]] ||
  fail "an older active deployment must allow retrying a stale same-version candidate, got: $retry_staged"

sibling_releases="$tmp/sibling-symlink-releases"
mkdir -p "$sibling_releases" "$tmp/untrusted-sibling"
sibling_name='jjdguard-2.0-offline-full-chat-amd64-20260811T020000Z'
ln -s "$tmp/untrusted-sibling" "$sibling_releases/$sibling_name"

if sibling_output="$(stage_bundle "$version_collision_bundle" "$sibling_releases" 2>&1)"; then
  fail 'an untrusted sibling release entry must block a same-version install'
fi
[[ "$sibling_output" == *'发现不受信任的现有 release 条目'* ]] || fail "sibling symlink must fail closed, got: $sibling_output"

symlink_parent="$tmp/symlink-source"
mkdir -p "$symlink_parent"
symlink_bundle_name='jjdguard-3.0-offline-full-chat-amd64-20260811T000000Z'
symlink_bundle="$symlink_parent/$symlink_bundle_name"
cp -a "$bundle" "$symlink_bundle"
sed -i \
  -e 's/"version":"2.0"/"version":"3.0"/' \
  -e "s/$bundle_name/$symlink_bundle_name/g" \
  "$symlink_bundle/manifest.json" \
  "$symlink_bundle/deploy/docker-compose/manifest.json"
ln -s "$tmp/untrusted-target" "$tmp/releases/$symlink_bundle_name"

if symlink_output="$(stage_bundle "$symlink_bundle" 2>&1)"; then
  fail 'a pre-existing symlink must not be accepted as a release directory'
fi
[[ "$symlink_output" == *'暂存目录不是受信任的普通目录'* ]] || fail "symlink collision must fail closed, got: $symlink_output"

invalid_parent="$tmp/invalid-bundle"
mkdir -p "$invalid_parent"
invalid_bundle="$invalid_parent/$bundle_name"
cp -a "$bundle" "$invalid_bundle"
sed -i 's|"bundle":"[^"]*"|"bundle":"../not-safe"|' \
  "$invalid_bundle/manifest.json" \
  "$invalid_bundle/deploy/docker-compose/manifest.json"

if invalid_output="$(stage_bundle "$invalid_bundle" 2>&1)"; then
  fail 'an unsafe manifest bundle root must be rejected'
fi
[[ "$invalid_output" == *'安装包 bundle 根目录不合法'* ]] || fail "unsafe bundle root must fail closed, got: $invalid_output"

echo '[ok] staged release retains and safely reuses the signed bundle root'
