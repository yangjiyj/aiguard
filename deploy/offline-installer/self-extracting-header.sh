#!/usr/bin/env bash
set -Eeuo pipefail

# Customer installation is independent of host Python and OpenSSL. Publisher
# provenance is retained in the bundle; the x86 package verifies its complete
# payload with the standard SHA-256 tools available on supported Linux hosts.
EMBEDDED_PUBLIC_KEY='__EMBEDDED_PUBLIC_KEY__'
EMBEDDED_HEADER_SIGNATURE='__EMBEDDED_HEADER_SIGNATURE__'
MAX_OUTER_PAYLOAD_BYTES=$((64 * 1024 * 1024 * 1024))
MAX_INNER_MEMBER_COUNT=50000

fail_integrity() {
  echo '[错误] JJDGuard 离线包完整性或内容校验失败，拒绝安装。' >&2
  exit 40
}

normalize_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) echo '[error] this offline bundle supports Linux amd64/arm64 only' >&2; exit 21 ;;
  esac
}

archive_line() {
  awk '/^__JJDGUARD_ARCHIVE_BELOW__$/{print NR + 1; exit}' "$0"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  echo '[错误] 系统缺少 sha256sum/shasum，无法校验离线包。' >&2
  return 1
}

json_string() {
  local key="$1" file="$2" count value
  count="$(grep -Ec "^[[:space:]]*\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"[[:space:]]*,?[[:space:]]*$" "$file" || true)"
  if [[ "$count" == 1 ]]; then
    value="$(sed -n "s/^[[:space:]]*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*,\?[[:space:]]*$/\1/p" "$file")"
  else
    # Historical fixture receipts were compact JSON. Production manifests are
    # pretty-printed, but accepting both keeps recovery receipts compatible.
    value="$(tr ',' '\n' <"$file" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1)"
  fi
  [[ -n "$value" ]] || return 1
  [[ "$value" != *$'\n'* ]] || return 1
  printf '%s' "$value"
}

json_number() {
  local key="$1" file="$2" count value
  count="$(grep -Ec "^[[:space:]]*\"${key}\"[[:space:]]*:[[:space:]]*[0-9]+[[:space:]]*,?[[:space:]]*$" "$file" || true)"
  if [[ "$count" == 1 ]]; then
    value="$(sed -n "s/^[[:space:]]*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*,\?[[:space:]]*$/\1/p" "$file")"
  else
    value="$(tr ',' '\n' <"$file" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" | head -n 1)"
  fi
  [[ -n "$value" ]] || return 1
  printf '%s' "$value"
}

read_run_manifest() {
  local file="$1"
  [[ -f "$file" && ! -L "$file" ]] || return 1
  [[ "$(stat -c '%s' "$file")" -le $((16 * 1024 * 1024)) ]] || return 1
  RUN_SCHEMA="$(json_string schema "$file")" || return 1
  RUN_PRODUCT="$(json_string product "$file")" || return 1
  RUN_VERSION="$(json_string version "$file")" || return 1
  RUN_TARGET_ARCH="$(json_string target_arch "$file")" || return 1
  RUN_BUNDLE_PROFILE="$(json_string bundle_profile "$file")" || return 1
  RUN_INCLUDE_CHAT="$(json_string include_chat "$file")" || return 1
  RUN_ARTIFACT_STAGE="$(json_string artifact_stage "$file")" || return 1
  RUN_SOURCE_REVISION="$(json_string source_revision "$file")" || return 1
  RUN_SOURCE_TREE="$(json_string source_tree "$file")" || return 1
  RUN_IMAGE_PROVENANCE_SHA256="$(json_string image_provenance_sha256 "$file")" || return 1
  RUN_SBOM_INDEX_SHA256="$(json_string sbom_index_sha256 "$file")" || return 1
  RUN_PAYLOAD_SHA256="$(json_string payload_sha256 "$file")" || return 1
  RUN_PAYLOAD_SIZE="$(json_number payload_size "$file")" || return 1
  RUN_BUILT_AT="$(json_string built_at "$file")" || return 1

  [[ "$RUN_SCHEMA" == jjdguard-offline-run-manifest/v2 ]] || return 1
  [[ "$RUN_PRODUCT" == JJDGuard || "$RUN_PRODUCT" =~ ^[0-9A-Za-z._\ -]+$ ]] || return 1
  [[ "$RUN_TARGET_ARCH" == amd64 || "$RUN_TARGET_ARCH" == arm64 ]] || return 1
  [[ "$RUN_BUNDLE_PROFILE" == lite || "$RUN_BUNDLE_PROFILE" == full ]] || return 1
  [[ "$RUN_INCLUDE_CHAT" == 0 || "$RUN_INCLUDE_CHAT" == 1 ]] || return 1
  [[ "$RUN_ARTIFACT_STAGE" == candidate ]] || return 1
  [[ "$RUN_VERSION" =~ ^[0-9A-Za-z.-]+$ ]] || return 1
  [[ "$RUN_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$RUN_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$RUN_IMAGE_PROVENANCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$RUN_SBOM_INDEX_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$RUN_PAYLOAD_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$RUN_PAYLOAD_SIZE" =~ ^[1-9][0-9]*$ ]] || return 1
  (( RUN_PAYLOAD_SIZE <= MAX_OUTER_PAYLOAD_BYTES )) || return 1
  [[ "$RUN_BUILT_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
}

safe_member() {
  local name="$1"
  case "$name" in
    ''|/*|*'\'*|../*|*/../*|*/..|./*|*/./*|*/.) return 1 ;;
  esac
  ! printf '%s' "$name" | grep -q '[[:cntrl:]]'
}

verify_outer_tar_headers() {
  local archive="$1" size blocks block=0 header type octal member_size data_blocks
  local remaining nonzero
  size="$(stat -c '%s' "$archive")" || return 1
  (( size > 0 && size % 512 == 0 )) || return 1
  blocks=$((size / 512))
  dd if=/dev/zero of="$tmp/tar-zero-header" bs=512 count=1 >/dev/null 2>&1 || return 1
  while (( block < blocks )); do
    header="$tmp/tar-header"
    dd if="$archive" of="$header" bs=512 skip="$block" count=1 >/dev/null 2>&1 || return 1
    if cmp -s "$header" "$tmp/tar-zero-header"; then
      (( block + 1 < blocks )) || return 1
      dd if="$archive" of="$header" bs=512 skip=$((block + 1)) count=1 >/dev/null 2>&1 || return 1
      cmp -s "$header" "$tmp/tar-zero-header" || return 1
      remaining=$((blocks - block))
      nonzero="$(dd if="$archive" bs=512 skip="$block" count="$remaining" 2>/dev/null | tr -d '\000' | wc -c)"
      [[ "$nonzero" == 0 ]] || return 1
      return 0
    fi
    type="$(dd if="$archive" bs=1 skip=$((block * 512 + 156)) count=1 2>/dev/null | od -An -t x1 | tr -d ' \n')"
    case "$type" in
      00|30) ;;
      *) echo 'invalid outer archive: tar extension records are forbidden' >&2; return 1 ;;
    esac
    octal="$(dd if="$archive" bs=1 skip=$((block * 512 + 124)) count=12 2>/dev/null | tr -d ' \000\n')"
    [[ "$octal" =~ ^[0-7]+$ ]] || return 1
    member_size=$((8#$octal))
    data_blocks=$(((member_size + 511) / 512))
    block=$((block + 1 + data_blocks))
  done
  return 1
}

verify_outer() {
  local line="$1" outer="$tmp/outer.tar" item raw expected name
  tail -n +"$line" "$0" >"$outer" || return 1
  dd if=/dev/zero of="$tmp/outer-zeroes" bs=1024 count=1 >/dev/null 2>&1 || return 1
  tail -c 1024 "$outer" | cmp -s "$tmp/outer-zeroes" - || return 1
  verify_outer_tar_headers "$outer" || return 1
  tar --quoting-style=literal -tf "$outer" >"$tmp/outer.list" || return 1
  if [[ "$(wc -l <"$tmp/outer.list")" != 3 ]]; then
    echo 'invalid outer archive: outer tar has too many members' >&2
    return 1
  fi
  while IFS= read -r raw; do
    case "$raw" in
      payload.tar.gz|run-manifest.json|run-manifest.sig) ;;
      *) return 1 ;;
    esac
  done <"$tmp/outer.list"
  for item in payload.tar.gz run-manifest.json run-manifest.sig; do
    [[ "$(grep -Fc "$item" "$tmp/outer.list")" == 1 ]] || return 1
  done
  tar -xf "$outer" -C "$tmp" || return 1
  [[ -f "$tmp/payload.tar.gz" && ! -L "$tmp/payload.tar.gz" ]] || return 1
  [[ -f "$tmp/run-manifest.json" && ! -L "$tmp/run-manifest.json" ]] || return 1
  [[ -f "$tmp/run-manifest.sig" && ! -L "$tmp/run-manifest.sig" ]] || return 1
  if [[ "$(stat -c '%s' "$tmp/run-manifest.sig")" != 64 ]]; then
    [[ "$(wc -l <"$tmp/run-manifest.sig")" == 1 ]] || return 1
    expected="$(awk '{print $1}' "$tmp/run-manifest.sig")"
    name="$(awk '{print $2}' "$tmp/run-manifest.sig")"
    [[ "$expected" =~ ^[0-9a-f]{64}$ && "$name" == run-manifest.json ]] || return 1
    [[ "$(sha256_file "$tmp/run-manifest.json")" == "$expected" ]] || return 1
  fi
}

verify_inner() {
  local archive="$1" list="$tmp/inner.list" raw name candidate relative root="" item
  tar --quoting-style=literal -tzf "$archive" >"$list" || return 1
  local member_count
  member_count="$(wc -l <"$list")"
  [[ "$member_count" =~ ^[0-9]+$ ]] || return 1
  (( member_count > 0 && member_count <= MAX_INNER_MEMBER_COUNT )) || return 1
  while IFS= read -r raw; do
    name="$raw"
    case "$name" in */) name="$(printf '%s\n' "$name" | sed 's#/$##')" ;; esac
    safe_member "$name" || return 1
    case "$name" in */*) ;; *) [[ "$raw" == "$name/" ]] || return 1 ;; esac
    candidate="$(printf '%s\n' "$name" | awk -F/ '{print $1}')"
    if [[ -z "$root" ]]; then
      root="$candidate"
    elif [[ "$root" != "$candidate" ]]; then
      return 1
    fi
  done <"$list"
  [[ "$root" =~ ^(jjdguard|agent-platform)-[A-Za-z0-9._-]+$ ]] || return 1
  tar -tvzf "$archive" | awk 'substr($1, 1, 1) != "d" && substr($1, 1, 1) != "-" {bad=1} END {exit bad ? 1 : 0}' || return 1
  for item in \
    manifest.json \
    deploy/docker-compose/manifest.json \
    deploy/docker-compose/upgrade-min-data-version \
    deploy/docker-compose/upgrade-bridge-target-version \
    release-source.json \
    image-provenance.json \
    sbom/index.json; do
    grep -Fqx "$root/$item" "$list" || return 1
  done
  mkdir -p "$tmp/inner"
  tar -xzf "$archive" -C "$tmp/inner" \
    "$root/manifest.json" \
    "$root/deploy/docker-compose/manifest.json" \
    "$root/deploy/docker-compose/upgrade-min-data-version" \
    "$root/deploy/docker-compose/upgrade-bridge-target-version" \
    "$root/release-source.json" \
    "$root/image-provenance.json" \
    "$root/sbom/index.json" || return 1
  local bundle="$tmp/inner/$root"
  cmp -s "$bundle/manifest.json" "$bundle/deploy/docker-compose/manifest.json" || return 1
  [[ "$(json_string schema "$bundle/manifest.json")" == offline-manifest/v2 ]] || return 1
  local inner_product
  inner_product="$(json_string product "$bundle/manifest.json")" || return 1
  if [[ "$root" == agent-platform-* ]]; then
    [[ "$inner_product" == agent-platform ]] || return 1
    [[ "$(json_string product_profile "$bundle/manifest.json")" == agent-platform ]] || return 1
    [[ "$(json_string product_name "$bundle/manifest.json")" == "$RUN_PRODUCT" ]] || return 1
    [[ "$(json_string product_version "$bundle/manifest.json")" =~ ^[0-9A-Za-z.-]+$ ]] || return 1
    [[ "$(json_string product_slug "$bundle/manifest.json")" =~ ^[a-z0-9-]+$ ]] || return 1
    [[ "$(json_string agent_kit_sha256 "$bundle/manifest.json")" =~ ^[0-9a-f]{64}$ ]] || return 1
    grep -Fqx "$root/deploy/docker-compose/agent-kit/" "$list" || return 1
  else
    [[ "$inner_product" == jjdguard-enterprise && "$RUN_PRODUCT" == JJDGuard ]] || return 1
  fi
  [[ "$(json_string version "$bundle/manifest.json")" == "$RUN_VERSION" ]] || return 1
  [[ "$(json_string source_revision "$bundle/manifest.json")" == "$RUN_SOURCE_REVISION" ]] || return 1
  [[ "$(json_string source_tree "$bundle/manifest.json")" == "$RUN_SOURCE_TREE" ]] || return 1
  [[ "$(json_string target_arch "$bundle/manifest.json")" == "$RUN_TARGET_ARCH" ]] || return 1
  [[ "$(json_string bundle_profile "$bundle/manifest.json")" == "$RUN_BUNDLE_PROFILE" ]] || return 1
  [[ "$(json_string include_chat "$bundle/manifest.json")" == "$RUN_INCLUDE_CHAT" ]] || return 1
  [[ "$(json_string artifact_stage "$bundle/manifest.json")" == "$RUN_ARTIFACT_STAGE" ]] || return 1
  [[ "$(json_string bundle "$bundle/manifest.json")" == "$root" ]] || return 1
  [[ -f "$bundle/deploy/docker-compose/upgrade-min-data-version" ]] || return 1
  [[ -f "$bundle/deploy/docker-compose/upgrade-bridge-target-version" ]] || return 1
  [[ "$(json_string min_data_version "$bundle/manifest.json")" == "$(tr -d '[:space:]' <"$bundle/deploy/docker-compose/upgrade-min-data-version")" ]] || return 1
  case "$(json_string manifest_signature "$bundle/manifest.json")" in ed25519-domain-v2|sha256-only) ;; *) return 1 ;; esac
  [[ "$(json_string image_provenance_sha256 "$bundle/manifest.json")" == "$RUN_IMAGE_PROVENANCE_SHA256" ]] || return 1
  [[ "$(json_string sbom_index_sha256 "$bundle/manifest.json")" == "$RUN_SBOM_INDEX_SHA256" ]] || return 1
  [[ "$(sha256_file "$bundle/image-provenance.json")" == "$RUN_IMAGE_PROVENANCE_SHA256" ]] || return 1
  [[ "$(sha256_file "$bundle/sbom/index.json")" == "$RUN_SBOM_INDEX_SHA256" ]] || return 1
  [[ "$(json_string schema "$bundle/release-source.json")" == jjdguard-release-source/v1 ]] || return 1
  [[ -n "$(json_string remote "$bundle/release-source.json")" ]] || return 1
  [[ "$(json_string source_revision "$bundle/release-source.json")" == "$RUN_SOURCE_REVISION" ]] || return 1
  [[ "$(json_string source_tree "$bundle/release-source.json")" == "$RUN_SOURCE_TREE" ]] || return 1
  BUNDLE_ROOT="$root"
}

write_verification_stamp() {
  local bundle="$1" manifest inventory
  manifest="$bundle/manifest.json"
  inventory="$bundle/offline-inventory.tsv"
  local manifest_sha inventory_sha run_sha files stamp
  [[ -f "$manifest" && ! -L "$manifest" ]] || return 1
  [[ -f "$bundle/deploy/docker-compose/manifest.json" && ! -L "$bundle/deploy/docker-compose/manifest.json" ]] || return 1
  [[ -f "$inventory" && ! -L "$inventory" ]] || return 1
  manifest_sha="$(sha256_file "$manifest")"
  [[ "$manifest_sha" == "$(sha256_file "$bundle/deploy/docker-compose/manifest.json")" ]] || return 1
  inventory_sha="$(sha256_file "$inventory")"
  run_sha="$(sha256_file "$tmp/run-manifest.json")"
  files="$(grep -c '^file	' "$inventory" || true)"
  [[ "$files" =~ ^[1-9][0-9]*$ ]] || return 1
  stamp="$tmp/verified.tsv"
  {
    printf 'schema	jjdguard-offline-verified/v2\n'
    printf 'archive_sha256	%s\n' "$RUN_PAYLOAD_SHA256"
    printf 'handoff_sha256	%s\n' "$run_sha"
    printf 'manifest_sha256	%s\n' "$manifest_sha"
    printf 'inventory_sha256	%s\n' "$inventory_sha"
    printf 'source_revision	%s\n' "$RUN_SOURCE_REVISION"
    printf 'source_tree	%s\n' "$RUN_SOURCE_TREE"
    printf 'image_provenance_sha256	%s\n' "$RUN_IMAGE_PROVENANCE_SHA256"
    printf 'sbom_index_sha256	%s\n' "$RUN_SBOM_INDEX_SHA256"
    printf 'artifact_stage	%s\n' "$RUN_ARTIFACT_STAGE"
    printf 'public_key_sha256	%s\n' "$run_sha"
    printf 'verified_files	%s\n' "$files"
    printf 'verified_at	%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$stamp"
  chmod 0400 "$stamp"
  mv "$stamp" "$bundle/.jjdguard-offline-verified.tsv"
}

mode=""
if [[ "$#" -gt 0 ]]; then mode="$1"; fi
case "$mode" in
  --verify-only|--list|install|'') ;;
  *) echo '用法：bash JJDGuard-offline-版本-架构.run [--verify-only|--list]' >&2; exit 64 ;;
esac
for command_name in awk cat chmod cmp date dd find grep head mkdir mktemp mv od rm sed sort stat tail tar tr wc sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail_integrity
done
command -v gzip >/dev/null 2>&1 || fail_integrity
line="$(archive_line)"
[[ "$line" =~ ^[0-9]+$ ]] || fail_integrity
tmp_base="${TMPDIR:-/tmp}"
[[ -d "$tmp_base" && ! -L "$tmp_base" ]] || fail_integrity
available_kb="$(df -Pk "$tmp_base" 2>/dev/null | awk 'NR==2{print $4+0}')"
run_size="$(stat -c '%s' "$0")"
required_kb=$((run_size / 1024 * 3 + 1048576))
[[ "${available_kb:-0}" -ge "$required_kb" ]] || {
  echo "[错误] 临时目录空间不足：path=$tmp_base available_kb=${available_kb:-0} required_kb=$required_kb" >&2
  exit 41
}
tmp="$(mktemp -d "$tmp_base/jjdguard-installer.XXXXXX")"
chmod 700 "$tmp"
trap 'rm -rf "$tmp"' EXIT
verify_outer "$line" || fail_integrity
read_run_manifest "$tmp/run-manifest.json" || fail_integrity
[[ "$(sha256_file "$tmp/payload.tar.gz")" == "$RUN_PAYLOAD_SHA256" ]] || fail_integrity
[[ "$(stat -c '%s' "$tmp/payload.tar.gz")" == "$RUN_PAYLOAD_SIZE" ]] || fail_integrity
verify_inner "$tmp/payload.tar.gz" || fail_integrity

case "$mode" in
  --verify-only)
    echo "$RUN_PRODUCT $RUN_VERSION ($RUN_TARGET_ARCH) 离线包完整性及内容校验通过。"
    exit 0
    ;;
  --list)
    echo "产品：$RUN_PRODUCT"
    echo "版本：$RUN_VERSION"
    echo "架构：$RUN_TARGET_ARCH"
    exit 0
    ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { echo '[错误] 安装或升级必须使用 root，当前系统也没有 sudo。' >&2; exit 20; }
  exec sudo bash "$0" "$@"
fi
actual_arch="$(normalize_arch)"
[[ "$actual_arch" == "$RUN_TARGET_ARCH" ]] || {
  echo "[错误] 这个包是 $RUN_TARGET_ARCH，当前机器是 $actual_arch，请换正确架构的安装包。" >&2
  exit 21
}
mkdir "$tmp/payload"
tar -xzf "$tmp/payload.tar.gz" -C "$tmp/payload" || fail_integrity
bundle_root="$tmp/payload/$BUNDLE_ROOT"
[[ -d "$bundle_root" && -x "$bundle_root/install.sh" ]] || fail_integrity
write_verification_stamp "$bundle_root" || fail_integrity
bash "$bundle_root/install.sh"
exit $?

# shellcheck disable=SC2317
__JJDGUARD_ARCHIVE_BELOW__
