#!/bin/sh
set -eu

# 客户离线候选必须由 package-offline-bundle.sh 统一生成，禁止绕过静态门手工打包。

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
BUNDLE_VARIANT="${BUNDLE_VARIANT:-full-stack}"
case "$BUNDLE_VARIANT" in
  full-stack) ;;
  gpu-judge-addon)
    exec "$SCRIPT_DIR/gpu-judge-addon/package.sh" "${1:-$SCRIPT_DIR/offline-release}"
    ;;
  gpu-judge-7b-lora-addon)
    exec "$SCRIPT_DIR/gpu-judge-7b-lora-addon/package.sh" "${1:-$SCRIPT_DIR/offline-release}"
    ;;
  *)
    echo "[error] unsupported BUNDLE_VARIANT: $BUNDLE_VARIANT" >&2
    exit 2
    ;;
esac
. "$SCRIPT_DIR/lib-arch.sh"
. "$SCRIPT_DIR/lib-image-provenance.sh"
. "$SCRIPT_DIR/lib-release-payload-snapshot.sh"

SOURCE_GATE="$SCRIPT_DIR/release-source-gate.sh"
CANDIDATE_SOURCE_GATE="$SCRIPT_DIR/release-candidate-source-gate.sh"
SOURCE_MODE="$(printenv OFFLINE_RELEASE_SOURCE_MODE 2>/dev/null || printf release)"
SOURCE_GATE_EXPECTED_REMOTE='git@github.com:yangjiyj/aiguard.git'
TOOLCHAIN_VERIFIER="$SCRIPT_DIR/verify-release-toolchain.sh"
TOOLCHAIN_LOCK="$SCRIPT_DIR/release-toolchain.lock"
SYFT_BIN=/home/dev/tool-cache/syft-1.44.0/syft
JUDGE_OWNED_MODEL_INPUT="${JUDGE_OWNED_MODEL_INPUT:-}"
SOURCE_ATTESTATION_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-release-source.XXXXXX")"
SOURCE_ATTESTATION_FILE="$SOURCE_ATTESTATION_DIR/release-source.json"
PAYLOAD_SOURCE_ROOT=
cleanup_source_attestation() {
  rm -f "$SOURCE_ATTESTATION_FILE"
  rmdir "$SOURCE_ATTESTATION_DIR" 2>/dev/null || true
}
cleanup_release_source_inputs() {
  if [ -n "${PAYLOAD_SOURCE_ROOT:-}" ] && [ -d "$PAYLOAD_SOURCE_ROOT" ] && [ ! -L "$PAYLOAD_SOURCE_ROOT" ]; then
    rm -rf -- "$PAYLOAD_SOURCE_ROOT"
  fi
  cleanup_source_attestation
}
trap cleanup_release_source_inputs EXIT HUP INT TERM
case "$SOURCE_MODE" in
  release)
    sh "$SOURCE_GATE" "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$SOURCE_GATE_EXPECTED_REMOTE"
    ;;
  candidate)
    sh "$CANDIDATE_SOURCE_GATE" "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$SOURCE_GATE_EXPECTED_REMOTE"
    ;;
  *)
    echo '[error] OFFLINE_RELEASE_SOURCE_MODE must be release or candidate' >&2
    exit 1
    ;;
esac
SOURCE_IDENTITY="$(read_release_source_identity "$SOURCE_ATTESTATION_FILE")" || {
  echo '[error] release source receipt is invalid' >&2
  exit 1
}
SOURCE_REMOTE="$(printf '%s\n' "$SOURCE_IDENTITY" | sed -n '1p')"
SOURCE_REVISION="$(printf '%s\n' "$SOURCE_IDENTITY" | sed -n '2p')"
SOURCE_TREE="$(printf '%s\n' "$SOURCE_IDENTITY" | sed -n '3p')"

PAYLOAD_SOURCE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-release-payload.XXXXXX")"
create_release_payload_snapshot "$PROJECT_ROOT" "$SOURCE_REVISION" "$PAYLOAD_SOURCE_ROOT"
[ -f "$PAYLOAD_SOURCE_ROOT/VERSION" ] || {
  echo '[error] verified source snapshot is missing VERSION' >&2
  exit 1
}
TOOLCHAIN_LOCK="$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/release-toolchain.lock"
[ -f "$TOOLCHAIN_LOCK" ] || {
  echo '[error] verified source snapshot is missing the release toolchain lock' >&2
  exit 1
}
OWNED_JUDGE_MODEL_LOCK="$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/owned-judge-model.lock.json"
OWNED_JUDGE_MODEL_VERIFIER="$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/verify-owned-judge-model.py"
[ -f "$OWNED_JUDGE_MODEL_LOCK" ] && [ ! -L "$OWNED_JUDGE_MODEL_LOCK" ] &&
  [ -x "$OWNED_JUDGE_MODEL_VERIFIER" ] || {
  echo '[error] verified source snapshot is missing the owned Judge model gate' >&2
  exit 1
}

OUTPUT_DIR_INPUT="${1:-$SCRIPT_DIR/offline-release}"
mkdir -p "$OUTPUT_DIR_INPUT"
OUTPUT_DIR="$(CDPATH= cd -- "$OUTPUT_DIR_INPUT" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
VERSION_FILE="$PAYLOAD_SOURCE_ROOT/VERSION"
if [ ! -f "$VERSION_FILE" ]; then
  echo "[error] VERSION file not found at $VERSION_FILE" >&2
  exit 1
fi
JJD_VERSION="$(sed -n '1{s/[[:space:]]//g;p;q;}' "$VERSION_FILE")"
case "$JJD_VERSION" in
  *[!0-9A-Za-z.-]*|"")
    echo "[error] invalid VERSION: $JJD_VERSION" >&2
    exit 1
    ;;
esac
JJD_COMMIT="$SOURCE_REVISION"
JJD_BUILT_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
PRODUCT_PROFILE="${PRODUCT_PROFILE:-gateway}"
case "$PRODUCT_PROFILE" in
  gateway) ;;
  agent-platform)
    PRODUCT_NAME="${PRODUCT_NAME:-JJDGuard Agent Platform}"
    PRODUCT_VERSION="${PRODUCT_VERSION:-1.0.0}"
    PRODUCT_SLUG="${PRODUCT_SLUG:-agent-platform}"
    case "$PRODUCT_VERSION" in
      *[!0-9A-Za-z.-]*|'') echo '[error] invalid PRODUCT_VERSION' >&2; exit 2 ;;
    esac
    case "$PRODUCT_SLUG" in
      *[!0-9a-z-]*|'') echo '[error] invalid PRODUCT_SLUG' >&2; exit 2 ;;
    esac
    case "$PRODUCT_NAME" in
      *[!0-9A-Za-z._\ -]*|'') echo '[error] invalid PRODUCT_NAME' >&2; exit 2 ;;
    esac
    ;;
  *) echo "[error] unsupported PRODUCT_PROFILE: $PRODUCT_PROFILE" >&2; exit 2 ;;
esac
BUNDLE_PROFILE="${BUNDLE_PROFILE:-lite}"   # lite | full（full 自带语义裁判模型）
INCLUDE_CHAT="${INCLUDE_CHAT:-0}"   # 0 | 1（1 时纳入 chat 门户镜像与配置载荷，正交于 BUNDLE_PROFILE）
CHAT_SUFFIX=""; [ "$INCLUDE_CHAT" = "1" ] && CHAT_SUFFIX="-chat"
TARGET_ARCH="$(normalize_offline_arch "${OFFLINE_TARGET_ARCH:-$(uname -m)}")"
case "$TARGET_ARCH" in
  amd64|arm64) ;;
  *) echo "[error] offline bundle supports amd64/arm64 only" >&2; exit 2 ;;
esac
TOOLCHAIN_ASSET_DIR="$("$SCRIPT_DIR/release-toolchain-cache-dir.sh" "$TARGET_ARCH")" || {
  echo '[error] unable to resolve the locked Docker and Compose cache directory' >&2
  exit 1
}
DOCKER_STATIC_TGZ="$TOOLCHAIN_ASSET_DIR/docker-static.tgz"
DOCKER_COMPOSE_BINARY="$TOOLCHAIN_ASSET_DIR/docker-compose"
RELEASE_EVIDENCE="${RELEASE_EVIDENCE:-}"
case "$RELEASE_EVIDENCE" in
  /*) ;;
  *) echo '[error] RELEASE_EVIDENCE must be an explicit absolute directory' >&2; exit 1 ;;
esac
[ -d "$RELEASE_EVIDENCE" ] && [ ! -L "$RELEASE_EVIDENCE" ] || {
  echo '[error] RELEASE_EVIDENCE is not a real directory' >&2
  exit 1
}
JUDGE_GGUF_SRC=
if [ "$BUNDLE_PROFILE" = "full" ]; then
  [ -n "$JUDGE_OWNED_MODEL_INPUT" ] || {
    echo '[error] JUDGE_OWNED_MODEL_INPUT is required for a full formal release' >&2
    exit 1
  }
  python3 "$OWNED_JUDGE_MODEL_VERIFIER" \
    --lock "$OWNED_JUDGE_MODEL_LOCK" \
    --input "$JUDGE_OWNED_MODEL_INPUT" || exit 1
  JUDGE_GGUF_SRC="$JUDGE_OWNED_MODEL_INPUT"
fi
IMAGE_PROVENANCE_FILE="$RELEASE_EVIDENCE/image-provenance.json"
[ -f "$IMAGE_PROVENANCE_FILE" ] && [ ! -L "$IMAGE_PROVENANCE_FILE" ] || {
  echo '[error] verified image provenance is missing; run the release image builder first' >&2
  exit 1
}
BUNDLE_NAME="$(offline_bundle_name "$JJD_VERSION" "$BUNDLE_PROFILE" "$CHAT_SUFFIX" "$TARGET_ARCH" "$STAMP")"
if [ "$PRODUCT_PROFILE" = agent-platform ]; then
  BUNDLE_NAME="agent-platform-${BUNDLE_NAME#jjdguard-}"
fi
BUNDLE_DIR="$OUTPUT_DIR/$BUNDLE_NAME"
ARCHIVE_FILE="$OUTPUT_DIR/${BUNDLE_NAME}.tar.gz"
CHECKSUM_FILE="${ARCHIVE_FILE}.sha256"
HANDOFF_FILE="${ARCHIVE_FILE}.handoff.tsv"
HANDOFF_SIGNATURE_FILE="${ARCHIVE_FILE}.handoff.sig"
OFFLINE_REQUIRE_CLEAN_TREE="${OFFLINE_REQUIRE_CLEAN_TREE:-1}"
OFFLINE_ALLOW_DIRTY_TREE="${OFFLINE_ALLOW_DIRTY_TREE:-0}"
# 正式交付上限是固定合同，不能由调用环境放宽。
PORTAL_IMAGE_MAX_BYTES=524288000
SIGNING_KEY_FILE="${OFFLINE_MANIFEST_SIGNING_KEY_FILE:-}"
if [ -n "$SIGNING_KEY_FILE" ]; then
  MANIFEST_SIGNATURE_STATUS=ed25519-domain-v2
else
  MANIFEST_SIGNATURE_STATUS=sha256-only
fi

# 镜像清单来自同一 Git snapshot（按 BUNDLE_PROFILE 过滤）。export 让子脚本 export-offline-images.sh 继承 profile。
. "$SCRIPT_DIR/lib-images.sh"
IMAGES_LST="$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/images.lst"
export IMAGES_LST BUNDLE_PROFILE INCLUDE_CHAT
required_images="$(read_images_for_profile "$BUNDLE_PROFILE")"
echo "[info] BUNDLE_PROFILE=$BUNDLE_PROFILE 镜像: $(echo $required_images | tr '\n' ' ')"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[error] missing required command: $1" >&2
    exit 1
  fi
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo '[error] no SHA-256 command is available' >&2
    exit 1
  fi
}

base64url() {
  printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

normalize_arch() {
  case "$1" in x86_64|amd64) printf 'amd64' ;; aarch64|arm64) printf 'arm64' ;; armv7|armv7l) printf 'armv7' ;; *) printf '%s' "$1" ;; esac
}

check_release_inputs() {
  host_arch="$(normalize_offline_arch "$(uname -m)")"
  TARGET_ARCH="$(normalize_offline_arch "$TARGET_ARCH")"
  if [ "$host_arch" != "$TARGET_ARCH" ] && [ "${OFFLINE_ALLOW_CROSS_ARCH:-0}" != "1" ]; then
    echo "[error] packaging host architecture ($host_arch) != target ($TARGET_ARCH); set OFFLINE_ALLOW_CROSS_ARCH=1 only after verifying multi-arch images" >&2
    exit 1
  fi
  status="$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=all 2>/dev/null || true)"
  if [ -n "$status" ]; then
    if [ "$OFFLINE_REQUIRE_CLEAN_TREE" = "1" ] && [ "$OFFLINE_ALLOW_DIRTY_TREE" != "1" ]; then
      echo "[error] refusing offline package from dirty tree (set OFFLINE_ALLOW_DIRTY_TREE=1 for an audited exception):" >&2
      printf '%s\n' "$status" >&2
      exit 1
    fi
    echo "[warn] dirty-tree exception enabled; release provenance is not reproducible" >&2
    DIRTY_TREE_STATUS="$status"
  fi
}

validate_release_signing_key() {
  [ -n "$SIGNING_KEY_FILE" ] || return 0
  [ -f "$SIGNING_KEY_FILE" ] && [ ! -L "$SIGNING_KEY_FILE" ] || {
    echo '[error] release signing key must be a regular non-symlink file' >&2
    exit 1
  }
  key_mode="$(stat -c '%a' "$SIGNING_KEY_FILE")"
  key_owner="$(stat -c '%u' "$SIGNING_KEY_FILE")"
  case "$key_mode" in 400|600) ;; *) echo '[error] release signing key mode must be 0400 or 0600' >&2; exit 1 ;; esac
  if [ "$key_owner" != "0" ] && [ "$key_owner" != "$(id -u)" ]; then
    echo '[error] release signing key must be owned by root or the invoking user' >&2
    exit 1
  fi
  openssl pkey -in "$SIGNING_KEY_FILE" -text -noout 2>/dev/null | grep -qi ED25519 || {
    echo '[error] release signing key must be Ed25519' >&2
    exit 1
  }
}

sign_domain_file() {
  domain="$1"
  input="$2"
  output="$3"
  payload="$(mktemp)"
  { printf '%s\0' "$domain"; cat "$input"; } >"$payload"
  if ! openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY_FILE" -in "$payload" -out "$output" >/dev/null 2>&1; then
    rm -f "$payload" "$output"
    echo "[error] Ed25519 signing failed for domain $domain" >&2
    exit 1
  fi
  rm -f "$payload"
  [ "$(stat -c '%s' "$output")" = 64 ] || { echo '[error] unexpected Ed25519 signature length' >&2; exit 1; }
  chmod 0444 "$output"
}

sign_manifest() {
  manifest="$BUNDLE_DIR/manifest.json"
  if [ -n "$SIGNING_KEY_FILE" ]; then
    require_cmd openssl
    validate_release_signing_key
    sign_domain_file jjdguard-offline-manifest/v2 "$manifest" "$BUNDLE_DIR/manifest.sig"
    cp "$BUNDLE_DIR/manifest.sig" "$BUNDLE_DIR/deploy/docker-compose/manifest.sig"
    echo '[ok] domain-separated manifest signature created (external public key required)'
  else
    (cd "$BUNDLE_DIR" && sha256sum manifest.json >manifest.sig)
    cp "$BUNDLE_DIR/manifest.sig" "$BUNDLE_DIR/deploy/docker-compose/manifest.sig"
    chmod 0444 "$BUNDLE_DIR/manifest.sig" "$BUNDLE_DIR/deploy/docker-compose/manifest.sig"
    echo "[ok] manifest SHA-256 identity created"
  fi
}

write_sbom() {
  env -u JJD_RELEASE_TESTING -u JJD_TEST_SYFT_BIN -u JJD_TEST_SYFT_SHA256 \
    bash "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/generate-release-sbom.sh" \
    --bundle "$BUNDLE_DIR" \
    --provenance "$BUNDLE_DIR/image-provenance.json"
}

run_n_minus_one_gate() {
  for gate_test in \
    test_rule_runtime_type_migration.sh \
    test_bundle_upgrade_contract.sh \
    test_bundle_upgrade_discovery.sh \
    test_bundle_upgrade_switch.sh \
    test_migration_version.sh \
    test_migration_runner.sh \
    test_customer_content_projection_migration.sh \
    test_backfill_framework.sh \
    test_large_migrations_expand_only.sh \
    test_sha256_packaging_contract.sh \
    test_upgrade_governance.sh \
    test_upgrade_min_data_version.sh \
    test_upgrade_script.sh \
    test_upgrade_preserves_live_database.sh; do
    if ! bash "$PROJECT_ROOT/deploy/tests/$gate_test" >/dev/null; then
      echo "[error] gateway N-1 gate failed: $gate_test" >&2
      exit 1
    fi
  done
  echo '[ok] gateway N-1 upgrade/rollback regression gate passed'
}

run_candidate_static_gates() {
  echo '[step] running candidate structural, signature, SBOM, provenance, and contract gates'
  for gate_test in \
    test_offline_release_hardening.sh \
    test_systemd_docker_readiness.sh \
    test_docker_cli_compat.sh \
    test_compose_wrapper.sh \
    test_customer_installer_contract.sh \
    test_chat_identity_mount_permissions.sh \
    test_captcha_login_helper.sh \
    test_jjd_env_loader.sh \
    test_upgrade_bundle_shared_state_probe.sh \
    test_directory_runtime_env_authority.sh \
    test_jjdguard_compose_env_contract.sh \
    test_portal_reachability_contract.sh \
    test_sso_public_url_packaging_contract.sh \
    test_upstream_egress_proxy_contract.sh \
    test_drift_audit_contract.sh \
    test_release_source_gate.sh \
    test_release_toolchain_lock.sh \
    test_release_toolchain_cache.sh \
    test_release_third_party_cache_only.sh \
    test_judge_model_integrity.sh \
    test_llm_judge_source_provenance.sh \
    test_llm_judge_openmp_wait_policy.sh \
    test_release_image_catalog.sh \
    test_release_image_provenance.sh \
    test_release_sbom.sh \
    test_release_manifest_chain.sh \
    test_installer_staged_bundle_root.sh \
    test_installer_same_release_live_rerun.sh \
    test_jjdctl_rollback_keeps_judge_model.sh \
    test_jjdctl_rollback_compose_authority.sh \
    test_proxy_override_service_boundary.sh \
    test_rollback_anchor_runtime_assets.sh \
    test_retry_after_failed_upgrade.sh \
    test_upgrade_security_probe_budget.sh \
    test_installer_orphan_release_recovery.sh \
    test_installer_development_receipt_compat.sh \
    test_console_receipt_upgrade_chain.sh \
    test_upgrade_preserves_runtime_header_preference.sh \
    test_offline_bundle_ustar_contract.sh \
    test_self_extracting_installer.sh \
    test_portal_proxy_source_provenance.sh \
    test_release_payload_snapshot.sh; do
    if ! TMPDIR=/tmp bash "$PROJECT_ROOT/deploy/tests/$gate_test"; then
      echo "[error] candidate static gate failed: $gate_test" >&2
      exit 1
    fi
  done
  echo '[ok] candidate static release gates passed; VM runtime acceptance remains external and artifact-bound'
}

write_manifest() {
  local min_data_version
  min_data_version="$(tr -d '[:space:]' <"$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/upgrade-min-data-version")"
  printf '%s\n' "$min_data_version" | grep -Eq '^[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql$' || {
    echo '[error] upgrade-min-data-version is invalid' >&2; exit 1;
  }
  IMAGE_PROVENANCE_SHA256="$(sha256_file "$BUNDLE_DIR/image-provenance.json")"
  SBOM_INDEX_SHA256="$(sha256_file "$BUNDLE_DIR/sbom/index.json")"
  printf '%s\n' "$IMAGE_PROVENANCE_SHA256" | grep -Eq '^[0-9a-f]{64}$' || {
    echo '[error] image provenance hash is invalid' >&2; exit 1;
  }
  printf '%s\n' "$SBOM_INDEX_SHA256" | grep -Eq '^[0-9a-f]{64}$' || {
    echo '[error] SBOM index hash is invalid' >&2; exit 1;
  }
  cat >"$BUNDLE_DIR/deploy/docker-compose/manifest.json" <<EOF
{
  "schema": "offline-manifest/v2",
  "product": "jjdguard-enterprise",
  "version": "$(json_escape "$JJD_VERSION")",
  "source_revision": "$(json_escape "$SOURCE_REVISION")",
  "source_tree": "$(json_escape "$SOURCE_TREE")",
  "image_provenance_sha256": "$IMAGE_PROVENANCE_SHA256",
  "sbom_index_sha256": "$SBOM_INDEX_SHA256",
  "target_arch": "$(json_escape "$TARGET_ARCH")",
  "bundle_profile": "$(json_escape "$BUNDLE_PROFILE")",
  "include_chat": "$(json_escape "$INCLUDE_CHAT")",
  "artifact_stage": "candidate",
  "min_data_version": "$(json_escape "$min_data_version")",
  "manifest_signature": "$(json_escape "$MANIFEST_SIGNATURE_STATUS")",
  "built_at": "$(json_escape "$JJD_BUILT_AT")",
  "bundle": "$(json_escape "$BUNDLE_NAME")"
}
EOF
  cp "$BUNDLE_DIR/deploy/docker-compose/manifest.json" "$BUNDLE_DIR/manifest.json"
  if [ "$PRODUCT_PROFILE" = agent-platform ]; then
    python3 - "$BUNDLE_DIR/manifest.json" "$BUNDLE_DIR/deploy/docker-compose/manifest.json" "$PRODUCT_NAME" "$PRODUCT_VERSION" "$PRODUCT_SLUG" "$AGENT_KIT_SHA256" <<'PY'
import json
import pathlib
import sys

root, compose, name, version, slug, kit_sha = sys.argv[1:]
manifest = json.loads(pathlib.Path(root).read_text(encoding="utf-8"))
manifest.update(product="agent-platform", product_profile="agent-platform", product_name=name,
                product_version=version, product_slug=slug, agent_kit_sha256=kit_sha)
for output in (root, compose):
    pathlib.Path(output).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
  fi
}

write_release_notes() {
  notes="$BUNDLE_DIR/RELEASE_NOTES.md"
  changelog="$PAYLOAD_SOURCE_ROOT/CHANGELOG.md"
  if [ -f "$changelog" ]; then
    awk -v version="$JJD_VERSION" '
      BEGIN { found = 0 }
      $0 ~ "^## \\[" version "\\]" || $0 ~ "^## " version "([[:space:]-]|$)" {
        found = 1
      }
      found && NR > 1 && /^## / && $0 !~ "^## \\[" version "\\]" && $0 !~ "^## " version "([[:space:]-]|$)" {
        exit
      }
      found { print }
      END { if (!found) exit 42 }
    ' "$changelog" >"$notes" || {
      cat >"$notes" <<EOF
# Release Notes

未在 CHANGELOG.md 中找到 $JJD_VERSION 对应版本段。请以仓库 CHANGELOG.md 为准。
EOF
    }
  else
    cat >"$notes" <<EOF
# Release Notes

当前源码未提供 CHANGELOG.md。
EOF
  fi
  cp "$notes" "$BUNDLE_DIR/deploy/docker-compose/RELEASE_NOTES.md"
  if [ -f "$PAYLOAD_SOURCE_ROOT/docs/releases/2.9.0-model-catalog-sync.md" ]; then
    mkdir -p "$BUNDLE_DIR/docs"
    cp "$PAYLOAD_SOURCE_ROOT/docs/releases/2.9.0-model-catalog-sync.md" "$BUNDLE_DIR/docs/model-catalog-sync.md"
  fi
  # 第三方组件与模型声明随包交付，供客户做软件成分审计。
  third_party="$PAYLOAD_SOURCE_ROOT/THIRD-PARTY-NOTICES.md"
  [ -f "$third_party" ] || {
    echo '[error] verified source snapshot is missing THIRD-PARTY-NOTICES.md' >&2
    exit 1
  }
  cp "$third_party" "$BUNDLE_DIR/THIRD-PARTY-NOTICES.md"
}

find_compose_binary() {
  [ -x "$DOCKER_COMPOSE_BINARY" ] || return 1
  printf '%s\n' "$DOCKER_COMPOSE_BINARY"
}

validate_target_elf() {
  payload="$1"
  label="$2"
  require_static="${3:-0}"
  [ -f "$payload" ] && [ -s "$payload" ] && [ -x "$payload" ] || {
    echo "[error] $label must be a non-empty executable regular file: $payload" >&2
    return 1
  }
  command -v file >/dev/null 2>&1 || {
    echo "[error] file command is required to validate $label" >&2
    return 1
  }
  payload_desc="$(file -Lb "$payload")"
  case "$TARGET_ARCH:$payload_desc" in
    amd64:*"ELF 64-bit"*"x86-64,"*|amd64:*"ELF 64-bit"*x86_64*|arm64:*"ELF 64-bit"*"ARM aarch64,"*|arm64:*"ELF 64-bit"*AArch64*) ;;
    *) echo "[error] $label is not a Linux $TARGET_ARCH ELF executable: $payload_desc" >&2; return 1 ;;
  esac
  if [ "$require_static" = "1" ]; then
    case "$payload_desc" in
      *"statically linked"*|*"static-pie linked"*) ;;
      *) echo "[error] $label must be statically linked: $payload_desc" >&2; return 1 ;;
    esac
  fi
}

copy_compose_binary() {
  mkdir -p "$BUNDLE_DIR/deploy/docker-compose/bin"
  if bin_path="$(find_compose_binary)"; then
    compose_dst="$BUNDLE_DIR/deploy/docker-compose/bin/docker-compose"
    validate_target_elf "$bin_path" "Docker Compose source" 1 || exit 1
    cp "$bin_path" "$compose_dst"
    validate_target_elf "$compose_dst" "bundled Docker Compose" 1 || exit 1
    [ -s "$BUNDLE_DIR/deploy/docker-compose/bin/docker-compose" ] || {
      echo "[error] bundled Docker Compose fallback is empty: $compose_dst" >&2
      exit 1
    }
    chmod +x "$compose_dst"
    [ -x "$BUNDLE_DIR/deploy/docker-compose/bin/docker-compose" ] || {
      echo "[error] bundled Docker Compose fallback is not executable: $compose_dst" >&2
      exit 1
    }
    if ! (
      umask 077
      version_dir="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-compose-version.XXXXXX")" || exit 1
      trap 'rm -rf "$version_dir"' EXIT HUP INT TERM
      raw_version="$version_dir/output"
      if ! "$compose_dst" version >"$raw_version" 2>&1; then
        echo "[error] bundled Docker Compose failed its version self-check" >&2
        exit 1
      fi
      compose_version_lines="$(awk 'END { print NR }' "$raw_version")"
      [ "$compose_version_lines" = "1" ] || {
        echo "[error] bundled Docker Compose version output must contain exactly one line" >&2
        exit 1
      }
      compose_version_output="$(sed -n '1p' "$raw_version")"
      if ! printf '%s\n' "$compose_version_output" | grep -Eq '^Docker Compose version v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
        echo "[error] bundled Docker Compose returned an invalid version string" >&2
        exit 1
      fi
      compose_semver="${compose_version_output#Docker Compose version }"
      compose_semver="${compose_semver#v}"
      compose_without_build="${compose_semver%%+*}"
      case "$compose_without_build" in
        *-*)
          prerelease="${compose_without_build#*-}"
          prerelease="${prerelease%%+*}"
          old_ifs="$IFS"
          IFS=.
          for identifier in $prerelease; do
            case "$identifier" in
              0|*[!0-9]*) ;;
              0[0-9]*) echo "[error] bundled Docker Compose version has a numeric prerelease identifier with a leading zero" >&2; exit 1 ;;
            esac
          done
          IFS="$old_ifs"
          ;;
      esac
    ); then
      echo "[error] bundled Docker Compose version validation failed" >&2
      exit 1
    fi
    echo "[info] bundled Docker Compose fallback: $bin_path"
  else
    echo "[error] Docker Compose fallback binary not found" >&2
    exit 1
  fi
}

copy_docker_engine() {
  src="$DOCKER_STATIC_TGZ"
  if [ ! -s "$src" ]; then
    echo "[error] Docker engine static tarball not found: $src" >&2
    exit 1
  fi
  case "$(normalize_arch "$TARGET_ARCH")" in
    amd64|arm64) ;;
    *) echo "[error] bundled Docker engine does not support target: $TARGET_ARCH" >&2; exit 1 ;;
  esac
  if ! (
    umask 077
    verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-dockerd-verify.XXXXXX")" || exit 1
    trap 'rm -rf "$verify_dir"' EXIT HUP INT TERM
    members="$verify_dir/members"
    expected="$verify_dir/expected"
    verbose="$verify_dir/verbose"
    extracted="$verify_dir/dockerd"

    tar -tzf "$src" >"$members" || {
      echo "[error] cannot list Docker engine tarball: $src" >&2
      exit 1
    }
    cat >"$expected" <<'EOF'
docker/
docker/containerd
docker/containerd-shim-runc-v2
docker/ctr
docker/docker
docker/docker-init
docker/docker-proxy
docker/dockerd
docker/runc
EOF
    LC_ALL=C sort "$members" -o "$members"
    if ! cmp -s "$expected" "$members"; then
      echo "[error] Docker engine tarball members do not match the approved Docker 29.5.2 allowlist: $src" >&2
      exit 1
    fi
    tar -tvzf "$src" >"$verbose" || exit 1
    if ! awk '
      {
        type = substr($1, 1, 1)
        name = $NF
        if (name == "docker/") {
          if (type != "d") exit 1
        } else if (type != "-") {
          exit 1
        }
      }
      END { if (NR != 9) exit 1 }
    ' "$verbose"; then
      echo "[error] Docker engine tarball contains links or special files" >&2
      exit 1
    fi
    for engine_binary in dockerd docker-init ctr docker-proxy containerd-shim-runc-v2 docker containerd runc; do
      extracted="$verify_dir/$engine_binary"
      tar -xOzf "$src" "docker/$engine_binary" >"$extracted" || exit 1
      chmod 700 "$extracted"
      [ -s "$extracted" ] || exit 1
      validate_target_elf "$extracted" "bundled Docker engine member $engine_binary" 1 || exit 1
    done
  ); then
    echo "[error] Docker engine tarball validation failed: $src" >&2
    exit 1
  fi

  dst_dir="$BUNDLE_DIR/deploy/docker-compose/docker-engine"
  mkdir -p "$dst_dir"
  printf '%s\n' "$TARGET_ARCH" >"$dst_dir/target-arch"
  cp "$src" "$dst_dir/docker-static.tgz"
  [ -s "$dst_dir/docker-static.tgz" ] || { echo "[error] bundled Docker engine tarball is empty" >&2; exit 1; }
  echo "[info] bundled Docker engine (static __TARGET_ARCH__, validated): $src"
}

check_images() {
  for image in $required_images; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      echo "[error] image not found: $image" >&2
      echo "[hint] build the stack first: cd $SCRIPT_DIR && sh deploy-oneclick.sh" >&2
      exit 1
    fi
  done
}

prepare_locked_image_export() {
  require_cmd python3
  PROVENANCE_CATALOG="$IMAGES_LST"
  PROVENANCE_REPOSITORY="$PROJECT_ROOT"
  PROVENANCE_UPSTREAM_RECEIPT=
  if [ "$BUNDLE_PROFILE" = full ]; then
    "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/prepare-upstream-sources.sh" verify
    llama_revision="$(sed -n 's/^llama_cpp_revision=//p' "$TOOLCHAIN_LOCK")"
    PROVENANCE_UPSTREAM_RECEIPT="/home/dev/tool-cache/llama.cpp-$llama_revision/receipt.json"
  fi
  export PROVENANCE_CATALOG PROVENANCE_REPOSITORY PROVENANCE_UPSTREAM_RECEIPT \
    IMAGE_PROVENANCE_FILE SOURCE_ATTESTATION_FILE
}

verify_task4_provenance() {
  task4_components="$(read_image_catalog_for_profile "$BUNDLE_PROFILE" |
    awk '
      $4 == "enterprise-ai-portal" { portal=1 }
      $4 == "tier1-classifier" { tier1=1 }
      END {
        if (portal && tier1) print "portal,tier1"
        else if (portal) print "portal"
        else if (tier1) print "tier1"
      }')"
  [ -n "$task4_components" ] || return 0
  task4_receipt_dir="$RELEASE_EVIDENCE/task4"
  [ -d "$task4_receipt_dir" ] && [ ! -L "$task4_receipt_dir" ] || {
    echo '[error] Task4 provenance evidence is missing' >&2
    exit 1
  }
  source_identity="$(read_release_source_identity "$SOURCE_ATTESTATION_FILE")" || {
    echo '[error] unable to read source identity for Task4 verification' >&2
    exit 1
  }
  task4_revision="$(printf '%s\n' "$source_identity" | sed -n '2p')"
  task4_tree="$(printf '%s\n' "$source_identity" | sed -n '3p')"
  bash "$PROJECT_ROOT/deploy/tests/test_jjdguard_task4_image_provenance.sh" \
    --candidate-revision "$task4_revision" \
    --candidate-tree "$task4_tree" \
    --receipt-dir "$task4_receipt_dir" \
    --expected-components "$task4_components" \
    --target-arch "$TARGET_ARCH" \
    --repo "$PROJECT_ROOT"
  [ ! -e "$BUNDLE_DIR/task4" ] && [ ! -L "$BUNDLE_DIR/task4" ] || {
    echo '[error] bundle Task4 provenance destination already exists' >&2
    exit 1
  }
  cp -a "$task4_receipt_dir" "$BUNDLE_DIR/task4"
  echo '[ok] Task4 provenance reverified and copied before docker save'
}

check_portal_image_size() {
  [ "$INCLUDE_CHAT" = "1" ] || return 0
  portal_image="$(printf '%s\n' $required_images | awk '/^enterprise-ai-portal:/ { print; exit }')"
  if [ -z "$portal_image" ]; then
    echo "[error] INCLUDE_CHAT=1 but portal image is missing from images.lst" >&2
    exit 1
  fi
  case "$PORTAL_IMAGE_MAX_BYTES" in
    *[!0-9]*|"") echo "[error] invalid PORTAL_IMAGE_MAX_BYTES: $PORTAL_IMAGE_MAX_BYTES" >&2; exit 1 ;;
  esac
  portal_size="$(docker image inspect "$portal_image" --format '{{.Size}}')"
  case "$portal_size" in
    *[!0-9]*|"") echo "[error] invalid image size for $portal_image: $portal_size" >&2; exit 1 ;;
  esac
  if [ "$portal_size" -gt "$PORTAL_IMAGE_MAX_BYTES" ]; then
    echo "[error] portal image $portal_image is $portal_size bytes; limit is $PORTAL_IMAGE_MAX_BYTES bytes" >&2
    exit 1
  fi
  echo "[ok] portal image size gate passed: $portal_image = $portal_size bytes (limit $PORTAL_IMAGE_MAX_BYTES)"
}

write_install_script() {
  cat >"$BUNDLE_DIR/install.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$SCRIPT_DIR/deploy/offline-installer/installer.sh" "$@"
EOF
  chmod +x "$BUNDLE_DIR/install.sh"
}

write_upgrade_script() {
  cat >"$BUNDLE_DIR/upgrade.sh" <<'EOF'
#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
CORE_SCRIPT="$SCRIPT_DIR/deploy/docker-compose/upgrade-bundle.sh"

exec bash "$CORE_SCRIPT" "$@"
EOF
  chmod +x "$BUNDLE_DIR/upgrade.sh"
}

write_status_script() {
  cat >"$BUNDLE_DIR/status.sh" <<'EOF'
#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/deploy/docker-compose"

# 读 .env 不能用 source：含空格的未加引号值会被当命令执行（见 deploy/lib/jjd-env.sh）。
. "$SCRIPT_DIR/deploy/lib/jjd-env.sh"
if [ -f ./.env ]; then
  jjd_load_env_file ./.env
fi

sh ./compose-wrapper.sh -f docker-compose.offline.yml ps
sh ./smoke-test.sh
EOF
  chmod +x "$BUNDLE_DIR/status.sh"
}

write_stop_script() {
  cat >"$BUNDLE_DIR/stop.sh" <<'EOF'
#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/deploy/docker-compose"

sh ./compose-wrapper.sh -f docker-compose.offline.yml down
EOF
  chmod +x "$BUNDLE_DIR/stop.sh"
}

write_diagnose_script() {
  cat >"$BUNDLE_DIR/diagnose.sh" <<'EOF'
#!/bin/sh
# 现场排障：网页打不开、但端口能 telnet 通时，在解压目录根下运行本脚本，
# 会生成一个已自动脱敏的诊断包 jjdguard-diagnostics-*.tar.gz，回传给实施/研发即可定位。
# 全程只读，不改动任何部署，不外发任何数据；密钥/口令/私钥一律脱敏，不含 TLS 私钥。
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/deploy/docker-compose"

exec sh ./diagnose.sh "$@"
EOF
  chmod +x "$BUNDLE_DIR/diagnose.sh"
}

write_readme() {
  cat >"$BUNDLE_DIR/README-离线部署.txt" <<'EOF'
智能体安全网关离线部署包

This directory contains the customer-installable offline payload.

Install directly from the delivered .run after verifying its SHA-256 checksum:
  chmod +x JJDGuard-offline-<version>-<shortsha>-__TARGET_ARCH__.run
  sudo ./JJDGuard-offline-<version>-<shortsha>-__TARGET_ARCH__.run

适用场景：
  客户现场不能访问互联网。
  - 若目标机器未安装 Docker 引擎，安装程序会自动使用随包内置的 Linux __TARGET_ARCH__ 静态二进制离线安装（需要 root 或 sudo）。
  - 若未安装 Compose v2，脚本会优先使用随包提供的 Linux __TARGET_ARCH__ Compose。

安装前检查：
  1. 确认操作系统架构与本包一致（__TARGET_ARCH__）。
  2. 准备 root 或可用的 sudo（首次安装 Docker 引擎 / 写入 systemd 服务需要）。
  3. 默认使用 443、3000、8080、8081、8082、8000、3128、5432、6379；如端口被占用，脚本会自动顺延避让并输出最终地址。
  （如目标机器已自带可用的 Docker，则脚本会跳过引擎安装、直接复用。）

脚本会自动完成：
Installation boundary:
  Do not manually extract the archive or invoke its internal install scripts.

The installer automatically:
  - verifies the offline Docker image archive SHA-256 and imports images
  - installs or reuses Docker Engine and Docker Compose
  - 生成本机 .env 配置、随机密钥和控制台 HTTPS 自签证书
  - 自动避让已占用端口
  - 生成管理员初始密码
  - 启动全部服务
  - 初始化数据库结构
  - 执行健康检查
  - 输出访问地址和管理员账号

常用命令：
  查看状态：sh status.sh
  停止服务：sh stop.sh

部署结果：
  安装完成后会写入 deploy/docker-compose/.deploy-result。
  里面包含 HTTPS 控制台地址、HTTP 跳转地址、网关地址、管理员账号和初始密码。

注意事项：
  - 内置 Docker 引擎为 Linux __TARGET_ARCH__ 静态二进制，仅适用于对应架构。
  - 浏览器首次访问 HTTPS 控制台时会看到自签证书提示；可将 deploy/docker-compose/tls/web-console.crt 导入客户内网受信任证书。
  - 初始管理员首次登录后需要修改密码。
  - 平台默认是检测/审计模式，不阻断业务调用。
  - 上游模型提供商、模型同步、业务密钥建议在控制台完成配置。
  - 不要删除 deploy/docker-compose/.env，否则重新部署会生成新的密钥和初始密码。
EOF
  sed -i "s/__TARGET_ARCH__/$TARGET_ARCH/g" "$BUNDLE_DIR/README-离线部署.txt"
  if [ "$PRODUCT_PROFILE" = agent-platform ]; then
    python3 - "$BUNDLE_DIR/README-离线部署.txt" "$PRODUCT_NAME" "$PRODUCT_VERSION" "$PRODUCT_SLUG" <<'PY'
import pathlib
import sys

path, name, version, slug = sys.argv[1:]
content = pathlib.Path(path).read_text(encoding="utf-8")
content = content.replace("智能体安全网关离线部署包", name + " 离线部署包", 1)
content = content.replace("JJDGuard-offline-<version>-<shortsha>-amd64.run", slug + "-offline-<version>-<shortsha>-amd64.run")
content += "\n产品档位：agent-platform\n产品品牌：" + name + "\n产品版本：" + version + "\n"
pathlib.Path(path).write_text(content, encoding="utf-8")
PY
  fi
  {
    printf '\n版本信息：\n'
    printf '  产品版本：%s\n' "$JJD_VERSION"
    printf '  构建提交：%s\n' "${JJD_COMMIT:-unknown}"
    printf '  构建时间：%s\n' "$JJD_BUILT_AT"
    printf '  变更说明：RELEASE_NOTES.md\n'
    printf '  第三方组件与模型声明：THIRD-PARTY-NOTICES.md\n'
  } >>"$BUNDLE_DIR/README-离线部署.txt"
}

copy_payload() {
  rm -rf "$BUNDLE_DIR"
  mkdir -p "$BUNDLE_DIR/deploy/docker-compose/offline-artifacts"
  mkdir -p "$BUNDLE_DIR/deploy/lib"
  mkdir -p "$BUNDLE_DIR/deploy/migrations"
  cp -R "$PAYLOAD_SOURCE_ROOT/deploy/offline-installer" "$BUNDLE_DIR/deploy/offline-installer"
  rm -f "$BUNDLE_DIR/deploy/offline-installer/verify-promoted-release.py" \
    "$BUNDLE_DIR/deploy/offline-installer/release-public.sha256"
  cp "$SOURCE_ATTESTATION_FILE" "$BUNDLE_DIR/release-source.json"
  cp "$TOOLCHAIN_LOCK" "$BUNDLE_DIR/release-toolchain.lock"
  cp "$TOOLCHAIN_LOCK" "$BUNDLE_DIR/deploy/docker-compose/release-toolchain.lock"
  cp "$OWNED_JUDGE_MODEL_LOCK" "$BUNDLE_DIR/owned-judge-model.lock.json"

  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/docker-compose.offline.yml "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/deploy-offline.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/judge-resource-autotune.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/engine-resource-autotune.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/compose-wrapper.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/tier1-scale.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/tier1-topology.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/tier1-cpu.override.yml "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/tier1-gpu.override.yml "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/docker-compose.scale.yml "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/lib-arch.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/lib-identity-mounts.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/install-docker.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/ensure-web-tls.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/ensure-jjdguard-portal-cp-network.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/migrate-private.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/judge-benchmark.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/bootstrap-runtime.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/smoke-test.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/backup-db.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade-bundle.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade-preflight.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/customer-environment-scope-repair-lib.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/redis-valkey-migrate-lib.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/customer-environment-scope-repair.sql "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/apply-customer-environment-scope-repair.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade-min-data-version "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade-bridge-target-version "$BUNDLE_DIR/deploy/docker-compose/"
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/.env.example "$BUNDLE_DIR/deploy/docker-compose/"
  if [ "$PRODUCT_PROFILE" = agent-platform ]; then
    python3 - "$BUNDLE_DIR/deploy/docker-compose/.env.example" "$PRODUCT_NAME" "$PRODUCT_VERSION" "$PRODUCT_SLUG" <<'PY'
import pathlib
import sys

path, name, version, slug = sys.argv[1:]
template = pathlib.Path(path).read_text(encoding="utf-8")
for key, value in (("PRODUCT_PROFILE", "agent-platform"), ("PRODUCT_NAME", name),
                   ("PRODUCT_VERSION", version)):
    marker = key + "="
    lines = template.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.startswith(marker)]
    if len(matches) != 1:
        raise SystemExit(f"[error] env template must contain exactly one {key}")
    lines[matches[0]] = marker + value + "\n"
    template = "".join(lines)
if any(line.startswith("PRODUCT_SLUG=") for line in template.splitlines()):
    raise SystemExit("[error] env template already defines PRODUCT_SLUG")
pathlib.Path(path).write_text(template + "PRODUCT_SLUG=" + slug + "\n", encoding="utf-8")
PY
  fi
  cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/diagnose.sh "$BUNDLE_DIR/deploy/docker-compose/"
  cp -R "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/initdb "$BUNDLE_DIR/deploy/docker-compose/"
  copy_compose_binary
  copy_docker_engine
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/lib/captcha-login.sh "$BUNDLE_DIR/deploy/lib/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/lib/jjd-env.sh "$BUNDLE_DIR/deploy/lib/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/lib/migration-runner.sh "$BUNDLE_DIR/deploy/lib/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/lib/migration-version.sh "$BUNDLE_DIR/deploy/lib/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/lib/judge-model-load.sh "$BUNDLE_DIR/deploy/lib/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/lib/legacy-migration-checksums.tsv "$BUNDLE_DIR/deploy/lib/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/migrations/*.sql "$BUNDLE_DIR/deploy/migrations/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/migrations/jjdguard-neutral-baseline-manifest.tsv "$BUNDLE_DIR/deploy/migrations/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/migrations/prepare-jjdguard-neutral-baseline.sh "$BUNDLE_DIR/deploy/migrations/"
  cp "$PAYLOAD_SOURCE_ROOT"/deploy/migrations/sign-jjdguard-customer-neutral-result.sh "$BUNDLE_DIR/deploy/migrations/"
  # 首装自带 90 天试用授权:每次打包生成一次性 bundle-trial-key,签一份 90 天全特性 trial license 随包,
  # deploy-offline 装机时灌进 system_settings;私钥即用即弃不入包,公钥入 license/ 供 control-plane 校验。
  mkdir -p "$BUNDLE_DIR/deploy/docker-compose/license"
  ( cd "$PAYLOAD_SOURCE_ROOT/apps/control-plane" && HOME="${HOME:-/home/dev}" PATH=/usr/local/go/bin:$PATH GOWORK=off go run ./cmd/licensegen \
      --mode dev --generate-dev-key --type trial --days 90 \
      --key-id bundle-trial-key --customer "JJDGUARD 试用授权" --customer-id jjdguard-trial \
      --out "$BUNDLE_DIR/deploy/docker-compose/license/trial-license.json" \
      --public-key-out "$BUNDLE_DIR/deploy/docker-compose/license/bundle-trial-pubkey.txt" ) \
    || { echo "[error] 生成随包试用授权失败" >&2; exit 1; }
  echo "[step] 随包 90 天试用授权已生成 (bundle-trial-key)"
  # 目录 LDAPS 的共享 CA 信任目录：control-plane 无条件挂载它（预览侧信任根），
  # 所以 base 包也必须带上，出厂状态才可复现。chat 包会再做一次权限归一。
  cp -R "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/directory-truststore" "$BUNDLE_DIR/deploy/docker-compose/"
  # 宿主机诊断采集器：静态二进制（仅标准库 + shared-go，shared-go 经 replace 指向本地目录，无需联网）
  # 与安装/卸载脚本一起放进 deploy/diag-agent/，由 deploy-offline.sh / upgrade.sh 末尾调用安装。
  mkdir -p "$BUNDLE_DIR/deploy/diag-agent"
  ( cd "$PAYLOAD_SOURCE_ROOT/apps/diag-agent" && HOME="${HOME:-/home/dev}" PATH=/usr/local/go/bin:$PATH \
      CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH="$TARGET_ARCH" GOPROXY=off GOFLAGS=-mod=mod \
      go build -trimpath -ldflags '-s -w' -o "$BUNDLE_DIR/deploy/diag-agent/jjdguard-diag-agent" . ) \
    || { echo "[error] 构建 diag-agent 失败" >&2; exit 1; }
  validate_target_elf "$BUNDLE_DIR/deploy/diag-agent/jjdguard-diag-agent" "diag-agent" 1 || exit 1
  for diag_file in install-diag-agent.sh uninstall-diag-agent.sh jjdguard-diag-agent.service; do
    cp "$PAYLOAD_SOURCE_ROOT/deploy/diag-agent/$diag_file" "$BUNDLE_DIR/deploy/diag-agent/$diag_file" \
      || { echo "[error] 缺少 deploy/diag-agent/$diag_file" >&2; exit 1; }
  done
  chmod 0755 "$BUNDLE_DIR/deploy/diag-agent/install-diag-agent.sh" "$BUNDLE_DIR/deploy/diag-agent/uninstall-diag-agent.sh" \
    "$BUNDLE_DIR/deploy/diag-agent/jjdguard-diag-agent"
  echo "[step] 诊断采集器已打包 (diag-agent, $TARGET_ARCH)"
  cp "$VERSION_FILE" "$BUNDLE_DIR/VERSION"

  if [ "$PRODUCT_PROFILE" = agent-platform ]; then
    kit_source="$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/agent-kit"
    [ -d "$kit_source" ] && [ ! -L "$kit_source" ] || {
      echo '[error] verified source snapshot is missing agent-kit' >&2
      exit 1
    }
    cp -R "$kit_source" "$BUNDLE_DIR/deploy/docker-compose/agent-kit"
    AGENT_KIT_SHA256="$(python3 - "$BUNDLE_DIR/deploy/docker-compose/agent-kit" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = sorted(root.rglob("*"))
if not any(path.is_file() and path.name != ".gitkeep" for path in files):
    raise SystemExit("[error] agent-kit has no distributable payload")
digest = hashlib.sha256()
for path in files:
    if path.is_symlink() or not (path.is_file() or path.is_dir()):
        raise SystemExit(f"[error] unsafe agent-kit member: {path}")
    if path.is_file():
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big") + relative)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
print(digest.hexdigest())
PY
)" || exit 1
  fi

  # full 包：纳入语义裁判 GGUF（独立 artifact，装机时灌进命名卷 judge-models）。
  if [ "$BUNDLE_PROFILE" = "full" ]; then
    if [ ! -f "$JUDGE_GGUF_SRC" ]; then
      echo "[error] full 包锁定的 GGUF 不存在: $JUDGE_GGUF_SRC" >&2
      exit 1
    fi
    mkdir -p "$BUNDLE_DIR/deploy/docker-compose/models"
    cp "$JUDGE_GGUF_SRC" "$BUNDLE_DIR/deploy/docker-compose/models/"
    echo "[step] full 包已纳入 GGUF ($(wc -c < "$JUDGE_GGUF_SRC" | tr -d ' ') bytes)"
  fi

  # chat 包：纳入 chat 配置载荷（Caddyfile + keycloak realm）。base 包绝不含 → deploy-offline 不会激活 chat。
  if [ "$INCLUDE_CHAT" = "1" ]; then
    cp -R "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/chat" "$BUNDLE_DIR/deploy/docker-compose/chat"
    rm -f "$BUNDLE_DIR/deploy/docker-compose/chat/ensure-user-profile-department.py"
    sh "$BUNDLE_DIR/deploy/docker-compose/lib-identity-mounts.sh" "$BUNDLE_DIR/deploy/docker-compose"
    echo "[step] chat 包已纳入 chat 配置载荷"
  fi
}

export_images() {
  echo "[step] exporting docker images"
  prepare_locked_image_export
  OFFLINE_TARGET_ARCH="$TARGET_ARCH" bash "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/export-offline-images.sh" "$BUNDLE_DIR/deploy/docker-compose/offline-artifacts"
  install -m 0444 "$IMAGE_PROVENANCE_FILE" "$BUNDLE_DIR/image-provenance.json"
  echo '[ok] image provenance and docker save completed under one image-store lock'
}

pack_bundle() {
  echo "[step] creating offline bundle archive"
  (
    cd "$OUTPUT_DIR"
    tar --format=ustar -czf "$ARCHIVE_FILE" "$BUNDLE_NAME"
  )

  if command -v shasum >/dev/null 2>&1; then
    (cd "$OUTPUT_DIR" && shasum -a 256 "$(basename "$ARCHIVE_FILE")" >"$(basename "$CHECKSUM_FILE")")
  else
    (cd "$OUTPUT_DIR" && sha256sum "$(basename "$ARCHIVE_FILE")" >"$(basename "$CHECKSUM_FILE")")
  fi
}

write_offline_inventory() {
  require_cmd python3
  python3 - "$BUNDLE_DIR" <<'PY'
import base64
import hashlib
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
destination = root / "offline-inventory.tsv"
rows = []
for path in root.rglob("*"):
    if path == destination:
        continue
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise SystemExit(f"unsupported bundle member: {path.relative_to(root)}")
    if not stat.S_ISREG(info.st_mode):
        continue
    rel = path.relative_to(root).as_posix()
    if any(ord(char) < 32 or ord(char) == 127 for char in rel):
        raise SystemExit(f"control character in bundle path: {rel!r}")
    encoded = base64.urlsafe_b64encode(rel.encode("utf-8")).decode("ascii").rstrip("=")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    rows.append((rel.encode("utf-8"), encoded, info.st_size, digest.hexdigest()))
rows.sort(key=lambda row: row[0])
temporary = destination.with_name(".offline-inventory.tmp")
with temporary.open("w", encoding="ascii", newline="\n") as handle:
    handle.write("schema\tjjdguard-offline-inventory/v1\n")
    for _, encoded, size, digest in rows:
        handle.write(f"file\t{encoded}\t{size}\t{digest}\n")
os.chmod(temporary, 0o444)
os.replace(temporary, destination)
print(f"[ok] offline inventory written: files={len(rows)}")
PY
}

write_archive_handoff() {
  require_cmd openssl
  PRODUCT_PROFILE_PRODUCT=jjdguard-enterprise
  [ "$PRODUCT_PROFILE" = agent-platform ] && PRODUCT_PROFILE_PRODUCT=agent-platform
  manifest="$BUNDLE_DIR/manifest.json"
  inventory="$BUNDLE_DIR/offline-inventory.tsv"
  [ -f "$ARCHIVE_FILE" ] && [ -f "$manifest" ] && [ -f "$inventory" ] || {
    echo '[error] archive handoff inputs are incomplete' >&2
    exit 1
  }
  printf '%s\t%s\n' \
    schema jjdguard-offline-handoff/v2 \
    archive_file "$(base64url "$(basename "$ARCHIVE_FILE")")" \
    bundle_root "$(base64url "$BUNDLE_NAME")" \
    archive_sha256 "$(sha256_file "$ARCHIVE_FILE")" \
    manifest_sha256 "$(sha256_file "$manifest")" \
    inventory_sha256 "$(sha256_file "$inventory")" \
    product "$(base64url "$PRODUCT_PROFILE_PRODUCT")" \
    version "$(base64url "$JJD_VERSION")" \
    source_revision "$(base64url "$SOURCE_REVISION")" \
    source_tree "$(base64url "$SOURCE_TREE")" \
    image_provenance_sha256 "$IMAGE_PROVENANCE_SHA256" \
    sbom_index_sha256 "$SBOM_INDEX_SHA256" \
    target_arch "$(base64url "$TARGET_ARCH")" \
    bundle_profile "$(base64url "$BUNDLE_PROFILE")" \
    include_chat "$(base64url "$INCLUDE_CHAT")" \
    artifact_stage "$(base64url candidate)" >"$HANDOFF_FILE"
  if [ "$PRODUCT_PROFILE" = agent-platform ]; then
    printf '%s\t%s\n' \
      product_profile "$(base64url "$PRODUCT_PROFILE")" \
      product_name "$(base64url "$PRODUCT_NAME")" \
      product_version "$(base64url "$PRODUCT_VERSION")" \
      product_slug "$(base64url "$PRODUCT_SLUG")" \
      agent_kit_sha256 "$AGENT_KIT_SHA256" >>"$HANDOFF_FILE"
  fi
  chmod 0444 "$HANDOFF_FILE"
  if [ -n "$SIGNING_KEY_FILE" ]; then
    sign_domain_file jjdguard-offline-handoff/v2 "$HANDOFF_FILE" "$HANDOFF_SIGNATURE_FILE"
    echo '[ok] signed archive handoff created (public key remains external)'
  else
    printf '%s  %s\n' "$(sha256_file "$HANDOFF_FILE")" "$(basename "$HANDOFF_FILE")" >"$HANDOFF_SIGNATURE_FILE"
    chmod 0444 "$HANDOFF_SIGNATURE_FILE"
    echo '[ok] archive handoff SHA-256 identity created'
  fi
}

# 出厂自检闸：真起一个 PG，把"随包 initdb 快照 → 随包 migration-runner"整条装机链跑一遍，
# 断言 schema 推到最新（所有迁移已应用 + tenants.industry 在 + 0 失效索引）。
# 任一不达标即拒绝出包——把"装机后 schema 残缺"从流到客户现场变成打包当场失败。
verify_bundle_schema() {
  echo "[step] verifying bundle schema (initdb snapshot -> migration-runner -> latest)"
  vimg="postgres:16-alpine"
  vname="jjdguard-pkg-verify-${STAMP}"
  vinit="$BUNDLE_DIR/deploy/docker-compose/initdb"
  vmig="$BUNDLE_DIR/deploy/migrations"
  vrunner="$BUNDLE_DIR/deploy/lib/migration-runner.sh"
  vfail=0

  docker rm -f -v "$vname" >/dev/null 2>&1 || true
  docker run -d --name "$vname" \
    -e POSTGRES_PASSWORD=verify -e POSTGRES_USER=jjdguard -e POSTGRES_DB=jjdguard \
    -v "$vinit":/initsnap:ro -v "$vmig":/migrations:ro \
    "$vimg" >/dev/null

  vok=0
  vi=0
  while [ "$vi" -lt 300 ]; do
    if docker exec "$vname" psql -U jjdguard -d jjdguard -tAc 'SELECT 1' >/dev/null 2>&1; then
      vok=$((vok + 1))
      if [ "$vok" -ge 5 ]; then break; fi
    else
      vok=0
    fi
    vi=$((vi + 1))
    sleep 1
  done

  if ! docker exec "$vname" psql -U jjdguard -d jjdguard -v ON_ERROR_STOP=1 -f /initsnap/001_init_enterprise.sql >/tmp/pkg-verify-initdb.log 2>&1; then
    echo "[error] 随包 initdb 快照执行失败" >&2
    vfail=1
  fi

  if [ "$vfail" -eq 0 ]; then
    vbridge="$(mktemp)"
    printf '#!/bin/sh\nexec docker exec -i %s psql -U jjdguard -d jjdguard "$@"\n' "$vname" >"$vbridge"
    chmod +x "$vbridge"
    if ! MIGRATION_PSQL="$vbridge" POSTGRES_USER=jjdguard POSTGRES_DB=jjdguard \
         bash "$vrunner" --migrations-dir "$vmig" </dev/null >/tmp/pkg-verify-runner.log 2>&1; then
      echo "[error] 随包 migration-runner 执行失败：" >&2
      tail -5 /tmp/pkg-verify-runner.log >&2
      vfail=1
    fi
    rm -f "$vbridge"
  fi

  if [ "$vfail" -eq 0 ]; then
    # 按随包 migration-version.sh 的规则统计（三位以上数字编号，与 migration-runner 一致）。
    vexp="$(bash -c '. "$1" && migration_versioned_count "$2"' migration-count "$BUNDLE_DIR/deploy/lib/migration-version.sh" "$vmig")"
    vact="$(docker exec "$vname" psql -U jjdguard -d jjdguard -tAc 'SELECT count(*) FROM schema_migrations' 2>/dev/null | tr -d '[:space:]')"
    vind="$(docker exec "$vname" psql -U jjdguard -d jjdguard -tAc "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='industry')" 2>/dev/null | tr -d '[:space:]')"
    vprivate="$(docker exec "$vname" psql -U jjdguard -d jjdguard -tAc "SELECT count(*) = 2 FROM information_schema.columns WHERE table_schema='public' AND table_name='reverse_proxy_routes' AND column_name IN ('allow_private_egress','private_egress_cidrs')" 2>/dev/null | tr -d '[:space:]')"
    vinv="$(docker exec "$vname" psql -U jjdguard -d jjdguard -tAc 'SELECT count(*) FROM pg_index WHERE NOT indisvalid' 2>/dev/null | tr -d '[:space:]')"
    if [ "$vact" != "$vexp" ] || [ "$vind" != "t" ] || [ "$vprivate" != "t" ] || [ "$vinv" != "0" ]; then
      echo "[error] 离线包 schema 自检未通过：" >&2
      echo "        已应用迁移=$vact 期望=$vexp ; tenants.industry=$vind 期望=t ; 私网回源字段=$vprivate 期望=t ; 失效索引=$vinv 期望=0" >&2
      vfail=1
    else
      echo "[ok] 包内 schema 自检通过：$vact 个迁移全部应用、industry 和私网回源字段在、0 失效索引"
    fi
  fi

  docker rm -f -v "$vname" >/dev/null 2>&1 || true
  if [ "$vfail" -ne 0 ]; then
    echo "[error] 离线包装机后 schema 不完整 —— 拒绝出包。请检查 migration-runner.sh / migrations / initdb 快照。" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd tar
require_cmd gzip
require_cmd /usr/local/go/bin/go
sh "$TOOLCHAIN_VERIFIER" "$TARGET_ARCH"

# ── 发货前对账单(drift-audit):打包前比对 home 运行态 vs 离线包应产出,提前暴露"home有/包没有"的漂移。
#    软关(只提示不拦);正式运行态验收只能由绑定 candidate SHA 的外部回执表达。
echo "================ 发货前对账单 (drift-audit) ================"
if command -v python3 >/dev/null 2>&1; then
  if python3 "$PROJECT_ROOT/deploy/lib/drift-audit.py"; then
    echo "[对账单] 无结构性漂移"
  else
    echo "[对账单] ⚠ 上方有漂移项,请确认是否预期(继续打包;候选静态/契约门仍会执行)"
  fi
else
  echo "[对账单] 跳过(无 python3)"
fi
echo "=========================================================="

check_release_inputs
check_images
check_portal_image_size
copy_payload
verify_bundle_schema
write_release_notes
write_install_script
write_upgrade_script
write_status_script
write_stop_script
write_diagnose_script
write_readme
verify_task4_provenance
export_images
write_sbom
write_manifest
sign_manifest
run_n_minus_one_gate
write_offline_inventory
pack_bundle
write_archive_handoff
run_candidate_static_gates

echo
echo "[ok] offline deployment package created"
echo "[info] package:  $ARCHIVE_FILE"
echo "[info] checksum: $CHECKSUM_FILE"
echo "[info] handoff:  $HANDOFF_FILE"
echo "[info] publisher handoff evidence: $HANDOFF_FILE / $HANDOFF_SIGNATURE_FILE"
echo "[info] customer flow: verify SHA-256 and run the self-contained x86 .run"
