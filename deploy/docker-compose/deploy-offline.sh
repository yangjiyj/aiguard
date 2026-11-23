#!/bin/sh
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
# 随包 judge 模型灌卷与哈希工具，安装与升级共用同一实现。
. "$SCRIPT_DIR/../lib/judge-model-load.sh"
# 安全读取 .env（逐行按字面解析，不 source，见 deploy/lib/jjd-env.sh）。
if [ ! -f "$SCRIPT_DIR/../lib/jjd-env.sh" ]; then
  echo "[error] 缺少安全读取 .env 的库: $SCRIPT_DIR/../lib/jjd-env.sh" >&2
  exit 1
fi
. "$SCRIPT_DIR/../lib/jjd-env.sh"
cd "$SCRIPT_DIR"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_WRAPPER="$SCRIPT_DIR/compose-wrapper.sh"

export COMPOSE_FILE="$SCRIPT_DIR/docker-compose.offline.yml"
ENV_FILE="$SCRIPT_DIR/.env"
RESULT_FILE="$SCRIPT_DIR/.deploy-result"
MANIFEST_FILE="$SCRIPT_DIR/manifest.json"
RESERVED_PORTS=""
DEPLOY_STARTED=0
DEPLOY_SUCCEEDED=0
FRESH_INSTALL=0

# 仅在从未生成过本发行版配置的首次安装中启用随包 Chat 门户。升级/修复必须
# 保留客户在控制台中明确关闭门户的选择。
if [ ! -e "$ENV_FILE" ]; then
  FRESH_INSTALL=1
fi

cleanup_failed_deploy() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ] && [ "$DEPLOY_STARTED" = "1" ] && [ "$DEPLOY_SUCCEEDED" != "1" ]; then
    # 只停止本次 COMPOSE_PROJECT_NAME 下的容器；保留卷、数据库和容器日志供诊断。
    echo "[error] 离线部署失败，正在停止本次启动的服务（日志和数据卷已保留）" >&2
    sh "$COMPOSE_WRAPPER" stop >/dev/null 2>&1 || true
  fi
  exit "$status"
}

trap cleanup_failed_deploy EXIT HUP INT TERM

stat_file_owner_uid() {
  if stat -c '%u' "$1" 2>/dev/null; then
    return 0
  fi
  stat -f '%u' "$1" 2>/dev/null
}

stat_file_mode() {
  if stat -c '%a' "$1" 2>/dev/null; then
    return 0
  fi
  stat -f '%Lp' "$1" 2>/dev/null
}

secure_env_file() {
  if [ -L "$ENV_FILE" ]; then
    echo "[error] refusing symbolic-link environment file: $ENV_FILE" >&2
    exit 1
  fi
  if [ ! -e "$ENV_FILE" ]; then
    return 0
  fi
  if [ ! -f "$ENV_FILE" ]; then
    echo "[error] environment file must be a regular file: $ENV_FILE" >&2
    exit 1
  fi

  current_uid="$(id -u)"
  owner_uid="$(stat_file_owner_uid "$ENV_FILE")" || {
    echo "[error] unable to verify environment file owner: $ENV_FILE" >&2
    exit 1
  }
  if [ "$owner_uid" != "$current_uid" ]; then
    echo "[error] environment file is not owned by the executing user: $ENV_FILE" >&2
    exit 1
  fi

  chmod 600 "$ENV_FILE" || {
    echo "[error] unable to secure environment file permissions: $ENV_FILE" >&2
    exit 1
  }

  # Re-check after chmod so a changed path is never accepted as a valid secret file.
  if [ -L "$ENV_FILE" ] || [ ! -f "$ENV_FILE" ]; then
    echo "[error] environment file changed during permission validation: $ENV_FILE" >&2
    exit 1
  fi
  verified_owner_uid="$(stat_file_owner_uid "$ENV_FILE")" || exit 1
  verified_mode="$(stat_file_mode "$ENV_FILE")" || exit 1
  if [ "$verified_owner_uid" != "$current_uid" ] || [ "$verified_mode" != "600" ]; then
    echo "[error] environment file failed owner/mode validation: $ENV_FILE" >&2
    exit 1
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[error] missing required command: $1" >&2
    exit 1
  fi
}

require_docker_compose() {
  if ! sh "$COMPOSE_WRAPPER" version >/dev/null 2>&1; then
    echo "[error] Docker Compose v2 is required; bundled fallback not found or not executable" >&2
    exit 1
  fi
}



random_hex() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
    return
  fi
  if command -v od >/dev/null 2>&1; then
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
    printf '\n'
    return
  fi
  echo "[error] missing random generator: openssl or od" >&2
  exit 1
}

random_password() {
  printf 'Jjd#%s!\n' "$(random_hex 6)"
}

port_in_use() {
  port="$1"
  for reserved in $RESERVED_PORTS; do
    if [ "$reserved" = "$port" ]; then
      return 0
    fi
  done
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$port" 2>/dev/null | grep -q ":$port"
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[.:])$port$"
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  return 1
}

allocate_port() {
  var_name="$1"
  port="$2"
  attempts=0
  max_attempts="${OFFLINE_PORT_SEARCH_LIMIT:-200}"
  printf '%s' "$port" | grep -Eq '^[0-9]+$' || {
    echo "[error] invalid starting port for $var_name" >&2; exit 1;
  }
  printf '%s' "$max_attempts" | grep -Eq '^[1-9][0-9]*$' || {
    echo '[error] OFFLINE_PORT_SEARCH_LIMIT must be positive' >&2; exit 1;
  }
  while port_in_use "$port"; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge "$max_attempts" ] || [ "$port" -ge 65535 ]; then
      echo "[error] no free port for $var_name in bounded range starting at $2" >&2
      exit 1
    fi
    port=$((port + 1))
  done
  RESERVED_PORTS="${RESERVED_PORTS} ${port}"
  eval "$var_name=$port"
}

detect_host() {
  if command -v hostname >/dev/null 2>&1; then
    for ip in $(hostname -I 2>/dev/null || true); do
      case "$ip" in
        127.*|169.254.*) ;;
        *)
          printf '%s' "$ip"
          return
          ;;
      esac
    done
  fi
  if command -v ip >/dev/null 2>&1; then
    ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
    return
  fi
  printf '127.0.0.1'
}

detect_hosts() {
  printed=""
  if command -v ip >/dev/null 2>&1; then
    for ip in $(ip -o -4 addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth|virbr)/ {split($4,a,"/"); print a[1]}'); do
      case "$ip" in
        127.*|169.254.*) continue ;;
      esac
      case " $printed " in
        *" $ip "*) continue ;;
      esac
      printed="${printed} ${ip}"
      printf '%s\n' "$ip"
    done
  fi
  if [ -z "$printed" ]; then
    for ip in $(hostname -I 2>/dev/null || true); do
      case "$ip" in
        *.*) ;;
        *) continue ;;
      esac
      case "$ip" in
        127.*|169.254.*) continue ;;
      esac
      case " $printed " in
        *" $ip "*) continue ;;
      esac
      printed="${printed} ${ip}"
      printf '%s\n' "$ip"
    done
  fi
  if [ -z "$printed" ]; then
    printf '127.0.0.1\n'
  fi
}

detect_hosts_csv() {
  hosts="$(detect_hosts | paste -sd, -)"
  printf '%s' "${hosts:-127.0.0.1}"
}

default_external_bind() {
  if [ -n "${JJD_EXTERNAL_BIND:-}" ]; then
    printf '%s' "$JJD_EXTERNAL_BIND"
    return
  fi
  printf '0.0.0.0'
}

append_env_if_missing() {
  key="$1"
  value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

manifest_value() {
  key="$1"
  if [ -f "$MANIFEST_FILE" ]; then
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$MANIFEST_FILE" | head -n 1
  fi
}

verify_extracted_inventory() {
  inventory="$PROJECT_ROOT/offline-inventory.tsv"
  [ -f "$inventory" ] && [ ! -L "$inventory" ] || {
    echo '[error] verified bundle inventory is missing' >&2
    exit 1
  }
  require_cmd base64
  require_cmd stat
  tmp_inventory="$(mktemp -d)"
  rows="$tmp_inventory/rows.tsv"
  expected_paths="$tmp_inventory/expected.paths"
  actual_paths="$tmp_inventory/actual.paths"
  tail -n +2 "$inventory" >"$rows"
  : >"$expected_paths"
  verified_count=0
  tab="$(printf '\t')"
  while IFS="$tab" read -r kind encoded size digest extra; do
    [ "$kind" = file ] && [ -n "$encoded" ] && [ -n "$size" ] && [ -n "$digest" ] && [ -z "$extra" ] || {
      rm -rf "$tmp_inventory"; echo '[error] malformed offline inventory row' >&2; exit 1;
    }
    printf '%s' "$encoded" | grep -Eq '^[A-Za-z0-9_-]+$' || {
      rm -rf "$tmp_inventory"; echo '[error] malformed offline inventory path encoding' >&2; exit 1;
    }
    printf '%s' "$size" | grep -Eq '^(0|[1-9][0-9]*)$' || {
      rm -rf "$tmp_inventory"; echo '[error] malformed offline inventory size' >&2; exit 1;
    }
    printf '%s' "$digest" | grep -Eq '^[0-9a-f]{64}$' || {
      rm -rf "$tmp_inventory"; echo '[error] malformed offline inventory digest' >&2; exit 1;
    }
    padded="$encoded"
    remainder=$((${#padded} % 4))
    case "$remainder" in 0) ;; 2) padded="${padded}==" ;; 3) padded="${padded}=" ;; *) rm -rf "$tmp_inventory"; echo '[error] invalid offline inventory path encoding' >&2; exit 1 ;; esac
    path="$(printf '%s' "$padded" | tr '_-' '/+' | base64 -d 2>/dev/null)" || {
      rm -rf "$tmp_inventory"; echo '[error] offline inventory path decode failed' >&2; exit 1;
    }
    canonical="$(printf '%s' "$path" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
    [ "$canonical" = "$encoded" ] || { rm -rf "$tmp_inventory"; echo '[error] non-canonical offline inventory path' >&2; exit 1; }
    case "$path" in
      ''|/*|*\\*|../*|*/../*|*/..|./*|*/./*|*/.|offline-inventory.tsv|.jjdguard-offline-verified.tsv)
        rm -rf "$tmp_inventory"; echo '[error] unsafe offline inventory path' >&2; exit 1 ;;
    esac
    payload="$PROJECT_ROOT/$path"
    [ -f "$payload" ] && [ ! -L "$payload" ] || { rm -rf "$tmp_inventory"; echo "[error] inventory payload missing: $path" >&2; exit 1; }
    [ "$(stat -c '%s' "$payload")" = "$size" ] || { rm -rf "$tmp_inventory"; echo "[error] inventory size mismatch: $path" >&2; exit 1; }
    [ "$(sha256_file "$payload")" = "$digest" ] || { rm -rf "$tmp_inventory"; echo "[error] inventory checksum mismatch: $path" >&2; exit 1; }
    printf '%s\n' "$path" >>"$expected_paths"
    verified_count=$((verified_count + 1))
  done <"$rows"
  [ "$verified_count" -gt 0 ] || { rm -rf "$tmp_inventory"; echo '[error] offline inventory is empty' >&2; exit 1; }
  if find "$PROJECT_ROOT" -type l -print -quit | grep -q .; then
    rm -rf "$tmp_inventory"; echo '[error] symlink found in verified bundle' >&2; exit 1
  fi
  # 排除清单外的安装期派生文件：offline-inventory.tsv 是清单自身，.jjdguard-offline-verified.tsv
  # 是验证戳，jjdctl 是 installer.sh stage_release 在 deploy 前安装到包根的管理工具副本，
  # .env 是 secure_env_file 已校验的客户运行配置；TLS、部署结果和身份运行凭据
  # 是安装期生成或继承的固定派生文件，重试时必须保留且不计入签名 payload。
  (cd "$PROJECT_ROOT" && find . -type f \
    ! -path './offline-inventory.tsv' \
    ! -path './.jjdguard-offline-verified.tsv' \
    ! -path './jjdctl' \
    ! -path './deploy/docker-compose/.env' \
    ! -path './deploy/docker-compose/.deploy-result' \
    ! -path './deploy/docker-compose/identity-runtime.env' \
    ! -path './deploy/docker-compose/tls/openssl.cnf' \
    ! -path './deploy/docker-compose/tls/web-console.crt' \
    ! -path './deploy/docker-compose/tls/web-console.key' \
    -print | sed 's#^./##' | LC_ALL=C sort) >"$actual_paths"
  LC_ALL=C sort -c -u "$expected_paths" >/dev/null 2>&1 || { rm -rf "$tmp_inventory"; echo '[error] inventory paths are not sorted and unique' >&2; exit 1; }
  cmp -s "$expected_paths" "$actual_paths" || { rm -rf "$tmp_inventory"; echo '[error] extracted bundle file set differs from signed inventory' >&2; exit 1; }
  rm -rf "$tmp_inventory"
}

json_file_value() {
  key="$1"
  file="$2"
  sed -n "s/^[[:space:]]*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*,\?[[:space:]]*$/\1/p" "$file" | head -n 1
}

verify_manifest_chain_shell() {
  manifest="$PROJECT_ROOT/manifest.json"
  compose_manifest="$SCRIPT_DIR/manifest.json"
  source="$PROJECT_ROOT/release-source.json"
  provenance="$PROJECT_ROOT/image-provenance.json"
  sbom="$PROJECT_ROOT/sbom/index.json"
  for file in "$manifest" "$compose_manifest" "$source" "$provenance" "$sbom"; do
    [ -f "$file" ] && [ ! -L "$file" ] || {
      echo "[error] offline manifest chain file is missing: $file" >&2
      return 1
    }
  done
  cmp -s "$manifest" "$compose_manifest" || {
    echo '[error] root and deploy manifests differ' >&2
    return 1
  }

  schema="$(json_file_value schema "$manifest")"
  product="$(json_file_value product "$manifest")"
  version="$(json_file_value version "$manifest")"
  source_revision="$(json_file_value source_revision "$manifest")"
  source_tree="$(json_file_value source_tree "$manifest")"
  image_sha="$(json_file_value image_provenance_sha256 "$manifest")"
  sbom_sha="$(json_file_value sbom_index_sha256 "$manifest")"
  target_arch="$(json_file_value target_arch "$manifest")"
  bundle_profile="$(json_file_value bundle_profile "$manifest")"
  include_chat="$(json_file_value include_chat "$manifest")"
  artifact_stage="$(json_file_value artifact_stage "$manifest")"
  min_data_version="$(json_file_value min_data_version "$manifest")"
  manifest_signature="$(json_file_value manifest_signature "$manifest")"
  built_at="$(json_file_value built_at "$manifest")"
  bundle="$(json_file_value bundle "$manifest")"

  [ "$schema" = offline-manifest/v2 ] || return 1
  case "$product" in
    jjdguard-enterprise) printf '%s' "$bundle" | grep -Eq '^jjdguard-[A-Za-z0-9._-]+$' || return 1 ;;
    agent-platform)
      printf '%s' "$bundle" | grep -Eq '^agent-platform-[A-Za-z0-9._-]+$' || return 1
      [ "$(json_file_value product_profile "$manifest")" = agent-platform ] || return 1
      platform_name="$(json_file_value product_name "$manifest")"
      platform_version="$(json_file_value product_version "$manifest")"
      platform_slug="$(json_file_value product_slug "$manifest")"
      platform_kit_sha="$(json_file_value agent_kit_sha256 "$manifest")"
      printf '%s' "$platform_name" | grep -Eq '^[0-9A-Za-z._ -]+$' || return 1
      printf '%s' "$platform_version" | grep -Eq '^[0-9A-Za-z.-]+$' || return 1
      printf '%s' "$platform_slug" | grep -Eq '^[a-z0-9-]+$' || return 1
      printf '%s' "$platform_kit_sha" | grep -Eq '^[0-9a-f]{64}$' || return 1
      [ -d "$SCRIPT_DIR/agent-kit" ] && [ ! -L "$SCRIPT_DIR/agent-kit" ] || return 1
      # 归档验签时校验 agent_kit_sha256；本机安装继续由签名 inventory 逐文件验哈希。
      ;;
    *) return 1 ;;
  esac
  [ "$version" ] && printf '%s' "$version" | grep -Eq '^[0-9A-Za-z.-]+$' || return 1
  printf '%s' "$source_revision" | grep -Eq '^[0-9a-f]{40}$' || return 1
  printf '%s' "$source_tree" | grep -Eq '^[0-9a-f]{40}$' || return 1
  printf '%s' "$image_sha" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s' "$sbom_sha" | grep -Eq '^[0-9a-f]{64}$' || return 1
  [ "$target_arch" = amd64 ] || [ "$target_arch" = arm64 ] || return 1
  [ "$bundle_profile" = lite ] || [ "$bundle_profile" = full ] || return 1
  [ "$include_chat" = 0 ] || [ "$include_chat" = 1 ] || return 1
  [ "$artifact_stage" = candidate ] || return 1
  [ -f "$SCRIPT_DIR/upgrade-min-data-version" ] || return 1
  [ "$min_data_version" = "$(tr -d '[:space:]' <"$SCRIPT_DIR/upgrade-min-data-version")" ] || return 1
  [ "$manifest_signature" = ed25519-domain-v2 ] || [ "$manifest_signature" = sha256-only ] || return 1
  printf '%s' "$built_at" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || return 1
  printf '%s' "$bundle" | grep -Eq '^(jjdguard|agent-platform)-[A-Za-z0-9._-]+$' || return 1

  [ "$(json_file_value schema "$source")" = jjdguard-release-source/v1 ] || return 1
  [ -n "$(json_file_value remote "$source")" ] || return 1
  [ "$(json_file_value source_revision "$source")" = "$source_revision" ] || return 1
  [ "$(json_file_value source_tree "$source")" = "$source_tree" ] || return 1
  [ "$(sha256_file "$provenance")" = "$image_sha" ] || return 1
  [ "$(sha256_file "$sbom")" = "$sbom_sha" ] || return 1
}

verify_offline_verification_stamp() {
  stamp="$PROJECT_ROOT/.jjdguard-offline-verified.tsv"
  if [ ! -f "$stamp" ] || [ -L "$stamp" ]; then
    if [ "${OFFLINE_ALLOW_UNVERIFIED_ARCHIVE:-0}" = "1" ]; then
      echo '[warn] unverified archive override enabled; this is only permitted for isolated release acceptance' >&2
      return 0
    fi
    echo '[error] archive has not passed the package integrity check' >&2
    echo '[hint] run the self-contained .run installer; it creates the verification stamp before deployment' >&2
    exit 1
  fi
  [ "$(stat -c '%a' "$stamp")" = 400 ] || { echo '[error] verification stamp mode must be 0400' >&2; exit 1; }
  stamp_owner="$(stat -c '%u' "$stamp")"
  if [ "$stamp_owner" != 0 ] && [ "$stamp_owner" != "$(id -u)" ]; then
    echo '[error] verification stamp owner mismatch' >&2; exit 1
  fi
  expected_keys="$(printf '%s\n' schema archive_sha256 handoff_sha256 manifest_sha256 inventory_sha256 source_revision source_tree image_provenance_sha256 sbom_index_sha256 artifact_stage public_key_sha256 verified_files verified_at)"
  actual_keys="$(cut -f1 "$stamp")"
  [ "$actual_keys" = "$expected_keys" ] || { echo '[error] verification stamp is not canonical' >&2; exit 1; }
  stamp_value() { awk -F '\t' -v key="$1" '$1==key {print $2}' "$stamp"; }
  [ "$(stamp_value schema)" = jjdguard-offline-verified/v2 ] || { echo '[error] verification stamp schema mismatch' >&2; exit 1; }
  for key in archive_sha256 handoff_sha256 manifest_sha256 inventory_sha256 image_provenance_sha256 sbom_index_sha256 public_key_sha256; do
    value="$(stamp_value "$key")"
    printf '%s' "$value" | grep -Eq '^[0-9a-f]{64}$' || { echo "[error] invalid verification stamp hash: $key" >&2; exit 1; }
  done
  [ -f "$MANIFEST_FILE" ] && [ -f "$PROJECT_ROOT/manifest.json" ] || { echo '[error] bundle manifests are missing' >&2; exit 1; }
  [ "$(sha256_file "$MANIFEST_FILE")" = "$(stamp_value manifest_sha256)" ] || { echo '[error] deploy manifest differs from verified manifest' >&2; exit 1; }
  [ "$(sha256_file "$PROJECT_ROOT/manifest.json")" = "$(stamp_value manifest_sha256)" ] || { echo '[error] root manifest differs from verified manifest' >&2; exit 1; }
  [ "$(sha256_file "$PROJECT_ROOT/offline-inventory.tsv")" = "$(stamp_value inventory_sha256)" ] || { echo '[error] bundle inventory differs from verified inventory' >&2; exit 1; }
  verify_manifest_chain_shell || { echo '[error] offline manifest chain is invalid' >&2; exit 1; }
  for key in source_revision source_tree image_provenance_sha256 sbom_index_sha256 artifact_stage; do
    [ "$(stamp_value "$key")" = "$(manifest_value "$key")" ] || { echo "[error] verification stamp $key differs from verified manifest" >&2; exit 1; }
  done
  verify_extracted_inventory
  [ "$verified_count" = "$(stamp_value verified_files)" ] || { echo '[error] verified file count mismatch' >&2; exit 1; }
  echo "[ok] self-verified offline archive: files=$verified_count"
}

verify_manifest_signature() {
  verify_offline_verification_stamp
}

normalize_arch() {
  case "$1" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    armv7|armv7l) printf 'armv7' ;;
    *) printf '%s' "$1" ;;
  esac
}

verify_target_arch() {
  expected="$(manifest_value target_arch)"
  if [ -z "$expected" ]; then
    echo "[error] manifest target_arch is missing" >&2
    exit 1
  fi
  actual="$(normalize_arch "$(uname -m)")"
  if [ "$actual" != "$expected" ] && [ "${OFFLINE_ALLOW_ARCH_MISMATCH:-0}" != "1" ]; then
    echo "[error] bundle architecture ($expected) does not match host ($actual)" >&2
    exit 1
  fi
  echo "[ok] bundle architecture: $expected (host=$actual)"
}


default_package_version() {
  version="$(manifest_value version)"
  if [ -z "$version" ] && [ -f "$PROJECT_ROOT/VERSION" ]; then
    version="$(sed -n '1{s/[[:space:]]//g;p;q;}' "$PROJECT_ROOT/VERSION")"
  fi
  printf '%s' "${version:-unknown}"
}

default_built_at() {
  built_at="$(manifest_value built_at)"
  printf '%s' "${built_at:-}"
}

default_commit() {
  commit="$(manifest_value commit)"
  printf '%s' "${commit:-}"
}

ensure_version_defaults() {
  append_env_if_missing JJD_VERSION "$(default_package_version)"
  append_env_if_missing JJD_COMMIT "$(default_commit)"
  append_env_if_missing JJD_BUILT_AT "$(default_built_at)"
}

ensure_platform_defaults() {
  [ "$(manifest_value product)" = agent-platform ] || return 0
  if grep -q '^PRODUCT_PROFILE=' "$ENV_FILE"; then
    [ "$(sed -n 's/^PRODUCT_PROFILE=//p' "$ENV_FILE" | tail -n 1)" = agent-platform ] || {
      echo '[error] existing .env product profile differs from signed platform package' >&2
      exit 1
    }
  fi
  append_env_if_missing PRODUCT_PROFILE agent-platform
  platform_name="$(manifest_value product_name)"
  case "$platform_name" in
    *[!0-9A-Za-z._\ -]*|'') echo '[error] invalid signed platform brand' >&2; exit 1 ;;
  esac
  append_env_if_missing PRODUCT_NAME "'$platform_name'"
  append_env_if_missing PRODUCT_VERSION "$(manifest_value product_version)"
  append_env_if_missing PRODUCT_SLUG "$(manifest_value product_slug)"
}

ensure_license_defaults() {
  # 交付包信任两把公钥:lse-lic-2026(正式授权,客户续费用)+bundle-trial-key(随包 90 天试用)。
  _trialpub=""
  [ -f "$SCRIPT_DIR/license/bundle-trial-pubkey.txt" ] && _trialpub="$(tr -d "\r\n" < "$SCRIPT_DIR/license/bundle-trial-pubkey.txt")"
  _lkeys="lse-lic-2026=WxiAqCV0BUqVnopcPSrOWcVlowUoz1JQtGyEUCZ2f_Y"
  [ -n "$_trialpub" ] && _lkeys="$_lkeys,bundle-trial-key=$_trialpub"
  append_env_if_missing JJD_LICENSE_PUBLIC_KEYS "$_lkeys"
  append_env_if_missing JJD_LICENSE_ENFORCE true
}

ensure_chat_defaults() {
  [ "${BUNDLE_CHAT:-0}" = "1" ] || return 0
  # 读现有值（支持 BYO/重装），并只迁移产品内置的旧默认 realm。
  _chat_host="$(grep '^CHAT_OIDC_HOST=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"; [ -n "$_chat_host" ] || _chat_host="$(detect_host)"
  _chat_idp_port="$(grep '^CHAT_IDP_PORT=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"; [ -n "$_chat_idp_port" ] || _chat_idp_port=8180
  _web_port="$(grep '^WEB_PORT=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"; [ -n "$_web_port" ] || _web_port=3000
  _web_https_port="$(grep '^WEB_HTTPS_PORT=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"; [ -n "$_web_https_port" ] || _web_https_port=443
  _tls_enabled="$(grep '^TLS_ENABLED=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"; [ -n "$_tls_enabled" ] || _tls_enabled=true
  _chat_realm="$(grep '^CHAT_REALM=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"; [ -n "$_chat_realm" ] || _chat_realm=jjdguard
  _existing_issuer="$(grep '^CHAT_OIDC_ISSUER=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  _chat_byo_idp="$(grep '^CHAT_BYO_IDP=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  [ -n "$_chat_byo_idp" ] || _chat_byo_idp="${CHAT_BYO_IDP:-false}"
  _jjd_sso_public="$(grep '^JJD_SSO_PUBLIC_URL=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  [ -n "$_jjd_sso_public" ] || _jjd_sso_public="${JJD_SSO_PUBLIC_URL:-}"
  _ext_bind="$(default_external_bind)"
  case "$_tls_enabled" in
    false|0|no|off)
      if [ "$_web_port" = "80" ]; then
        _web_public="http://${_chat_host}"
      else
        _web_public="http://${_chat_host}:${_web_port}"
      fi
      ;;
    *) _web_public="$(format_https_url "$_chat_host" "$_web_https_port")" ;;
  esac
  _legacy_sso_public="http://${_chat_host}:${_chat_idp_port}"

  if [ "$_chat_realm" = "chat-portal-dev" ]; then
    _chat_realm=jjdguard
    sed -i 's/^CHAT_REALM=chat-portal-dev$/CHAT_REALM=jjdguard/' "$ENV_FILE"
  fi
  case "$_jjd_sso_public" in
    "$_legacy_sso_public"|\
    "http://0.0.0.0:${_chat_idp_port}"|\
    "http://[::]:${_chat_idp_port}") _jjd_sso_public="$_web_public" ;;
  esac
  if [ -z "$_jjd_sso_public" ]; then
    case "$_existing_issuer" in
      "$_legacy_sso_public"/realms/chat-portal-dev|\
      "$_legacy_sso_public"/sso/realms/chat-portal-dev|\
      "$_legacy_sso_public"/sso/realms/jjdguard) _jjd_sso_public="$_web_public" ;;
      */realms/chat-portal-dev) _jjd_sso_public="${_existing_issuer%/realms/chat-portal-dev}" ;;
      *) _jjd_sso_public="$_web_public" ;;
    esac
  fi
  JJD_ENV_FILE="$ENV_FILE" \
  CHAT_OIDC_HOST="$_chat_host" \
  CHAT_IDP_PORT="$_chat_idp_port" \
  JJD_SSO_PUBLIC_URL="$_jjd_sso_public" \
    bash "$SCRIPT_DIR/chat/ensure-public-sso-url.sh" >/dev/null
  _jjd_sso_public="$(grep '^JJD_SSO_PUBLIC_URL=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  _jjd_sso_public="${_jjd_sso_public%/}"

  if grep -q '^JJD_SSO_PUBLIC_URL=$' "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^JJD_SSO_PUBLIC_URL=$|JJD_SSO_PUBLIC_URL=${_jjd_sso_public}|" "$ENV_FILE"
  else
    append_env_if_missing JJD_SSO_PUBLIC_URL "$_jjd_sso_public"
  fi
  case "$_jjd_sso_public" in
    http://*)
      _jjd_allow_insecure=true
      _portal_cookie_secure=false
      ;;
    *)
      _jjd_allow_insecure=false
      _portal_cookie_secure=true
      ;;
  esac
  if grep -q '^JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=$' "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=$/JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=${_jjd_allow_insecure}/" "$ENV_FILE"
  else
    append_env_if_missing JJD_SSO_ALLOW_INSECURE_PUBLIC_URL "$_jjd_allow_insecure"
  fi
  append_env_if_missing PORTAL_COOKIE_SECURE "$_portal_cookie_secure"

  append_env_if_missing CHAT_OIDC_HOST "$_chat_host"
  append_env_if_missing CHAT_IDP_PORT "$_chat_idp_port"
  append_env_if_missing CHAT_REALM "$_chat_realm"
  if [ "$_chat_byo_idp" != "true" ]; then
    # 内置身份引擎必须与唯一公开入口同源。即使升级继承了任意旧 issuer，
    # 也要幂等覆盖，避免 Portal 与 control-plane 的 issuer 校验漂移。
    if grep -q '^CHAT_OIDC_ISSUER=' "$ENV_FILE" 2>/dev/null; then
      sed -i "s|^CHAT_OIDC_ISSUER=.*|CHAT_OIDC_ISSUER=${_jjd_sso_public}/sso/realms/jjdguard|" "$ENV_FILE"
    else
      append_env_if_missing CHAT_OIDC_ISSUER "${_jjd_sso_public}/sso/realms/jjdguard"
    fi
  fi
  if grep -q "^CHAT_PORTAL_UI_OIDC_CLIENT_ID=chat-portal-ui$" "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^CHAT_PORTAL_UI_OIDC_CLIENT_ID=chat-portal-ui$/CHAT_PORTAL_UI_OIDC_CLIENT_ID=enterprise-ai-portal/" "$ENV_FILE"
  fi
  append_env_if_missing CHAT_PORTAL_UI_OIDC_CLIENT_ID enterprise-ai-portal
  append_env_if_missing CHAT_UI_PORT 3100
  append_env_if_missing CHAT_ADMIN_PORT 8280
  append_env_if_missing CHAT_UI_BIND "$_ext_bind"
  append_env_if_missing CHAT_ADMIN_BIND "$_ext_bind"
  append_env_if_missing CHAT_IDP_BIND "$_ext_bind"
  append_env_if_missing CHAT_POSTGRES_DB enterprise_ai_portal
  append_env_if_missing CHAT_POSTGRES_PASSWORD "$(random_hex 24)"
  append_env_if_missing AUTH_SECRET "$(random_hex 32)"
  append_env_if_missing CHAT_PORTAL_UI_OIDC_SECRET "$(random_hex 32)"
  append_env_if_missing PORTAL_INTERNAL_TOKEN "$(random_hex 32)"
  append_env_if_missing PORTAL_KEY_ENC_SECRET "$(random_hex 32)"
  append_env_if_missing PORTAL_OIDC_CLIENT_SECRET "$(random_hex 32)"
  append_env_if_missing KEYCLOAK_ADMIN_PASSWORD "$(random_password)"
  # 网关 portal-integration 通道密钥：chat 包必须非空(否则 /gate 503→整站 fail-closed；portal-proxy 也会 fail-fast)
  if [ -z "$(grep '^JJD_PORTAL_API_SECRET=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)" ]; then
    if grep -q '^JJD_PORTAL_API_SECRET=' "$ENV_FILE" 2>/dev/null; then
      # 值为空(重装/BYO 遗留空行)需原地改写；本脚本仅在 Linux 目标运行(GNU sed -i 语法)。
      sed -i "s|^JJD_PORTAL_API_SECRET=.*|JJD_PORTAL_API_SECRET=$(random_hex 32)|" "$ENV_FILE"
    else
      append_env_if_missing JJD_PORTAL_API_SECRET "$(random_hex 32)"
    fi
  fi
}

validate_chat_env() {
  [ "${BUNDLE_CHAT:-0}" = "1" ] || return 0
  # chat 通道密钥恒须非空（自带/BYO 都要）
  if [ -z "${JJD_PORTAL_API_SECRET:-}" ]; then
    echo "[error] chat 包缺 JJD_PORTAL_API_SECRET（门户通道密钥），/gate 将恒 fail-closed" >&2
    echo "[hint] 请检查 .env 的 JJD_PORTAL_API_SECRET 是否被误删/置空，或重跑本脚本自动生成" >&2
    exit 1
  fi
  if [ "${CHAT_BYO_IDP:-false}" = "true" ]; then
    _missing=""
    for k in CHAT_OIDC_ISSUER CHAT_PORTAL_UI_OIDC_CLIENT_ID CHAT_PORTAL_UI_OIDC_SECRET; do
      eval "_v=\${$k:-}"; [ -z "$_v" ] && _missing="$_missing $k"
    done
    if [ -n "$_missing" ]; then
      echo "[error] CHAT_BYO_IDP=true 但缺客户 IdP 必配:$_missing" >&2
      echo "[hint] 自带 IdP 时须在 .env 提供 issuer 与 chat-portal-ui client 凭据" >&2
      exit 1
    fi
  fi
}

prepare_chat_identity_mounts() {
  [ "${BUNDLE_CHAT:-0}" = "1" ] || return 0
  [ "${CHAT_BYO_IDP:-false}" = "true" ] && return 0
  sh "$SCRIPT_DIR/lib-identity-mounts.sh" "$SCRIPT_DIR"
}

# control-plane 无条件挂载共享 CA 目录（目录预览的 LDAPS 信任根），
# base 包也必须有这份目录：缺失时 compose 会现场建一个 root 拥有的空目录，
# 能跑但出厂状态不可复现，运维也不知道该往哪放 CA。
ensure_directory_truststore() {
  truststore_dir="$SCRIPT_DIR/directory-truststore"
  if [ -L "$truststore_dir" ]; then
    echo "[error] directory truststore path must not be a symlink" >&2
    exit 1
  fi
  mkdir -p "$truststore_dir"
  chmod 0755 "$truststore_dir"
}

ensure_hardening_defaults() {
  external_bind="$(default_external_bind)"
  append_env_if_missing WEB_BIND "$external_bind"
  append_env_if_missing WEB_HTTPS_BIND "$external_bind"
  append_env_if_missing GATEWAY_BIND "$external_bind"
  append_env_if_missing PROXY_BIND "$external_bind"
  append_env_if_missing FORWARD_PROXY_BIND "$external_bind"
  append_env_if_missing CONTROL_BIND 127.0.0.1
  append_env_if_missing SECURITY_BIND 127.0.0.1
  append_env_if_missing POSTGRES_BIND 127.0.0.1
  append_env_if_missing REDIS_BIND 127.0.0.1
  append_env_if_missing REDIS_PASSWORD "$(random_hex 32)"
  append_env_if_missing JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY "$(random_hex 32)"
  append_env_if_missing MCP_CONFIRMATION_SCOPE_SECRET "$(random_hex 32)"
  append_env_if_missing JJD_TIER1_INTERNAL_TOKEN "$(random_hex 32)"
  append_env_if_missing JJD_RULE_PACK_ATTESTATION_TENANT tenant_default
  if ! grep -q '^JJD_RULE_PACK_ATTESTATION_TOKEN=' "$ENV_FILE"; then
    append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$(random_hex 32)"
  fi
  append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKENS_JSON ""
}

ensure_https_defaults() {
  host_addrs="$(detect_hosts_csv)"
  if ! grep -q '^WEB_HTTPS_PORT=' "$ENV_FILE"; then
    allocate_port WEB_HTTPS_PORT 443
    append_env_if_missing WEB_HTTPS_PORT "$WEB_HTTPS_PORT"
  fi
  append_env_if_missing TLS_ENABLED true
  append_env_if_missing TLS_CERT_HOSTS "localhost,127.0.0.1,$host_addrs"
}

format_https_url() {
  host="$1"
  port="$2"
  if [ "$port" = "443" ]; then
    printf 'https://%s' "$host"
  else
    printf 'https://%s:%s' "$host" "$port"
  fi
}

derive_project_name() {
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    printf '%s' "$COMPOSE_PROJECT_NAME"
    return
  fi
  root_base="$(basename "$PROJECT_ROOT")"
  if [ "$root_base" = "newapi-enterprise-local" ]; then
    base="$(basename "$(dirname "$PROJECT_ROOT")")"
  else
    base="$root_base"
  fi
  base="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')"
  base="${base#-}"
  base="${base%-}"
  if [ -z "$base" ]; then
    base="jjdguard"
  fi
  printf '%s' "$base"
}

ensure_env() {
  if [ -e "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
    secure_env_file
    ensure_platform_defaults
    return
  fi

  allocate_port WEB_PORT 3000
  allocate_port WEB_HTTPS_PORT 443
  allocate_port GATEWAY_PORT 8080
  allocate_port PROXY_PORT 8082
  allocate_port CONTROL_PORT 8081
  allocate_port SECURITY_PORT 8000
  allocate_port FORWARD_PROXY_PORT 3128
  allocate_port POSTGRES_PORT 5432
  allocate_port REDIS_PORT 6379
  SECRET_KEY="$(random_hex 32)"
  INTERNAL_SECRET="$(random_hex 32)"
  RULE_PACK_ATTESTATION_TOKEN="$(random_hex 32)"
  AUDIT_HMAC_KEY="$(random_hex 32)"
  ADMIN_PASSWORD="$(random_password)"
  POSTGRES_PASSWORD="$(random_hex 24)"
  REDIS_PASSWORD="$(random_hex 32)"
  EXTERNAL_BIND="$(default_external_bind)"

  if ! (
    set -C
    cat >"$ENV_FILE" <<EOF
JJD_PROVIDER_SECRET_KEY=$SECRET_KEY
UAG_AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY
JJD_INTERNAL_API_SECRET=$INTERNAL_SECRET
JJD_RULE_PACK_ATTESTATION_TENANT=tenant_default
JJD_RULE_PACK_ATTESTATION_TOKEN=$RULE_PACK_ATTESTATION_TOKEN
JJD_RULE_PACK_ATTESTATION_TOKENS_JSON=
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_EMAIL=admin@local
BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD
WEB_PORT=$WEB_PORT
WEB_HTTPS_PORT=$WEB_HTTPS_PORT
WEB_BIND=$EXTERNAL_BIND
WEB_HTTPS_BIND=$EXTERNAL_BIND
GATEWAY_PORT=$GATEWAY_PORT
PROXY_PORT=$PROXY_PORT
GATEWAY_BIND=$EXTERNAL_BIND
PROXY_BIND=$EXTERNAL_BIND
CONTROL_PORT=$CONTROL_PORT
SECURITY_PORT=$SECURITY_PORT
FORWARD_PROXY_PORT=$FORWARD_PROXY_PORT
FORWARD_PROXY_BIND=$EXTERNAL_BIND
POSTGRES_PORT=$POSTGRES_PORT
REDIS_PORT=$REDIS_PORT
CONTROL_BIND=127.0.0.1
SECURITY_BIND=127.0.0.1
POSTGRES_BIND=127.0.0.1
REDIS_BIND=127.0.0.1
REDIS_PASSWORD=$REDIS_PASSWORD
GATEWAY_ENVIRONMENT_SCOPE=customer
SECURITY_AUDIT_ONLY=false
SECURITY_PII_CHECKSUM_ENABLED=true
BILLING_ENABLED=true
BILLING_MODE=metering
TLS_ENABLED=true
TLS_CERT_HOSTS=localhost,127.0.0.1,$(detect_hosts_csv)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DEFAULT_PROVIDER_NAME=
DEFAULT_PROVIDER_TYPE=openai
DEFAULT_PROVIDER_BASE_URL=
DEFAULT_PROVIDER_API_KEY=
DEFAULT_KEY_PROJECT_ID=project_default
DEFAULT_KEY_USER_ID=user_admin
DEFAULT_KEY_SCOPES=["chat","responses","embeddings","models"]
JJD_VERSION=$(default_package_version)
JJD_COMMIT=$(default_commit)
JJD_BUILT_AT=$(default_built_at)
POSTGRES_USER=jjdguard
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=jjdguard
EOF
  ); then
    echo "[error] unable to create a new regular environment file: $ENV_FILE" >&2
    exit 1
  fi
  secure_env_file
  ensure_version_defaults
  ensure_platform_defaults
  ensure_license_defaults
  echo "[ok] generated .env automatically"
}

recover_pending_install_ports() {
  [ ! -f "$RESULT_FILE" ] || return 0
  RESERVED_PORTS=""
  own_ports="$(docker ps --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" --format '{{.Ports}}' 2>/dev/null || true)"
  changed=0
  for var_name in WEB_PORT WEB_HTTPS_PORT GATEWAY_PORT PROXY_PORT CONTROL_PORT SECURITY_PORT FORWARD_PROXY_PORT POSTGRES_PORT REDIS_PORT; do
    port="$(sed -n "s/^${var_name}=\([0-9][0-9]*\)$/\1/p" "$ENV_FILE" | tail -n 1)"
    [ -n "$port" ] || continue
    if port_in_use "$port" && ! printf '%s\n' "$own_ports" | grep -Eq "[:.]$port->"; then
      next=$((port + 1))
      allocate_port replacement "$next"
      tmp="$(mktemp "$SCRIPT_DIR/.env.ports.XXXXXX")"
      awk -v key="$var_name" -v value="$replacement" -F= '
        BEGIN { OFS="=" }
        $1 == key { print key,value; next }
        { print }
      ' "$ENV_FILE" >"$tmp"
      chmod 0600 "$tmp"
      mv -f "$tmp" "$ENV_FILE"
      echo "[warn] 首装重试发现端口竞态：$var_name $port -> $replacement" >&2
      changed=1
    fi
  done
  [ "$changed" -eq 0 ] || secure_env_file
}

load_env() {
  # 不能 source .env（含空格的未加引号值会被当命令执行），经 deploy/lib/jjd-env.sh 按字面读取并 export。
  jjd_load_env_file "$ENV_FILE" || return 1
  WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-443}"
  PROXY_PORT="${PROXY_PORT:-8082}"
  FORWARD_PROXY_PORT="${FORWARD_PROXY_PORT:-3128}"
  TLS_ENABLED="${TLS_ENABLED:-true}"
  TLS_CERT_HOSTS="${TLS_CERT_HOSTS:-localhost,127.0.0.1,$(detect_hosts_csv)}"
  WEB_BIND="${WEB_BIND:-0.0.0.0}"
  WEB_HTTPS_BIND="${WEB_HTTPS_BIND:-0.0.0.0}"
  GATEWAY_BIND="${GATEWAY_BIND:-0.0.0.0}"
  PROXY_BIND="${PROXY_BIND:-0.0.0.0}"
  FORWARD_PROXY_BIND="${FORWARD_PROXY_BIND:-0.0.0.0}"
  CONTROL_BIND="${CONTROL_BIND:-127.0.0.1}"
  SECURITY_BIND="${SECURITY_BIND:-127.0.0.1}"
  POSTGRES_BIND="${POSTGRES_BIND:-127.0.0.1}"
  REDIS_BIND="${REDIS_BIND:-127.0.0.1}"
  JJD_VERSION="${JJD_VERSION:-$(default_package_version)}"
  JJD_COMMIT="${JJD_COMMIT:-$(default_commit)}"
  JJD_BUILT_AT="${JJD_BUILT_AT:-$(default_built_at)}"
  export WEB_HTTPS_PORT PROXY_PORT FORWARD_PROXY_PORT TLS_ENABLED TLS_CERT_HOSTS
  export WEB_BIND WEB_HTTPS_BIND GATEWAY_BIND PROXY_BIND FORWARD_PROXY_BIND CONTROL_BIND SECURITY_BIND POSTGRES_BIND REDIS_BIND
  export JJD_VERSION JJD_COMMIT JJD_BUILT_AT
}

load_images() {
  IMAGE_ARCHIVE="${OFFLINE_IMAGE_ARCHIVE:-}"
  if [ -z "$IMAGE_ARCHIVE" ]; then
    IMAGE_ARCHIVE="$(ls -1 "$SCRIPT_DIR"/offline-artifacts/jjdguard-offline-images-*.tar.gz 2>/dev/null | tail -n 1 || true)"
  fi
  if [ -z "$IMAGE_ARCHIVE" ] || [ ! -f "$IMAGE_ARCHIVE" ]; then
    echo "[error] offline image archive not found" >&2
    echo "[hint] place jjdguard-offline-images-*.tar.gz under deploy/docker-compose/offline-artifacts" >&2
    exit 1
  fi

  CHECKSUM_FILE="${IMAGE_ARCHIVE}.sha256"
  if [ -f "$CHECKSUM_FILE" ]; then
    echo "[step] verifying image archive checksum"
    expected="$(awk '{print $1}' "$CHECKSUM_FILE")"
    actual="$(sha256_file "$IMAGE_ARCHIVE")"
    if [ "$expected" != "$actual" ]; then
      echo "[error] image archive checksum mismatch" >&2
      echo "[info] expected: $expected" >&2
      echo "[info] actual:   $actual" >&2
      exit 1
    fi
  else
    echo "[warn] checksum file not found for image archive: $CHECKSUM_FILE" >&2
  fi

  echo "[step] loading offline images from $IMAGE_ARCHIVE"
  gzip -dc "$IMAGE_ARCHIVE" | docker load
}


# PostgreSQL 官方镜像首次初始化时会短暂启动一个临时 server；此时 pg_isready
# 可能成功，但 entrypoint 随后会主动 shutdown 并切换到 PID 1 的正式 postgres。
# 必须等正式主进程接管后再 bootstrap，避免撞上初始化切换窗口。
wait_postgres_main_process_ready() {
  attempts="${JJD_POSTGRES_STABLE_ATTEMPTS:-60}"
  interval="${JJD_POSTGRES_STABLE_INTERVAL:-2}"
  case "$attempts" in *[!0-9]*|'') attempts=60 ;; esac
  case "$interval" in *[!0-9]*|'') interval=2 ;; esac
  [ "$attempts" -gt 0 ] || attempts=60

  current=1
  while [ "$current" -le "$attempts" ]; do
    main_process="$(
      sh "$COMPOSE_WRAPPER" exec -T postgres sh -c 'cat /proc/1/comm' 2>/dev/null |
        tr -d '[:space:]' || true
    )"
    if [ "$main_process" = "postgres" ] &&
      sh "$COMPOSE_WRAPPER" exec -T postgres \
        pg_isready -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" >/dev/null 2>&1; then
      echo "[ok] PostgreSQL stable main process is ready"
      return 0
    fi
    [ "$current" -eq "$attempts" ] || sleep "$interval"
    current=$((current + 1))
  done

  echo "[error] PostgreSQL initialization did not reach stable main process" >&2
  return 1
}

wait_service_ready() {
  service="$1"
  attempts="${JJD_SERVICE_READY_ATTEMPTS:-180}"
  interval="${JJD_SERVICE_READY_INTERVAL:-2}"
  case "$attempts" in *[!0-9]*|'') attempts=180 ;; esac
  case "$interval" in *[!0-9]*|'') interval=2 ;; esac
  [ "$attempts" -gt 0 ] || attempts=180

  current=1
  while [ "$current" -le "$attempts" ]; do
    container="$(sh "$COMPOSE_WRAPPER" ps -q "$service" 2>/dev/null | head -n 1 || true)"
    if [ -n "$container" ]; then
      state="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container" 2>/dev/null || true)"
      case "$state" in
        "running healthy"|"running ")
          echo "[ok] service $service is ready"
          return 0
          ;;
        "exited "*|"dead "*)
          echo "[error] service $service stopped: $state" >&2
          docker logs --tail 80 "$container" >&2 2>/dev/null || true
          return 1
          ;;
      esac
    fi
    [ "$current" -eq "$attempts" ] || sleep "$interval"
    current=$((current + 1))
  done

  echo "[error] service $service did not become ready within $((attempts * interval))s" >&2
  if [ -n "${container:-}" ]; then
    docker inspect --format '{{json .State}}' "$container" >&2 2>/dev/null || true
    docker logs --tail 80 "$container" >&2 2>/dev/null || true
  fi
  return 1
}

wait_active_services() {
  services="postgres redis redis-cache control-plane gateway-core security-engine proxy-server web-console worker"
  if [ "$BUNDLE_PROFILE" = "full" ]; then
    services="$services llm-judge tier1-classifier"
  fi
  if [ "$BUNDLE_CHAT" = "1" ]; then
    services="$services chat-postgres chat-portal-proxy chat-portal-ui chat-idp chat-edge"
  fi
  for service in $services; do
    wait_service_ready "$service"
  done
}

write_result() {
  HOST_ADDR="$(detect_host)"
  HOST_ADDRS="$(detect_hosts_csv)"
  cat >"$RESULT_FILE" <<EOF
WEB_URLS=$(for h in $(printf '%s' "$HOST_ADDRS" | tr ',' ' '); do printf '%s ' "$(format_https_url "$h" "$WEB_HTTPS_PORT")"; done | awk '{$1=$1; print}')
WEB_URL=$(format_https_url "$HOST_ADDR" "$WEB_HTTPS_PORT")
WEB_HTTP_REDIRECT_URL=http://$HOST_ADDR:$WEB_PORT
TLS_CERT_FILE=$SCRIPT_DIR/tls/web-console.crt
GATEWAY_URLS=$(for h in $(printf '%s' "$HOST_ADDRS" | tr ',' ' '); do printf 'http://%s:%s ' "$h" "$GATEWAY_PORT"; done | awk '{$1=$1; print}')
GATEWAY_URL=http://$HOST_ADDR:$GATEWAY_PORT
REVERSE_PROXY_URL=http://$HOST_ADDR:$PROXY_PORT
CONTROL_URL=http://127.0.0.1:$CONTROL_PORT
SECURITY_URL=http://127.0.0.1:$SECURITY_PORT
FORWARD_PROXY_URL=http://$HOST_ADDR:$FORWARD_PROXY_PORT
BOOTSTRAP_ADMIN_USERNAME=$BOOTSTRAP_ADMIN_USERNAME
ADMIN_CREDENTIALS_FILE=$ENV_FILE
ENV_FILE=$ENV_FILE
COMPOSE_FILE=$COMPOSE_FILE
EOF
  if [ "${BUNDLE_CHAT:-0}" = "1" ]; then
    _result_public="$(grep '^JJD_SSO_PUBLIC_URL=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
    _result_public="${_result_public%/}"
    printf 'CHAT_URL=%s/chat\nPORTAL_ADMIN_URL=%s/portal\nSSO_URL=%s/sso\n' \
      "$_result_public" "$_result_public" "$_result_public" >>"$RESULT_FILE"
  fi
}

seed_public_base_url() {
  # 私有化部署:首次部署把探测到的主网关地址预填进控制台「对外调用地址」(gateway_public_base_url),
  # 让密钥管理页的接入说明开箱即显示客户自己服务器的地址。
  # 已存在则保留(ON CONFLICT DO NOTHING),绝不覆盖客户在「系统管理」里手填的值。
  _seed_host="$(detect_host)"
  if [ -z "$_seed_host" ]; then
    echo "[warn] skip seeding gateway_public_base_url: host not detected" >&2
    return 0
  fi
  _seed_base="http://$_seed_host:${GATEWAY_PORT:-8080}/v1"
  echo "[step] seeding console call address (gateway_public_base_url=$_seed_base)"
  # Only a newly seeded default chooses host-following mode. Existing customer
  # domains and explicit address modes remain untouched on reinstall/upgrade.
  printf "WITH seeded_base AS (INSERT INTO system_settings (key, value, updated_at) VALUES ('gateway_public_base_url', '%s', NOW()) ON CONFLICT (key) DO NOTHING RETURNING key) INSERT INTO system_settings (key, value, updated_at) SELECT 'gateway_public_url_mode', 'current_host', NOW() FROM seeded_base ON CONFLICT (key) DO NOTHING;\n" "$_seed_base" \
    | sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 \
    || echo "[warn] failed to seed gateway_public_base_url (non-fatal)" >&2
}

secure_env_file
require_cmd docker
require_cmd gzip
require_docker_compose
verify_manifest_signature
verify_target_arch

export COMPOSE_PROJECT_NAME="$(derive_project_name)"
ensure_env
recover_pending_install_ports

# jjdctl / systemd 后续管理只读 .env；必须把派生的 compose 项目名持久化进去，
# 否则 compose 默认项目名(docker-compose)会另起一套重复栈与装机栈端口互撞。
if ! grep -q '^COMPOSE_PROJECT_NAME=' "$ENV_FILE" 2>/dev/null; then
  printf 'COMPOSE_PROJECT_NAME=%s\n' "$COMPOSE_PROJECT_NAME" >>"$ENV_FILE"
fi

# 包类型自描述：随包带 GGUF = full（激活 llm-judge profile），否则 lite。
if [ -f "$SCRIPT_DIR/models/$GGUF_NAME" ]; then
  BUNDLE_PROFILE=full
  export COMPOSE_PROFILES=full
  echo "[info] 检测到随包 GGUF —— full 包，启用 llm-judge"
  sh "$SCRIPT_DIR/judge-resource-autotune.sh" "$ENV_FILE"
  sh "$SCRIPT_DIR/engine-resource-autotune.sh" "$ENV_FILE"
else
  BUNDLE_PROFILE=lite
fi

# chat 自描述：包内带 chat 载荷目录 = chat 包，追加 chat profile（叠加现有 lite/full）。
# chat-idp 默认叠加（自带 keycloak）；.env 里 CHAT_BYO_IDP=true 则不叠（客户自带 IdP）。
BUNDLE_CHAT=0
if [ -d "$SCRIPT_DIR/chat" ]; then
  BUNDLE_CHAT=1
  COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}chat"
  if [ "$(grep -E '^CHAT_BYO_IDP=true' "$ENV_FILE" 2>/dev/null || true)" = "" ]; then
    COMPOSE_PROFILES="${COMPOSE_PROFILES},chat-idp"
  fi
  export COMPOSE_PROFILES
fi

# jjdctl 与 systemd 只会重新读取 .env，不能继承本次安装进程的 export。
# 把包自描述推导出的 profile 持久化，否则主机重启或 `jjdctl start` 会只拉起
# 无 profile 的基础服务，chat-edge / chat-idp 等门户服务静默缺失。
if [ -n "${COMPOSE_PROFILES:-}" ]; then
  if grep -q '^COMPOSE_PROFILES=' "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=${COMPOSE_PROFILES}/" "$ENV_FILE"
  else
    printf 'COMPOSE_PROFILES=%s\n' "$COMPOSE_PROFILES" >>"$ENV_FILE"
  fi
  echo "[info] 持久化离线包 profiles (COMPOSE_PROFILES=$COMPOSE_PROFILES)"
fi

ensure_hardening_defaults
ensure_https_defaults
ensure_version_defaults
ensure_platform_defaults
ensure_license_defaults
ensure_chat_defaults
load_env
validate_chat_env
prepare_chat_identity_mounts
ensure_directory_truststore
load_images

# 已扩容的存量安装再次执行装机脚本时，必须沿用 tier1-scale.sh --apply 记录的拓扑：
# 否则会退回基础 compose 的单副本形态，GPU 机器静默掉回 CPU 推理。
TIER1_TOPO_OVERLAY_ARG=""
TIER1_TOPO_SCALE_ARG=""
TIER1_TOPOLOGY_LIB="$SCRIPT_DIR/tier1-topology.sh"
if [ -r "$TIER1_TOPOLOGY_LIB" ]; then
  . "$TIER1_TOPOLOGY_LIB"
  case "$SCRIPT_DIR" in
    *[[:space:]]*)
      echo "[error] the deploy directory must not contain whitespace: $SCRIPT_DIR" >&2
      exit 1
      ;;
  esac
  TIER1_TOPO_MODE="$(tier1_scale_mode "$ENV_FILE")" || {
    echo "[error] TIER1_SCALE_MODE in $ENV_FILE must be empty, cpu or gpu" >&2
    exit 1
  }
  if [ -n "$TIER1_TOPO_MODE" ]; then
    TIER1_TOPO_REPLICAS="$(tier1_replicas "$ENV_FILE")" || {
      echo "[error] TIER1_REPLICAS in $ENV_FILE must be 1..32" >&2
      exit 1
    }
    TIER1_TOPO_OVERLAY="$(tier1_scale_overlay "$SCRIPT_DIR" "$TIER1_TOPO_MODE")"
    if [ ! -f "$TIER1_TOPO_OVERLAY" ] || [ -L "$TIER1_TOPO_OVERLAY" ]; then
      echo "[error] missing Tier-1 overlay for TIER1_SCALE_MODE=$TIER1_TOPO_MODE: $TIER1_TOPO_OVERLAY" >&2
      exit 1
    fi
    if [ "$TIER1_TOPO_MODE" = gpu ]; then
      if ! tier1_gpu_preflight "$(tier1_env_value "$ENV_FILE" TIER1_GPU_IMAGE)"; then
        echo "[error] GPU Tier-1 preflight failed; fix the GPU stack, or run tier1-scale.sh reset --apply to return to CPU" >&2
        exit 1
      fi
    fi
    # Both files must be passed: an explicit -f makes Compose ignore COMPOSE_FILE.
    TIER1_TOPO_OVERLAY_ARG="-f $COMPOSE_FILE -f $TIER1_TOPO_OVERLAY"
    TIER1_TOPO_SCALE_ARG="--scale tier1-classifier=$TIER1_TOPO_REPLICAS"
    echo "[step] restoring Tier-1 topology: mode=$TIER1_TOPO_MODE replicas=$TIER1_TOPO_REPLICAS"
  fi
elif grep -q '^TIER1_SCALE_MODE=.' "${ENV_FILE:-}" 2>/dev/null; then
  # 共享库不在但 .env 记录了扩容拓扑：这是不完整的离线包，装下去就会悄悄退回单副本/CPU。
  echo "[error] $ENV_FILE records TIER1_SCALE_MODE but $TIER1_TOPOLOGY_LIB is missing; the offline bundle is incomplete" >&2
  exit 1
fi

if [ "$BUNDLE_PROFILE" = "full" ]; then
  echo "[step] full 包：装载语义裁判模型到命名卷"
  load_judge_model
fi

echo "[step] preparing web console TLS certificate"
sh ./ensure-web-tls.sh

# Portal↔control-plane 隔离网络在 compose 里声明为 external:true，compose 不会自动创建。
# 部分 Docker Compose 版本在执行 up 时会校验整个 compose 模型引用的外部网络是否存在，
# 全新机器上该网络尚未创建 → 连 up postgres redis 都会直接报 network not found 中断装机。
# 因此必须在首次 compose up 之前幂等创建（ensure 脚本检测到已存在会直接放行）。
echo "[step] ensuring isolated Portal-to-control-plane network"
bash "$SCRIPT_DIR/ensure-jjdguard-portal-cp-network.sh" --name "${JJD_PORTAL_CP_NETWORK:-jjdguard-portal-control-net}" --owner jjdguard

echo "[step] starting database services first (postgres/redis/redis-cache)"
# 先起 DB 层并等健康，再迁移，最后起应用服务：避免整栈并发起时 control-plane 抢在
# postgres 尚未接受 TCP 前连库失败→不健康→装机中断；也保证应用服务面对已迁移到最新的 schema。
DEPLOY_STARTED=1
sh "$COMPOSE_WRAPPER" up -d postgres redis redis-cache
wait_postgres_main_process_ready

echo "[step] bootstrapping base schema (manual psql -f /bootstrap)"
# docker-entrypoint-initdb.d 直跑 001_init_enterprise.sql 会只建到 001 就停(入口点执行方式与 psql -f 不同,
# 实测残缺 13 表→迁移基线失败→装机中断)。故 initdb 改挂 /bootstrap(入口点不自跑),起库后手动 psql -f
# (实测建全 33 表+种子),再由 migrate-private 基线并施加其余迁移。仅空库(无 tenants 表)执行,幂等;升级走 upgrade.sh。
if [ "$(sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -tAc "SELECT to_regclass('public.tenants') IS NOT NULL" 2>/dev/null | tr -d "[:space:]")" != "t" ]; then
  sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 -f /bootstrap/001_init_enterprise.sql
  # This marker is written only for a database created by this installer. It
  # survives an interrupted first run, while upgrades never acquire it.
  printf "INSERT INTO system_settings(key,value,updated_at) VALUES('fresh_onboarding_generation','v1:pending',NOW()) ON CONFLICT (key) DO NOTHING;\n" \
    | sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 >/dev/null
fi

echo "[step] applying private migrations"
sh ./migrate-private.sh

ONBOARDING_FRESH_MARKER="$(sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -tAc "SELECT value FROM system_settings WHERE key='fresh_onboarding_generation'" 2>/dev/null | tr -d '[:space:]')"
if [ "$BUNDLE_CHAT" = "1" ] && [ -n "$ONBOARDING_FRESH_MARKER" ]; then
  echo "[step] arming first-admin enterprise initialization"
  printf "INSERT INTO deployment_initializations(tenant_id,initialization_key,status,fresh_install) SELECT id,'enterprise_chat_defaults_v1','pending',TRUE FROM tenants WHERE id <> 'tenant_system' ON CONFLICT (tenant_id,initialization_key) DO NOTHING; UPDATE system_settings SET value='v1:registered',updated_at=NOW() WHERE key='fresh_onboarding_generation';\n" \
    | sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 >/dev/null
fi

# Chat 包向客户交付的是可直接访问的员工门户；迁移中的 fail-closed 默认值只
# 适用于未随包交付门户的部署。仅首次安装写入，后续升级不改客户设置。
if [ "$BUNDLE_CHAT" = "1" ] && [ -n "$ONBOARDING_FRESH_MARKER" ]; then
  echo "[step] enabling bundled Chat / SSO portal for first installation"
  printf "UPDATE system_settings SET value='true', updated_at=NOW() WHERE key='chat_portal_enabled';\n" \
    | sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 >/dev/null
fi

# 首装自带试用授权:把随包 90 天 trial license 灌进 system_settings(control-plane 读库校验,
# JJD_LICENSE_PUBLIC_KEYS 已含 bundle-trial-key 公钥)。仅当尚无 license 时灌,幂等,不覆盖客户后续导入的正式 license。
if [ -f "$SCRIPT_DIR/license/trial-license.json" ]; then
  _lhave="$(sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -tAc "SELECT count(*) FROM system_settings WHERE key='enterprise_license'" 2>/dev/null | tr -d '[:space:]')"
  if [ "${_lhave:-0}" = "0" ]; then
    _lnow="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    { printf "INSERT INTO system_settings(key,value,updated_at) VALUES('enterprise_license', \$LIC\$"; cat "$SCRIPT_DIR/license/trial-license.json"; printf "\$LIC\$, NOW()) ON CONFLICT (key) DO NOTHING;\nINSERT INTO system_settings(key,value,updated_at) VALUES('enterprise_license_imported_at', '%s', NOW()) ON CONFLICT (key) DO NOTHING;\n" "$_lnow"; } | sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 >/dev/null \
      && echo "[step] 随包 90 天试用授权已灌入(system_settings.enterprise_license)"
  fi
fi

# 宿主机诊断采集器：必须在应用服务启动前写好 .env 里的 DIAG_AGENT_HMAC_KEY，
# 这样首次 up -d 创建的 control-plane 直接带上；失败只告警，不影响装机。
install_diag_agent() {
  _diag_dir="$SCRIPT_DIR/../diag-agent"
  [ "${JJD_SKIP_DIAG_AGENT:-0}" = 1 ] && return 0
  [ -x "$_diag_dir/install-diag-agent.sh" ] && [ -x "$_diag_dir/jjdguard-diag-agent" ] || return 0
  echo "[step] 安装宿主机诊断采集器"
  if ! sh "$_diag_dir/install-diag-agent.sh" --deploy-dir "$SCRIPT_DIR" --binary "$_diag_dir/jjdguard-diag-agent"; then
    echo "[warn] 诊断采集器安装失败（不影响部署）；可稍后手动执行 $_diag_dir/install-diag-agent.sh --deploy-dir $SCRIPT_DIR" >&2
  fi
  return 0
}
install_diag_agent

echo "[step] starting offline services"
# shellcheck disable=SC2086  # overlay args are validated above (no whitespace, existing files)
sh "$COMPOSE_WRAPPER" $TIER1_TOPO_OVERLAY_ARG up -d $TIER1_TOPO_SCALE_ARG
wait_active_services

seed_public_base_url

# full 包：语义裁判性能自适应。CPU 强弱差异大，实测真实裁判路径后按档调整执行超时，
# 避免弱 CPU 上语义分析全 fail-open 失效。检测阈值保持不变；客户手配值不会被升级覆盖。lite 包跳过。
if [ "$BUNDLE_PROFILE" = "full" ]; then
  echo "[step] running judge performance benchmark (adaptive timeout)"
  sh ./judge-benchmark.sh
fi

echo "[step] initializing runtime defaults"
sh ./bootstrap-runtime.sh

# 内置身份引擎的管理面永不对外；只在容器网络内创建最小权限编排账号。
if [ "${BUNDLE_CHAT:-0}" = "1" ] && ! grep -qE '^CHAT_BYO_IDP=true' "$ENV_FILE" 2>/dev/null; then
  echo "[step] initializing JJDGuard enterprise SSO runtime"
  JJD_ENV_FILE="$ENV_FILE" \
  IDENTITY_RUNTIME_ENV_FILE="$SCRIPT_DIR/identity-runtime.env" \
  COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    bash ./chat/bootstrap-identity-runtime.sh
  # 目录发布/同步用的是另一个最小权限服务账号，凭据写进同一个 0600 文件。
  # 必须在 control-plane 重建之前引导，否则新容器读不到 DIRECTORY_RUNTIME_*。
  echo "[step] initializing directory synchronization runtime"
  JJD_ENV_FILE="$ENV_FILE" \
  IDENTITY_RUNTIME_ENV_FILE="$SCRIPT_DIR/identity-runtime.env" \
  COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    bash ./chat/bootstrap-directory-runtime.sh
  echo "[ok] directory synchronization runtime initialized"
  echo "[step] reloading control-plane with scoped identity runtime credentials"
  sh "$COMPOSE_WRAPPER" up -d --no-deps --force-recreate --wait control-plane
fi

echo "[step] running smoke test"
sh ./smoke-test.sh

write_result

HOST_ADDR="$(detect_host)"
HOST_ADDRS="$(detect_hosts_csv)"
echo
echo "[ok] offline deployment completed"
echo "[info] web console: $(for h in $(printf '%s' "$HOST_ADDRS" | tr ',' ' '); do printf '%s ' "$(format_https_url "$h" "$WEB_HTTPS_PORT")"; done | awk '{$1=$1; print}')"
echo "[info] http redirect: http://$HOST_ADDR:$WEB_PORT"
echo "[info] gateway api:  http://$HOST_ADDR:$GATEWAY_PORT"
echo "[info] reverse proxy: http://$HOST_ADDR:$PROXY_PORT"
echo "[info] control api:  http://127.0.0.1:$CONTROL_PORT"
echo "[info] forward proxy: http://$HOST_ADDR:$FORWARD_PROXY_PORT"
echo "[info] admin user:   $BOOTSTRAP_ADMIN_USERNAME"
echo "[info] admin credentials: $ENV_FILE (mode 600; read once and rotate immediately)"
if [ "${BUNDLE_CHAT:-0}" = "1" ]; then
  _co_public="$(grep '^JJD_SSO_PUBLIC_URL=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)"
  _co_public="${_co_public%/}"
  echo "[info] 员工门户:   ${_co_public}/chat   (企业 SSO 登录入口)"
  echo "[info] 门户管理:   ${_co_public}/portal"
  echo "[note] 企业身份源只在 JJDGuard 的「登录与单点登录」页面配置；内部身份管理面未公开。对接步骤见 deploy/docker-compose/chat/SSO-企业对接指南.md。"
fi
echo "[info] saved result: $RESULT_FILE"
echo "[info] compose project: $COMPOSE_PROJECT_NAME"
DEPLOY_SUCCEEDED=1
