#!/usr/bin/env bash
set -Eeuo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_ROOT="${JJD_PAYLOAD_ROOT:-$(cd "$SELF_DIR/../.." && pwd)}"
MANIFEST="$PAYLOAD_ROOT/manifest.json"
DC_REL=deploy/docker-compose
OPT_ROOT=/opt/jjdguard
# 固定布局：/opt/jjdguard/releases、/opt/jjdguard/current、/opt/jjdguard/previous，
# 状态与备份分别位于 /etc/jjdguard/install.env、/var/backups/jjdguard。
RELEASES=$OPT_ROOT/releases
CURRENT=$OPT_ROOT/current
PREVIOUS=$OPT_ROOT/previous
ETC_ROOT=/etc/jjdguard
STATE=$ETC_ROOT/install.env
LAST_UPGRADE=$ETC_ROOT/last-upgrade.env
BACKUP_ROOT=/var/backups/jjdguard
LOG_ROOT=/var/log/jjdguard
SYSTEMD_UNIT=/etc/systemd/system/jjdguard.service
LOCK_FILE="${JJD_INSTALL_LOCK_FILE:-/run/jjdguard-install.lock}"
LEGACY_ROOT=${JJD_LEGACY_ROOT:-/home/dev/jjdguard}
DEVELOPMENT_RECEIPT_DIR=""

say() { printf '%s\n' "$*"; }
die() { printf '[错误] %s\n' "$*" >&2; exit 1; }

normalize_arch() {
  case "${1:-$(uname -m)}" in
    x86_64 | amd64) printf 'amd64\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    *) die "不支持的 CPU 架构：${1:-$(uname -m)}" ;;
  esac
}

manifest_file_value() {
  local manifest="$1" key="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$manifest" | head -1
}

manifest_value() {
  manifest_file_value "$MANIFEST" "$1"
}

manifest_exact_string_value() {
  local key="$1" count value
  [[ "$key" =~ ^[a-z_]+$ ]] || return 1
  [[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || return 1
  count="$(grep -Ec "^[[:space:]]*\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"[[:space:]]*,?[[:space:]]*$" "$MANIFEST")" || return 1
  [[ "$count" == 1 ]] || return 1
  value="$(sed -n "s/^[[:space:]]*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*,\?[[:space:]]*$/\1/p" "$MANIFEST")" || return 1
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
  printf '%s' "$value"
}

persist_package_metadata() {
  local env_file="$1" version source_revision source_tree built_at tmp owner mode
  version="$(manifest_exact_string_value version)" || die 'package manifest version is missing or invalid'
  source_revision="$(manifest_exact_string_value source_revision)" || die 'package manifest source_revision is missing or invalid'
  source_tree="$(manifest_exact_string_value source_tree)" || die 'package manifest source_tree is missing or invalid'
  built_at="$(manifest_exact_string_value built_at)" || die 'package manifest built_at is missing or invalid'
  [[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || die 'package version has an invalid format'
  [[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || die 'package source revision has an invalid format'
  [[ "$source_tree" =~ ^[0-9a-f]{40}$ ]] || die 'package source tree has an invalid format'
  [[ "$built_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || die 'package build time has an invalid format'
  [[ -f "$env_file" && ! -L "$env_file" ]] || die 'inherited environment file is missing or unsafe'
  owner="$(stat -Lc %u -- "$env_file")" || die 'cannot verify inherited environment file owner'
  [[ "$owner" == "$EUID" ]] || die 'inherited environment file is not owned by the installer user'

  tmp="$(mktemp "$(dirname "$env_file")/.env.next.XXXXXX")" || die 'cannot create atomic environment update file'
  if ! awk '!/^JJD_(VERSION|COMMIT|BUILT_AT)=/' "$env_file" >"$tmp" ||
     ! printf 'JJD_VERSION=%s\nJJD_COMMIT=%s\nJJD_BUILT_AT=%s\n' \
       "$version" "$source_revision" "$built_at" >>"$tmp"; then
    rm -f -- "$tmp"
    die 'cannot write package version metadata'
  fi
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; die 'cannot protect updated environment file'; }
  mv -f -- "$tmp" "$env_file" || { rm -f -- "$tmp"; die 'cannot atomically update environment file'; }
  [[ -f "$env_file" && ! -L "$env_file" ]] || die 'updated environment file is unsafe'
  owner="$(stat -Lc %u -- "$env_file")" || die 'cannot recheck updated environment file owner'
  mode="$(stat -Lc %a -- "$env_file")" || die 'cannot recheck updated environment file mode'
  [[ "$owner" == "$EUID" && "$mode" == 600 ]] || die 'updated environment file owner or mode is invalid'
  say "[install] package metadata bound version=$version revision=${source_revision:0:12}"
}

acquire_install_lock() {
  # 文件锁防止并发安装/升级。锁在进程退出（含 die）时随 fd 关闭自动释放。
  # 用 fd 9 持锁，避免与 stdin/stdout/stderr 冲突。默认 /run（tmpfs，重启清空）。
  install -d -m 755 "$(dirname "$LOCK_FILE")" 2>/dev/null || true
  exec 9>"$LOCK_FILE" || die "无法创建安装锁文件：$LOCK_FILE"
  if ! flock -n 9; then
    die "检测到另一个 JJDGuard 安装/升级进程正在运行，请等待其完成后再试（锁: $LOCK_FILE）。如确认无其他进程，删除该锁文件后重试。"
  fi
}

detect_distro() {
  # 读 /etc/os-release 识别发行版族（debian/rhel/suse/other）。
  # 仅用于安装前环境告知，不构成硬性拒绝——只要受支持 init + Docker 可用即可运行。
  # os-release 本身就是 shell 变量格式，直接 source 最稳。测试钩子：JJD_OS_RELEASE_FILE。
  local os_release="${JJD_OS_RELEASE_FILE:-/etc/os-release}"
  local ID="" ID_LIKE=""
  if [[ -r "$os_release" ]]; then
    # shellcheck disable=SC1090
    source "$os_release" 2>/dev/null || true
  fi
  local combined="$ID $ID_LIKE"
  if [[ "$combined" == *debian* || "$combined" == *ubuntu* ]]; then
    printf 'debian'
  elif [[ "$combined" == *rhel* || "$combined" == *fedora* || "$combined" == *centos* || "$combined" == *rocky* || "$combined" == *almalinux* || "$combined" == *ol* ]]; then
    printf 'rhel'
  elif [[ "$combined" == *suse* || "$combined" == *sles* ]]; then
    printf 'suse'
  else
    printf 'other'
  fi
}

preflight_resources() {
  # 安装前校验 CPU/内存/磁盘满足最低要求；不满足立即 die，避免装到一半才失败。
  # 测试钩子：JJD_NPROC_STUB / JJD_MEMINFO_STUB / JJD_DF_STUB 注入假数据；
  #           JJD_PREFLIGHT_MIN_CPU/MEM_MB/DISK_MB 覆盖阈值。
  local min_cpu="${JJD_PREFLIGHT_MIN_CPU:-2}"
  local min_mem_mb="${JJD_PREFLIGHT_MIN_MEM_MB:-2048}"
  local min_disk_mb="${JJD_PREFLIGHT_MIN_DISK_MB:-10240}"
  local nproc_cmd="${JJD_NPROC_STUB:-}"
  local cpus
  if [[ -n "$nproc_cmd" ]]; then cpus="$nproc_cmd"; else cpus="$(command -v nproc >/dev/null 2>&1 && nproc || echo 0)"; fi
  [[ "$cpus" =~ ^[0-9]+$ ]] || cpus=0
  (( cpus >= min_cpu )) || die "CPU 核数不足：需要 ${min_cpu} 核，当前 ${cpus} 核"
  local meminfo="${JJD_MEMINFO_STUB:-/proc/meminfo}"
  local mem_kb=0
  if [[ -r "$meminfo" ]]; then
    mem_kb="$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]\+\)[[:space:]]*kB.*/\1/p' "$meminfo" | head -1)"
  fi
  [[ "$mem_kb" =~ ^[0-9]+$ ]] || mem_kb=0
  (( mem_kb >= min_mem_mb * 1024 )) || die "内存不足：需要 ${min_mem_mb}MB，当前 $((mem_kb/1024))MB"
  local df_data="${JJD_DF_STUB:-}"
  local avail_kb=0 df_target="${OPT_ROOT:-/opt}"
  if [[ -n "$df_data" ]]; then
    avail_kb="$(awk 'NR==2{print $4}' "$df_data" 2>/dev/null || echo 0)"
  elif command -v df >/dev/null 2>&1; then
    # OPT_ROOT（如 /opt/jjdguard）首次安装时尚不存在，df 会失败误报 0 可用；
    # 向上取最近存在的祖先目录做空间判断。
    while [[ "$df_target" != "/" && ! -d "$df_target" ]]; do
      df_target="${df_target%/*}"
      [[ -z "$df_target" ]] && df_target="/"
    done
    avail_kb="$(df -Pk "$df_target" 2>/dev/null | awk 'NR==2{print $4}')"
  fi
  [[ "$avail_kb" =~ ^[0-9]+$ ]] || avail_kb=0
  (( avail_kb >= min_disk_mb * 1024 )) || die "磁盘空间不足：需要 ${min_disk_mb}MB，当前 $((avail_kb/1024))MB（${df_target:-${OPT_ROOT:-/opt}}）"
}

detect_init_system() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    printf 'systemd'
  elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    printf 'openrc'
  elif command -v service >/dev/null 2>&1 && command -v update-rc.d >/dev/null 2>&1; then
    printf 'sysv-update-rc-d'
  elif command -v service >/dev/null 2>&1 && command -v chkconfig >/dev/null 2>&1; then
    printf 'sysv-chkconfig'
  else
    return 1
  fi
}

preflight_ports() {
  # 安装前识别默认端口占用并提示；首次部署由 deploy-offline.sh 自动顺延分配。
  # 端口取自既有 .env（升级场景）或默认值（首次）。测试钩子：JJD_PORT_CHECK_BINDIR
  # 指向含 fake ss 的目录；JJD_PORT_CHECK_SKIP=1 跳过（无 ss 工具的环境）。
  [[ "${JJD_PORT_CHECK_SKIP:-0}" == 1 ]] && return 0
  # 升级场景：当前部署容器已在监听对应端口，不视作冲突
  local live=""
  live="$(discover_running_compose)" || die '无法安全识别正在运行的 Compose 实例'
  if [[ -n "$live" || -n "$(discover_current)" ]]; then return 0; fi
  local ss_bin=""
  if [[ -n "${JJD_PORT_CHECK_BINDIR:-}" ]] && [[ -x "$JJD_PORT_CHECK_BINDIR/ss" ]]; then
    ss_bin="$JJD_PORT_CHECK_BINDIR/ss"
  elif command -v ss >/dev/null 2>&1; then
    ss_bin="ss"
  else
    return 0
  fi
  local env_file="${CURRENT:+$CURRENT/$DC_REL/.env}"
  local default_ports="3000 443 8080 8081 8082 8000 3128"
  local ports="$default_ports"
  if [[ -n "$env_file" && -r "$env_file" ]]; then
    local picked="" port_val
    for var in WEB_PORT WEB_HTTPS_PORT GATEWAY_PORT CONTROL_PORT PROXY_PORT SECURITY_PORT FORWARD_PROXY_PORT; do
      port_val="$(sed -n "s/^${var}=\\([0-9]\\+\\).*/\\1/p" "$env_file" | head -1)"
      [[ -n "$port_val" ]] && picked="$picked $port_val"
    done
    [[ -n "${picked// /}" ]] && ports="$picked"
  fi
  local listening occupied=""
  listening="$("$ss_bin" -tlnH 2>/dev/null || true)"
  local p
  for p in $ports; do
    if printf '%s\n' "$listening" | grep -Eq "[.:]${p}[[:space:]]"; then
      occupied="$occupied $p"
    fi
  done
  if [[ -n "${occupied// /}" ]]; then
    say "[检查] 以下默认端口已被占用，首次部署将自动顺延到可用端口：${occupied}"
  fi
}

preflight() {
  [[ "$EUID" -eq 0 ]] || die '安装和升级必须使用 root 或 sudo 权限'
  [[ "$(uname -s)" == Linux ]] || die '仅支持 Linux'
  INIT_SYSTEM="$(detect_init_system)" || die '未检测到受支持的 init 系统（systemd、OpenRC 或 SysV init）'
  [[ -r "$MANIFEST" ]] || die "安装包损坏：缺少 $MANIFEST"
  local expected actual
  expected="$(manifest_value target_arch)"
  actual="$(normalize_arch)"
  [[ "$expected" == "$actual" ]] || die "安装包架构为 $expected，当前机器为 $actual，请换正确的安装包"
  command -v gzip >/dev/null 2>&1 || die '系统缺少 gzip'
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die '系统缺少 SHA256 校验工具'
  # 安装前资源/端口/发行版告知（装一半失败是客户体验大忌）
  local distro
  distro="$(detect_distro)"
  say "[检查] 发行版族：${distro}（apt/dnf/yum 等包管理器非必需，Docker 走包内静态二进制）"
  preflight_resources
  preflight_ports
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

discover_orphan_current() {
  # 兼容安装事务在 deploy-offline 成功后、CURRENT 原子提交前被关机/中断的现场。
  # 仅当能够唯一绑定到一个本机 JJDGuard Compose 项目时才恢复；任何歧义都失败关闭。
  [[ -d "$RELEASES" && ! -L "$RELEASES" ]] || return 0
  command -v docker >/dev/null 2>&1 || return 0

  local release dc env_file manifest compose_file project version env_version
  local owner candidate="" matches=0
  for release in "$RELEASES"/*; do
    [[ -d "$release" && ! -L "$release" ]] || continue
    dc="$release/$DC_REL"
    env_file="$dc/.env"
    manifest="$release/manifest.json"
    compose_file="$dc/docker-compose.offline.yml"
    [[ -f "$env_file" && ! -L "$env_file" ]] || continue
    [[ -f "$manifest" && ! -L "$manifest" ]] || continue
    [[ -f "$compose_file" && ! -L "$compose_file" ]] || continue
    owner="$(stat -Lc %u -- "$release" 2>/dev/null || true)"
    [[ "$owner" == "$EUID" ]] || continue

    [[ "$(grep -Ec '^COMPOSE_PROJECT_NAME=[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' "$env_file")" == 1 ]] || continue
    project="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$env_file")"
    [[ "$(grep -Ec '^JJD_VERSION=[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$' "$env_file")" == 1 ]] || continue
    env_version="$(sed -n 's/^JJD_VERSION=//p' "$env_file")"
    version="$(manifest_file_value "$manifest" version)"
    [[ -n "$version" && "$version" == "$env_version" ]] || continue
    [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null)" ]] || continue

    candidate="$release"
    matches=$((matches + 1))
  done
  if [[ "$matches" == 1 ]]; then
    printf '%s\n' "$candidate"
  elif [[ "$matches" == 0 ]]; then
    # A staged release without a matching Compose project is not an active
    # install, but it is a valid interrupted-install state that can be retried.
    return 0
  fi
}

discover_current() {
  if [[ -L "$CURRENT" && -r "$CURRENT/$DC_REL/.env" ]]; then
    readlink -f "$CURRENT"
    return
  fi
  if [[ -r "$LEGACY_ROOT/$DC_REL/.env" ]]; then
    printf '%s\n' "$LEGACY_ROOT"
    return
  fi
  discover_orphan_current
}

discover_running_compose() {
  command -v docker >/dev/null 2>&1 || return 0
  local output container metadata project work_dir config_files env_file extra
  local -a gateways=()
  output="$(docker ps --filter status=running --filter label=com.docker.compose.service=gateway-core --format '{{.ID}}')" || return 1
  while IFS= read -r container; do [[ -n "$container" ]] && gateways+=("$container"); done <<<"$output"
  (( ${#gateways[@]} <= 1 )) || die "发现多个运行中的 gateway-core，拒绝猜测活动实例"
  (( ${#gateways[@]} == 1 )) || return 0
  metadata="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.project.working_dir" }}|{{ index .Config.Labels "com.docker.compose.project.config_files" }}|{{ index .Config.Labels "com.docker.compose.project.environment_file" }}' "${gateways[0]}")" || return 1
  [[ "$metadata" != *$'\n'* && "$metadata" != *$'\r'* ]] || return 1
  IFS='|' read -r project work_dir config_files env_file extra <<<"$metadata"
  [[ -z "${extra:-}" && "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 1
  [[ "$work_dir" == /* && -d "$work_dir" && ! -L "$work_dir" ]] || return 1
  work_dir="$(realpath -e -- "$work_dir")" || return 1
  [[ -n "$config_files" && "$config_files" == /* && "$config_files" != *$'\n'* && "$config_files" != *$'\r'* ]] || return 1
  if [[ -z "$env_file" || "$env_file" == '<no value>' ]]; then env_file="$work_dir/.env"; fi
  [[ "$env_file" == /* && -f "$env_file" && ! -L "$env_file" ]] || return 1
  [[ "$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=postgres | wc -l)" == 1 ]] || return 1
  printf '%s|%s\n' "$project" "$work_dir"
}

stage_release() {
  local active_version='' version arch name staged expected_manifest actual_manifest
  local existing existing_manifest existing_version existing_arch
  if (( $# > 0 )); then active_version="$1"; fi
  version="$(manifest_value version)"
  arch="$(manifest_value target_arch)"
  [[ "$version" =~ ^[0-9A-Za-z._-]+$ ]] || die '安装包版本号不合法'
  name="$(manifest_value bundle)"
  [[ "$name" =~ ^(jjdguard|agent-platform)-[A-Za-z0-9._-]+$ ]] || die '安装包 bundle 根目录不合法'
  if [[ "$name" == agent-platform-* ]]; then
    [[ "$(manifest_value product)" == agent-platform ]] || die '安装包档位与 bundle 根目录不符'
  else
    [[ "$(manifest_value product)" == jjdguard-enterprise ]] || die '安装包档位与 bundle 根目录不符'
  fi
  staged="$RELEASES/$name"
  install -d -m 755 "$RELEASES" "$ETC_ROOT" "$BACKUP_ROOT" "$LOG_ROOT"
  expected_manifest="$(sha256_file "$MANIFEST")"
  if [[ -e "$staged" || -L "$staged" ]]; then
    [[ -d "$staged" && ! -L "$staged" ]] || die '暂存目录不是受信任的普通目录'
    [[ -f "$staged/manifest.json" && ! -L "$staged/manifest.json" ]] || die '暂存目录缺少受信任的 manifest'
    actual_manifest="$(sha256_file "$staged/manifest.json")"
    [[ "$expected_manifest" == "$actual_manifest" ]] || die '暂存目录已存在，但 manifest 与当前安装包不一致'
    printf '%s\n' "$staged"
    return
  fi
  for existing in "$RELEASES"/jjdguard-* "$RELEASES"/agent-platform-*; do
    [[ -e "$existing" || -L "$existing" ]] || continue
    [[ -d "$existing" && ! -L "$existing" ]] || die "发现不受信任的现有 release 条目：${existing##*/}"
    [[ "$existing" != "$staged" ]] || continue
    existing_manifest="$existing/manifest.json"
    [[ -f "$existing_manifest" && ! -L "$existing_manifest" ]] || continue
    existing_version="$(manifest_file_value "$existing_manifest" version)"
    existing_arch="$(manifest_file_value "$existing_manifest" target_arch)"
    [[ "$existing_version" == "$version" && "$existing_arch" == "$arch" ]] || continue
    # A failed candidate can leave an immutable same-version root behind. It
    # may coexist only when the active deployment is explicitly an older
    # version; without that evidence, keep the historical fail-closed rule.
    [[ -n "$active_version" && "$active_version" != "$version" ]] && continue
    actual_manifest="$(sha256_file "$existing_manifest")"
    [[ "$expected_manifest" == "$actual_manifest" ]] || die '暂存目录已有相同版本和架构但 manifest 不一致'
    die '暂存目录已有相同版本和架构但 bundle 根目录不同'
  done
  install -d -m 755 "$staged"
  cp -a "$PAYLOAD_ROOT/." "$staged/"
  install -m 755 "$staged/deploy/offline-installer/jjdctl" "$staged/jjdctl"
  printf '%s\n' "$staged"
}

ensure_docker() {
  local dc="$1/$DC_REL" probe context installed=0
  if ! command -v docker >/dev/null 2>&1; then
    say '[安装] 未发现可用容器环境，正在使用包内 Docker……'
    sh "$dc/install-docker.sh"
    installed=1
  elif ! probe="$(docker info 2>&1)"; then
    context="$(docker context show 2>/dev/null || printf default)"
    case "$probe" in
      *[Pp]ermission.denied*|*permission.denied*|*Got.permission.denied*)
        die 'Docker 已安装但当前用户无 Engine 权限；不会覆盖或更新共享 Docker'
        ;;
    esac
    if [[ -n "${DOCKER_HOST:-}" || "$context" != default ]]; then
      die "Docker context/DOCKER_HOST 无法连接 Engine（context=$context）；不会修改远程或共享运行时"
    fi
    if command -v systemctl >/dev/null 2>&1 &&
       systemctl cat docker.service >/dev/null 2>&1; then
      say '[安装] Docker 已安装但 daemon 未就绪，尝试启动现有 docker.service……'
      systemctl start docker.service >/dev/null 2>&1 || true
    fi
    docker info >/dev/null 2>&1 ||
      die 'Docker CLI 已安装但 Engine 不可用；请检查 daemon、socket 权限和 context，安装器不会覆盖现有 Docker'
  fi
  docker info >/dev/null 2>&1 || die 'Docker 启动失败'
  if (( installed == 1 )) && command -v systemctl >/dev/null 2>&1; then
    systemctl enable docker.service >/dev/null 2>&1 || true
  fi
  if ! sh "$dc/compose-wrapper.sh" version >/dev/null 2>&1; then
    if [[ -x "$dc/docker-compose" ]]; then
      die '随包 Docker Compose 存在但能力探测失败；不会更新客户 Docker Engine'
    fi
    die 'Docker Engine 可用但 Compose 缺失，且安装包未携带可用 Compose'
  fi
  say '[检查] Docker Engine 与 Compose 实际能力可用，复用现有运行时'
}

preflight_runtime_storage() {
  local release="$1" min_kb="${JJD_RUNTIME_MIN_FREE_KB:-2097152}"
  local docker_root install_free backup_free docker_free
  [[ "$min_kb" =~ ^[1-9][0-9]*$ ]] || die 'JJD_RUNTIME_MIN_FREE_KB 必须是正整数'
  docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
  [[ "$docker_root" == /* ]] || die '无法取得 Docker data-root，拒绝继续写入镜像'
  install_free="$(df -Pk "$release" | awk 'NR==2{print $4+0}')"
  install -d -m 700 "$BACKUP_ROOT"
  backup_free="$(df -Pk "$BACKUP_ROOT" | awk 'NR==2{print $4+0}')"
  docker_free="$(df -Pk "$docker_root" | awk 'NR==2{print $4+0}')"
  (( install_free >= min_kb )) || die "安装目录空间不足：$release"
  (( backup_free >= min_kb )) || die "备份目录空间不足：$BACKUP_ROOT"
  (( docker_free >= min_kb )) || die "Docker data-root 空间不足：$docker_root"
  say "[检查] 存储可用 install=${install_free}KB backup=${backup_free}KB docker=${docker_free}KB"
}

archive_path() {
  find "$1/$DC_REL/offline-artifacts" -maxdepth 1 -type f -name 'jjdguard-offline-images-*.tar.gz' | sort | tail -1
}

verify_and_load_images() {
  local release="$1" archive expected actual
  archive="$(archive_path "$release")"
  [[ -s "$archive" ]] || die '安装包内没有离线镜像'
  if [[ -r "$archive.sha256" ]]; then
    expected="$(awk '{print $1}' "$archive.sha256")"
    actual="$(sha256_file "$archive")"
    [[ "$expected" == "$actual" ]] || die '离线镜像校验失败，安装包可能损坏'
  fi
  say '[安装] 正在导入离线镜像……'
  gzip -dc "$archive" | docker load >/dev/null
}

image_id() {
  local image="$1" id
  id="$(docker image inspect "$image" --format '{{.Id}}' 2>/dev/null || true)"
  [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "镜像缺失或损坏：$image"
  printf '%s\n' "$id"
}

optional_image_id() {
  local id
  id="$(docker image inspect "$1" --format '{{.Id}}' 2>/dev/null || true)"
  [[ -z "$id" || "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "镜像损坏：$1"
  printf '%s\n' "$id"
}

running_image_id() {
  local dc="$1" service="$2" cid
  cid="$(cd "$dc" && sh ./compose-wrapper.sh -f docker-compose.offline.yml ps -q "$service" 2>/dev/null | head -1)"
  [[ -n "$cid" ]] || return 0
  docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true
}

pin_old_release() {
  local old_dc="$1"
  shift
  install -d -m 700 "$old_dc/.upgrade"
  {
    printf 'services:\n'
    printf '  gateway-core: {image: %s}\n' "$1"
    printf '  control-plane: {image: %s}\n' "$2"
    printf '  security-engine: {image: %s}\n' "$3"
    printf '  proxy-server: {image: %s}\n' "$4"
    printf '  proxy-server-vm: {image: %s}\n' "$4"
    printf '  web-console: {image: %s}\n' "$5"
    printf '  worker: {image: %s}\n' "$6"
    if [[ -n "${7:-}" ]]; then printf '  llm-judge: {image: %s}\n' "$7"; fi
    if [[ -n "${8:-}" ]]; then printf '  tier1-classifier: {image: %s}\n' "$8"; fi
    if [[ -n "${9:-}" ]]; then printf '  chat-portal-ui: {image: %s}\n' "$9"; fi
    if [[ -n "${10:-}" ]]; then printf '  chat-portal-proxy: {image: %s}\n' "${10}"; fi
  } >"$old_dc/.upgrade/compose.upgrade.yml"
  chmod 600 "$old_dc/.upgrade/compose.upgrade.yml"
}

capture_development_receipt() {
  local new_release="$1"
  local root index release expected actual receipt target
  root="$OPT_ROOT/development-releases"
  index="$root/current.json"
  [[ -f "$index" && ! -L "$index" ]] || return 0
  [[ "$(stat -Lc %u -- "$index" 2>/dev/null || true)" == "$EUID" ]] ||
    die '开发回执索引的属主不可信'
  [[ "$(stat -Lc %a -- "$index" 2>/dev/null || true)" == 600 ]] ||
    die '开发回执索引权限不安全'
  release="$(sed -n 's/.*"release"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$index" | head -1)"
  expected="$(sed -n 's/.*"receipt_sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$index" | head -1)"
  [[ -n "$release" && -n "$expected" ]] || die '开发回执索引缺少 release 或 receipt_sha256'
  case "$release" in
    "$root"/*) ;;
    *) die '开发回执路径越出受控目录' ;;
  esac
  release="$(realpath -e -- "$release")" || die '开发回执 release 路径不存在'
  case "$release" in
    "$root"/*) ;;
    *) die '开发回执 release 实际路径越出受控目录' ;;
  esac
  receipt="$release/receipt.json"
  [[ -f "$receipt" && ! -L "$receipt" ]] || die '开发回执文件缺失'
  [[ "$(stat -Lc %u -- "$receipt" 2>/dev/null || true)" == "$EUID" ]] ||
    die '开发回执文件的属主不可信'
  [[ "$(stat -Lc %a -- "$receipt" 2>/dev/null || true)" == 600 ]] ||
    die '开发回执文件权限不安全'
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die '开发回执摘要格式非法'
  actual="$(sha256_file "$receipt")"
  [[ "$actual" == "$expected" ]] || die '开发回执摘要不匹配，拒绝继续升级'
  grep -Eq '"status"[[:space:]]*:[[:space:]]*"deployed"' "$receipt" ||
    die '开发回执不是已部署状态'
  # Console-only receipts bind the version through their manifest and retain
  # the predecessor pointer. Preserve that evidence chain to the full release
  # which owns the running gateway digest and its database rollback backup.
  target="$new_release/$DC_REL/.upgrade/development-receipt"
  source "$SELF_DIR/lib/development-receipt-chain.sh"
  development_receipt_anchor "$root" "$index" "$target" || die '开发回执链无效或缺少可信整套发布依据'
  index="$DEV_RECEIPT_ANCHOR_INDEX"
  release="$DEV_RECEIPT_ANCHOR_RELEASE"
  receipt="$release/receipt.json"
  actual="$(sha256_file "$receipt")"
  # upgrade-bundle.sh 从自己的 SCRIPT_DIR（<release>/deploy/docker-compose）读取
  # .upgrade 状态，开发回执必须落在同一处，否则 validate_digest_from_development_receipt
  # 永远读不到，经开发发布更新过的环境会在升级前被判成不可信摘要。
  target="$new_release/$DC_REL/.upgrade/development-receipt"
  install -d -m 700 "$target"
  install -m 600 "$index" "$target/current.json"
  install -m 600 "$receipt" "$target/receipt.json"
  printf '%s\n' "$actual" >"$target/receipt.sha256"
  chmod 600 "$target/receipt.sha256"
  DEVELOPMENT_RECEIPT_DIR="$target"
}

write_link() {
  local link="$1" target="$2" tmp
  tmp="$(dirname "$link")/.${link##*/}.$$"
  ln -s "$target" "$tmp"
  mv -Tf "$tmp" "$link"
}

write_state() {
  local release="$1" mode="$2"
  {
    printf 'VERSION=%q\n' "$(manifest_value version)"
    printf 'ARCH=%q\n' "$(manifest_value target_arch)"
    printf 'RELEASE=%q\n' "$release"
    printf 'MODE=%q\n' "$mode"
    printf 'UPDATED_AT=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$STATE"
  if [[ -n "$DEVELOPMENT_RECEIPT_DIR" ]]; then
    printf 'DEVELOPMENT_RECEIPT_DIR=%q\n' "$DEVELOPMENT_RECEIPT_DIR" >>"$STATE"
  fi
  chmod 600 "$STATE"
}

install_service() {
  ln -sf "$CURRENT/jjdctl" /usr/local/bin/jjdctl
  case "$INIT_SYSTEM" in
    systemd)
      install -m 644 "$CURRENT/deploy/offline-installer/jjdguard.service" "$SYSTEMD_UNIT"
      systemctl daemon-reload
      systemctl enable --now jjdguard.service
      ;;
    openrc)
      cat >/etc/init.d/jjdguard <<'OPENRC'
#!/sbin/openrc-run
description="JJDGuard"

depend() {
    need docker
    after net
}

start() {
    ebegin "Starting JJDGuard"
    /usr/local/bin/jjdctl start
    eend $?
}

stop() {
    ebegin "Stopping JJDGuard"
    /usr/local/bin/jjdctl stop
    eend $?
}

restart() {
    stop && start
}
OPENRC
      chmod 755 /etc/init.d/jjdguard
      rc-update add jjdguard default >/dev/null 2>&1 || true
      rc-service jjdguard start
      ;;
    sysv-update-rc-d|sysv-chkconfig)
      cat >/etc/init.d/jjdguard <<'SYSV'
#!/bin/sh
case "${1:-}" in
  start) /usr/local/bin/jjdctl start ;;
  stop) /usr/local/bin/jjdctl stop ;;
  restart) /usr/local/bin/jjdctl restart ;;
  status) /usr/local/bin/jjdctl status ;;
  *) echo "Usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
SYSV
      chmod 755 /etc/init.d/jjdguard
      if [[ "$INIT_SYSTEM" == sysv-update-rc-d ]]; then
        update-rc.d jjdguard defaults >/dev/null 2>&1 || true
      else
        chkconfig --add jjdguard >/dev/null 2>&1 || true
        chkconfig jjdguard on >/dev/null 2>&1 || true
      fi
      service jjdguard start
      ;;
    *) die 'init 系统未在安装前置检查中确认' ;;
  esac
}

fresh_install() {
  local release="$1"
  capture_development_receipt "$release"
  ensure_docker "$release"
  preflight_runtime_storage "$release"
  say '[安装] 首次安装 JJDGuard……'
  (cd "$release/$DC_REL" && sh ./deploy-offline.sh)
  write_link "$CURRENT" "$release"
  write_state "$release" fresh
  install_service
}

upgrade_install() {
  local old="$1" release="$2" old_dc="$old/$DC_REL" new_dc="$release/$DC_REL"
  local same_release=0
  [[ -r "$old_dc/.env" ]] || die '旧版本配置不完整，已停止升级'
  # 同一 .run 的修复重跑会命中当前 release 本身；GNU install 会拒绝自复制。
  if [[ "$old_dc/.env" -ef "$new_dc/.env" ]]; then
    same_release=1
    say '[修复] 当前版本已释放，复用现有 .env'
  else
    install -m 600 "$old_dc/.env" "$new_dc/.env"
  fi
  persist_package_metadata "$new_dc/.env"
  if [[ "$same_release" == 0 ]]; then
    [[ -d "$old_dc/tls" ]] && cp -a "$old_dc/tls" "$new_dc/tls"
    [[ -d "$old_dc/.upgrade" ]] && cp -a "$old_dc/.upgrade" "$new_dc/.upgrade"
    if [[ -r "$old_dc/.deploy-result" ]]; then
      sed \
        -e "s#^TLS_CERT_FILE=.*#TLS_CERT_FILE=$new_dc/tls/web-console.crt#" \
        -e "s#^ENV_FILE=.*#ENV_FILE=$new_dc/.env#" \
        -e "s#^COMPOSE_FILE=.*#COMPOSE_FILE=$new_dc/docker-compose.offline.yml#" \
        "$old_dc/.deploy-result" >"$new_dc/.deploy-result"
      chmod 600 "$new_dc/.deploy-result"
    fi
  fi
  capture_development_receipt "$release"
  ensure_docker "$release"
  preflight_runtime_storage "$release"

  local pg_before cp_before se_before ps_before web_before worker_before judge_before tier1_before portal_ui_before portal_proxy_before
  pg_before="$(running_image_id "$old_dc" gateway-core)"
  cp_before="$(running_image_id "$old_dc" control-plane)"
  se_before="$(running_image_id "$old_dc" security-engine)"
  ps_before="$(running_image_id "$old_dc" proxy-server)"
  web_before="$(running_image_id "$old_dc" web-console)"
  worker_before="$(running_image_id "$old_dc" worker)"
  judge_before="$(running_image_id "$old_dc" llm-judge)"
  tier1_before="$(running_image_id "$old_dc" tier1-classifier)"
  portal_ui_before="$(running_image_id "$old_dc" chat-portal-ui)"
  portal_proxy_before="$(running_image_id "$old_dc" chat-portal-proxy)"
  for ref in "$pg_before" "$cp_before" "$se_before" "$ps_before" "$web_before" "$worker_before" "$judge_before" "$tier1_before" "$portal_ui_before" "$portal_proxy_before"; do
    [[ -z "$ref" || "$ref" =~ ^sha256:[0-9a-f]{64}$ ]] || die '无法取得旧版本完整镜像锚点，已停止升级'
  done
  pin_old_release "$old_dc" "$pg_before" "$cp_before" "$se_before" "$ps_before" "$web_before" "$worker_before" "$judge_before" "$tier1_before" "$portal_ui_before" "$portal_proxy_before"

  verify_and_load_images "$release"
  local gateway control security proxy web worker judge tier1 portal_ui portal_proxy
  gateway="$(image_id docker-compose-gateway-core:latest)"
  control="$(image_id docker-compose-control-plane:latest)"
  security="$(image_id docker-compose-security-engine:latest)"
  proxy="$(image_id docker-compose-proxy-server:latest)"
  web="$(image_id docker-compose-web-console:latest)"
  worker="$(image_id docker-compose-worker:latest)"
  judge="$(optional_image_id docker-compose-llm-judge:latest)"
  tier1="$(optional_image_id docker-compose-tier1-classifier:latest)"
  portal_ui="$(optional_image_id enterprise-ai-portal:0.2.0-slim)"
  portal_proxy="$(optional_image_id chat-portal/portal-proxy:0.1.0)"

  say '[升级] 正在在线备份数据库并升级；失败将回退应用并保留数据库……'
  (cd "$new_dc" && UPGRADE_OFFLINE_MODE=1 UPGRADE_BACKUP_DIR="$new_dc/.upgrade/backups" bash ./upgrade.sh \
    --customer-deployment \
    --from-version "$(sed -n 's/^JJD_VERSION=//p' "$old_dc/.env" | tail -1)" \
    --to-version "$(manifest_value version)" \
    --gateway-core "$gateway" --control-plane "$control" \
    --security-engine "$security" --proxy-server "$proxy" \
    --web-console "$web" --worker "$worker" \
    --llm-judge "$judge" --tier1-classifier "$tier1" \
    --chat-portal-ui "$portal_ui" --chat-portal-proxy "$portal_proxy" \
    --min-data-version "$(manifest_value min_data_version)")

  local backup
  backup="$(find "$new_dc/.upgrade/backups" -type f -name '*.sql' 2>/dev/null | sort | tail -1)"
  [[ -s "$backup" ]] || die '升级虽完成但未找到数据库备份，拒绝提交新版本'
  {
    printf 'PREVIOUS_RELEASE=%q\nCURRENT_RELEASE=%q\nBACKUP_FILE=%q\n' "$old" "$release" "$backup"
    printf 'GATEWAY_CORE_IMAGE=%q\nCONTROL_PLANE_IMAGE=%q\nSECURITY_ENGINE_IMAGE=%q\n' "$pg_before" "$cp_before" "$se_before"
    printf 'PROXY_SERVER_IMAGE=%q\nWEB_CONSOLE_IMAGE=%q\nWORKER_IMAGE=%q\n' "$ps_before" "$web_before" "$worker_before"
    printf 'LLM_JUDGE_IMAGE=%q\nTIER1_CLASSIFIER_IMAGE=%q\n' "$judge_before" "$tier1_before"
    printf 'CHAT_PORTAL_UI_IMAGE=%q\nCHAT_PORTAL_PROXY_IMAGE=%q\n' "$portal_ui_before" "$portal_proxy_before"
    if [[ -n "$DEVELOPMENT_RECEIPT_DIR" ]]; then
      printf 'DEVELOPMENT_RECEIPT_DIR=%q\n' "$DEVELOPMENT_RECEIPT_DIR"
    fi
  } >"$LAST_UPGRADE"
  chmod 600 "$LAST_UPGRADE"

  [[ -e "$CURRENT" || -L "$CURRENT" ]] && write_link "$PREVIOUS" "$old"
  write_link "$CURRENT" "$release"
  write_state "$release" upgrade
  install_service
}

rollback_image_from_manifest() {
  local manifest="$1" service="$2" image
  image="$(awk -F '\t' -v wanted="$service" '$1 == wanted { print $2; exit }' "$manifest")" || return 1
  [[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$image"
}

live_upgrade_install() {
  local release="$1" discovery="$2" project work_dir extra new_dc state rollback_manifest
  local gateway control security proxy web worker judge tier1 portal_ui portal_proxy
  IFS='|' read -r project work_dir extra <<<"$discovery"
  [[ -z "${extra:-}" && "$project" =~ ^[a-z0-9][a-z0-9_-]*$ && "$work_dir" == /* ]] || \
    die '运行实例发现结果非法'
  new_dc="$release/$DC_REL"
  capture_development_receipt "$release"
  ensure_docker "$release"
  preflight_runtime_storage "$release"
  say "[升级] 已从 Compose labels 识别活动实例 project=$project"
  say "[升级] 活动工作目录：$work_dir"
  if [[ -L "$CURRENT" && "$(readlink -f "$CURRENT")" != "$work_dir" ]]; then
    say "[升级] 忽略与活动实例不一致的旧 current 指向：$(readlink -f "$CURRENT")"
  fi
  # This installer has already verified the signed release before reaching the
  # live-upgrade path. Pass that provenance explicitly so a 2.6.5 environment
  # without the new scope key can be upgraded as a customer deployment.
  (cd "$new_dc" && JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE=1 bash ./upgrade-bundle.sh)

  state="$new_dc/.upgrade/bundle-upgrade.env"
  [[ -f "$state" && ! -L "$state" && "$(stat -Lc %u -- "$state")" == 0 && "$(stat -Lc %a -- "$state")" == 600 ]] || \
    die '原地升级已返回但状态文件不安全'
  # shellcheck disable=SC1090
  source "$state"
  [[ "${EXISTING_PROJECT_NAME:-}" == "$project" && "${PREVIOUS_WORK_DIR:-}" == "$work_dir" ]] || \
    die '原地升级状态与发现的活动实例不一致'
  [[ "${LEGACY_RELEASE_ANCHOR:-}" == "$new_dc/backups/"* && -d "$LEGACY_RELEASE_ANCHOR/deploy/docker-compose" ]] || \
    die '原地升级缺少回退 release 锚点'
  [[ "${BACKUP_DIR:-}" == "$new_dc/backups/"* && -s "${MAIN_BACKUP_FILE:-}" ]] || \
    die '原地升级缺少主数据库备份'
  if [[ -n "${CHAT_BACKUP_FILE:-}" ]]; then [[ -s "$CHAT_BACKUP_FILE" ]] || die '门户数据库备份缺失'; fi
  rollback_manifest="$BACKUP_DIR/rollback-images.tsv"
  [[ -f "$rollback_manifest" && ! -L "$rollback_manifest" ]] || die '回滚镜像清单缺失'
  gateway="$(rollback_image_from_manifest "$rollback_manifest" gateway-core)" || die 'gateway-core 回滚镜像缺失'
  control="$(rollback_image_from_manifest "$rollback_manifest" control-plane)" || die 'control-plane 回滚镜像缺失'
  security="$(rollback_image_from_manifest "$rollback_manifest" security-engine)" || die 'security-engine 回滚镜像缺失'
  proxy="$(rollback_image_from_manifest "$rollback_manifest" proxy-server)" || die 'proxy-server 回滚镜像缺失'
  web="$(rollback_image_from_manifest "$rollback_manifest" web-console)" || die 'web-console 回滚镜像缺失'
  worker="$(rollback_image_from_manifest "$rollback_manifest" worker)" || die 'worker 回滚镜像缺失'
  judge="$(rollback_image_from_manifest "$rollback_manifest" llm-judge 2>/dev/null || true)"
  tier1="$(rollback_image_from_manifest "$rollback_manifest" tier1-classifier 2>/dev/null || true)"
  portal_ui="$(rollback_image_from_manifest "$rollback_manifest" chat-portal-ui 2>/dev/null || true)"
  portal_proxy="$(rollback_image_from_manifest "$rollback_manifest" chat-portal-proxy 2>/dev/null || true)"
  {
    printf 'PREVIOUS_RELEASE=%q\nCURRENT_RELEASE=%q\nBACKUP_FILE=%q\nCHAT_BACKUP_FILE=%q\n' \
      "$LEGACY_RELEASE_ANCHOR" "$release" "$MAIN_BACKUP_FILE" "${CHAT_BACKUP_FILE:-}"
    printf 'GATEWAY_CORE_IMAGE=%q\nCONTROL_PLANE_IMAGE=%q\nSECURITY_ENGINE_IMAGE=%q\n' "$gateway" "$control" "$security"
    printf 'PROXY_SERVER_IMAGE=%q\nWEB_CONSOLE_IMAGE=%q\nWORKER_IMAGE=%q\n' "$proxy" "$web" "$worker"
    printf 'LLM_JUDGE_IMAGE=%q\nTIER1_CLASSIFIER_IMAGE=%q\n' "$judge" "$tier1"
    printf 'CHAT_PORTAL_UI_IMAGE=%q\nCHAT_PORTAL_PROXY_IMAGE=%q\n' "$portal_ui" "$portal_proxy"
    if [[ -n "$DEVELOPMENT_RECEIPT_DIR" ]]; then
      printf 'DEVELOPMENT_RECEIPT_DIR=%q\n' "$DEVELOPMENT_RECEIPT_DIR"
    fi
  } >"$LAST_UPGRADE"
  chmod 600 "$LAST_UPGRADE"

  write_link "$PREVIOUS" "$LEGACY_RELEASE_ANCHOR"
  write_link "$CURRENT" "$release"
  write_state "$release" upgrade
  install_service
}

live_is_staged_release() {
  local discovery="$1" release="$2" project work_dir extra
  IFS='|' read -r project work_dir extra <<<"$discovery"
  [[ -z "${extra:-}" && -n "$work_dir" && -d "$release/$DC_REL" ]] || return 1
  [[ "$work_dir" -ef "$release/$DC_REL" ]]
}

main() {
  preflight
  acquire_install_lock
  local old release live active_work_dir active_version=''
  live="$(discover_running_compose)" || die '无法安全识别正在运行的 Compose 实例'
  if [[ -n "$live" ]]; then
    old=""
    IFS='|' read -r _ active_work_dir <<<"$live"
  else
    old="$(discover_current)"
    active_work_dir="$old"
  fi
  if [[ -n "$active_work_dir" && -r "$active_work_dir/.env" ]]; then
    active_version="$(sed -n 's/^JJD_VERSION=//p' "$active_work_dir/.env" | tail -n 1)"
  fi
  if [[ -z "$active_version" && -r "$STATE" ]]; then
    active_version="$(sed -n 's/^VERSION=//p' "$STATE" | tail -n 1)"
  fi
  release="$(stage_release "$active_version")"
  trap 'status=$?; if [[ $status -ne 0 ]]; then echo "[错误] 安装/升级失败，现有版本未切换。" >&2; fi; exit $status' EXIT
  if [[ -n "$live" ]] && live_is_staged_release "$live" "$release"; then
    # Re-running the same signed .run on its own live deployment is a repair.
    # The live upgrader would copy tls/ and .upgrade/ onto themselves.
    say "[修复] same-release rerun: live instance is ${release##*/}"
    old="$release"
    upgrade_install "$old" "$release"
  elif [[ -n "$live" ]]; then live_upgrade_install "$release" "$live"
  elif [[ -n "$old" ]]; then upgrade_install "$old" "$release"
  else fresh_install "$release"; fi
  trap - EXIT
  say
  say '[完成] JJDGuard 已安装并设置为开机自启动。'
  [[ -r "$release/$DC_REL/.deploy-result" ]] && cat "$release/$DC_REL/.deploy-result"
  say '以后查看状态：sudo jjdctl status'
}

if [[ "${JJD_INSTALLER_LIB_ONLY:-0}" != 1 ]]; then
  main "$@"
fi
