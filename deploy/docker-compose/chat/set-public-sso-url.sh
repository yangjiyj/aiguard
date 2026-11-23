#!/usr/bin/env bash
# 运维命令：变更 JJDGuard 对外 SSO 地址（IP -> 域名、域名 -> 域名、改端口、http <-> https），以及回滚。
#
#   jjdctl sso set-public-url <https://新地址> [--apply] [--drop-old] ...
#   jjdctl sso rollback <备份目录> [--apply] ...
#
# 默认 dry-run，只打印将要执行的改动；加 --apply 才真正执行。
# 步骤：备份 -> 改写 .env / identity-runtime.env -> 复制 user_identity_links（所有租户）
#       -> Keycloak 追加 redirect/post-logout -> 按当前启动链重建受影响服务。
# 通用性约定：
#   - 不假设 compose 项目名、容器名、数据库用户/库名、realm、Keycloak 子路径与端口、客户端 ID；
#     容器一律按 compose 项目 + service 标签查找，其余参数从 .env 或容器配置推导，推导不出再用产品默认值。
#   - 老版本缺少的部件（identity-runtime.env、.upgrade/compose-files、user_identity_links 表、chat-idp）
#     逐项跳过并给出提示，不报错。
# 安全：不打印任何 secret，只输出白名单键（地址类）的新旧值。

set -Eeuo pipefail

# 全部规范化为真实路径（pwd -P）：客户机上 /opt/jjdguard/current 是指向 releases/<版本> 的软链，
# 而 .upgrade/compose-files 记录的是真实路径，逻辑路径与真实路径混用会让启动链前缀校验误判。
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd -P)"
COMPOSE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
ENV_FILE="${JJD_ENV_FILE:-$COMPOSE_DIR/.env}"
RUNTIME_ENV_FILE="${IDENTITY_RUNTIME_ENV_FILE:-$COMPOSE_DIR/identity-runtime.env}"
COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$COMPOSE_DIR/compose-wrapper.sh}"
BACKUP_ROOT="${JJD_BACKUP_ROOT:-/var/backups/jjdguard}"
DOCKER_BIN="${DOCKER_BIN:-docker}"

# 读取这些变量的服务（以 docker-compose.offline.yml 实际引用为准）：
#   chat-idp(KC_HOSTNAME/PORTAL_*)、chat-edge(网络别名)、chat-portal-proxy、
#   chat-portal-ui、control-plane(identity-runtime.env 的 JJD_SSO_PUBLIC_URL)
# 容器不存在的服务（老版本、未启用内置 Keycloak 等）自动跳过。
AFFECTED_SERVICES=(chat-idp chat-edge chat-portal-proxy chat-portal-ui control-plane)

# 本命令会改写的白名单键（只有这些键的值会出现在输出里）
WHITELIST_KEYS=(JJD_SSO_PUBLIC_URL JJD_SSO_ALLOW_INSECURE_PUBLIC_URL CHAT_OIDC_HOST CHAT_OIDC_ISSUER)

APPLY=0
DROP_OLD=0
SKIP_DB=0
SKIP_KC=0
SKIP_RECREATE=0
ALLOW_IMAGE_CHANGE=0
FORCE=0
CHAIN_MODE=auto
NEW_URL=""
ROLLBACK_DIR=""

say() { printf '%s\n' "$*"; }
note() { printf '[提示] %s\n' "$*"; }
warn() { printf '[警告] %s\n' "$*" >&2; }
die() { printf '[错误] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法：
  jjdctl sso set-public-url <新地址> [选项]     变更对外 SSO 地址
  jjdctl sso rollback <备份目录> [选项]         按 apply 时生成的备份目录回滚

新地址只能是 origin（协议://主机[:端口]），例如 https://sso.example.com 或 https://10.0.0.8:8443，
不能带路径、查询串或凭据。大小写、尾斜杠、默认端口（http:80 / https:443）会先规范化再比较；
新地址与当前地址一致时提示“无变化”并以 0 退出。

默认 dry-run；加 --apply 才执行。
选项：
  --apply                  真正执行
  --keep-old               Keycloak 保留旧地址（默认行为，仅 set-public-url）
  --drop-old               Keycloak 只保留新地址，旧地址从 redirect/web origin/post-logout 中移除
                           （地址已经一致时，加此选项仍会执行 Keycloak 清理）
  --skip-db                不复制/不删除 user_identity_links
  --skip-keycloak          不改 Keycloak 客户端
  --skip-recreate          不重建服务（改完需自行用当前启动链重建）
  --chain=auto|file|labels 启动链来源：auto=优先 .upgrade/compose-files，否则运行中容器标签
  --allow-image-change     允许重建后镜像引用与运行中不一致（默认拒绝，防止被回退成裸 offline.yml 的镜像）
  --force                  仅 rollback：忽略“apply 之后配置又被改过”的保护
环境变量：
  JJD_COMPOSE_PROJECT      显式指定 compose 项目名（同机多套部署且自动识别有歧义时使用）
EOF
}

# ---------- 参数 ----------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --keep-old) DROP_OLD=0 ;;
    --drop-old) DROP_OLD=1 ;;
    --skip-db) SKIP_DB=1 ;;
    --skip-keycloak) SKIP_KC=1 ;;
    --skip-recreate) SKIP_RECREATE=1 ;;
    --allow-image-change) ALLOW_IMAGE_CHANGE=1 ;;
    --force) FORCE=1 ;;
    --chain=*) CHAIN_MODE="${1#--chain=}" ;;
    --rollback)
      [ "$#" -ge 2 ] || die "--rollback 需要指定备份目录"
      ROLLBACK_DIR="$2"; shift ;;
    --rollback=*) ROLLBACK_DIR="${1#--rollback=}" ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; die "未知选项: $1" ;;
    *) [ -z "$NEW_URL" ] || die "只能指定一个新地址"; NEW_URL="$1" ;;
  esac
  shift
done
case "$CHAIN_MODE" in auto|file|labels) ;; *) die "--chain 只能是 auto|file|labels" ;; esac
if [ -n "$ROLLBACK_DIR" ]; then
  [ -z "$NEW_URL" ] || die "rollback 模式不接受新地址参数"
else
  [ -n "$NEW_URL" ] || { usage >&2; exit 2; }
fi

# ---------- 地址规范化 ----------
# normalize_origin <原始地址>
#   成功：设置 N_ORIGIN（规范化后的 origin）、N_HOST（不含方括号）、N_SCHEME，返回 0
#   失败：设置 ERRMSG（中文原因），返回 1
RE_IPV6='^\[([0-9A-Fa-f:.]+)\](:([0-9]{1,5}))?$'
RE_HOST='^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(:([0-9]{1,5}))?$'
RE_NUMERIC='^[0-9.]+$'
RE_IPV4='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
normalize_origin() {
  local raw="$1" scheme rest path host port host_fmt i
  ERRMSG=""
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  if [ -z "$raw" ]; then ERRMSG="地址为空"; return 1; fi
  case "${raw,,}" in
    http://*|https://*) ;;
    *) ERRMSG="地址必须以 http:// 或 https:// 开头（收到：$raw）"; return 1 ;;
  esac
  scheme="${raw%%://*}"; scheme="${scheme,,}"
  rest="${raw#*://}"
  case "$rest" in
    *[[:space:]]*|*\\*|*\"*|*\'*) ERRMSG="地址不得含空白、反斜杠或引号"; return 1 ;;
  esac
  if [[ "$rest" == */* ]]; then
    path="/${rest#*/}"; rest="${rest%%/*}"
    if [ "$path" != "/" ]; then
      ERRMSG="地址只能是 origin（协议://主机[:端口]），不能带路径（检测到路径 $path），请去掉路径后重试"
      return 1
    fi
  fi
  case "$rest" in
    *\?*|*\#*) ERRMSG="地址不得含查询串或片段（? #）"; return 1 ;;
    *@*) ERRMSG="地址不得含用户名或密码（@）"; return 1 ;;
  esac
  if [[ "$rest" =~ $RE_IPV6 ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]}"; host="${host,,}"; host_fmt="[$host]"
  elif [[ "$rest" =~ $RE_HOST ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[4]}"; host="${host,,}"; host_fmt="$host"
    if [[ "$host" =~ $RE_NUMERIC ]]; then
      if [[ "$host" =~ $RE_IPV4 ]]; then
        for i in 1 2 3 4; do
          if [ "$((10#${BASH_REMATCH[$i]}))" -gt 255 ]; then ERRMSG="不是合法的 IPv4 地址: $host"; return 1; fi
        done
      else
        ERRMSG="不是合法的 IPv4 地址: $host"; return 1
      fi
    fi
  else
    ERRMSG="主机或端口格式非法（收到：$rest）"; return 1
  fi
  if [ -n "$port" ]; then
    port="$((10#$port))"
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then ERRMSG="端口必须是 1 到 65535"; return 1; fi
    if { [ "$scheme" = http ] && [ "$port" = 80 ]; } || { [ "$scheme" = https ] && [ "$port" = 443 ]; }; then port=""; fi
  fi
  case "$host" in 0.0.0.0|::|::1|127.*|localhost) ERRMSG="地址不能是通配或回环地址"; return 1 ;; esac
  N_SCHEME="$scheme"; N_HOST="$host"; N_ORIGIN="$scheme://$host_fmt${port:+:$port}"
  return 0
}

# ---------- env 读写 ----------
read_env() { # file key
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1
}
has_key() { [ -f "$1" ] && grep -q "^$2=" "$1"; }
file_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# 在文件副本里设置一个键：保留其他行，重复键只留一个，缺失则追加。
set_key_in() { # file key value
  local f="$1" k="$2" v="$3" t
  t="$(mktemp "$f.sso.XXXXXX")"
  K="$k" V="$v" awk '
    BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; s = 0 }
    index($0, k "=") == 1 { if (!s) { print k "=" v; s = 1 } ; next }
    { print }
    END { if (!s) print k "=" v }
  ' "$f" >"$t"
  cat "$t" >"$f"   # 写回原 inode 副本，保留 cp -p 带来的属主/权限
  rm -f "$t"
}

tmp_files=()
cleanup() { local f; for f in "${tmp_files[@]:-}"; do [ -n "$f" ] && rm -f "$f"; done; return 0; }
trap cleanup EXIT HUP INT TERM

# rewrite_env <file> <KEY=VAL>...  ->  把改动落到临时副本；打印差异
# 结果：REWRITE_TMP（副本路径，无变化时为空）
rewrite_env() {
  local f="$1"; shift
  local work pair k v old changed=0
  REWRITE_TMP=""
  [ -f "$f" ] || return 0
  [ ! -L "$f" ] || die "拒绝改写符号链接: $f"
  work="$(mktemp "$f.sso.XXXXXX")"
  tmp_files+=("$work")
  cp -p "$f" "$work"
  say "  文件: $f"
  for pair in "$@"; do
    k="${pair%%=*}"; v="${pair#*=}"
    old="$(read_env "$f" "$k")"
    if [ "$old" = "$v" ] && [ "$(grep -c "^$k=" "$f")" -le 1 ]; then
      say "    $k 无变化"
      continue
    fi
    say "    $k: ${old:-<未设置>} -> $v"
    set_key_in "$work" "$k" "$v"
    changed=1
  done
  if [ "$changed" -eq 1 ]; then REWRITE_TMP="$work"; fi
}

commit_env() { # file tmp
  [ -n "$2" ] || return 0
  mv -f "$2" "$1"
}

# 把备份里的文件还原到原位（保留备份时的属主/权限）
restore_file() { # backup target
  local t
  [ ! -L "$2" ] || die "拒绝改写符号链接: $2"
  t="$(mktemp "$2.sso.XXXXXX")"
  tmp_files+=("$t")
  cp -p "$1" "$t"
  mv -f "$t" "$2"
}

# ---------- docker 容器定位（一律按 compose 项目 + service 标签） ----------
PROJECT_NAME=""
SCOPE_ARGS=()
SCOPE_DESC=""

# 决定“本次安装”的容器范围：项目名优先（显式 > .upgrade/project-name > .env 的
# COMPOSE_PROJECT_NAME），其次 compose 工作目录标签，最后在整机只有一个项目时取该项目。
resolve_scope() {
  local pname="" src="" wd probe projects count
  if [ -n "${JJD_COMPOSE_PROJECT:-}" ]; then pname="$JJD_COMPOSE_PROJECT"; src="环境变量 JJD_COMPOSE_PROJECT"
  elif [ -r "$COMPOSE_DIR/.upgrade/project-name" ]; then
    pname="$(tr -d '[:space:]' <"$COMPOSE_DIR/.upgrade/project-name")"; src=".upgrade/project-name"
  fi
  if [ -z "$pname" ]; then
    pname="$(read_env "$ENV_FILE" COMPOSE_PROJECT_NAME)"; [ -z "$pname" ] || src=".env COMPOSE_PROJECT_NAME"
  fi
  if [ -n "$pname" ]; then
    [[ "$pname" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "compose 项目名非法: $pname"
    probe="$("$DOCKER_BIN" ps -a -q --filter "label=com.docker.compose.project=$pname" 2>/dev/null | head -n 1 || true)"
    if [ -n "$probe" ]; then
      PROJECT_NAME="$pname"
      SCOPE_ARGS=(--filter "label=com.docker.compose.project=$pname")
      SCOPE_DESC="项目 $pname（来自 $src）"
      return 0
    fi
    warn "按项目名 $pname 没有找到容器，改用工作目录标签识别"
  fi
  for wd in "$COMPOSE_DIR" "$(cd "$COMPOSE_DIR" && pwd -P)"; do
    probe="$("$DOCKER_BIN" ps -a -q --filter "label=com.docker.compose.project.working_dir=$wd" 2>/dev/null | head -n 1 || true)"
    if [ -n "$probe" ]; then
      SCOPE_ARGS=(--filter "label=com.docker.compose.project.working_dir=$wd")
      SCOPE_DESC="工作目录 $wd"
      return 0
    fi
  done
  # 整机只有一个包含 postgres 服务的 compose 项目时，直接取它
  projects="$("$DOCKER_BIN" ps -a --filter "label=com.docker.compose.service=postgres" --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | sort -u | sed '/^$/d' || true)"
  count="$(printf '%s\n' "$projects" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "$count" = 1 ]; then
    PROJECT_NAME="$projects"
    SCOPE_ARGS=(--filter "label=com.docker.compose.project=$projects")
    SCOPE_DESC="项目 $projects（整机唯一）"
    return 0
  elif [ "$count" -gt 1 ]; then
    die "本机有多个 compose 项目（$(printf '%s' "$projects" | paste -sd, -)），无法确定本安装。请设置 JJD_COMPOSE_PROJECT=<项目名> 后重试"
  fi
  # 没有任何容器：保留工作目录范围，后续各步骤会按“容器不存在”逐项跳过
  SCOPE_ARGS=(--filter "label=com.docker.compose.project.working_dir=$COMPOSE_DIR")
  SCOPE_DESC="工作目录 $COMPOSE_DIR（未发现运行中的容器）"
}

svc_container() { # service -> 第一个容器 ID（含已停止），不存在则输出空
  "$DOCKER_BIN" ps -a -q "${SCOPE_ARGS[@]}" --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -n 1 || true
}
container_env() { # cid key -> 容器环境变量的值（只取指定键，绝不整体输出）
  [ -n "$1" ] || return 0
  "$DOCKER_BIN" inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null | sed -n "s/^$2=//p" | head -n 1 || true
}
container_cmd() { # cid -> 启动参数，每行一个
  [ -n "$1" ] || return 0
  "$DOCKER_BIN" inspect --format '{{range .Config.Cmd}}{{println .}}{{end}}' "$1" 2>/dev/null || true
}

# ---------- 启动链解析 ----------
COMPOSE_ARGS=()
CHAIN_SOURCE=""
CHAIN_FILES=()

# 与 jjdctl 一致：必须在 active-config 下、普通文件、自身不是软链。
# 在此基础上两边都先规范化为真实路径再比较：compose-files 可以用软链形式的目录前缀书写，
# 但解析后的真实路径必须仍落在真实 COMPOSE_DIR/active-config 内（拒绝 active-config 或其上级被软链逃逸）。
# 校验通过后规范化的真实路径存入 CHAIN_ENTRY_REAL。
CHAIN_ENTRY_REAL=""
is_active_chain_path() {
  local entry="$1" real_entry real_dir real_active
  CHAIN_ENTRY_REAL=""
  [[ "$entry" == /* && -f "$entry" && ! -L "$entry" ]] || return 1
  real_entry="$(readlink -f -- "$entry")" || return 1
  real_dir="$(CDPATH= cd -- "$COMPOSE_DIR" && pwd -P)" || return 1
  real_active="$(readlink -f -- "$COMPOSE_DIR/active-config")" || return 1
  [[ "$real_active" == "$real_dir/active-config" ]] || return 1
  [[ "$real_entry" == "$real_active/"* && -f "$real_entry" && ! -L "$real_entry" ]] || return 1
  CHAIN_ENTRY_REAL="$real_entry"
}

resolve_chain_from_file() {
  local chain="$COMPOSE_DIR/.upgrade/compose-files" entry pname="" pdir="$COMPOSE_DIR"
  [ -r "$chain" ] && [ -f "$chain" ] && [ ! -L "$chain" ] || return 1
  CHAIN_FILES=("$COMPOSE_DIR/docker-compose.offline.yml")
  while IFS= read -r entry || [ -n "$entry" ]; do
    [ -n "$entry" ] || continue
    is_active_chain_path "$entry" || die "活动 Compose 链包含非法路径: $entry"
    CHAIN_FILES+=("$CHAIN_ENTRY_REAL")
  done <"$chain"
  [ -r "$COMPOSE_DIR/.upgrade/project-name" ] && pname="$(tr -d '[:space:]' <"$COMPOSE_DIR/.upgrade/project-name")"
  [ -r "$COMPOSE_DIR/.upgrade/project-directory" ] && pdir="$(tr -d '\r\n' <"$COMPOSE_DIR/.upgrade/project-directory")"
  [[ -z "$pname" || "$pname" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "活动 Compose 项目名非法"
  # 没有 project-name 文件时，沿用已识别的项目名，保证 up 作用在同一个项目上
  [ -n "$pname" ] || pname="$PROJECT_NAME"
  COMPOSE_ARGS=()
  [ -z "$pname" ] || COMPOSE_ARGS+=(--project-name "$pname")
  [ -z "$pname" ] || COMPOSE_ARGS+=(--project-directory "$pdir")
  COMPOSE_ARGS+=(--env-file "$ENV_FILE")
  local f; for f in "${CHAIN_FILES[@]}"; do COMPOSE_ARGS+=(-f "$f"); done
  CHAIN_SOURCE="file:$chain"
}

# 运行中容器标签：com.docker.compose.project.config_files 即该容器创建时的完整 -f 链
resolve_chain_from_labels() {
  local cid probe labels project workdir files envfile f
  for probe in control-plane gateway-core postgres; do
    cid="$(svc_container "$probe")"
    [ -n "$cid" ] && break
  done
  [ -n "$cid" ] || return 1
  labels="$("$DOCKER_BIN" inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.project.working_dir" }}|{{ index .Config.Labels "com.docker.compose.project.config_files" }}|{{ index .Config.Labels "com.docker.compose.project.environment_file" }}' "$cid" 2>/dev/null)" || return 1
  IFS='|' read -r project workdir files envfile <<<"$labels"
  [ -n "$project" ] && [ -n "$files" ] || return 1
  [[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "容器标签中的项目名非法"
  CHAIN_FILES=()
  local IFS=','
  for f in $files; do
    [ -f "$f" ] || die "容器标签引用的 Compose 文件不存在: $f"
    CHAIN_FILES+=("$f")
  done
  unset IFS
  [ -n "$envfile" ] && [ -f "$envfile" ] || envfile="$ENV_FILE"
  COMPOSE_ARGS=(--project-name "$project")
  [ -z "$workdir" ] || COMPOSE_ARGS+=(--project-directory "$workdir")
  COMPOSE_ARGS+=(--env-file "$envfile")
  for f in "${CHAIN_FILES[@]}"; do COMPOSE_ARGS+=(-f "$f"); done
  CHAIN_SOURCE="labels:container=${cid:0:12}"
}

resolve_chain() {
  case "$CHAIN_MODE" in
    file) resolve_chain_from_file || die "无法读取 $COMPOSE_DIR/.upgrade/compose-files（需 root 读取）" ;;
    labels) resolve_chain_from_labels || die "找不到运行中的 Compose 容器标签" ;;
    auto)
      if ! resolve_chain_from_file; then
        note "没有可读的 .upgrade/compose-files（老版本部署），回退到运行中容器标签"
        resolve_chain_from_labels || die "无法确定启动链：既没有可读的 .upgrade/compose-files，也没有运行中的 Compose 容器标签（可手动先用 jjdctl 启动）"
      fi
      ;;
  esac
  # 启动链文件 vs 运行中容器标签：不一致说明运行态可能是手工拼出来的（现场回退镜像的根因）
  if [ "$CHAIN_MODE" = auto ] && [[ "$CHAIN_SOURCE" == file:* ]]; then
    local label_files saved_args saved_src saved_files
    saved_args=("${COMPOSE_ARGS[@]}"); saved_src="$CHAIN_SOURCE"; saved_files=("${CHAIN_FILES[@]}")
    # 子 shell 探测：失败（无容器、标签文件不存在等）只是不比较，绝不能中止主流程。
    label_files="$( (resolve_chain_from_labels >/dev/null 2>&1 && printf '%s' "${CHAIN_FILES[*]}") 2>/dev/null || true )"
    COMPOSE_ARGS=("${saved_args[@]}"); CHAIN_SOURCE="$saved_src"; CHAIN_FILES=("${saved_files[@]}")
    if [ -n "$label_files" ] && [ "$label_files" != "${CHAIN_FILES[*]}" ]; then
      warn "运行中容器的配置链与 .upgrade/compose-files 不一致："
      warn "  启动链文件: ${CHAIN_FILES[*]}"
      warn "  容器标签:   $label_files"
      warn "  将按启动链文件重建（与 jjdctl restart 一致）；若容器是手工重建的，重建后服务会回到启动链的配置。"
    fi
  fi
}

# 统一的 compose 入口（仅用于 config / up）：永远带完整启动链，绝不退化成裸 offline.yml
dc() { (cd "$COMPOSE_DIR" && sh "$COMPOSE_WRAPPER" "${COMPOSE_ARGS[@]}" "$@"); }

# ---------- 镜像漂移检查 + 重建 ----------
config_image() { # 服务名 -> compose 渲染后的 image
  dc config 2>/dev/null | awk -v svc="$1" '
    $0 ~ "^  " svc ":$" { in_svc = 1; next }
    in_svc && /^  [A-Za-z0-9_-]+:$/ { in_svc = 0 }
    in_svc && $1 == "image:" { print $2; exit }'
}
running_image() { # 服务名 -> 运行中容器的 image 引用
  local cid
  cid="$(svc_container "$1")"
  [ -n "$cid" ] || return 0
  "$DOCKER_BIN" inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || true
}

recreate_services() { # 失败提示里引用 BACKUP_DIR / RESTORE_HINT
  if [ "$SKIP_RECREATE" -eq 1 ]; then
    say "  已跳过（--skip-recreate）。自行重建时必须带完整启动链: ${CHAIN_FILES[*]}"
    return 0
  fi
  local targets=() s ri ci drift=0
  for s in "${AFFECTED_SERVICES[@]}"; do
    if [ -n "$(svc_container "$s")" ]; then targets+=("$s"); else note "服务 $s 没有容器（未启用或老版本），不重建"; fi
  done
  if [ "${#targets[@]}" -eq 0 ]; then
    say "  没有找到已创建的受影响服务容器，无需重建"
    return 0
  fi
  for s in "${targets[@]}"; do
    ri="$(running_image "$s")"; ci="$(config_image "$s")"
    if [ -n "$ri" ] && [ -n "$ci" ] && [ "$ri" != "$ci" ]; then
      warn "镜像漂移: $s 运行中=$ri 启动链渲染=$ci"
      drift=1
    fi
  done
  say "  将重建: ${targets[*]}"
  say "  命令:   compose ${COMPOSE_ARGS[*]} up -d --no-deps --force-recreate ${targets[*]}"
  if [ "$drift" -eq 1 ] && [ "$ALLOW_IMAGE_CHANGE" -eq 0 ]; then
    if [ "$APPLY" -eq 1 ]; then
      die "重建会改变镜像引用（上方已列出）。通常说明启动链不是现网实际使用的链；确认无误后加 --allow-image-change。${RESTORE_HINT:-}"
    fi
    warn "apply 时会因镜像漂移而拒绝，除非加 --allow-image-change"
  fi
  if [ "$APPLY" -eq 1 ]; then
    dc up -d --no-deps --force-recreate "${targets[@]}" || die "重建服务失败。${RESTORE_HINT:-}"
    say "  已重建"
  fi
}

# ---------- Keycloak ----------
IDP_CID=""
KC_REALM=""
KC_REL="/sso"
KC_PORT="8180"
KC_READY=0

kc() { # kcadm 参数
  # </dev/null：kc 常在 while-read 循环里被调用，docker exec -i 会吞掉循环的 stdin，导致后续客户端被跳过
  if [ -n "${KCADM_BIN:-}" ]; then "$KCADM_BIN" "$@" </dev/null; return; fi
  "$DOCKER_BIN" exec -i "$IDP_CID" /opt/keycloak/bin/kcadm.sh "$@" </dev/null
}
kc_login() { # 成功返回 0；失败返回 1（调用方决定是否致命）
  [ -z "${KCADM_BIN:-}" ] || return 0
  # 凭据只在容器内展开，不经过宿主 argv、不打印。
  "$DOCKER_BIN" exec -i "$IDP_CID" sh -c '
    u="${KC_BOOTSTRAP_ADMIN_USERNAME:-${KEYCLOAK_ADMIN:-admin}}"
    p="${KC_BOOTSTRAP_ADMIN_PASSWORD:-$KEYCLOAK_ADMIN_PASSWORD}"
    /opt/keycloak/bin/kcadm.sh config credentials --server "http://localhost:'"$KC_PORT$KC_REL"'" --realm master --user "$u" --password "$p"' </dev/null >/dev/null 2>&1
}
json_id() { tr -d '\n' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1; }
json_array() { # 字段名；从 stdin 取简单字符串数组，一行一个
  tr -d '\n' | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p" | tr ',' '\n' | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//' | sed '/^$/d'
}
json_attr() { # 属性名
  tr -d '\n' | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}
union_lines() { awk 'NF && !seen[$0]++'; }
to_json_array() { # 换行分隔的列表 -> ["a","b"]
  local out="" l
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    case "$l" in *\"*|*\\*) die "Keycloak 地址含引号或反斜杠，拒绝处理: $l" ;; esac
    out+="${out:+,}\"$l\""
  done <<<"$1"
  printf '[%s]' "$out"
}
join_logout() { awk 'NF { printf "%s%s", (n++ ? "##" : ""), $0 }'; }

# 从 .env / 容器配置推导 Keycloak 相关参数；推导不出才用产品默认值
derive_keycloak_params() {
  local envrel cmd_port arg
  KC_REALM="$(read_env "$ENV_FILE" CHAT_REALM)"
  if [ -z "$KC_REALM" ] && [ -n "$OLD_ENV_ISSUER" ]; then KC_REALM="${OLD_ENV_ISSUER##*/realms/}"; fi
  KC_REALM="${KC_REALM:-jjdguard}"
  [[ "$KC_REALM" =~ ^[A-Za-z0-9._-]+$ ]] || die "realm 名非法: $KC_REALM"

  # 子路径：容器实际生效值 > 现有 issuer 中的路径 > 默认 /sso
  envrel="$(container_env "$IDP_CID" KC_HTTP_RELATIVE_PATH)"
  if [ -n "$envrel" ]; then KC_REL="$envrel"
  elif [ -n "$OLD_ENV_ISSUER" ] && [[ "$OLD_ENV_ISSUER" == *"/realms/"* ]]; then
    KC_REL="${OLD_ENV_ISSUER#*://}"; KC_REL="${KC_REL#*/}"; KC_REL="${KC_REL%%/realms/*}"
    [ "$KC_REL" = "${OLD_ENV_ISSUER#*://}" ] && KC_REL=""
    KC_REL="/$KC_REL"
  fi
  KC_REL="/${KC_REL#/}"; KC_REL="${KC_REL%/}"
  [[ "$KC_REL" =~ ^(/[A-Za-z0-9._~-]+)*$ ]] || die "Keycloak 子路径非法: $KC_REL"

  # 管理端口：--http-port 参数 > KC_HTTP_PORT > 8180
  cmd_port=""
  while IFS= read -r arg; do
    case "$arg" in --http-port=*) cmd_port="${arg#--http-port=}" ;; esac
  done < <(container_cmd "$IDP_CID")
  KC_PORT="${cmd_port:-$(container_env "$IDP_CID" KC_HTTP_PORT)}"
  KC_PORT="${KC_PORT:-8180}"
  [[ "$KC_PORT" =~ ^[0-9]{1,5}$ ]] || die "Keycloak 端口非法: $KC_PORT"
}

path_of_url() { # https://h:p/x/y -> /x/y
  local r="${1#*://}"
  [[ "$r" == */* ]] && printf '/%s' "${r#*/}"
  return 0
}

KC_SUMMARY=()
# reconcile_kc_client <clientId> <redirect;分号分隔> <webOrigin;分号分隔> <post-logout;分号分隔>
reconcile_kc_client() {
  local cid="$1" want_redirect="$2" want_origins="$3" want_logout="$4"
  local raw uuid cur_redirect cur_origins cur_logout new_redirect new_origins new_logout
  raw="$(kc get clients -r "$KC_REALM" -q "clientId=$cid" --fields "id,redirectUris,webOrigins,attributes(*)" 2>/dev/null)" || die "查询 Keycloak 客户端 $cid 失败"
  uuid="$(printf '%s' "$raw" | json_id)"
  if [ -z "$uuid" ]; then warn "Keycloak realm $KC_REALM 中没有客户端 $cid，跳过"; return 0; fi
  [[ "$uuid" =~ ^[A-Za-z0-9._-]+$ ]] || die "Keycloak 客户端内部 ID 格式异常: $cid"
  cur_redirect="$(printf '%s' "$raw" | json_array redirectUris)"
  cur_origins="$(printf '%s' "$raw" | json_array webOrigins)"
  cur_logout="$(printf '%s' "$raw" | json_attr 'post.logout.redirect.uris' | sed 's/##/\n/g')"
  local want_r want_o want_l
  want_r="$(printf '%s' "$want_redirect" | tr ';' '\n')"
  want_o="$(printf '%s' "$want_origins" | tr ';' '\n')"
  want_l="$(printf '%s' "$want_logout" | tr ';' '\n')"
  if [ "$DROP_OLD" -eq 1 ]; then
    new_redirect="$want_r"; new_origins="$want_o"; new_logout="$want_l"
  else
    new_redirect="$(printf '%s\n%s\n' "$cur_redirect" "$want_r" | union_lines)"
    new_origins="$(printf '%s\n%s\n' "$cur_origins" "$want_o" | union_lines)"
    new_logout="$(printf '%s\n%s\n' "$cur_logout" "$want_l" | union_lines)"
  fi
  say "  客户端 $cid（realm $KC_REALM）"
  say "    redirectUris -> $(printf '%s' "$new_redirect" | paste -sd' ' -)"
  say "    webOrigins   -> $(printf '%s' "$new_origins" | paste -sd' ' -)"
  say "    post.logout.redirect.uris -> $(printf '%s\n' "$new_logout" | join_logout)"
  [ "$APPLY" -eq 1 ] || return 0
  # 备份：导出客户端完整 JSON（rollback 只回写 redirect/webOrigins/post-logout 三项，不回写 secret）
  mkdir -p "$BACKUP_DIR/keycloak-clients"
  (umask 077; kc get "clients/$uuid" -r "$KC_REALM" >"$BACKUP_DIR/keycloak-clients/$cid.json") ||
    die "导出 Keycloak 客户端 $cid 备份失败，已中止（该客户端尚未改动）。${RESTORE_HINT:-}"
  [ -s "$BACKUP_DIR/keycloak-clients/$cid.json" ] || die "Keycloak 客户端 $cid 备份为空，已中止。${RESTORE_HINT:-}"
  printf 'KC_CLIENT=%s|%s\n' "$cid" "$uuid" >>"$BACKUP_DIR/meta.env"
  kc_put_client "$uuid" "$new_redirect" "$new_origins" "$new_logout" || die "更新 Keycloak 客户端 $cid 失败。${RESTORE_HINT:-}"
  KC_SUMMARY+=("$cid")
}
kc_put_client() { # uuid redirect(换行) origins(换行) logout(换行)
  local arr_r arr_o logout_attr
  arr_r="$(to_json_array "$2")"; arr_o="$(to_json_array "$3")"
  logout_attr="$(printf '%s\n' "$4" | join_logout)"
  kc update "clients/$1" -r "$KC_REALM" \
    -s "redirectUris=$arr_r" -s "webOrigins=$arr_o" \
    -s "attributes.\"post.logout.redirect.uris\"=$logout_attr" >/dev/null
}

# 准备 Keycloak：成功时 KC_READY=1。dry_ok=1 表示失败只提示（dry-run 里允许 Keycloak 不可达）
prepare_keycloak() {
  KC_READY=0
  if [ "$SKIP_KC" -eq 1 ]; then say "  已跳过（--skip-keycloak）"; return 0; fi
  if [ "$BYO" = "true" ]; then
    note "CHAT_BYO_IDP=true：使用外部 IdP，本命令不改 Keycloak。请在外部 IdP 上为下列地址追加登记（旧地址可保留到验证完成）："
    say "    登录回调:   $NEW_ORIGIN$UI_ACCT_PATH、$NEW_ORIGIN$UI_SSO_PATH、$NEW_ORIGIN$ADMIN_CB_PATH"
    say "    登出回跳:   $NEW_ORIGIN/chat、$NEW_ORIGIN/chat/*、$NEW_ORIGIN、$NEW_ORIGIN/*"
    say "    Web Origin: $NEW_ORIGIN"
    return 0
  fi
  if [ "$CHAT_INSTALLED" -eq 0 ]; then note "未检测到 chat/SSO 配置（老版本或未启用门户），跳过 Keycloak"; return 0; fi
  IDP_CID="$(svc_container chat-idp)"
  if [ -z "$IDP_CID" ] && [ -z "${KCADM_BIN:-}" ]; then
    note "未找到 chat-idp 容器（未启用内置 Keycloak），跳过 Keycloak 步骤"
    return 0
  fi
  derive_keycloak_params
  say "  realm=$KC_REALM  子路径=$KC_REL  管理端口=$KC_PORT  容器=${IDP_CID:0:12}${IDP_CID:+ }"
  say "  客户端: $UI_CLIENT, $ADMIN_CLIENT"
  if kc_login; then KC_READY=1
  elif [ "$APPLY" -eq 1 ]; then die "Keycloak 管理登录失败（chat-idp 未运行或管理员凭据已变更）。可加 --skip-keycloak 后手工处理。${RESTORE_HINT:-}"
  else warn "Keycloak 当前不可达，dry-run 仅展示计划"; fi
}

# ---------- 数据库 ----------
PGCID=""
PGUSER_=""
PGDB_=""
DB_STATE="skip"     # skip|byo|none|nocontainer|notable|error|ok
LINK_COLS=""
psql_run() { "$DOCKER_BIN" exec -i "$PGCID" psql -X -v ON_ERROR_STOP=1 -U "$PGUSER_" -d "$PGDB_" "$@"; }
psql_q() { printf '%s\n' "$1" | psql_run -At "${@:2}"; }

# 解析数据库连接参数：容器 env（POSTGRES_USER/POSTGRES_DB）> .env > 产品默认值
init_db_conn() {
  PGCID="$(svc_container postgres)"
  [ -n "$PGCID" ] || return 1
  PGUSER_="$(container_env "$PGCID" POSTGRES_USER)"; PGUSER_="${PGUSER_:-$(read_env "$ENV_FILE" POSTGRES_USER)}"; PGUSER_="${PGUSER_:-jjdguard}"
  PGDB_="$(container_env "$PGCID" POSTGRES_DB)"; PGDB_="${PGDB_:-$(read_env "$ENV_FILE" POSTGRES_DB)}"; PGDB_="${PGDB_:-$PGUSER_}"
  [[ "$PGUSER_" =~ ^[A-Za-z0-9_.-]+$ && "$PGDB_" =~ ^[A-Za-z0-9_.-]+$ ]] || die "数据库用户或库名含非法字符"
  return 0
}

db_probe() { # 设置 DB_STATE / LINK_COLS
  local r cols
  if ! init_db_conn; then DB_STATE=nocontainer; return 0; fi
  r="$(psql_q "SELECT to_regclass('user_identity_links') IS NOT NULL;" 2>/dev/null | tail -n 1 || true)"
  case "$r" in
    t) ;;
    f) DB_STATE=notable; return 0 ;;
    *) DB_STATE=error; return 0 ;;
  esac
  # 复制的列 = 表里除 id/issuer/时间戳之外的所有列（自动适配不同版本的表结构）
  cols="$(psql_q "SELECT string_agg(quote_ident(column_name), ',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'user_identity_links' AND column_name NOT IN ('id','issuer','created_at','updated_at');" 2>/dev/null | tail -n 1 || true)"
  [[ "$cols" =~ ^[a-z_][a-z0-9_]*(,[a-z_][a-z0-9_]*)*$ ]] || { DB_STATE=error; return 0; }
  for need in tenant_id source_type external_subject; do
    [[ ",$cols," == *",$need,"* ]] || { DB_STATE=error; warn "user_identity_links 缺少列 $need，表结构不认识，跳过数据库步骤"; return 0; }
  done
  LINK_COLS="$cols"; DB_STATE=ok
}

link_insert_sql() { # 按所有租户复制：同租户 + 同 source_type + 同 subject 已有新 issuer 行则跳过
  local c sel="" ins=""
  local IFS=','
  for c in $LINK_COLS; do sel+="l.$c,"; ins+="$c,"; done
  unset IFS
  cat <<SQL
WITH ins AS (
  INSERT INTO user_identity_links (id, issuer, ${ins%,})
  SELECT 'uil_' || md5(random()::text || clock_timestamp()::text || l.id || :'new_issuer'),
         :'new_issuer', ${sel%,}
    FROM user_identity_links l
   WHERE l.issuer = :'old_issuer'
     AND NOT EXISTS (
       SELECT 1 FROM user_identity_links n
        WHERE n.tenant_id = l.tenant_id AND n.issuer = :'new_issuer'
          AND n.source_type = l.source_type AND n.external_subject = l.external_subject)
  ON CONFLICT DO NOTHING
  RETURNING id)
SELECT id FROM ins;
SQL
}
LINK_COUNT_SQL='SELECT count(*), count(DISTINCT l.tenant_id) FROM user_identity_links l
 WHERE l.issuer = :'"'"'old_issuer'"'"'
   AND NOT EXISTS (
     SELECT 1 FROM user_identity_links n
      WHERE n.tenant_id = l.tenant_id AND n.issuer = :'"'"'new_issuer'"'"'
        AND n.source_type = l.source_type AND n.external_subject = l.external_subject);'
LINK_DELETE_SQL='WITH del AS (
  DELETE FROM user_identity_links
   WHERE id = ANY(string_to_array(:'"'"'ids'"'"', '"'"','"'"')) AND issuer = :'"'"'new_issuer'"'"'
  RETURNING 1)
SELECT count(*) FROM del;'

# ================= 回滚 =================
do_rollback() {
  local dir="$ROLLBACK_DIR" meta cur_url cur_n m_n m_new m_old m_realm kc_lines line cid uuid sha_env sha_rt now_env now_rt k ids n
  [ -d "$dir" ] && [ ! -L "$dir" ] || die "备份目录不存在或不是普通目录: $dir"
  dir="$(cd "$dir" && pwd)"
  meta="$dir/meta.env"
  [ -f "$meta" ] && [ ! -L "$meta" ] || die "$dir 不是 set-public-url 生成的备份目录（缺少 meta.env）"
  [ -f "$dir/env.bak" ] || die "备份缺少 env.bak"
  m_old="$(read_env "$meta" OLD_URL)"; m_new="$(read_env "$meta" NEW_URL)"
  m_realm="$(read_env "$meta" REALM)"
  [ -n "$m_new" ] || die "meta.env 缺少 NEW_URL"
  BACKUP_DIR="$dir"
  RESTORE_HINT="可修正后重新执行 rollback（回滚各步骤均可重复执行）。"

  local MODE_TXT="dry-run（不会改动任何东西，加 --apply 执行）"
  [ "$APPLY" -eq 0 ] || MODE_TXT="APPLY（真实执行）"
  say "== JJDGuard SSO 对外地址回滚 =="
  say "模式:     $MODE_TXT"
  say "备份目录: $dir"
  say "回滚目标: $m_new -> ${m_old:-<原先未设置>}"

  # 保护：apply 之后配置又被改过（例如又做了一次变更），盲目还原会丢失后来的改动
  cur_url="$(read_env "$ENV_FILE" JJD_SSO_PUBLIC_URL)"
  cur_n=""; normalize_origin "$cur_url" >/dev/null 2>&1 && cur_n="$N_ORIGIN"
  m_n="$m_new"; normalize_origin "$m_new" >/dev/null 2>&1 && m_n="$N_ORIGIN"
  if [ "$cur_n" != "$m_n" ]; then
    if [ "$FORCE" -eq 1 ]; then warn "当前 JJD_SSO_PUBLIC_URL=${cur_url:-<未设置>} 与备份记录的 $m_new 不同，已按 --force 继续"
    else die "当前 JJD_SSO_PUBLIC_URL=${cur_url:-<未设置>} 与该备份记录的变更结果 $m_new 不一致，说明之后又改过。确认要还原到此备份请加 --force"; fi
  fi
  sha_env="$(read_env "$meta" ENV_SHA_AFTER)"; sha_rt="$(read_env "$meta" RUNTIME_SHA_AFTER)"
  if [ -n "$sha_env" ] && [ -f "$ENV_FILE" ] && [ "$(file_sha "$ENV_FILE")" != "$sha_env" ]; then
    if [ "$FORCE" -eq 1 ]; then warn ".env 自 apply 之后被修改过，已按 --force 整文件还原（其他改动将丢失）"
    else die ".env 自 apply 之后又被修改过，整文件还原会丢失这些改动。确认请加 --force，或手工合并 $dir/env.bak"; fi
  fi
  if [ -n "$sha_rt" ] && [ -f "$RUNTIME_ENV_FILE" ] && [ "$(file_sha "$RUNTIME_ENV_FILE")" != "$sha_rt" ]; then
    if [ "$FORCE" -eq 1 ]; then warn "identity-runtime.env 自 apply 之后被修改过，已按 --force 整文件还原"
    else die "identity-runtime.env 自 apply 之后又被修改过，确认请加 --force"; fi
  fi

  resolve_scope
  say "容器范围: $SCOPE_DESC"
  resolve_chain
  say "启动链来源: $CHAIN_SOURCE"
  say "启动链文件: ${CHAIN_FILES[*]}"

  # 1) 环境文件
  say ""
  say "[1/4] 还原环境文件"
  say "  $ENV_FILE <- $dir/env.bak"
  for k in "${WHITELIST_KEYS[@]}"; do
    now_env="$(read_env "$ENV_FILE" "$k")"
    if has_key "$dir/env.bak" "$k" || has_key "$ENV_FILE" "$k"; then
      say "    $k: ${now_env:-<未设置>} -> $(read_env "$dir/env.bak" "$k" | sed 's/^$/<未设置>/')"
    fi
  done
  if [ -f "$dir/identity-runtime.env.bak" ]; then
    say "  $RUNTIME_ENV_FILE <- $dir/identity-runtime.env.bak"
    now_rt="$(read_env "$RUNTIME_ENV_FILE" JJD_SSO_PUBLIC_URL)"
    say "    JJD_SSO_PUBLIC_URL: ${now_rt:-<未设置>} -> $(read_env "$dir/identity-runtime.env.bak" JJD_SSO_PUBLIC_URL)"
  else
    note "备份中没有 identity-runtime.env（变更时该文件不存在），不处理"
  fi
  if [ "$APPLY" -eq 1 ]; then
    restore_file "$dir/env.bak" "$ENV_FILE"
    [ ! -f "$dir/identity-runtime.env.bak" ] || restore_file "$dir/identity-runtime.env.bak" "$RUNTIME_ENV_FILE"
    say "  已还原"
  fi

  # 2) 数据库：只删除本次新增的行
  say ""
  say "[2/4] 删除本次新增的 user_identity_links 行"
  ids=""
  if [ -f "$dir/added-link-ids.txt" ]; then ids="$(sed '/^$/d' "$dir/added-link-ids.txt" | paste -sd, -)"; fi
  if [ "$SKIP_DB" -eq 1 ]; then say "  已跳过（--skip-db）"
  elif [ -z "$ids" ]; then say "  备份中没有新增行记录，无需删除"
  else
    [[ "$ids" =~ ^[A-Za-z0-9_,-]+$ ]] || die "added-link-ids.txt 含非法字符，拒绝执行"
    n="$(printf '%s\n' "$ids" | tr ',' '\n' | wc -l | tr -d ' ')"
    say "  将删除 $n 行（id 记录于 $dir/added-link-ids.txt，且要求 issuer=$(read_env "$meta" NEW_ISSUER)）；旧 issuer 的行始终保留"
    if [ "$APPLY" -eq 1 ]; then
      init_db_conn || die "找不到 postgres 容器，无法删除新增的 identity link（可加 --skip-db 跳过后手工处理）"
      n="$(printf '%s\n' "$LINK_DELETE_SQL" | psql_run -At -v "ids=$ids" -v "new_issuer=$(read_env "$meta" NEW_ISSUER)" | tail -n 1)" ||
        die "删除新增的 identity link 失败"
      say "  已删除 ${n:-?} 行"
    fi
  fi

  # 3) Keycloak
  say ""
  say "[3/4] 还原 Keycloak 客户端属性"
  kc_lines="$(grep '^KC_CLIENT=' "$meta" | sed 's/^KC_CLIENT=//' || true)"
  if [ "$SKIP_KC" -eq 1 ]; then say "  已跳过（--skip-keycloak）"
  elif [ -z "$kc_lines" ]; then say "  备份中没有 Keycloak 客户端记录，无需还原"
  else
    CHAT_INSTALLED=1; BYO=""; OLD_ENV_ISSUER="$(read_env "$dir/env.bak" CHAT_OIDC_ISSUER)"
    NEW_ORIGIN="$m_new"; UI_ACCT_PATH=""; UI_SSO_PATH=""; ADMIN_CB_PATH=""; UI_CLIENT=""; ADMIN_CLIENT=""
    IDP_CID="$(svc_container chat-idp)"
    if [ -z "$IDP_CID" ] && [ -z "${KCADM_BIN:-}" ]; then
      [ "$APPLY" -eq 0 ] || die "未找到 chat-idp 容器，无法还原 Keycloak 客户端（可加 --skip-keycloak 后手工处理）"
      warn "未找到 chat-idp 容器，apply 时会失败（除非加 --skip-keycloak）"
    else
      derive_keycloak_params
      [ -z "$m_realm" ] || KC_REALM="$m_realm"
      if [ "$APPLY" -eq 1 ]; then kc_login || die "Keycloak 管理登录失败，无法还原客户端"; fi
      while IFS='|' read -r cid uuid; do
        [ -n "$cid" ] || continue
        [ -s "$dir/keycloak-clients/$cid.json" ] || die "备份缺少客户端 $cid 的 JSON"
        local j_r j_o j_l
        j_r="$(json_array redirectUris <"$dir/keycloak-clients/$cid.json")"
        j_o="$(json_array webOrigins <"$dir/keycloak-clients/$cid.json")"
        j_l="$(json_attr 'post.logout.redirect.uris' <"$dir/keycloak-clients/$cid.json" | sed 's/##/\n/g')"
        say "  客户端 $cid <- keycloak-clients/$cid.json"
        say "    redirectUris -> $(printf '%s' "$j_r" | paste -sd' ' -)"
        say "    post.logout.redirect.uris -> $(printf '%s\n' "$j_l" | join_logout)"
        if [ "$APPLY" -eq 1 ]; then
          [[ "$uuid" =~ ^[A-Za-z0-9._-]+$ ]] || die "meta.env 中的客户端 ID 格式异常"
          kc_put_client "$uuid" "$j_r" "$j_o" "$j_l" || die "还原 Keycloak 客户端 $cid 失败"
        fi
      done <<<"$kc_lines"
    fi
  fi

  # 4) 重建
  say ""
  say "[4/4] 按当前启动链重建受影响服务"
  recreate_services

  say ""
  if [ "$APPLY" -eq 1 ]; then
    date -u +%Y-%m-%dT%H:%M:%SZ >"$dir/rolled-back-at" 2>/dev/null || true
    say "回滚完成。备份目录保留: $dir"
  else
    say "以上为 dry-run，未做任何改动。确认后追加 --apply 执行。"
  fi
}

if [ -n "$ROLLBACK_DIR" ]; then
  do_rollback
  exit 0
fi

# ================= 变更：校验新地址 =================
normalize_origin "$NEW_URL" || die "新地址不合法：$ERRMSG"
NEW_ORIGIN="$N_ORIGIN"; NEW_HOST="$N_HOST"
if [ "$N_SCHEME" = https ]; then NEW_INSECURE=false
else NEW_INSECURE=true; warn "新地址是 http，将设置 JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=true"; fi
if [ "$NEW_ORIGIN" != "${NEW_URL%/}" ]; then note "新地址已规范化: ${NEW_URL} -> $NEW_ORIGIN"; fi

# ---------- 旧值与计划 ----------
[ -f "$ENV_FILE" ] || die "找不到 $ENV_FILE"
OLD_URL="$(read_env "$ENV_FILE" JJD_SSO_PUBLIC_URL)"; OLD_URL="${OLD_URL%/}"
OLD_RT_URL="$(read_env "$RUNTIME_ENV_FILE" JJD_SSO_PUBLIC_URL)"; OLD_RT_URL="${OLD_RT_URL%/}"
OLD_ENV_ISSUER="$(read_env "$ENV_FILE" CHAT_OIDC_ISSUER)"; OLD_ENV_ISSUER="${OLD_ENV_ISSUER%/}"
BYO="$(read_env "$ENV_FILE" CHAT_BYO_IDP)"
OLD_HOST_ENV="$(read_env "$ENV_FILE" CHAT_OIDC_HOST)"

CHAT_INSTALLED=0
if has_key "$ENV_FILE" CHAT_OIDC_HOST || has_key "$ENV_FILE" CHAT_OIDC_ISSUER || has_key "$ENV_FILE" CHAT_PORTAL_UI_OIDC_CLIENT_ID; then
  CHAT_INSTALLED=1
fi

# 旧地址规范化后与新地址比较
OLD_N=""; normalize_origin "$OLD_URL" >/dev/null 2>&1 && OLD_N="$N_ORIGIN"
OLD_RT_N=""; normalize_origin "$OLD_RT_URL" >/dev/null 2>&1 && OLD_RT_N="$N_ORIGIN"

# 地址一致：先判断是否真的“全部一致”，一致则无事可做（除非要求 --drop-old 清理 Keycloak）
if [ "$OLD_N" = "$NEW_ORIGIN" ] && [ -z "$ROLLBACK_DIR" ] && [ "$DROP_OLD" -eq 0 ]; then
  consistent=1
  [ -z "$OLD_RT_URL" ] || [ "$OLD_RT_N" = "$NEW_ORIGIN" ] || consistent=0
  if [ "$CHAT_INSTALLED" -eq 1 ]; then
    [ -z "$OLD_HOST_ENV" ] || [ "${OLD_HOST_ENV,,}" = "$NEW_HOST" ] || consistent=0
  fi
  if [ "$consistent" -eq 1 ]; then
    say "新地址 $NEW_ORIGIN 与当前地址 ${OLD_URL} 一致（无变化），无需变更。"
    # 上一次 apply 若中途失败（env 已写、数据库/Keycloak 未完成），再跑会落到这里：给出恢复指引
    for d in $(ls -1dt "$BACKUP_ROOT"/sso-public-url-* 2>/dev/null | head -n 1); do
      if [ -f "$d/meta.env" ] && [ ! -f "$d/completed" ] && [ ! -f "$d/rolled-back-at" ]; then
        warn "发现未完成的变更备份 $d（上次 apply 可能中途失败）。如需重来：jjdctl sso rollback $d --apply，然后重新执行本命令"
      fi
    done
    exit 0
  fi
  note "JJD_SSO_PUBLIC_URL 已是 $NEW_ORIGIN，但相关配置（identity-runtime.env 或 CHAT_OIDC_HOST）不一致，按修复模式继续"
fi

# 派生参数（realm、子路径）在没有容器信息时先用 .env/issuer 推导，容器信息在 Keycloak 步骤里补强
resolve_scope
REALM_PRE="$(read_env "$ENV_FILE" CHAT_REALM)"
if [ -z "$REALM_PRE" ] && [ -n "$OLD_ENV_ISSUER" ] && [[ "$OLD_ENV_ISSUER" == *"/realms/"* ]]; then REALM_PRE="${OLD_ENV_ISSUER##*/realms/}"; fi
REALM_PRE="${REALM_PRE:-jjdguard}"
[[ "$REALM_PRE" =~ ^[A-Za-z0-9._-]+$ ]] || die "realm 名非法: $REALM_PRE"
IDP_CID_PRE="$(svc_container chat-idp)"
REL_PRE="$(container_env "$IDP_CID_PRE" KC_HTTP_RELATIVE_PATH)"
if [ -z "$REL_PRE" ] && [ -n "$OLD_ENV_ISSUER" ] && [[ "$OLD_ENV_ISSUER" == *"/realms/"* ]]; then
  REL_PRE="${OLD_ENV_ISSUER#*://}"
  if [[ "$REL_PRE" == */* ]]; then REL_PRE="/${REL_PRE#*/}"; REL_PRE="${REL_PRE%%/realms/*}"; else REL_PRE=""; fi
fi
REL_PRE="/${REL_PRE#/}"; REL_PRE="${REL_PRE%/}"
REL_PRE="${REL_PRE:-}"; [ -n "$REL_PRE" ] || REL_PRE="/sso"
[[ "$REL_PRE" =~ ^(/[A-Za-z0-9._~-]+)*$ ]] || die "Keycloak 子路径非法: $REL_PRE"
NEW_ISSUER="$NEW_ORIGIN$REL_PRE/realms/$REALM_PRE"

# 旧 issuer 候选（去重，剔除新值）。内置 Keycloak 才由地址推导；外部 IdP 的 issuer 不随对外地址变化。
OLD_ISSUERS=()
add_issuer() {
  local i="$1" x
  [ -n "$i" ] && [ "$i" != "$NEW_ISSUER" ] || return 0
  for x in "${OLD_ISSUERS[@]:-}"; do [ "$x" = "$i" ] && return 0; done
  OLD_ISSUERS+=("$i")
}
if [ "$BYO" != "true" ]; then
  add_issuer "$OLD_ENV_ISSUER"
  [ -z "$OLD_URL" ] || add_issuer "$OLD_URL$REL_PRE/realms/$REALM_PRE"
  [ -z "$OLD_N" ] || add_issuer "$OLD_N$REL_PRE/realms/$REALM_PRE"
  [ -z "$OLD_RT_URL" ] || add_issuer "$OLD_RT_URL$REL_PRE/realms/$REALM_PRE"
fi
issuer_re='^https?://[][A-Za-z0-9._:-]+(/[A-Za-z0-9._~-]+)*/realms/[A-Za-z0-9._-]+$'
for i in "${OLD_ISSUERS[@]:-}"; do
  [[ -z "$i" || "$i" =~ $issuer_re ]] || die "旧 issuer 格式异常，拒绝继续"
done

# 客户端 ID / 回调路径：尽量从 .env 与容器配置推导
UI_CLIENT="$(read_env "$ENV_FILE" CHAT_PORTAL_UI_OIDC_CLIENT_ID)"
[ -n "$UI_CLIENT" ] || UI_CLIENT="$(container_env "$(svc_container chat-portal-ui)" OIDC_CLIENT_ID)"
UI_CLIENT="${UI_CLIENT:-enterprise-ai-portal}"
ADMIN_CLIENT="$(container_env "$(svc_container chat-portal-proxy)" PORTAL_OIDC_CLIENT_ID)"
ADMIN_CLIENT="${ADMIN_CLIENT:-chat-portal-admin}"
[[ "$UI_CLIENT" =~ ^[A-Za-z0-9._-]+$ && "$ADMIN_CLIENT" =~ ^[A-Za-z0-9._-]+$ ]] || die "OIDC 客户端 ID 含非法字符"
UI_ACCT_PATH="$(path_of_url "$(container_env "$IDP_CID_PRE" PORTAL_UI_ACCOUNT_REDIRECT)")"; UI_ACCT_PATH="${UI_ACCT_PATH:-/chat/api/auth/callback/account-login}"
UI_SSO_PATH="$(path_of_url "$(container_env "$IDP_CID_PRE" PORTAL_UI_SSO_REDIRECT)")"; UI_SSO_PATH="${UI_SSO_PATH:-/chat/api/auth/callback/enterprise-sso}"
ADMIN_CB_PATH="$(path_of_url "$(container_env "$IDP_CID_PRE" PORTAL_ADMIN_REDIRECT_8280)")"; ADMIN_CB_PATH="${ADMIN_CB_PATH:-/portal/auth/callback}"
for p in "$UI_ACCT_PATH" "$UI_SSO_PATH" "$ADMIN_CB_PATH"; do
  [[ "$p" =~ ^/[A-Za-z0-9._~/-]*$ ]] || die "回调路径含非法字符: $p"
done

# ================= 主流程 =================
MODE_TXT="dry-run（不会改动任何东西，加 --apply 执行）"
[ "$APPLY" -eq 0 ] || MODE_TXT="APPLY（真实执行）"
say "== JJDGuard SSO 对外地址变更 =="
say "模式:     $MODE_TXT"
say "旧地址:   ${OLD_URL:-<未设置>}  (identity-runtime.env: ${OLD_RT_URL:-<无>})"
say "新地址:   $NEW_ORIGIN"
say "新 issuer: $NEW_ISSUER"
if [ "$BYO" = "true" ]; then
  say "待迁移的旧 issuer: 无（CHAT_BYO_IDP=true，外部 IdP 的 issuer 不随对外地址变化）"
elif [ "${#OLD_ISSUERS[@]}" -gt 0 ]; then
  say "待迁移的旧 issuer: ${OLD_ISSUERS[*]}"
else
  say "待迁移的旧 issuer: 无（可能已迁移过）"
fi
say "容器范围: $SCOPE_DESC"

resolve_chain
say "启动链来源: $CHAIN_SOURCE"
say "启动链文件: ${CHAIN_FILES[*]}"

BACKUP_DIR=""
RESTORE_HINT=""

# 1) 备份
if [ "$APPLY" -eq 1 ]; then
  (umask 077; mkdir -p "$BACKUP_ROOT")
  BACKUP_DIR="$(umask 077; mktemp -d "$BACKUP_ROOT/sso-public-url-$(date +%Y%m%d-%H%M%S)-XXXXXX")"
  chmod 700 "$BACKUP_DIR"
  RESTORE_HINT="env 可能已改写，备份在 $BACKUP_DIR；回滚：jjdctl sso rollback $BACKUP_DIR --apply"
else
  BACKUP_DIR="$BACKUP_ROOT/sso-public-url-<时间戳>"
fi
db_probe
say ""
say "[1/5] 备份 -> $BACKUP_DIR"
say "  将备份: $ENV_FILE$([ -f "$RUNTIME_ENV_FILE" ] && echo ", $RUNTIME_ENV_FILE")$([ "$DB_STATE" = ok ] && echo ", user_identity_links(pg_dump)")、Keycloak 客户端 JSON、meta.env"
[ -f "$RUNTIME_ENV_FILE" ] || note "$RUNTIME_ENV_FILE 不存在（老版本未启用身份运行态），跳过该文件"
if [ "$APPLY" -eq 1 ]; then
  (umask 077; cp -p "$ENV_FILE" "$BACKUP_DIR/env.bak")
  [ ! -f "$RUNTIME_ENV_FILE" ] || (umask 077; cp -p "$RUNTIME_ENV_FILE" "$BACKUP_DIR/identity-runtime.env.bak")
  (umask 077; {
    printf 'SCHEMA=1\n'
    printf 'CREATED=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'OLD_URL=%s\nNEW_URL=%s\nNEW_ISSUER=%s\nREALM=%s\n' "$OLD_URL" "$NEW_ORIGIN" "$NEW_ISSUER" "$REALM_PRE"
    printf 'ENV_FILE=%s\nHAD_RUNTIME_ENV=%s\n' "$ENV_FILE" "$([ -f "$RUNTIME_ENV_FILE" ] && echo 1 || echo 0)"
  } >"$BACKUP_DIR/meta.env")
  if [ "$DB_STATE" = ok ]; then
    ( umask 077; "$DOCKER_BIN" exec -i "$PGCID" pg_dump -U "$PGUSER_" -d "$PGDB_" -t user_identity_links --no-owner >"$BACKUP_DIR/user_identity_links.sql" ) ||
      die "pg_dump 备份 user_identity_links 失败，已中止（尚未改动任何配置）"
    [ -s "$BACKUP_DIR/user_identity_links.sql" ] || die "user_identity_links 备份为空，已中止"
  fi
  say "  已备份。回滚命令: jjdctl sso rollback $BACKUP_DIR --apply"
fi

# 2) env
say ""
say "[2/5] 改写环境文件"
env_pairs=("JJD_SSO_PUBLIC_URL=$NEW_ORIGIN" "JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=$NEW_INSECURE")
if [ "$CHAT_INSTALLED" -eq 1 ]; then
  env_pairs+=("CHAT_OIDC_HOST=$NEW_HOST")
  if [ "$BYO" = "true" ]; then
    warn "CHAT_BYO_IDP=true：外部 IdP，不改 CHAT_OIDC_ISSUER"
  else
    env_pairs+=("CHAT_OIDC_ISSUER=$NEW_ISSUER")
  fi
fi
rewrite_env "$ENV_FILE" "${env_pairs[@]}"; ENV_TMP="$REWRITE_TMP"
rt_pairs=("JJD_SSO_PUBLIC_URL=$NEW_ORIGIN")
has_key "$RUNTIME_ENV_FILE" JJD_SSO_ALLOW_INSECURE_PUBLIC_URL && rt_pairs+=("JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=$NEW_INSECURE")
if [ -f "$RUNTIME_ENV_FILE" ]; then
  rewrite_env "$RUNTIME_ENV_FILE" "${rt_pairs[@]}"; RT_TMP="$REWRITE_TMP"
else
  say "  - $RUNTIME_ENV_FILE 不存在，跳过"; RT_TMP=""
fi
# 先让 apply 的后续步骤（compose config / 重建）看到新值
if [ "$APPLY" -eq 1 ]; then
  commit_env "$ENV_FILE" "$ENV_TMP"
  commit_env "$RUNTIME_ENV_FILE" "$RT_TMP"
  printf 'ENV_SHA_AFTER=%s\n' "$(file_sha "$ENV_FILE")" >>"$BACKUP_DIR/meta.env"
  [ ! -f "$RUNTIME_ENV_FILE" ] || printf 'RUNTIME_SHA_AFTER=%s\n' "$(file_sha "$RUNTIME_ENV_FILE")" >>"$BACKUP_DIR/meta.env"
fi

# 3) 数据库
say ""
say "[3/5] 复制 user_identity_links（保留旧行，覆盖所有租户）"
if [ "$SKIP_DB" -eq 1 ]; then
  say "  已跳过（--skip-db）"
elif [ "$BYO" = "true" ]; then
  say "  已跳过：外部 IdP 的 issuer 不变，无需复制"
elif [ "${#OLD_ISSUERS[@]}" -eq 0 ]; then
  say "  没有需要迁移的旧 issuer"
else
  case "$DB_STATE" in
    notable) note "数据库中没有 user_identity_links 表（老版本尚未建表），跳过；用户映射将在门户首次登录时按新 issuer 重新建立" ;;
    nocontainer)
      if [ "$APPLY" -eq 1 ]; then die "找不到 postgres 容器，无法复制 identity link。若数据库不在本机 compose 中，请加 --skip-db 后手工处理。$RESTORE_HINT"; fi
      warn "找不到 postgres 容器，dry-run 无法预估行数" ;;
    error)
      if [ "$APPLY" -eq 1 ]; then die "无法访问数据库（容器未运行，或表结构不认识）。$RESTORE_HINT"; fi
      warn "数据库当前不可访问，dry-run 无法预估行数" ;;
    ok)
      say "  数据库: 用户=$PGUSER_ 库=$PGDB_（来自容器 ${PGCID:0:12}）  复制列: $LINK_COLS"
      [ "$APPLY" -eq 0 ] || : >"$BACKUP_DIR/added-link-ids.txt"
      for oi in "${OLD_ISSUERS[@]}"; do
        if [ "$APPLY" -eq 1 ]; then
          new_ids="$(link_insert_sql | psql_run -At -v "old_issuer=$oi" -v "new_issuer=$NEW_ISSUER")" ||
            die "复制 user_identity_links 失败。$RESTORE_HINT"
          new_ids="$(printf '%s\n' "$new_ids" | sed -n '/^uil_[A-Za-z0-9_-]*$/p')"
          [ -z "$new_ids" ] || printf '%s\n' "$new_ids" >>"$BACKUP_DIR/added-link-ids.txt"
          n="$(printf '%s' "$new_ids" | sed '/^$/d' | wc -l | tr -d ' ')"
          say "  $oi -> 新增 ${n:-0} 行"
        else
          res="$(printf '%s\n' "$LINK_COUNT_SQL" | psql_run -At -F'|' -v "old_issuer=$oi" -v "new_issuer=$NEW_ISSUER" 2>/dev/null | tail -n 1 || true)"
          if [[ "$res" == *"|"* ]]; then
            say "  $oi -> 预计新增 ${res%%|*} 行（涉及 ${res#*|} 个租户）"
          else
            say "  $oi -> 预计新增 ${res:-<无法查询>} 行"
          fi
        fi
      done
      [ "$APPLY" -eq 0 ] || printf 'DB_COPIED=1\n' >>"$BACKUP_DIR/meta.env"
      ;;
  esac
fi

# 4) Keycloak
say ""
say "[4/5] Keycloak 客户端"
prepare_keycloak
if [ "$KC_READY" -eq 1 ]; then
  reconcile_kc_client "$UI_CLIENT" \
    "$NEW_ORIGIN$UI_ACCT_PATH;$NEW_ORIGIN$UI_SSO_PATH" \
    "$NEW_ORIGIN" "$NEW_ORIGIN/chat;$NEW_ORIGIN/chat/*"
  reconcile_kc_client "$ADMIN_CLIENT" \
    "$NEW_ORIGIN$ADMIN_CB_PATH" \
    "$NEW_ORIGIN" "$NEW_ORIGIN;$NEW_ORIGIN/*"
elif [ "$SKIP_KC" -eq 0 ] && [ "$BYO" != "true" ] && [ "$CHAT_INSTALLED" -eq 1 ] && { [ -n "$IDP_CID" ] || [ -n "${KCADM_BIN:-}" ]; }; then
  say "  将追加（旧地址$([ "$DROP_OLD" -eq 1 ] && echo 被移除 || echo 默认保留)）："
  say "    $UI_CLIENT: redirect $NEW_ORIGIN$UI_ACCT_PATH, $NEW_ORIGIN$UI_SSO_PATH; post-logout $NEW_ORIGIN/chat, $NEW_ORIGIN/chat/*"
  say "    $ADMIN_CLIENT: redirect $NEW_ORIGIN$ADMIN_CB_PATH; post-logout $NEW_ORIGIN, $NEW_ORIGIN/*"
fi

# 5) 重建
say ""
say "[5/5] 按当前启动链重建受影响服务"
recreate_services

say ""
if [ "$APPLY" -eq 1 ]; then
  date -u +%Y-%m-%dT%H:%M:%SZ >"$BACKUP_DIR/completed"
  say "完成。备份目录: $BACKUP_DIR"
  say "验证后若需撤销: jjdctl sso rollback $BACKUP_DIR --apply"
  say "注意：之后若重跑 chat/bootstrap-identity-runtime.sh，会把 Keycloak redirect 重置为只含新地址（旧地址失效）。"
else
  say "以上为 dry-run，未做任何改动。确认后追加 --apply 执行。"
fi
