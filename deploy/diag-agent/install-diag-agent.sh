#!/bin/sh
# 安装宿主机诊断采集器 jjdguard-diag-agent。幂等：重复执行结果一致。
# 用法：install-diag-agent.sh [--deploy-dir DIR] [--binary FILE] [--diag-dir DIR] [--apply]
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DEFAULT_DEPLOY_DIR=/opt/jjdguard/current/deploy/docker-compose
DEFAULT_DIAG_DIR=/var/lib/jjdguard/diag

DEPLOY_DIR="$DEFAULT_DEPLOY_DIR"
BINARY="$SCRIPT_DIR/jjdguard-diag-agent"
DIAG_DIR="$DEFAULT_DIAG_DIR"
APPLY=0

KEY_DIR=/etc/jjdguard
KEY_FILE="$KEY_DIR/diag-agent.key"
BIN_DST=/usr/local/bin/jjdguard-diag-agent
UNIT_NAME=jjdguard-diag-agent.service
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
CRON_DST=/etc/cron.d/jjdguard-diag-agent
OVERRIDE_NAME=diag-agent.override.yml
OVERRIDE_MARK='# jjdguard-diag-agent-override'
MOUNT_MARK='/var/lib/jjdguard/diag/inbox'

log() { printf '[diag-agent] %s\n' "$*"; }
warn() { printf '[diag-agent][warn] %s\n' "$*" >&2; }
die() { printf '[diag-agent][error] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
用法：$0 [--deploy-dir DIR] [--binary FILE] [--diag-dir DIR] [--apply]
  --deploy-dir  部署目录（含 .env 与 .upgrade），默认 $DEFAULT_DEPLOY_DIR
  --binary      采集器二进制，默认脚本同目录的 jjdguard-diag-agent
  --diag-dir    共享诊断目录，默认 $DEFAULT_DIAG_DIR
  --apply       按开机链只重建 control-plane，使诊断立即生效
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deploy-dir) [ "$#" -ge 2 ] || die "--deploy-dir 缺少参数"; DEPLOY_DIR="$2"; shift 2 ;;
    --binary) [ "$#" -ge 2 ] || die "--binary 缺少参数"; BINARY="$2"; shift 2 ;;
    --diag-dir) [ "$#" -ge 2 ] || die "--diag-dir 缺少参数"; DIAG_DIR="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

# 诊断目录守卫：会被 rm -rf 或 chown，只接受 /.../diag 这种专用目录，防止误传 / 或 /var。
case "$DIAG_DIR" in
  /*/diag) ;;
  *) die "--diag-dir 必须是以 /diag 结尾的绝对路径：$DIAG_DIR" ;;
esac
case "$DIAG_DIR" in *..*|*//*) die "--diag-dir 不允许包含 .. 或 //：$DIAG_DIR" ;; esac

# 路径会写进 unit、cron、YAML 和 sed，只接受保守字符集。
safe_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9_./-]*|*..*) return 1 ;;
  esac
  return 0
}

[ "$(id -u)" = 0 ] || die "需要 root 权限"
safe_path "$DIAG_DIR" || die "--diag-dir 必须是绝对路径且只含字母数字和 _ . / -：$DIAG_DIR"
safe_path "$DEPLOY_DIR" || die "--deploy-dir 必须是绝对路径且只含字母数字和 _ . / -：$DEPLOY_DIR"
[ -d "$DEPLOY_DIR" ] || die "部署目录不存在：$DEPLOY_DIR"
DEPLOY_DIR="$(CDPATH= cd -- "$DEPLOY_DIR" && pwd -P)"  # 开机链条目必须是真实路径（jjdctl 与发布工具按 readlink -f 校验），不能经 current 软链
ENV_FILE="$DEPLOY_DIR/.env"
[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || die "部署目录缺少 .env（或是符号链接）：$ENV_FILE"
[ -f "$BINARY" ] && [ -x "$BINARY" ] || die "采集器二进制不存在或不可执行：$BINARY"
UNIT_SRC="$SCRIPT_DIR/jjdguard-diag-agent.service"

TMPS=""
cleanup() { for _f in $TMPS; do rm -f -- "$_f"; done; }
trap cleanup EXIT
mktmp() {
  _t="$(mktemp "$1.XXXXXX")" || die "无法创建临时文件：$1"
  TMPS="$TMPS $_t"
  printf '%s' "$_t"
}

# 1. 密钥：不存在才生成（不依赖 openssl），已存在保留。
mkdir -p "$KEY_DIR"
chmod 0755 "$KEY_DIR"
if [ ! -s "$KEY_FILE" ]; then
  KT="$(mktmp "$KEY_FILE")"
  chmod 0600 "$KT"
  od -An -tx1 -N32 /dev/urandom | tr -d ' \n' >"$KT"
  [ "$(wc -c <"$KT" | tr -d ' ')" = 64 ] || die "密钥生成失败"
  mv -f -- "$KT" "$KEY_FILE"
  log "已生成密钥 $KEY_FILE"
fi
chown root:root "$KEY_FILE" 2>/dev/null || chown root "$KEY_FILE"
chmod 0600 "$KEY_FILE"
KEY="$(tr -d ' \r\n' <"$KEY_FILE")"
[ "${#KEY}" -ge 16 ] || die "密钥文件内容过短：$KEY_FILE"
case "$KEY" in *[!0-9A-Za-z]*) die "密钥文件含非字母数字字符：$KEY_FILE" ;; esac

# 2. 二进制：先写临时文件再 rename，避免 text file busy。
mkdir -p "$(dirname -- "$BIN_DST")"
BIN_CHANGED=0
if ! cmp -s "$BINARY" "$BIN_DST" 2>/dev/null; then
  BT="$(mktmp "$BIN_DST")"
  cat "$BINARY" >"$BT"
  chmod 0755 "$BT"
  chown root:root "$BT" 2>/dev/null || true
  mv -f -- "$BT" "$BIN_DST"
  BIN_CHANGED=1
  log "已安装 $BIN_DST"
fi

# 3. 目录：inbox 供控制面容器内 uid 100 写入（镜像 USER app = 100:101），属组 101 并开组写。
mkdir -p "$DIAG_DIR/snapshot" "$DIAG_DIR/outbox" "$DIAG_DIR/inbox" "$DIAG_DIR/state"
chown root:root "$DIAG_DIR" "$DIAG_DIR/snapshot" "$DIAG_DIR/outbox" "$DIAG_DIR/state"
chmod 0755 "$DIAG_DIR" "$DIAG_DIR/snapshot" "$DIAG_DIR/outbox"
chown root:101 "$DIAG_DIR/inbox"
chmod 0770 "$DIAG_DIR/inbox"
chmod 0700 "$DIAG_DIR/state"

# 4. 开机链最终读的 env：jjdctl 与 upgrade-bundle 都以 `--env-file <部署目录>/.env` 调用 compose，
#    control-plane 的 DIAG_AGENT_HMAC_KEY=${DIAG_AGENT_HMAC_KEY:-} 由它插值，所以写入这份 .env。
set_env_key() {
  _k="$1"; _v="$2"
  _t="$(mktmp "$ENV_FILE")"
  awk -v k="$_k" -v v="$_v" '
    BEGIN { done = 0; p = k "=" }
    index($0, p) == 1 { if (!done) { print p v; done = 1 } ; next }
    { print }
    END { if (!done) print p v }
  ' "$ENV_FILE" >"$_t"
  if cmp -s "$_t" "$ENV_FILE"; then
    rm -f -- "$_t"
  else
    # 原地写回以保留属主与权限（升级流程会校验 .env 属主不变）
    cat "$_t" >"$ENV_FILE"
    rm -f -- "$_t"
    log "已更新 $ENV_FILE 中的 $_k"
  fi
}
set_env_key DIAG_AGENT_HMAC_KEY "$KEY"
if [ "$DIAG_DIR" != "$DEFAULT_DIAG_DIR" ] || grep -q '^JJD_DIAG_DIR=' "$ENV_FILE"; then
  set_env_key JJD_DIAG_DIR "$DIAG_DIR"
fi

# 5. 开机链里的挂载：基础 compose 已带诊断挂载则无需 override；
#    旧版本基础文件没有时，生成 override 追加到 .upgrade/compose-files 末尾。
BASE_COMPOSE="$DEPLOY_DIR/docker-compose.offline.yml"
[ -f "$BASE_COMPOSE" ] || BASE_COMPOSE="$DEPLOY_DIR/docker-compose.yml"
CHAIN="$DEPLOY_DIR/.upgrade/compose-files"
OVERRIDE_FILE="$DEPLOY_DIR/active-config/$OVERRIDE_NAME"
if [ -f "$BASE_COMPOSE" ] && grep -Fq "$MOUNT_MARK" "$BASE_COMPOSE"; then
  log "基础 compose 已含诊断挂载，无需 override"
elif [ ! -f "$CHAIN" ] || [ -L "$CHAIN" ]; then
  warn "基础 compose 不含诊断挂载，且没有 $CHAIN；无法接入开机链，请先升级到含诊断挂载的版本"
else
  if [ -d "$DEPLOY_DIR/active-config" ] && [ ! -L "$DEPLOY_DIR/active-config" ]; then :; else
    [ ! -e "$DEPLOY_DIR/active-config" ] || die "active-config 不是普通目录：$DEPLOY_DIR/active-config"
    mkdir -m 0700 "$DEPLOY_DIR/active-config"
  fi
  OT="$(mktmp "$OVERRIDE_FILE")"
  cat >"$OT" <<YAML
$OVERRIDE_MARK
services:
  control-plane:
    environment:
      - DIAG_AGENT_HMAC_KEY=\${DIAG_AGENT_HMAC_KEY:-}
    volumes:
      - $DIAG_DIR/snapshot:/var/lib/jjdguard/diag/snapshot:ro
      - $DIAG_DIR/outbox:/var/lib/jjdguard/diag/outbox:ro
      - $DIAG_DIR/inbox:/var/lib/jjdguard/diag/inbox
YAML
  chmod 0600 "$OT"
  chown root:root "$OT" 2>/dev/null || true
  if cmp -s "$OT" "$OVERRIDE_FILE" 2>/dev/null; then
    rm -f -- "$OT"
  else
    mv -f -- "$OT" "$OVERRIDE_FILE"
    log "已写入 override $OVERRIDE_FILE"
  fi
  if ! grep -Fxq "$OVERRIDE_FILE" "$CHAIN"; then
    # 保持 compose-files 的属主/权限（jjdctl 要求 root 0600），原地追加
    if [ -s "$CHAIN" ] && [ "$(tail -c 1 "$CHAIN" | od -An -tx1 | tr -d ' \n')" != 0a ]; then
      printf '\n' >>"$CHAIN"
    fi
    printf '%s\n' "$OVERRIDE_FILE" >>"$CHAIN"
    log "已把 override 追加到 $CHAIN"
  fi
fi

# 6. 服务：有 systemd 装 unit，否则用 cron 每分钟 --once。
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then HAS_SYSTEMD=1; fi
if [ "$HAS_SYSTEMD" = 1 ]; then
  [ -f "$UNIT_SRC" ] || die "缺少 unit 模板：$UNIT_SRC"
  case "$DEPLOY_DIR" in /home/*|/root/*|/root) PH=read-only ;; *) PH=yes ;; esac
  mkdir -p "$(dirname -- "$UNIT_DST")"
  UT="$(mktmp "$UNIT_DST")"
  sed -e "s|@DIAG_DIR@|$DIAG_DIR|g" -e "s|@DEPLOY_DIR@|$DEPLOY_DIR|g" -e "s|@PROTECT_HOME@|$PH|g" "$UNIT_SRC" >"$UT"
  chmod 0644 "$UT"
  UNIT_CHANGED=0
  if ! cmp -s "$UT" "$UNIT_DST" 2>/dev/null; then
    mv -f -- "$UT" "$UNIT_DST"
    UNIT_CHANGED=1
    log "已安装 $UNIT_DST"
  else
    rm -f -- "$UT"
  fi
  rm -f -- "$CRON_DST"
  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME"
  if [ "$UNIT_CHANGED" = 1 ] || [ "$BIN_CHANGED" = 1 ]; then
    systemctl restart "$UNIT_NAME"
  fi
else
  command -v crond >/dev/null 2>&1 || command -v cron >/dev/null 2>&1 || warn "未发现 cron，已写入 $CRON_DST，但需要安装并启动 cron 才会运行"
  mkdir -p /etc/cron.d
  LOCK=""
  if command -v flock >/dev/null 2>&1; then LOCK="$(command -v flock) -n /run/jjdguard-diag-agent.lock "; fi
  CT="$(mktmp "$CRON_DST")"
  cat >"$CT" <<CRON
# 由 install-diag-agent.sh 生成，请勿手工修改
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root ${LOCK}$BIN_DST --once --dir $DIAG_DIR --key-file $KEY_FILE --deploy-dir $DEPLOY_DIR >/dev/null 2>&1
CRON
  chmod 0644 "$CT"
  if cmp -s "$CT" "$CRON_DST" 2>/dev/null; then
    rm -f -- "$CT"
  else
    mv -f -- "$CT" "$CRON_DST"
    log "已写入 $CRON_DST"
  fi
fi

# 7. 控制面生效：默认不动任何容器。
project_name() {
  _n=""
  if [ -r "$DEPLOY_DIR/.upgrade/project-name" ]; then
    _n="$(tr -d ' \r\n' <"$DEPLOY_DIR/.upgrade/project-name")"
  fi
  if [ -z "$_n" ]; then
    _n="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$ENV_FILE" | tail -n 1 | tr -d ' \r"'"'")"
  fi
  if [ -z "$_n" ] && command -v docker >/dev/null 2>&1; then
    _n="$(docker ps -a --filter label=com.docker.compose.service=control-plane \
      --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | sed -n '1p' || true)"
  fi
  case "$_n" in
    ''|*[!a-z0-9_-]*|[-_]*) _n=docker-compose ;;
  esac
  printf '%s' "$_n"
}

if [ "$APPLY" = 1 ]; then
  PROJ="$(project_name)"
  PDIR="$DEPLOY_DIR"
  if [ -r "$DEPLOY_DIR/.upgrade/project-directory" ]; then
    _p="$(tr -d '\r\n' <"$DEPLOY_DIR/.upgrade/project-directory")"
    [ -n "$_p" ] && [ -d "$_p" ] && PDIR="$_p"
  fi
  set -- sh ./compose-wrapper.sh --project-name "$PROJ" --project-directory "$PDIR" --env-file .env -f docker-compose.offline.yml
  if [ -f "$CHAIN" ]; then
    while IFS= read -r _l || [ -n "$_l" ]; do
      [ -n "$_l" ] && set -- "$@" -f "$_l"
    done <"$CHAIN"
  fi
  # 强制重建：配置未变时 compose 不会重建，容器标签里的旧文件链会一直留着，发布工具按标签校验开机链。
  set -- "$@" up -d --no-deps --force-recreate control-plane
  log "按开机链重建 control-plane（项目 $PROJ）"
  (cd "$DEPLOY_DIR" && "$@")
  log "完成，控制面已带新的诊断配置"
else
  log "已安装。控制面重启后生效（或加 --apply 按开机链只重建 control-plane）"
fi
