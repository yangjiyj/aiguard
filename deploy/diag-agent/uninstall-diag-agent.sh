#!/bin/sh
# 卸载宿主机诊断采集器。默认保留密钥；--purge 才删除密钥、.env 中的键和 override。
set -eu

DEFAULT_DEPLOY_DIR=/opt/jjdguard/current/deploy/docker-compose
DEFAULT_DIAG_DIR=/var/lib/jjdguard/diag
DEPLOY_DIR="$DEFAULT_DEPLOY_DIR"
DIAG_DIR="$DEFAULT_DIAG_DIR"
PURGE=0

KEY_FILE=/etc/jjdguard/diag-agent.key
BIN_DST=/usr/local/bin/jjdguard-diag-agent
UNIT_NAME=jjdguard-diag-agent.service
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
CRON_DST=/etc/cron.d/jjdguard-diag-agent
OVERRIDE_MARK='# jjdguard-diag-agent-override'

log() { printf '[diag-agent] %s\n' "$*"; }
warn() { printf '[diag-agent][warn] %s\n' "$*" >&2; }
die() { printf '[diag-agent][error] %s\n' "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deploy-dir) [ "$#" -ge 2 ] || die "--deploy-dir 缺少参数"; DEPLOY_DIR="$2"; shift 2 ;;
    --diag-dir) [ "$#" -ge 2 ] || die "--diag-dir 缺少参数"; DIAG_DIR="$2"; shift 2 ;;
    --purge) PURGE=1; shift ;;
    -h|--help) echo "用法：$0 [--deploy-dir DIR] [--diag-dir DIR] [--purge]"; exit 0 ;;
    *) die "未知参数：$1" ;;
  esac
done

# 诊断目录守卫：会被 rm -rf 或 chown，只接受 /.../diag 这种专用目录，防止误传 / 或 /var。
case "$DIAG_DIR" in
  /*/diag) ;;
  *) die "--diag-dir 必须是以 /diag 结尾的绝对路径：$DIAG_DIR" ;;
esac
case "$DIAG_DIR" in *..*|*//*) die "--diag-dir 不允许包含 .. 或 //：$DIAG_DIR" ;; esac

[ "$(id -u)" = 0 ] || die "需要 root 权限"
case "$DIAG_DIR" in
  /*) ;;
  *) die "--diag-dir 必须是绝对路径：$DIAG_DIR" ;;
esac
case "$DIAG_DIR" in
  *[!A-Za-z0-9_./-]*|*..*) die "--diag-dir 含不允许的字符：$DIAG_DIR" ;;
esac
# 拒绝删除过浅的目录（如 /、/var、/var/lib）
_depth="$(printf '%s' "$DIAG_DIR" | tr -s '/' | awk -F/ '{n=0; for(i=1;i<=NF;i++) if($i!="") n++; print n}')"
[ "$_depth" -ge 3 ] || die "--diag-dir 过浅，拒绝删除：$DIAG_DIR"

# 1. 服务
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  if [ -e "$UNIT_DST" ]; then
    rm -f -- "$UNIT_DST"
    log "已删除 $UNIT_DST"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ -e "$CRON_DST" ]; then
  rm -f -- "$CRON_DST"
  log "已删除 $CRON_DST"
fi

# 2. 二进制与诊断目录
rm -f -- "$BIN_DST"
if [ -d "$DIAG_DIR" ] && { [ -d "$DIAG_DIR/inbox" ] || [ -d "$DIAG_DIR/snapshot" ]; }; then
  rm -rf -- "$DIAG_DIR"
  log "已删除 $DIAG_DIR"
fi

# 3. --purge：密钥、.env 中的键、override
if [ "$PURGE" = 1 ]; then
  rm -f -- "$KEY_FILE"
  log "已删除密钥 $KEY_FILE"
  ENV_FILE="$DEPLOY_DIR/.env"
  if [ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ]; then
    _t="$(mktemp "$ENV_FILE.XXXXXX")"
    awk 'index($0, "DIAG_AGENT_HMAC_KEY=") != 1' "$ENV_FILE" >"$_t"
    if ! cmp -s "$_t" "$ENV_FILE"; then
      cat "$_t" >"$ENV_FILE"
      log "已从 $ENV_FILE 删除 DIAG_AGENT_HMAC_KEY"
    fi
    rm -f -- "$_t"
  fi
  CHAIN="$DEPLOY_DIR/.upgrade/compose-files"
  if [ -f "$CHAIN" ] && [ ! -L "$CHAIN" ]; then
    _t="$(mktemp "$CHAIN.XXXXXX")"
    : >"$_t"
    while IFS= read -r _l || [ -n "$_l" ]; do
      # 升级会把 override 收口为 inherited-NNN.yml，所以按标记行识别而不是按文件名
      if [ -n "$_l" ] && [ -f "$_l" ] && head -n 1 "$_l" 2>/dev/null | grep -Fxq "$OVERRIDE_MARK"; then
        rm -f -- "$_l"
        log "已删除 override $_l"
        continue
      fi
      printf '%s\n' "$_l" >>"$_t"
    done <"$CHAIN"
    if ! cmp -s "$_t" "$CHAIN"; then
      cat "$_t" >"$CHAIN"
    fi
    rm -f -- "$_t"
  fi
  rm -f -- "$DEPLOY_DIR/active-config/diag-agent.override.yml"
fi
log "已卸载${PURGE:+（含 --purge 清理）}。控制面重启后不再注入诊断密钥。"
