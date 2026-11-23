#!/bin/sh
# 为已安装的 JJDGuard 接入响应缓存专用的 redis-cache（不持久化、有内存上限），并让网关连接它。
# 适用于“镜像替换式”升级不会新建服务的环境（如开发 VM 的 dev 发布）。离线包全新安装与
# upgrade.sh 已在 compose 里自带 redis-cache，不需要本脚本。幂等：重复执行结果一致。
#
# 做法与 diag-agent 相同：生成 root 0600 的 active-config/response-cache.override.yml，
# 追加到 .upgrade/compose-files 末尾；--apply 时按开机链只起 redis-cache、只重建 gateway-core。
# 缓存是否生效仍由控制台系统设置 response_cache_enabled 决定（默认关闭）。
#
# 用法：install-response-cache.sh [--deploy-dir DIR] [--maxmemory 256mb] [--apply]
#       install-response-cache.sh --uninstall [--deploy-dir DIR] [--apply]
set -eu

DEFAULT_DEPLOY_DIR=/opt/jjdguard/current/deploy/docker-compose
DEPLOY_DIR="$DEFAULT_DEPLOY_DIR"
MAXMEMORY=256mb
APPLY=0
UNINSTALL=0
OVERRIDE_NAME=response-cache.override.yml
OVERRIDE_MARK='# jjdguard-response-cache-override'
VALKEY_IMAGE='valkey/valkey:8.1.10-alpine'

log() { printf '[response-cache] %s\n' "$*"; }
die() { printf '[response-cache][error] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
用法：$0 [--deploy-dir DIR] [--maxmemory SIZE] [--apply]
      $0 --uninstall [--deploy-dir DIR] [--apply]
  --deploy-dir  部署目录（含 .env 与 .upgrade），默认 $DEFAULT_DEPLOY_DIR
  --maxmemory   缓存实例内存上限，默认 256mb（如 128mb、1gb）
  --apply       按开机链只起 redis-cache、只重建 gateway-core
  --uninstall   从开机链移除并删除 override；配合 --apply 时重建 gateway-core 并删除 redis-cache 容器
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deploy-dir) [ "$#" -ge 2 ] || die "--deploy-dir 缺少参数"; DEPLOY_DIR="$2"; shift 2 ;;
    --maxmemory) [ "$#" -ge 2 ] || die "--maxmemory 缺少参数"; MAXMEMORY="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "未知参数：$1" ;;
  esac
done

case "$MAXMEMORY" in
  [1-9]*mb|[1-9]*gb|[1-9]*MB|[1-9]*GB) ;;
  *) die "--maxmemory 只接受形如 256mb、1gb 的值：$MAXMEMORY" ;;
esac
case "$MAXMEMORY" in *[!0-9mbgMBG]*) die "--maxmemory 含非法字符：$MAXMEMORY" ;; esac

case "$DEPLOY_DIR" in
  /*) ;;
  *) die "--deploy-dir 必须是绝对路径：$DEPLOY_DIR" ;;
esac
case "$DEPLOY_DIR" in *[!A-Za-z0-9_./-]*|*..*) die "--deploy-dir 只能含字母数字和 _ . / -：$DEPLOY_DIR" ;; esac

[ "$(id -u)" = 0 ] || die "需要 root 权限"
[ -d "$DEPLOY_DIR" ] || die "部署目录不存在：$DEPLOY_DIR"
DEPLOY_DIR="$(CDPATH= cd -- "$DEPLOY_DIR" && pwd -P)"  # 开机链条目必须是真实路径
ENV_FILE="$DEPLOY_DIR/.env"
[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || die "部署目录缺少 .env（或是符号链接）：$ENV_FILE"
grep -q '^REDIS_PASSWORD=.' "$ENV_FILE" || die ".env 里没有 REDIS_PASSWORD，缓存实例沿用主 Redis 的密码"
CHAIN="$DEPLOY_DIR/.upgrade/compose-files"
[ -f "$CHAIN" ] && [ ! -L "$CHAIN" ] || die "没有开机链 $CHAIN；这个部署方式请改用离线包升级"
ACTIVE="$DEPLOY_DIR/active-config"
[ -d "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || die "active-config 目录不可用：$ACTIVE"
OVERRIDE_FILE="$ACTIVE/$OVERRIDE_NAME"

TMPS=""
cleanup() { for _f in $TMPS; do rm -f -- "$_f"; done; }
trap cleanup EXIT INT TERM

# 开机链（jjdctl 实际读取的文件）：offline 基础 + compose-files 各条目。
compose_chain() {
  set -- -f "$DEPLOY_DIR/docker-compose.offline.yml"
  while IFS= read -r entry || [ -n "$entry" ]; do
    [ -n "$entry" ] && set -- "$@" -f "$entry"
  done <"$CHAIN"
  project=""
  [ -f "$DEPLOY_DIR/.upgrade/project-name" ] && project="$(tr -d '[:space:]' <"$DEPLOY_DIR/.upgrade/project-name")"
  if [ -n "$project" ]; then
    (cd "$DEPLOY_DIR" && "$DEPLOY_DIR/bin/docker-compose" --project-name "$project" --project-directory "$DEPLOY_DIR" --env-file "$ENV_FILE" "$@" $COMPOSE_ARGS)
  else
    (cd "$DEPLOY_DIR" && "$DEPLOY_DIR/bin/docker-compose" --project-directory "$DEPLOY_DIR" --env-file "$ENV_FILE" "$@" $COMPOSE_ARGS)
  fi
}
compose() { COMPOSE_ARGS="$*" compose_chain; }

remove_chain_entry() {
  CT="$(mktemp "$DEPLOY_DIR/.upgrade/.compose-files.XXXXXX")"; TMPS="$TMPS $CT"
  grep -Fxv -- "$OVERRIDE_FILE" "$CHAIN" >"$CT" || true
  chown root:root "$CT" 2>/dev/null || true
  chmod 0600 "$CT"
  mv -f -- "$CT" "$CHAIN"
}

if [ "$UNINSTALL" = 1 ]; then
  if grep -Fxq -- "$OVERRIDE_FILE" "$CHAIN"; then
    remove_chain_entry
    log "已从开机链移除 $OVERRIDE_NAME"
  fi
  if [ -f "$OVERRIDE_FILE" ]; then
    head -n 1 "$OVERRIDE_FILE" | grep -Fxq -- "$OVERRIDE_MARK" || die "$OVERRIDE_FILE 不是本脚本生成的，拒绝删除"
    rm -f -- "$OVERRIDE_FILE"
    log "已删除 $OVERRIDE_FILE"
  fi
  if [ "$APPLY" = 1 ]; then
    compose up -d --no-deps --pull never --force-recreate gateway-core
    docker ps -a --filter "label=com.docker.compose.service=redis-cache" --format '{{.Names}}' | while IFS= read -r name; do
      [ -n "$name" ] && docker rm -f "$name" >/dev/null && log "已删除容器 $name"
    done
  fi
  exit 0
fi

# 基础 compose 已带 redis-cache（新离线包）时不需要 override。
if grep -Eq '^  redis-cache:' "$DEPLOY_DIR/docker-compose.offline.yml"; then
  log "基础 compose 已含 redis-cache，无需 override"
else
  OT="$(mktemp "$ACTIVE/.response-cache.XXXXXX")"; TMPS="$TMPS $OT"
  cat >"$OT" <<YAML
$OVERRIDE_MARK
services:
  redis-cache:
    image: $VALKEY_IMAGE
    restart: unless-stopped
    environment:
      - REDIS_PASSWORD=\${REDIS_PASSWORD:?REDIS_PASSWORD is required}
      - RESPONSE_CACHE_MAXMEMORY=$MAXMEMORY
    command: ["sh", "-c", "exec valkey-server --save '' --appendonly no --maxmemory \$\${RESPONSE_CACHE_MAXMEMORY} --maxmemory-policy allkeys-lru --requirepass \"\$\${REDIS_PASSWORD}\""]
    networks:
      - jjdguard-net
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "valkey-cli -a \"\$\${REDIS_PASSWORD}\" ping | grep PONG"]
      interval: 5s
      timeout: 5s
      retries: 5
  gateway-core:
    environment:
      - RESPONSE_CACHE_REDIS_URL=redis://:\${REDIS_PASSWORD:?REDIS_PASSWORD is required}@redis-cache:6379/0
YAML
  chown root:root "$OT" 2>/dev/null || true
  chmod 0600 "$OT"
  if [ -f "$OVERRIDE_FILE" ] && cmp -s "$OT" "$OVERRIDE_FILE"; then
    log "override 已是最新：$OVERRIDE_FILE"
  else
    mv -f -- "$OT" "$OVERRIDE_FILE"
    log "已写入 $OVERRIDE_FILE"
  fi
  if ! grep -Fxq -- "$OVERRIDE_FILE" "$CHAIN"; then
    # 保持 compose-files 的属主/权限（jjdctl 要求 root 0600），原地追加
    [ -s "$CHAIN" ] && [ "$(tail -c 1 "$CHAIN")" != "" ] && printf '\n' >>"$CHAIN"
    printf '%s\n' "$OVERRIDE_FILE" >>"$CHAIN"
    log "已追加到开机链 $CHAIN"
  fi
fi

compose config --quiet || die "开机链渲染失败，请检查 $OVERRIDE_FILE"
compose config --services | grep -Fxq redis-cache || die "开机链里没有 redis-cache 服务"

if [ "$APPLY" = 1 ]; then
  compose up -d --no-deps --pull never redis-cache
  compose up -d --no-deps --pull never --force-recreate gateway-core
  log "已启动 redis-cache 并重建 gateway-core"
else
  log "未执行 --apply：下次 jjdctl start/restart 时生效"
fi
