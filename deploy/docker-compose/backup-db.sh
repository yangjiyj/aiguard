#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
COMPOSE_WRAPPER="$SCRIPT_DIR/compose-wrapper.sh"

# 读 .env 不能用 source：未加引号且含空格的值（如 REDIS_EXTRA_ARGS=--a yes）会被当成命令执行，
# 值里的 $(...) / 反引号 / 分号也会被执行。统一经共享库按字面解析，见 deploy/lib/jjd-env.sh。
JJD_ENV_LIB="$SCRIPT_DIR/../lib/jjd-env.sh"
if [ ! -f "$JJD_ENV_LIB" ]; then
  echo "[error] 缺少安全读取 .env 的库: $JJD_ENV_LIB" >&2
  exit 1
fi
# shellcheck source=../lib/jjd-env.sh
. "$JJD_ENV_LIB"
if [ -f ./.env ]; then
  jjd_load_env_file ./.env
fi

POSTGRES_USER="${POSTGRES_USER:-jjdguard}"
POSTGRES_DB="${POSTGRES_DB:-jjdguard}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_FILE="${BACKUP_DIR}/jjdguard-${POSTGRES_DB}-${TIMESTAMP}.sql"

mkdir -p "$BACKUP_DIR"

echo "[check] creating database backup -> ${OUTPUT_FILE}"
sh "$COMPOSE_WRAPPER" exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" >"$OUTPUT_FILE"
echo "[ok] backup completed -> ${OUTPUT_FILE}"

# chat 包：额外 dump chat-postgres 的门户库（会话/留痕）。未装 chat（chat-postgres 未运行）则干净跳过。
if [ -n "$(sh "$COMPOSE_WRAPPER" ps -q chat-postgres 2>/dev/null)" ]; then
  CHAT_DB="${CHAT_POSTGRES_DB:-enterprise_ai_portal}"
  CHAT_OUT="${BACKUP_DIR}/chat-${CHAT_DB}-${TIMESTAMP}.sql"
  echo "[check] creating chat database backup -> ${CHAT_OUT}"
  sh "$COMPOSE_WRAPPER" exec -T chat-postgres pg_dump -U postgres -d "$CHAT_DB" >"$CHAT_OUT"
  echo "[ok] chat backup completed -> ${CHAT_OUT}"
fi
