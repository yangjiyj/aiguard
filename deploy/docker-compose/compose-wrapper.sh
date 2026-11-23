#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BUNDLED_COMPOSE="$SCRIPT_DIR/bin/docker-compose"

# Offline installations use the toolchain validated with this release.
# A damaged bundled executable must not silently select an older host plugin.
if [ -e "$BUNDLED_COMPOSE" ] || [ -L "$BUNDLED_COMPOSE" ]; then
  if [ ! -f "$BUNDLED_COMPOSE" ] || [ ! -x "$BUNDLED_COMPOSE" ]; then
    echo "[error] Bundled Docker Compose is not executable: $BUNDLED_COMPOSE" >&2
    exit 1
  fi
  exec "$BUNDLED_COMPOSE" "$@"
fi

# Source checkouts do not carry the release toolchain.
if docker compose version >/dev/null 2>&1; then
  exec docker compose "$@"
fi

echo "[error] Docker Compose v2 is required." >&2
echo "[hint] Install Docker Compose v2, or use an offline bundle that includes deploy/docker-compose/bin/docker-compose." >&2
exit 1
