#!/bin/sh
set -eu

attempts="${DOCKER_WAIT_ATTEMPTS:-120}"
interval_seconds="${DOCKER_WAIT_INTERVAL_SECONDS:-1}"
attempt=1

invalid_configuration() {
  echo '[error] Docker 等待参数无效' >&2
  exit 2
}

case "$attempts" in
  ''|*[!0-9]*) invalid_configuration ;;
esac
case "$interval_seconds" in
  ''|*[!0-9]*) invalid_configuration ;;
esac

if [ "${#attempts}" -gt 3 ] || [ "${#interval_seconds}" -gt 1 ]; then
  invalid_configuration
fi
if [ "$attempts" -lt 1 ] || [ "$attempts" -gt 120 ]; then
  invalid_configuration
fi
if [ "$interval_seconds" -lt 0 ] || [ "$interval_seconds" -gt 5 ]; then
  invalid_configuration
fi

while [ "$attempt" -le "$attempts" ]; do
  if docker info >/dev/null 2>&1; then
    exit 0
  fi

  if [ "$attempt" -lt "$attempts" ]; then
    sleep "$interval_seconds"
  fi
  attempt=$((attempt + 1))
done

echo '[error] Docker daemon 在有界等待后仍不可用' >&2
exit 1
