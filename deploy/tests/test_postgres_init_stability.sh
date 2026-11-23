#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY="$ROOT/deploy/docker-compose/deploy-offline.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

awk '
  /^wait_postgres_main_process_ready\(\)[[:space:]]*\{/ { capture=1 }
  capture { print }
  capture && /^}/ { exit }
' "$DEPLOY" >"$tmp/function.sh"

grep -q '^wait_postgres_main_process_ready()' "$tmp/function.sh" ||
  fail "deploy script has no PostgreSQL init-stability gate"

cat >"$tmp/compose-wrapper.sh" <<'EOF'
#!/bin/sh
set -eu
case "$*" in
  *"/proc/1/comm"*)
    n=0
    [ ! -f "$COUNTER_FILE" ] || n="$(cat "$COUNTER_FILE")"
    n=$((n + 1))
    printf '%s\n' "$n" >"$COUNTER_FILE"
    if [ "$ALWAYS_INIT" = "1" ] || [ "$n" -lt 3 ]; then
      printf 'bash\n'
    else
      printf 'postgres\n'
    fi
    ;;
  *"pg_isready"*)
    exit 0
    ;;
  *)
    echo "unexpected compose call: $*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$tmp/compose-wrapper.sh"

# shellcheck disable=SC1090
source "$tmp/function.sh"
COMPOSE_WRAPPER="$tmp/compose-wrapper.sh"
POSTGRES_USER=jjdguard
POSTGRES_DB=jjdguard
JJD_POSTGRES_STABLE_ATTEMPTS=4
JJD_POSTGRES_STABLE_INTERVAL=0
COUNTER_FILE="$tmp/counter"
export COUNTER_FILE

ALWAYS_INIT=0
export ALWAYS_INIT
wait_postgres_main_process_ready
[[ "$(cat "$COUNTER_FILE")" == "3" ]] ||
  fail "gate did not wait through the temporary init server"

rm -f "$COUNTER_FILE"
ALWAYS_INIT=1
export ALWAYS_INIT
if wait_postgres_main_process_ready >"$tmp/stdout" 2>"$tmp/stderr"; then
  fail "gate accepted docker-entrypoint temporary server as stable"
fi
grep -q 'PostgreSQL initialization did not reach stable main process' "$tmp/stderr" ||
  fail "timeout did not emit the expected diagnostic"

start_line="$(grep -n 'up -d --wait postgres redis' "$DEPLOY" | head -1 | cut -d: -f1)"
gate_line="$(grep -n '^wait_postgres_main_process_ready$' "$DEPLOY" | head -1 | cut -d: -f1)"
bootstrap_line="$(grep -n 'bootstrapping base schema' "$DEPLOY" | head -1 | cut -d: -f1)"
[[ -n "$start_line" && -n "$gate_line" && -n "$bootstrap_line" ]] ||
  fail "database startup ordering markers are incomplete"
(( start_line < gate_line && gate_line < bootstrap_line )) ||
  fail "stability gate must run after compose wait and before bootstrap"

echo "[ok] PostgreSQL temporary init server is rejected until PID 1 is postgres"
