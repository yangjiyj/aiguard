#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WAIT_SCRIPT="$ROOT/deploy/offline-installer/wait-docker.sh"
SERVICE="$ROOT/deploy/offline-installer/jjdguard.service"
EXPECTED_ERROR='[error] Docker daemon 在有界等待后仍不可用'
EXPECTED_CONFIG_ERROR='[error] Docker 等待参数无效'
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() { echo "[fail] $*" >&2; exit 1; }

assert_eq() {
  local actual="$1" expected="$2" message="$3"
  [[ "$actual" == "$expected" ]] ||
    fail "$message: expected <$expected>, got <$actual>"
}

make_fake_commands() {
  local fixture="$1"

  mkdir -p "$fixture/bin"
  : >"$fixture/docker-count"
  : >"$fixture/sleep-log"

  cat >"$fixture/bin/docker" <<'EOF'
#!/bin/sh
set -eu

[ "${1:-}" = info ] || exit 90

count=0
if [ -s "$FAKE_DOCKER_COUNT_FILE" ]; then
  count="$(cat "$FAKE_DOCKER_COUNT_FILE")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$FAKE_DOCKER_COUNT_FILE"

echo 'DOCKER_HOST=tcp://sensitive.example:2376'
echo 'Server Version: secret-build' >&2

if [ "$count" -eq "${FAKE_DOCKER_SUCCEED_ON:-0}" ]; then
  exit 0
fi
exit 1
EOF

  cat >"$fixture/bin/sleep" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "${1:-}" >>"$FAKE_SLEEP_LOG"
if [ "${1:-}" = infinity ]; then
  exec "$REAL_SLEEP_BIN" infinity
fi
EOF

  chmod +x "$fixture/bin/docker" "$fixture/bin/sleep"
}

test_succeeds_on_third_docker_info_without_extra_sleep() {
  local fixture="$FIXTURE_ROOT/success" output
  make_fake_commands "$fixture"

  output="$(
    env PATH="$fixture/bin:$PATH" \
      FAKE_DOCKER_COUNT_FILE="$fixture/docker-count" \
      FAKE_DOCKER_SUCCEED_ON=3 \
      FAKE_SLEEP_LOG="$fixture/sleep-log" \
      DOCKER_WAIT_ATTEMPTS=5 \
      DOCKER_WAIT_INTERVAL_SECONDS=1 \
      "$WAIT_SCRIPT" 2>&1
  )" || fail "wait script should succeed on the third docker info call: $output"

  assert_eq "$output" '' 'successful wait must not expose docker output'
  assert_eq "$(cat "$fixture/docker-count")" 3 'docker info call count'
  assert_eq "$(cat "$fixture/sleep-log")" $'1\n1' 'sleep calls before success'
}

test_fails_at_limit_without_leaking_docker_details() {
  local fixture="$FIXTURE_ROOT/failure" output status
  make_fake_commands "$fixture"

  set +e
  output="$(
    env PATH="$fixture/bin:$PATH" \
      FAKE_DOCKER_COUNT_FILE="$fixture/docker-count" \
      FAKE_DOCKER_SUCCEED_ON=0 \
      FAKE_SLEEP_LOG="$fixture/sleep-log" \
      DOCKER_WAIT_ATTEMPTS=2 \
      DOCKER_WAIT_INTERVAL_SECONDS=0 \
      "$WAIT_SCRIPT" 2>&1
  )"
  status=$?
  set -e

  assert_eq "$status" 1 'wait script failure status'
  assert_eq "$output" "$EXPECTED_ERROR" 'wait script failure output'
  [[ "$output" != *'DOCKER_HOST='* ]] || fail 'failure output leaked Docker environment details'
  [[ "$output" != *'secret-build'* ]] || fail 'failure output leaked docker info details'
  assert_eq "$(cat "$fixture/docker-count")" 2 'bounded docker info call count'
  assert_eq "$(cat "$fixture/sleep-log")" 0 'sleep calls before bounded failure'
}

invalid_config_is_rejected() {
  local label="$1" attempts="$2" interval_seconds="$3"
  local fixture="$FIXTURE_ROOT/invalid-$label" output status failed=0
  make_fake_commands "$fixture"

  set +e
  output="$(
    env PATH="$fixture/bin:$PATH" \
      FAKE_DOCKER_COUNT_FILE="$fixture/docker-count" \
      FAKE_DOCKER_SUCCEED_ON=0 \
      FAKE_SLEEP_LOG="$fixture/sleep-log" \
      REAL_SLEEP_BIN="$REAL_SLEEP_BIN" \
      DOCKER_WAIT_ATTEMPTS="$attempts" \
      DOCKER_WAIT_INTERVAL_SECONDS="$interval_seconds" \
      "$TIMEOUT_BIN" 1 "$WAIT_SCRIPT" 2>&1
  )"
  status=$?
  set -e

  if [[ "$status" -eq 124 ]]; then
    echo "[test-fail] invalid config $label timed out" >&2
    failed=1
  elif [[ "$status" -ne 2 ]]; then
    echo "[test-fail] invalid config $label returned $status instead of 2" >&2
    failed=1
  fi
  if [[ "$output" != "$EXPECTED_CONFIG_ERROR" ]]; then
    echo "[test-fail] invalid config $label exposed unstable output: <$output>" >&2
    failed=1
  fi
  if [[ -s "$fixture/docker-count" ]]; then
    echo "[test-fail] invalid config $label called docker before validation" >&2
    failed=1
  fi
  if [[ -s "$fixture/sleep-log" ]]; then
    echo "[test-fail] invalid config $label called sleep before validation" >&2
    failed=1
  fi

  return "$failed"
}

test_rejects_invalid_wait_configuration_before_commands() {
  local label attempts interval_seconds spec failures=0
  local specs=(
    'attempts-zero|0|0'
    'attempts-negative|-1|0'
    'attempts-text|abc|0'
    'attempts-over-limit|121|0'
    'attempts-overflow|999999999999999999999999|0'
    'interval-negative|2|-1'
    'interval-text|2|abc'
    'interval-infinity|2|infinity'
    'interval-over-limit|2|6'
    'interval-overflow|2|999999999999999999999999'
  )

  for spec in "${specs[@]}"; do
    IFS='|' read -r label attempts interval_seconds <<<"$spec"
    if ! invalid_config_is_rejected "$label" "$attempts" "$interval_seconds"; then
      failures=$((failures + 1))
    fi
  done

  assert_eq "$failures" 0 'invalid wait configuration failures'
}

test_accepts_maximum_wait_configuration() {
  local fixture="$FIXTURE_ROOT/maximum" output
  make_fake_commands "$fixture"

  output="$(
    env PATH="$fixture/bin:$PATH" \
      FAKE_DOCKER_COUNT_FILE="$fixture/docker-count" \
      FAKE_DOCKER_SUCCEED_ON=1 \
      FAKE_SLEEP_LOG="$fixture/sleep-log" \
      DOCKER_WAIT_ATTEMPTS=120 \
      DOCKER_WAIT_INTERVAL_SECONDS=5 \
      "$WAIT_SCRIPT" 2>&1
  )" || fail "maximum valid wait configuration should succeed: $output"

  assert_eq "$output" '' 'maximum valid wait must not expose docker output'
  assert_eq "$(cat "$fixture/docker-count")" 1 'maximum valid docker info call count'
  [[ ! -s "$fixture/sleep-log" ]] || fail 'maximum valid configuration slept after immediate success'
}

test_service_waits_before_start() {
  local pre_line start_line

  pre_line="$(grep -nF 'ExecStartPre=/opt/jjdguard/current/deploy/offline-installer/wait-docker.sh' "$SERVICE" | cut -d: -f1 || true)"
  start_line="$(grep -nF 'ExecStart=/opt/jjdguard/current/jjdctl start' "$SERVICE" | cut -d: -f1 || true)"

  [[ -n "$pre_line" ]] || fail 'service missing Docker readiness ExecStartPre'
  [[ -n "$start_line" ]] || fail 'service missing jjdctl ExecStart'
  [[ "$pre_line" -lt "$start_line" ]] || fail 'Docker readiness ExecStartPre must precede ExecStart'
}

[[ -f "$WAIT_SCRIPT" ]] || fail "missing wait script: $WAIT_SCRIPT"
[[ -x "$WAIT_SCRIPT" ]] || fail "wait script is not executable: $WAIT_SCRIPT"
TIMEOUT_BIN="$(command -v timeout || true)"
REAL_SLEEP_BIN="$(command -v sleep || true)"
[[ -x "$TIMEOUT_BIN" ]] || fail 'timeout command is required for readiness tests'
[[ -x "$REAL_SLEEP_BIN" ]] || fail 'sleep command is required for readiness tests'

test_succeeds_on_third_docker_info_without_extra_sleep
test_fails_at_limit_without_leaking_docker_details
test_accepts_maximum_wait_configuration
test_rejects_invalid_wait_configuration_before_commands
test_service_waits_before_start

echo '[ok] systemd Docker readiness contract passed'
