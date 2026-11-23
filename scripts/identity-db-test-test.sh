#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUBJECT="$ROOT/scripts/identity-db-test.sh"
TEST_ROOT="$(mktemp -d /tmp/jjdguard-identity-db-owner-test.XXXXXX)"
FAKE_BIN="$TEST_ROOT/bin"
mkdir -p "$FAKE_BIN"

cleanup() {
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

cat >"$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "$*" >>"$FAKE_DOCKER_LOG"
case "${1:-}" in
  ps)
    if [ "$FAKE_DOCKER_MODE" = "preexisting" ]; then
      echo "jjdguard-identity-db-test-pg"
      echo "jjdguard-identity-db-test-pg-preexisting1"
    fi
    ;;
  run)
    if [[ "$FAKE_DOCKER_MODE" == run-fail-* ]]; then
      exit 125
    fi
    ;;
  exec)
    exit 1
    ;;
  logs)
    ;;
  inspect)
    if [ "$FAKE_DOCKER_MODE" = "run-fail-empty" ]; then
      exit 1
    fi
    container="${!#}"
    echo "${container#jjdguard-identity-db-test-pg-}"
    ;;
  rm)
    ;;
esac
EOF
chmod +x "$FAKE_BIN/docker"

cat >"$FAKE_BIN/seq" <<'EOF'
#!/usr/bin/env bash
echo 1
EOF
cat >"$FAKE_BIN/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$FAKE_BIN/seq" "$FAKE_BIN/sleep"

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

run_subject() {
  local mode="$1"
  local nonce="$2"
  local log="$3"
  local output="$4"
  : >"$log"
  set +e
  FAKE_DOCKER_MODE="$mode" FAKE_DOCKER_LOG="$log" JJD_IDENTITY_DB_TEST_OWNER_NONCE="$nonce" PATH="$FAKE_BIN:$PATH" "$SUBJECT" >"$output" 2>&1
  RUN_STATUS=$?
  set -e
}

preexisting_log="$TEST_ROOT/preexisting.log"
run_subject preexisting preexisting1 "$preexisting_log" "$TEST_ROOT/preexisting.out"
if [ "$RUN_STATUS" -eq 0 ]; then
  fail "preexisting container was not rejected"
fi
if grep -q '^rm -f ' "$preexisting_log"; then
  fail "preexisting container was removed"
fi

run_fail_owned_log="$TEST_ROOT/run-fail-owned.log"
run_subject run-fail-owned runowned1 "$run_fail_owned_log" "$TEST_ROOT/run-fail-owned.out"
if [ "$RUN_STATUS" -eq 0 ]; then
  fail "owned docker run failure did not fail the DB gate"
fi
run_fail_owned_rm="rm -f jjdguard-identity-db-test-pg-runowned1"
if [ "$(grep -Fxc "$run_fail_owned_rm" "$run_fail_owned_log" || true)" -ne 1 ]; then
  fail "docker run failure leaked its exact owner-labelled container"
fi

run_fail_empty_log="$TEST_ROOT/run-fail-empty.log"
run_subject run-fail-empty runempty1 "$run_fail_empty_log" "$TEST_ROOT/run-fail-empty.out"
if [ "$RUN_STATUS" -eq 0 ]; then
  fail "empty docker run failure did not fail the DB gate"
fi
if grep -q '^rm -f ' "$run_fail_empty_log"; then
  fail "docker run failure without a container triggered removal"
fi

created_log="$TEST_ROOT/created.log"
run_subject created owncreated1 "$created_log" "$TEST_ROOT/created.out"
if [ "$RUN_STATUS" -eq 0 ]; then
  fail "fake readiness failure did not fail the DB gate"
fi
expected_rm="rm -f jjdguard-identity-db-test-pg-owncreated1"
if [ "$(grep -Fxc "$expected_rm" "$created_log" || true)" -ne 1 ]; then
  fail "owned container was not removed exactly once"
fi
if [ "$(grep -c '^rm -f ' "$created_log" || true)" -ne 1 ]; then
  fail "cleanup removed a container other than the owned container"
fi

concurrent_log="$TEST_ROOT/concurrent.log"
: >"$concurrent_log"
set +e
FAKE_DOCKER_MODE=concurrent FAKE_DOCKER_LOG="$concurrent_log" PATH="$FAKE_BIN:$PATH" "$SUBJECT" >"$TEST_ROOT/concurrent-1.out" 2>&1 &
pid_one=$!
FAKE_DOCKER_MODE=concurrent FAKE_DOCKER_LOG="$concurrent_log" PATH="$FAKE_BIN:$PATH" "$SUBJECT" >"$TEST_ROOT/concurrent-2.out" 2>&1 &
pid_two=$!
wait "$pid_one"
status_one=$?
wait "$pid_two"
status_two=$?
set -e
if [ "$status_one" -eq 0 ] || [ "$status_two" -eq 0 ]; then
  fail "fake concurrent readiness failures did not fail both DB gates"
fi
mapfile -t concurrent_names < <(
  awk '
    $1 == "run" {
      for (i = 1; i <= NF; i++) {
        if ($i == "--name") {
          print $(i + 1)
        }
      }
    }
  ' "$concurrent_log"
)
if [ "${#concurrent_names[@]}" -ne 2 ]; then
  fail "expected two concurrent docker run names"
elif [ "${concurrent_names[0]}" = "${concurrent_names[1]}" ]; then
  fail "concurrent DB gates reused the same container name"
fi
for name in "${concurrent_names[@]}"; do
  if ! [[ "$name" =~ ^jjdguard-identity-db-test-pg-[a-z0-9-]+$ ]]; then
    fail "unsafe concurrent container name: $name"
  fi
done

if [ "$failures" -ne 0 ]; then
  exit 1
fi
echo "PASS: identity DB container ownership and concurrency cleanup"
