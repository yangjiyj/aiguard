#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
LOG="$TEST_ROOT/docker.log"
BIN="$TEST_ROOT/control-plane"
trap 'rm -rf "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/bin"

for required in 'IDENTITY_LAB_GO ?=' 'IDENTITY_LAB_WAIT ?='; do
  grep -Fq "$required" "$REPO_ROOT/Makefile" ||
    { echo "Makefile lacks fakeable tool variable: $required" >&2; exit 1; }
done

cat >"$TEST_ROOT/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu
echo "$*" >>"$FAKE_DOCKER_LOG"
if [ "$FAIL_STAGE" = up ] && [[ "$*" == *" up -d"* ]]; then exit 7; fi
EOF
chmod +x "$TEST_ROOT/bin/docker"

cat >"$TEST_ROOT/bin/go" <<'EOF'
#!/usr/bin/env bash
set -eu
[ "$FAIL_STAGE" != build ] || exit 7
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then shift; : >"$1"; exit 0; fi
  shift
done
exit 8
EOF
chmod +x "$TEST_ROOT/bin/go"

cat >"$TEST_ROOT/wait" <<'EOF'
#!/usr/bin/env bash
set -eu
[ "$FAIL_STAGE" != wait ] || exit 7
EOF
cat >"$TEST_ROOT/smoke" <<'EOF'
#!/usr/bin/env bash
set -eu
[ "$FAIL_STAGE" != smoke ] || exit 7
EOF
chmod +x "$TEST_ROOT/wait" "$TEST_ROOT/smoke"

make_lab() {
  PATH="$TEST_ROOT/bin:$PATH" FAKE_DOCKER_LOG="$LOG" FAIL_STAGE="$FAIL_STAGE" make -s -C "$REPO_ROOT" "$@" IDENTITY_LAB_GO="$TEST_ROOT/bin/go" IDENTITY_LAB_WAIT="$TEST_ROOT/wait" IDENTITY_LAB_SMOKE="$TEST_ROOT/smoke" IDENTITY_LAB_CP_BIN="$BIN"
}

down_count() {
  awk '/compose --project-name jjdguard-identity-lab/ && /down -v --remove-orphans/ {n++} END {print n+0}' "$LOG"
}

for stage in build up wait; do
  : >"$LOG"
  rm -f "$BIN"
  set +e
  FAIL_STAGE="$stage" make_lab identity-lab-up
  status=$?
  set -e
  [ "$status" -ne 0 ] || { echo "$stage failure was accepted" >&2; exit 1; }
  [ "$(down_count)" -ge 2 ] || { echo "$stage failure did not run exact cleanup" >&2; exit 1; }
  [ ! -e "$BIN" ] || { echo "$stage failure left the control-plane binary" >&2; exit 1; }
done

: >"$LOG"
rm -f "$BIN"
set +e
FAIL_STAGE=smoke make_lab identity-lab-smoke
status=$?
set -e
[ "$status" -ne 0 ] || { echo "smoke failure was accepted" >&2; exit 1; }
[ "$(down_count)" -ge 1 ] || { echo "smoke failure did not run exact cleanup" >&2; exit 1; }
[ ! -e "$BIN" ] || { echo "smoke failure left the control-plane binary" >&2; exit 1; }

: >"$LOG"
FAIL_STAGE= make_lab identity-lab-up
[ -e "$BIN" ] || { echo "successful up did not create the binary" >&2; exit 1; }
FAIL_STAGE= make_lab identity-lab-down
[ ! -e "$BIN" ] || { echo "explicit down left the control-plane binary" >&2; exit 1; }
[ "$(down_count)" -ge 2 ] || { echo "success path was not explicitly torn down" >&2; exit 1; }

echo "PASS: identity lab Make failures clean exact project resources"
