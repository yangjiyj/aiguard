#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_SCRIPT="$ROOT_DIR/deploy/docker-compose/install-docker.sh"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT
fail() { echo "[fail] $*" >&2; exit 1; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "expected $1 to contain: $2"; }
assert_not_contains() { ! grep -Fq -- "$2" "$1" || fail "expected $1 not to contain: $2"; }

make_payload() {
  local root="$1"
  mkdir -p "$root/payload/docker"
  printf '#!/bin/sh\nexit 0\n' >"$root/payload/docker/docker"
  cat >"$root/fake-dockerd.c" <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t stopping;
static void stop_now(int signo) { (void)signo; stopping = 1; }
int main(int argc, char **argv) {
  const char *pidfile = NULL;
  for (int i = 1; i < argc; i++) if (!strncmp(argv[i], "--pidfile=", 10)) pidfile = argv[i] + 10;
  if (!pidfile) return 2;
  FILE *file = fopen(pidfile, "w"); if (!file) return 3;
  fprintf(file, "%ld\n", (long)getpid()); fclose(file);
  printf("fake dockerd started %ld\n", (long)getpid()); fflush(stdout);
  signal(SIGTERM, stop_now); signal(SIGINT, stop_now);
  while (!stopping) pause();
  unlink(pidfile); printf("fake dockerd stopped %ld\n", (long)getpid()); fflush(stdout);
  return 0;
}
EOF
  cc -O2 -o "$root/payload/docker/dockerd" "$root/fake-dockerd.c"
  chmod +x "$root/payload/docker/"*
  tar -czf "$root/docker-static.tgz" -C "$root/payload" docker
}
link_command() { ln -s "$(command -v "$2")" "$1/$2"; }
make_common_fakes() {
  local root="$1" bin="$root/bin" name
  mkdir -p "$bin" "$root/state" "$root/install-bin" "$root/etc/systemd/system" \
    "$root/etc/init.d" "$root/run" "$root/log"
  for name in dirname mktemp tar gzip cat install basename ls tr rm mkdir chmod; do link_command "$bin" "$name"; done
  printf '#!/bin/sh\n[ "${1:-}" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n' >"$bin/id"
  printf '#!/bin/sh\necho x86_64\n' >"$bin/uname"
  printf '#!/bin/sh\nexit 0\n' >"$bin/getent"
  printf '#!/bin/sh\nexit 0\n' >"$bin/sleep"
  cat >"$bin/docker" <<'EOF'
#!/bin/sh
if [ "${1:-}" = info ]; then [ -f "${FAKE_STATE:?}/ready" ]; exit; fi
if [ "${1:-}" = --version ]; then echo 'Docker version fixture'; fi
exit 0
EOF
  chmod +x "$bin/"*
  make_payload "$root"
}
write_service_fake() {
  cat >"$1" <<EOF
#!/bin/sh
printf '%s\\n' "\$0 \$*" >>"\${FAKE_LOG:?}"
[ "\${FAKE_FAIL_MATCH:-}" = "\$*" ] && exit 19
[ "\$*" = '$2' ] && /usr/bin/touch "\${FAKE_STATE:?}/ready"
exit 0
EOF
  chmod +x "$1"
}
run_fixture() {
  local root="$1"
  env OFFLINE_EXPECTED_ARCH=x86_64 DOCKER_INSTALL_TEST_MODE=1 PATH="$root/bin" FAKE_STATE="$root/state" FAKE_LOG="$root/commands.log" \
    DOCKER_STATIC_TGZ="$root/docker-static.tgz" DOCKER_INSTALL_BIN_DIR="$root/install-bin" \
    DOCKER_SYSTEMD_RUN_DIR="$root/run/systemd/system" \
    DOCKER_SYSTEMD_UNIT_DIR="$root/etc/systemd/system" DOCKER_INITD_DIR="$root/etc/init.d" \
    DOCKER_RUN_DIR="$root/run" DOCKER_LOG_DIR="$root/log" /bin/sh "$INSTALL_SCRIPT"
}
test_systemd() {
  local root="$FIXTURE_ROOT/systemd" unit
  make_common_fakes "$root"; mkdir -p "$root/run/systemd/system"
  write_service_fake "$root/bin/systemctl" 'restart docker.service'; run_fixture "$root"
  unit="$root/etc/systemd/system/docker.service"
  assert_contains "$unit" "ExecStart=$root/install-bin/dockerd --host=unix://$root/run/docker.sock"
  assert_contains "$unit" "--feature containerd-snapshotter=false"
  assert_contains "$unit" 'Restart=always'; assert_contains "$unit" 'KillMode=control-group'; assert_contains "$unit" 'WantedBy=multi-user.target'
  assert_contains "$root/commands.log" 'daemon-reload'; assert_contains "$root/commands.log" 'enable docker.service'
  assert_contains "$root/commands.log" 'restart docker.service'
}
test_openrc() {
  local root="$FIXTURE_ROOT/openrc" init
  make_common_fakes "$root"; write_service_fake "$root/bin/rc-service" 'docker restart'
  write_service_fake "$root/bin/rc-update" never; run_fixture "$root"; init="$root/etc/init.d/docker"
  assert_contains "$init" '#!/sbin/openrc-run'; assert_contains "$init" "command=\"$root/install-bin/dockerd\""
  assert_contains "$init" "command_args=\"--host=unix://$root/run/docker.sock --feature containerd-snapshotter=false --pidfile=$root/run/docker.pid\""
  assert_contains "$init" '--feature containerd-snapshotter=false'
  assert_contains "$init" 'supervisor=supervise-daemon'; assert_contains "$root/commands.log" 'add docker default'
  assert_contains "$init" "pidfile=\"$root/run/docker-supervise.pid\""
  assert_not_contains "$init" "pidfile=\"$root/run/docker.pid\""
  assert_contains "$root/commands.log" 'docker restart'
}
exercise_sysv_fallback() {
  local root="$1" init="$2" runtime="$root/runtime-bin" pid1 pid2 unrelated status name
  mkdir -p "$runtime"
  for name in cat rm sleep readlink tr grep; do link_command "$runtime" "$name"; done
  PATH="$runtime" "$init" start
  pid1="$(cat "$root/run/docker.pid")"
  PATH="$runtime" "$init" status || fail 'SysV status rejected running dockerd'
  assert_contains "$root/log/dockerd.log" 'fake dockerd started'
  PATH="$runtime" "$init" restart
  pid2="$(cat "$root/run/docker.pid")"
  [ "$pid1" != "$pid2" ] || fail 'SysV restart did not replace dockerd'
  PATH="$runtime" "$init" status || fail 'SysV restart left dockerd stopped'
  PATH="$runtime" "$init" stop
  set +e; PATH="$runtime" "$init" status >/dev/null 2>&1; status=$?; set -e
  [ "$status" -eq 3 ] || fail "stopped SysV status must return 3, got $status"

  /bin/sh -c 'while :; do /bin/sleep 1; done' unrelated "$root/install-bin/dockerd" & unrelated=$!
  echo "$unrelated" >"$root/run/docker.pid"
  if PATH="$runtime" "$init" restart >/dev/null 2>&1; then fail 'SysV restart accepted unrelated pid'; fi
  kill -0 "$unrelated" 2>/dev/null || fail 'SysV stop killed unrelated process'
  kill "$unrelated" 2>/dev/null || true; wait "$unrelated" 2>/dev/null || true
  rm -f "$root/run/docker.pid"
}
exercise_sysv_start_stop_daemon() {
  local root="$1" init="$2" runtime="$root/ssd-runtime" pid1 pid2 status name
  mkdir -p "$runtime"
  for name in cat rm sleep readlink grep start-stop-daemon; do link_command "$runtime" "$name"; done
  PATH="$runtime" "$init" start
  pid1="$(cat "$root/run/docker.pid")"
  PATH="$runtime" "$init" status || fail 'start-stop-daemon status rejected running dockerd'
  assert_contains "$root/log/dockerd.log" 'fake dockerd started'
  PATH="$runtime" "$init" restart
  pid2="$(cat "$root/run/docker.pid")"
  [ "$pid1" != "$pid2" ] || fail 'start-stop-daemon restart did not replace dockerd'
  PATH="$runtime" "$init" stop
  set +e; PATH="$runtime" "$init" status >/dev/null 2>&1; status=$?; set -e
  [ "$status" -eq 3 ] || fail "stopped start-stop-daemon status must return 3, got $status"
}
exercise_sysv_legacy_capability() {
  local root="$1" init="$2" capability="$3" runtime="$root/ssd-$3" pid1 pid2 status name
  mkdir -p "$runtime"
  for name in cat rm sleep readlink grep; do link_command "$runtime" "$name"; done
  cat >"$runtime/start-stop-daemon" <<'EOF'
#!/bin/sh
+if [ "${1:-}" = '--help' ]; then
+  [ "${FAKE_SSD_CAP:?}" = old ] && echo '  --no-close'
+  exit 0
+fi
+case "$*" in *--output*) exit 73 ;; esac
+if [ "${1:-}" = '--start' ]; then
+  [ "${FAKE_SSD_CAP:?}" = none ] && exit 74
+  startas=''
+  while [ "$#" -gt 0 ] && [ "$1" != '--' ]; do
+    if [ "$1" = '--startas' ]; then shift; startas="$1"; fi
+    shift
+  done
+  shift
+  [ -n "$startas" ] || exit 75
+  "$startas" "$@" &
+  exit 0
+fi
+exec /usr/sbin/start-stop-daemon "$@"
EOF
  sed -i 's/^+//' "$runtime/start-stop-daemon"
  chmod +x "$runtime/start-stop-daemon"
  : >"$root/log/dockerd.log"
  FAKE_SSD_CAP="$capability" PATH="$runtime" "$init" start
  pid1="$(cat "$root/run/docker.pid")"
  FAKE_SSD_CAP="$capability" PATH="$runtime" "$init" status
  assert_contains "$root/log/dockerd.log" 'fake dockerd started'
  FAKE_SSD_CAP="$capability" PATH="$runtime" "$init" restart
  pid2="$(cat "$root/run/docker.pid")"
  [ "$pid1" != "$pid2" ] || fail "$capability capability restart did not replace dockerd"
  FAKE_SSD_CAP="$capability" PATH="$runtime" "$init" stop
  set +e; FAKE_SSD_CAP="$capability" PATH="$runtime" "$init" status >/dev/null 2>&1; status=$?; set -e
  [ "$status" -eq 3 ] || fail "$capability capability stop status was $status"
}
test_sysv() {
  local flavor="$1" root="$FIXTURE_ROOT/sysv-$1" init
  make_common_fakes "$root"; write_service_fake "$root/bin/service" 'docker restart'
  write_service_fake "$root/bin/$flavor" never; run_fixture "$root"; init="$root/etc/init.d/docker"
  assert_contains "$init" '### BEGIN INIT INFO'; assert_contains "$init" "DAEMON=$root/install-bin/dockerd"
  assert_contains "$init" 'start-stop-daemon'; assert_contains "$root/commands.log" 'docker restart'
  assert_contains "$init" "DAEMON_ARGS=\"--host=unix://$root/run/docker.sock --feature containerd-snapshotter=false --pidfile=$root/run/docker.pid\""
  assert_contains "$init" '--feature containerd-snapshotter=false'
  assert_not_contains "$init" '--make-pidfile'
  assert_contains "$init" 'start-stop-daemon --start --background --startas "$DAEMON" --pidfile "$PIDFILE" --exec "$DAEMON"'
  assert_contains "$init" '--output "$LOGFILE"'
  assert_not_contains "$init" 'do_stop || true; do_start'
  assert_contains "$init" '>>"$LOGFILE" 2>&1'
  if [ "$flavor" = update-rc.d ]; then assert_contains "$root/commands.log" 'docker defaults'; exercise_sysv_fallback "$root" "$init"
  else
    assert_contains "$init" '# chkconfig: 2345 20 80'
    assert_contains "$init" '# description: Docker Application Container Engine'
    assert_contains "$root/commands.log" '--add docker'; assert_contains "$root/commands.log" 'docker on'
    exercise_sysv_start_stop_daemon "$root" "$init"
    exercise_sysv_legacy_capability "$root" "$init" old
    exercise_sysv_legacy_capability "$root" "$init" none
  fi
}
test_unsupported() {
  local root="$FIXTURE_ROOT/unsupported" output
  make_common_fakes "$root"
  if output="$(run_fixture "$root" 2>&1)"; then fail 'unsupported init unexpectedly succeeded'; fi
  [[ "$output" == *'未检测到受支持的 init 系统'* ]] || fail "wrong failure: $output"
  [ ! -e "$root/install-bin/dockerd" ] || fail 'installed binaries before init validation'
}
test_registration_failures() {
  local root
  root="$FIXTURE_ROOT/systemd-enable-failure"
  make_common_fakes "$root"; mkdir -p "$root/run/systemd/system"
  write_service_fake "$root/bin/systemctl" 'restart docker.service'
  if FAKE_FAIL_MATCH='enable docker.service' run_fixture "$root" >/dev/null 2>&1; then
    fail 'systemd enable failure was ignored'
  fi

  root="$FIXTURE_ROOT/openrc-enable-failure"
  make_common_fakes "$root"; write_service_fake "$root/bin/rc-service" 'docker restart'
  write_service_fake "$root/bin/rc-update" never
  if FAKE_FAIL_MATCH='add docker default' run_fixture "$root" >/dev/null 2>&1; then
    fail 'OpenRC enable failure was ignored'
  fi

  root="$FIXTURE_ROOT/sysv-enable-failure"
  make_common_fakes "$root"; write_service_fake "$root/bin/service" 'docker restart'
  write_service_fake "$root/bin/update-rc.d" never
  if FAKE_FAIL_MATCH='docker defaults' run_fixture "$root" >/dev/null 2>&1; then
    fail 'SysV enable failure was ignored'
  fi
}
test_path_override_boundaries() {
  local root="$FIXTURE_ROOT/path-boundaries" output
  make_common_fakes "$root"; mkdir -p "$root/run/systemd/system"
  write_service_fake "$root/bin/systemctl" 'restart docker.service'
  if output="$(env PATH="$root/bin" FAKE_STATE="$root/state" FAKE_LOG="$root/commands.log" \
      DOCKER_INSTALL_BIN_DIR="$root/install-bin" /bin/sh "$INSTALL_SCRIPT" 2>&1)"; then
    fail 'production mode accepted path overrides'
  fi
  [[ "$output" == *'生产模式禁止路径覆盖'* ]] || fail "wrong production override failure: $output"
  if output="$(env OFFLINE_EXPECTED_ARCH=x86_64 DOCKER_INSTALL_TEST_MODE=1 PATH="$root/bin" FAKE_STATE="$root/state" FAKE_LOG="$root/commands.log" \
      DOCKER_STATIC_TGZ="$root/docker-static.tgz" DOCKER_INSTALL_BIN_DIR="$root/install-bin" \
      DOCKER_SYSTEMD_RUN_DIR="$root/run/systemd/system" DOCKER_SYSTEMD_UNIT_DIR="$root/etc/systemd/system" \
      DOCKER_INITD_DIR="$root/etc/init.d" DOCKER_RUN_DIR="$root/run" DOCKER_LOG_DIR="$root/log;unsafe" \
      /bin/sh "$INSTALL_SCRIPT" 2>&1)"; then
    fail 'test mode accepted unsafe path override'
  fi
  [[ "$output" == *'测试路径不安全'* ]] || fail "wrong unsafe path failure: $output"
}
test_systemd; test_openrc; test_sysv update-rc.d; test_sysv chkconfig
test_unsupported; test_registration_failures; test_path_override_boundaries
echo '[pass] install-docker init persistence checks passed'
