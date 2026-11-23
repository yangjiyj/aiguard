#!/usr/bin/env bash
# deploy/tests/lib/test-containers.sh 的自测（用假 docker，不碰真实容器）：
#   - 标签带 owner_pid、created、host、kind；
#   - 回收只删“本套标签、同一台主机、owner 进程已不在、创建超过 30 分钟”的容器，且用 rm -f -v；
#   - owner 还活着、不到 30 分钟、别的主机、标签不全的一律不碰；docker 不可用时不报错。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/deploy/tests/lib/test-containers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

host="$(hostname)"
now="$(date +%s)"
old=$((now - 31 * 60))
young=$((now - 29 * 60))
sleep 300 & alive_pid=$!
trap 'kill "$alive_pid" 2>/dev/null || true; rm -rf "$work"' EXIT
dead_pid=$( (sh -c 'echo $$') )
while ps -p "$dead_pid" >/dev/null 2>&1; do dead_pid=$((dead_pid + 7919)); done

mkdir -p "$work/bin"
cat >"$work/bin/docker" <<FAKE
#!/usr/bin/env bash
echo "\$*" >>"$work/calls"
if [[ "\$1" == ps ]]; then
  printf '%s\t%s\t%s\t%s\n' \
    dead-old "$dead_pid" "$old" "$host" \
    alive-old "$alive_pid" "$old" "$host" \
    dead-young "$dead_pid" "$young" "$host" \
    other-host "$dead_pid" "$old" other-host.invalid \
    bad-pid abc "$old" "$host" \
    bad-created "$dead_pid" yesterday "$host" \
    zero-pid 0 "$old" "$host"
fi
FAKE
chmod +x "$work/bin/docker"

# shellcheck source=deploy/tests/lib/test-containers.sh
. "$LIB"
jjd_test_container_labels pg-fixture
labels="${JJD_TEST_CONTAINER_LABELS[*]}"
[[ "$labels" == "--label jjdguard.test.owner_pid=$$ --label jjdguard.test.created="*" --label jjdguard.test.host=$host --label jjdguard.test.kind=pg-fixture" ]] ||
  fail "labels: $labels"
created_label="${JJD_TEST_CONTAINER_LABELS[3]#jjdguard.test.created=}"
(( created_label >= now && created_label <= now + 5 )) || fail "created label $created_label"

PATH="$work/bin:$PATH" jjd_test_reap_orphan_containers 2>"$work/stderr"
grep -Fxq 'ps -a --filter label=jjdguard.test.owner_pid --format {{.ID}}	{{.Label "jjdguard.test.owner_pid"}}	{{.Label "jjdguard.test.created"}}	{{.Label "jjdguard.test.host"}}' "$work/calls" ||
  fail "list command: $(cat "$work/calls")"
removed="$(grep '^rm ' "$work/calls" || true)"
[[ "$removed" == "rm -f -v dead-old" ]] || fail "only the dead, old, same-host container may be removed: $removed"

# 直接执行（Python 测试用）：bash lib reap
: >"$work/calls"
PATH="$work/bin:$PATH" bash "$LIB" reap 2>/dev/null
[[ "$(grep '^rm ' "$work/calls" || true)" == "rm -f -v dead-old" ]] || fail "script mode reap"

# docker 不可用：不报错、不删任何东西
cat >"$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
exit 1
FAKE
PATH="$work/bin:$PATH" jjd_test_reap_orphan_containers 2>/dev/null || fail "reap must not fail when docker is unavailable"
echo "test_test_containers_lib: ok"
