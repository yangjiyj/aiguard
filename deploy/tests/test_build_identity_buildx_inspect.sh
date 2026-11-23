#!/usr/bin/env bash
# 回归：buildx inspect 输出含 Devices:/Labels:/GC Policy 子段（例如加载了
# NVIDIA CDI 规范的 docker 守护进程）时，子段里缩进的 Name: 行不得被当成
# Buildx 节点；真正不完整的节点仍必须被拒绝。
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="$ROOT_DIR/deploy/tests/fixtures/buildx-inspect-cdi-devices.txt"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail() {
  echo "[fail] $*" >&2
  exit 1
}

[[ -f "$FIXTURE" ]] || fail "fixture is missing: $FIXTURE"
# shellcheck disable=SC1091
source "$ROOT_DIR/deploy/docker-compose/lib-build-identity.sh"

# make_fake_docker <name> <inspect-output-file>
make_fake_docker() {
  local fake="$TMP_ROOT/$1"
  cat >"$fake" <<FAKE
#!/usr/bin/env bash
case "\$*" in
  "version --format {{.Client.Version}}") printf "29.6.2\n" ;;
  "version --format {{.Server.Version}}") printf "29.6.2\n" ;;
  "buildx version") printf "github.com/docker/buildx v0.35.0 fixture\n" ;;
  "buildx inspect") cat "$2" ;;
  *) echo "unexpected fake docker call: \$*" >&2; exit 97 ;;
esac
FAKE
  chmod 0755 "$fake"
  printf "%s\n" "$fake"
}

expected_single_default='{"buildx_builder":"default","buildx_nodes":[{"buildkit_version":"v0.31.2","endpoint":"default","name":"default","status":"running"}],"buildx_version":"github.com/docker/buildx v0.35.0 fixture","docker_client_version":"29.6.2","docker_server_version":"29.6.2"}'

# 1) 真实宿主机输出（含 CDI Devices 段）只解析出一个 default 节点。
fake="$(make_fake_docker cdi "$FIXTURE")"
identity="$(build_identity_json "$fake")" ||
  fail "build identity rejected buildx inspect output with a Devices section"
[[ "$identity" == "$expected_single_default" ]] ||
  fail "unexpected identity for CDI fixture: $identity"
assert_build_identity_unchanged "$identity" "$fake" ||
  fail "identity drift reported for an unchanged CDI fixture"

# 2) 去掉子段后的同一节点，身份必须与上面完全一致（子段不影响身份）。
plain="$TMP_ROOT/plain.txt"
printf "Name:          default\nDriver:        docker\n\nNodes:\nName:             default\nEndpoint:         default\nStatus:           running\nBuildKit version: v0.31.2\n" >"$plain"
fake_plain="$(make_fake_docker plain "$plain")"
[[ "$(build_identity_json "$fake_plain")" == "$expected_single_default" ]] ||
  fail "identity without sub-sections differs from identity with sub-sections"

# 3) 多节点 + 每个节点都带 Devices 子段：两个节点都被识别，不多不少。
multi="$TMP_ROOT/multi.txt"
printf "Name: multi\nDriver: docker-container\n\nNodes:\nName: n0\nEndpoint: unix:///a\nStatus: running\nBuildKit version: v0.31.2\nDevices:\n Name: nvidia.com/gpu=0\n Automatically allowed: false\n\nName: n1\nEndpoint: unix:///b\nStatus: running\nBuildKit version: v0.31.2\nLabels:\n Name: not-a-node\nGC Policy rule#0:\n All: false\n" >"$multi"
fake_multi="$(make_fake_docker multi "$multi")"
multi_identity="$(build_identity_json "$fake_multi")" || fail "multi-node fixture rejected"
python3 - "$multi_identity" <<'PY' || fail "multi-node identity is wrong: $multi_identity"
import json, sys
nodes = json.loads(sys.argv[1])["buildx_nodes"]
assert [n["name"] for n in nodes] == ["n0", "n1"], nodes
assert [n["endpoint"] for n in nodes] == ["unix:///a", "unix:///b"], nodes
PY

# 4) 真正缺字段的节点仍然 fail-closed。
broken="$TMP_ROOT/broken.txt"
printf "Name: default\nDriver: docker\n\nNodes:\nName: default\nStatus: running\nBuildKit version: v0.31.2\nDevices:\n Name: nvidia.com/gpu=0\n" >"$broken"
fake_broken="$(make_fake_docker broken "$broken")"
if build_identity_json "$fake_broken" >/dev/null 2>&1; then
  fail "node without Endpoint was accepted"
fi

# 5) 没有任何节点级 Name 时仍然拒绝（只有缩进的子段 Name 不算节点）。
nonode="$TMP_ROOT/nonode.txt"
printf "Name: default\nDriver: docker\n\nNodes:\nDevices:\n Name: nvidia.com/gpu=0\n" >"$nonode"
fake_nonode="$(make_fake_docker nonode "$nonode")"
if build_identity_json "$fake_nonode" >/dev/null 2>&1; then
  fail "inspect output without node-level Name was accepted"
fi

echo "[ok] buildx inspect identity ignores node sub-sections and stays fail-closed"
