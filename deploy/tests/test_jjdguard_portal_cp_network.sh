#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels jjdguard-portal-cp-network
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="$ROOT/deploy/docker-compose/ensure-jjdguard-portal-cp-network.sh"

validate_members() {
  local network="$1" core_project="$2" portal_project="$3"
  local rows
  rows="$(docker network inspect "$network" --format '{{range .Containers}}{{.Name}} {{end}}')"
  local count=0 name project service core=0 portal=0
  for name in $rows; do
    count=$((count + 1))
    project="$(docker inspect "$name" --format '{{index .Config.Labels "com.docker.compose.project"}}')"
    service="$(docker inspect "$name" --format '{{index .Config.Labels "com.docker.compose.service"}}')"
    if [[ "$project" == "$core_project" && "$service" == "control-plane" ]]; then
      core=$((core + 1))
    elif [[ "$project" == "$portal_project" && ( "$service" == "chat-portal-ui" || "$service" == "web" ) ]]; then
      portal=$((portal + 1))
    else
      printf 'foreign portal-control member: %s project=%s service=%s\n' "$name" "$project" "$service" >&2
      return 1
    fi
  done
  [[ "$count" -eq 2 && "$core" -eq 1 && "$portal" -eq 1 ]]
}

if [[ "${1:-}" == "--core-project" ]]; then
  core_project="$2"; shift 2
  [[ "$1" == "--portal-project" ]]; portal_project="$2"; shift 2
  [[ "$1" == "--network" ]]; network="$2"
  validate_members "$network" "$core_project" "$portal_project"
  printf 'portal_control_network=ok members=2\n'
  exit 0
fi

token="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
case "$token" in (*[!0-9a-f]*|'') exit 1;; esac
network="jjdguard-pc-test-$token"
drift="jjdguard-pc-drift-$token"
owner="contract-$token"
core="jjdguard-pc-core-$token"
portal="jjdguard-pc-portal-$token"
foreign="jjdguard-pc-foreign-$token"
cleanup() {
  for container in "$foreign" "$portal" "$core"; do
    docker stop "$container" >/dev/null 2>&1 || true
    docker rm -v "$container" >/dev/null 2>&1 || true
  done
  "$HELPER" --remove-if-owner "$owner" --name "$network" >/dev/null 2>&1 || true
  docker network rm "$drift" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$HELPER" --name "$network" --owner "$owner"
"$HELPER" --name "$network" --owner "$owner"
inspect="$(docker network inspect "$network" --format '{{.Driver}} {{.Internal}} {{index .Labels "com.jjdguard.owner"}} {{index .Labels "com.jjdguard.purpose"}}')"
[[ "$inspect" == "bridge true $owner portal-control" ]]

docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$core" --network "$network" \
  --label com.docker.compose.project=core-fixture \
  --label com.docker.compose.service=control-plane alpine:3.20 sleep 60 >/dev/null
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$portal" --network "$network" \
  --label com.docker.compose.project=portal-fixture \
  --label com.docker.compose.service=chat-portal-ui alpine:3.20 sleep 60 >/dev/null
validate_members "$network" core-fixture portal-fixture
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$foreign" --network "$network" \
  --label com.docker.compose.project=foreign-fixture \
  --label com.docker.compose.service=gateway-core alpine:3.20 sleep 60 >/dev/null
if validate_members "$network" core-fixture portal-fixture 2>/dev/null; then
  echo 'foreign member was accepted' >&2
  exit 1
fi
docker stop "$foreign" >/dev/null
docker rm -v "$foreign" >/dev/null

docker network create --driver bridge \
  --label "com.jjdguard.owner=$owner" --label com.jjdguard.purpose=portal-control "$drift" >/dev/null
if "$HELPER" --name "$drift" --owner "$owner" 2>/dev/null; then
  echo 'network attribute drift was accepted' >&2
  exit 1
fi

docker stop "$portal" "$core" >/dev/null
docker rm -v "$portal" "$core" >/dev/null
"$HELPER" --remove-if-owner "$owner" --name "$network"
if docker network inspect "$network" >/dev/null 2>&1; then
  echo 'owned test network was not removed' >&2
  exit 1
fi
printf 'portal_control_network_self_test=ok idempotent=1 drift_rejected=1 foreign_rejected=1 cleanup=1\n'
