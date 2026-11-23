#!/usr/bin/env bash
# 测试辅助起一次性 docker 容器的公共约定（与 Go 的 packages/shared-go/testcontainer 同一套标签和规则）。
#
#   - 清理一律 docker rm -f -v：postgres 等镜像声明了 VOLUME，每次 docker run 都会建一个匿名卷；
#     不带 -v 时，即使容器是 --rm 起的，被 rm -f 删掉后匿名卷也会留下（home 的 /fast 曾因此被撑满）。
#   - 起容器时带上 "${JJD_TEST_CONTAINER_LABELS[@]}"（owner_pid、created、host、kind）。测试进程被杀、trap
#     没跑时容器会一直运行；起容器之前调 jjd_test_reap_orphan_containers，只回收本套标签、同一台主机、
#     owner 进程已不存在、创建超过 30 分钟的容器。别的进程正在用的容器、标签不全的容器一律不碰。
#
# 用法：
#   . "$ROOT/deploy/tests/lib/test-containers.sh"
#   jjd_test_reap_orphan_containers
#   jjd_test_container_labels pg-fixture          # 设置数组 JJD_TEST_CONTAINER_LABELS，owner 为当前脚本 $$
#   docker run -d "${JJD_TEST_CONTAINER_LABELS[@]}" ... postgres:16-alpine
#   docker rm -f -v "$container"
# Python 等其他语言的测试：标签照同一套键自己拼，回收直接执行 `bash deploy/tests/lib/test-containers.sh reap`。

JJD_TEST_LABEL_OWNER_PID=jjdguard.test.owner_pid
JJD_TEST_LABEL_CREATED=jjdguard.test.created
JJD_TEST_LABEL_HOST=jjdguard.test.host
JJD_TEST_LABEL_KIND=jjdguard.test.kind
JJD_TEST_ORPHAN_MIN_AGE_SECONDS=1800

jjd_test_host() { hostname 2>/dev/null || echo unknown; }

# jjd_test_container_labels KIND：设置 JJD_TEST_CONTAINER_LABELS（docker run 的 --label 参数）。
jjd_test_container_labels() {
  local kind="${1:?jjd_test_container_labels: kind required}"
  JJD_TEST_CONTAINER_LABELS=(
    --label "$JJD_TEST_LABEL_OWNER_PID=$$"
    --label "$JJD_TEST_LABEL_CREATED=$(date +%s)"
    --label "$JJD_TEST_LABEL_HOST=$(jjd_test_host)"
    --label "$JJD_TEST_LABEL_KIND=$kind"
  )
}

# jjd_test_container_labels_kept KIND：保留现场排查时用，不带 owner_pid，回收不会碰；用完手工 docker rm -f -v。
jjd_test_container_labels_kept() {
  local kind="${1:?jjd_test_container_labels_kept: kind required}"
  JJD_TEST_CONTAINER_LABELS=(--label "$JJD_TEST_LABEL_KIND=$kind" --label jjdguard.test.kept=1)
}

# jjd_test_reap_orphan_containers：回收孤儿测试容器（rm -f -v）。docker 不可用或列不出来时什么都不做，总是返回 0。
jjd_test_reap_orphan_containers() {
  local host now listing id pid created container_host
  host="$(jjd_test_host)"
  now="$(date +%s)"
  listing="$(docker ps -a --filter "label=$JJD_TEST_LABEL_OWNER_PID" \
    --format "{{.ID}}	{{.Label \"$JJD_TEST_LABEL_OWNER_PID\"}}	{{.Label \"$JJD_TEST_LABEL_CREATED\"}}	{{.Label \"$JJD_TEST_LABEL_HOST\"}}" \
    2>/dev/null)" || return 0
  while IFS=$'\t' read -r id pid created container_host; do
    [[ -n "$id" && "$container_host" == "$host" ]] || continue
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$created" =~ ^[0-9]+$ ]] || continue
    (( now - created >= JJD_TEST_ORPHAN_MIN_AGE_SECONDS )) || continue
    # ps -p 对别的用户的进程也成立：owner 还在就算有人在用，不回收。
    if ps -p "$pid" >/dev/null 2>&1; then
      continue
    fi
    if docker rm -f -v "$id" >/dev/null 2>&1; then
      echo "[test-containers] reaped orphan test container $id (owner_pid=$pid exited)" >&2
    fi
  done <<<"$listing"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    reap) jjd_test_reap_orphan_containers ;;
    *) echo "usage: $0 reap" >&2; exit 64 ;;
  esac
fi
