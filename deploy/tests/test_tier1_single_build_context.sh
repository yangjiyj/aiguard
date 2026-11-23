#!/bin/sh
# 回归：tier1-classifier 镜像必须只有【单一】构建上下文，杜绝两份发散上下文打同一 tag。
# 背景（spec-vs-spec 冲突）：曾同时存在
#   (1) apps/tier1-classifier/        —— 真 app 源 + fetch-model.sh + 契约测试，可独立 build（权威）
#   (2) deploy/docker-compose/tier1-classifier/ —— 无 app 源、模型路径/uid/启动方式皆异，不可独立 build
# 两者都 docker build -t docker-compose-tier1-classifier:latest，谁后 build 谁覆盖 → 不确定交付物。
# 统一为单一权威上下文：保留 apps/ 版（buildable+测试守护），删除 deploy/ 版发散副本。
# images.lst 仍消费 docker-compose-tier1-classifier:latest（由 apps/ 版构建脚本产出）。
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

APPS_CTX="$ROOT/apps/tier1-classifier"
DEPLOY_CTX="$ROOT/deploy/docker-compose/tier1-classifier"

fail() { echo "FAIL test_tier1_single_build_context: $1"; exit 1; }

# 1) 权威构建上下文存在且可 build（有 Dockerfile + app 源 + 构建脚本）。
[ -f "$APPS_CTX/Dockerfile" ] || fail "缺权威 Dockerfile: apps/tier1-classifier/Dockerfile"
[ -f "$APPS_CTX/app/main.py" ] || fail "缺 app 源: apps/tier1-classifier/app/main.py（apps/ 版才是可 build 的权威上下文）"
[ -f "$APPS_CTX/scripts/build-tier1-image.sh" ] || fail "缺构建脚本: apps/tier1-classifier/scripts/build-tier1-image.sh"

# 2) 不得存在第二份发散构建上下文打同一 tag。
if [ -d "$DEPLOY_CTX" ]; then
  fail "发散副本仍在: deploy/docker-compose/tier1-classifier/ —— 两份上下文打同一 tag docker-compose-tier1-classifier:latest，必删其一统一"
fi

# 3) 只以受版本控制的交付源码为准，生成的 offline-release 不得反向充当真相源。
contexts="$(git -C "$ROOT" ls-files '*/tier1-classifier/Dockerfile')"
[ "$contexts" = "apps/tier1-classifier/Dockerfile" ] || fail "受控 Tier1 Dockerfile 必须且只能是 apps/tier1-classifier/Dockerfile，实得: $contexts"
# 4) 旧工作区入口必须在执行时拒绝构建，避免绕过候选归档、受控模型
# 输入和 provenance；正式构建入口仍只能从同一 apps/ 权威上下文取源码。
if "$APPS_CTX/scripts/build-tier1-image.sh" >/dev/null 2>&1; then
  fail "旧 Tier1 工作区构建入口不应成功"
else
  retired_exit=$?
fi
[ "$retired_exit" = 78 ] || fail "旧 Tier1 工作区构建入口必须以 78 拒绝，实得: $retired_exit"
awk '
  index($0, "\"$docker_cmd\" build --pull=false") &&
    index($0, "\"${source_labels[@]}\"") &&
    index($0, "--tag \"$tier1_image\"") {
      context_line = NR + 1
      next
    }
  NR == context_line && $0 == "  \"$tier1_context\"" {
    found = 1
  }
  END { exit !found }
' "$ROOT/deploy/tests/build_jjdguard_task4_images.sh" ||
  fail "候选归档构建入口未使用 apps/ 权威上下文"
grep -Fq 'cp -a "$source_root/apps/tier1-classifier/." "$tier1_context/"' \
  "$ROOT/deploy/tests/build_jjdguard_task4_images.sh" ||
  fail "Tier1 临时构建上下文不是来自统一源码根"

echo "PASS test_tier1_single_build_context (单一权威构建上下文 apps/tier1-classifier)"
