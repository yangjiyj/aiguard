#!/bin/sh
set -eu

ROOT="${1:?用法: $0 <home hotfix source dir>}"
. "$ROOT/hotfix-lib.sh"

actual="$(
  printf '%s\n' \
    'name: demo' \
    'services:' \
    '  control-plane:' \
    '    image: example/control-plane:1.0' \
    '  gateway-core:' \
    '    environment:' \
    '      DATABASE_URL: redacted' \
    '    image: docker-compose-gateway-core:verified-047fed3b' \
    '    restart: unless-stopped' \
    '  worker:' \
    '    image: example/worker:1.0' |
    compose_service_image_ref_from_config "gateway-core"
)"
[ "$actual" = "docker-compose-gateway-core:verified-047fed3b" ] || {
  echo "FAIL: Compose 目标镜像解析错误: $actual" >&2
  exit 1
}

expected_original="sha256:original"
expected_patch="sha256:patch"

recoverable_failed_install_state \
  "$expected_original" \
  "$expected_original" \
  "$expected_original" \
  "$expected_patch" \
  "$expected_patch" \
  "$expected_original" \
  "$expected_original"

if recoverable_failed_install_state \
  "sha256:unknown" \
  "$expected_original" \
  "$expected_original" \
  "$expected_patch" \
  "$expected_patch" \
  "$expected_original" \
  "$expected_original"; then
  echo "FAIL: 当前运行镜像漂移时不应允许迁移 state" >&2
  exit 1
fi

if recoverable_failed_install_state \
  "$expected_original" \
  "$expected_original" \
  "$expected_original" \
  "$expected_patch" \
  "sha256:other-patch" \
  "$expected_original" \
  "$expected_original"; then
  echo "FAIL: state 中补丁镜像不匹配时不应允许迁移" >&2
  exit 1
fi

if recoverable_failed_install_state \
  "$expected_original" \
  "$expected_original" \
  "$expected_original" \
  "$expected_patch" \
  "$expected_patch" \
  "sha256:other-original" \
  "$expected_original"; then
  echo "FAIL: 回滚镜像不匹配时不应允许迁移" >&2
  exit 1
fi

rollback_image_state_is_safe \
  "$expected_original" \
  "$expected_original" \
  "$expected_original" \
  "$expected_patch"

rollback_image_state_is_safe \
  "$expected_patch" \
  "" \
  "$expected_original" \
  "$expected_patch"

if rollback_image_state_is_safe \
  "sha256:unknown-running" \
  "$expected_original" \
  "$expected_original" \
  "$expected_patch"; then
  echo "FAIL: 旧容器运行未知镜像时不应允许回滚覆盖" >&2
  exit 1
fi

if rollback_image_state_is_safe \
  "$expected_original" \
  "sha256:unknown-compose-target" \
  "$expected_original" \
  "$expected_patch"; then
  echo "FAIL: Compose 目标 tag 指向未知镜像时不应允许回滚覆盖" >&2
  exit 1
fi

echo "PASS: Compose 镜像解析、失败 state 迁移和回滚镜像保护"
