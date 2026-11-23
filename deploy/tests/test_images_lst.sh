#!/bin/sh
# images.lst 解析 + profile 过滤回归。
set -eu
DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../docker-compose" && pwd)"
IMAGES_LST="$DIR/images.lst"
export IMAGES_LST
. "$DIR/lib-images.sh"

validate_image_catalog

lite="$(read_images_for_profile lite | wc -l | tr -d ' ')"
full="$(read_images_for_profile full | wc -l | tr -d ' ')"
[ "$lite" = "8" ] || { echo "FAIL lite expected 8 got $lite"; exit 1; }
[ "$full" = "10" ] || { echo "FAIL full expected 10 got $full"; exit 1; }
read_images_for_profile full | grep -q "docker-compose-llm-judge:latest" || { echo "FAIL judge missing in full"; exit 1; }
if read_images_for_profile lite | grep -q "llm-judge"; then echo "FAIL judge leaked into lite"; exit 1; fi
read_images_for_profile full | grep -q "docker-compose-tier1-classifier:latest" || { echo "FAIL tier1-classifier missing in full"; exit 1; }
if read_images_for_profile lite | grep -q "tier1-classifier"; then echo "FAIL tier1-classifier leaked into lite"; exit 1; fi
# common 镜像两包都在
read_images_for_profile lite | grep -q "docker-compose-gateway-core:latest" || { echo "FAIL gateway-core missing"; exit 1; }

# chat 包必须引用瘦身后的门户镜像，避免打包链继续夹带旧 1.9 GiB 镜像。
INCLUDE_CHAT=1
export INCLUDE_CHAT
full_chat="$(read_images_for_profile full | wc -l | tr -d ' ')"
[ "$full_chat" = "14" ] || { echo "FAIL full+chat expected 14 got $full_chat"; exit 1; }
read_images_for_profile full | grep -qx "enterprise-ai-portal:0.2.0-slim" || { echo "FAIL slim portal image missing in chat bundle"; exit 1; }
if read_images_for_profile full | grep -qx "enterprise-ai-portal:0.1.0"; then
  echo "FAIL legacy portal image leaked into chat bundle"
  exit 1
fi

# 运行时引用必须是纯标签：images.lst 第一列禁止 @sha256: digest 形式
# （digest 导出会丢 RepoTags → 离线客户 load 后 dangling → compose 联网 Pull 卡死）。
if read_images_for_profile full | grep -q '@sha256:'; then
  echo "FAIL digest-pinned image reference found in images.lst (runtime refs must be pure tags)"
  exit 1
fi
read_images_for_profile full | grep -qx "docker.1ms.run/keycloak/keycloak:26.3" || { echo "FAIL keycloak pure tag missing in chat bundle"; exit 1; }
read_images_for_profile full | grep -qx "docker.1ms.run/library/caddy:2-alpine" || { echo "FAIL caddy pure tag missing in chat bundle"; exit 1; }
# third-party 摘要由目录读取器按 profile 过滤；full+chat 共四个固定上游镜像。
digest_count="$(read_image_digests_for_profile full | wc -l | tr -d ' ')"
[ "$digest_count" = "4" ] || { echo "FAIL full+chat expected 4 digest rows got $digest_count"; exit 1; }
read_image_digests_for_profile full | grep -qx 'docker.1ms.run/keycloak/keycloak:26.3 sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba' ||
  { echo "FAIL keycloak expected digest missing"; exit 1; }

# 运行时 compose（在线+离线两份）的 image: 行同样禁止 digest 钉死引用
for compose_file in "$DIR/docker-compose.yml" "$DIR/docker-compose.offline.yml"; do
  if grep -E '^[[:space:]]*image:[[:space:]]*[^#]*@sha256:' "$compose_file" >/dev/null; then
    echo "FAIL digest-pinned image reference in runtime compose: $compose_file"
    exit 1
  fi
done
echo "PASS test_images_lst (lite=$lite full=$full)"
