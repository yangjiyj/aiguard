#!/usr/bin/env bash
# 目录运行态凭据的两条合约：
#
# 1) 凭据来源唯一 —— 0600 的 identity-runtime.env 必须是权威来源。
#    compose 里写 `DIRECTORY_RUNTIME_X=${DIRECTORY_RUNTIME_X:-}` 会在
#    宿主未导出该变量时展开成空串，而 `environment:` 优先级高于
#    `env_file:`，于是 0600 文件被静默覆盖成空 —— 现场表现为目录预览
#    能跑、激活/同步却拿不到运行态凭据。
#
# 2) 引导必须被调用 —— bootstrap-directory-runtime.sh 一直在仓库里、
#    也随包发出去，但 deploy-offline.sh/upgrade.sh 从未调用它，所以
#    全新安装和升级后 DIRECTORY_RUNTIME_* 三项永远为空。
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
. deploy/tests/lib/jjdguard_contract_env.sh

COMPOSE_FILES=(
  deploy/docker-compose/docker-compose.yml
  deploy/docker-compose/docker-compose.offline.yml
)
KEYS=(DIRECTORY_RUNTIME_URL DIRECTORY_RUNTIME_CLIENT_ID DIRECTORY_RUNTIME_CLIENT_SECRET)

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# --- 合约 1：compose 不得声明空默认的目录运行态覆盖 ---
for compose in "${COMPOSE_FILES[@]}"; do
  for key in "${KEYS[@]}"; do
    if grep -Eq "^[[:space:]]*-[[:space:]]*${key}=\\\$\{${key}:-\}" "$compose"; then
      fail "$compose 声明了空默认的 $key，会覆盖 0600 identity-runtime.env"
    fi
  done
done

# --- 合约 1（行为验证）：env_file 必须真正生效 ---
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
env_file="$tmpdir/contract.env"
write_jjdguard_contract_env "$env_file"

# env_file 的相对路径按 project-directory 解析，所以夹具放在 project-directory 里。
printf '%s\n' \
  'DIRECTORY_RUNTIME_URL=http://chat-idp:8180/sso' \
  'DIRECTORY_RUNTIME_CLIENT_ID=jjdguard-directory-orchestrator' \
  'DIRECTORY_RUNTIME_CLIENT_SECRET=fixture-directory-secret' >"$tmpdir/identity-runtime.env"
chmod 600 "$tmpdir/identity-runtime.env"

for compose in "${COMPOSE_FILES[@]}"; do
  json="$tmpdir/$(basename "$compose").present.json"
  docker compose --profile '*' --project-directory "$tmpdir" \
    --env-file "$env_file" -f "$compose" config --format json >"$json"
  jq -e '.services["control-plane"].environment.DIRECTORY_RUNTIME_URL
         == "http://chat-idp:8180/sso"' "$json" >/dev/null ||
    fail "$compose 未让 identity-runtime.env 的 DIRECTORY_RUNTIME_URL 生效"
  jq -e '.services["control-plane"].environment.DIRECTORY_RUNTIME_CLIENT_ID
         == "jjdguard-directory-orchestrator"' "$json" >/dev/null ||
    fail "$compose 未让 identity-runtime.env 的 DIRECTORY_RUNTIME_CLIENT_ID 生效"
  jq -e '.services["control-plane"].environment.DIRECTORY_RUNTIME_CLIENT_SECRET
         == "fixture-directory-secret"' "$json" >/dev/null ||
    fail "$compose 未让 identity-runtime.env 的 DIRECTORY_RUNTIME_CLIENT_SECRET 生效"
done

# --- 合约 1（缺文件不得炸）：required:false 语义保持，未引导时仍能渲染 ---
absent_dir="$tmpdir/absent"
mkdir -p "$absent_dir"
for compose in "${COMPOSE_FILES[@]}"; do
  json="$tmpdir/$(basename "$compose").absent.json"
  docker compose --profile '*' --project-directory "$absent_dir" \
    --env-file "$env_file" -f "$compose" config --format json >"$json" ||
    fail "$compose 在 identity-runtime.env 缺失时无法渲染"
  for key in "${KEYS[@]}"; do
    jq -e --arg key "$key" \
      '.services["control-plane"].environment | has($key) | not' "$json" >/dev/null ||
      fail "$compose 在未引导时仍注入了空的 $key"
  done
done

# --- 合约 2：目录 LDAPS 的信任根必须一份两用 ---
# 预览（Go 侧，control-plane）与 FullSync（JVM 侧，Keycloak）是两条独立的
# 信任链。只配一边就会重演「预览通过、激活时 PKIX path building failed」。
for compose in "${COMPOSE_FILES[@]}"; do
  json="$tmpdir/$(basename "$compose").present.json"
  jq -e '.services["chat-idp"].environment.KC_TRUSTSTORE_PATHS
         == "/opt/keycloak/conf/truststores"' "$json" >/dev/null ||
    fail "$compose chat-idp 未加载目录 CA 信任目录"
  jq -e '.services["control-plane"].environment.DIRECTORY_TRUST_DIR
         == "/etc/jjdguard/directory-truststore"' "$json" >/dev/null ||
    fail "$compose control-plane 未指向共享目录 CA 信任目录"
  # 必须是同一份宿主目录，否则「放一处生效两边」不成立。
  jq -e '[.services["chat-idp"].volumes[]
          | select(.target == "/opt/keycloak/conf/truststores")
          | .source] == [.services["control-plane"].volumes[]
          | select(.target == "/etc/jjdguard/directory-truststore")
          | .source]' "$json" >/dev/null ||
    fail "$compose 两个消费者的 CA 目录不是同一份挂载"
  # control-plane 侧必须只读：控制面不得改写信任根。
  jq -e '.services["control-plane"].volumes[]
         | select(.target == "/etc/jjdguard/directory-truststore")
         | .read_only == true' "$json" >/dev/null ||
    fail "$compose control-plane 的 CA 目录必须只读挂载"
done

# --- 合约 3：两个入口都必须调用目录运行态引导 ---
for entry in deploy/docker-compose/deploy-offline.sh deploy/docker-compose/upgrade.sh; do
  grep -q 'bootstrap-directory-runtime\.sh' "$entry" ||
    fail "$entry 未调用 bootstrap-directory-runtime.sh"
done

printf 'directory_runtime_env_authority=ok compose_files=%d keys=%d\n' \
  "${#COMPOSE_FILES[@]}" "${#KEYS[@]}"
