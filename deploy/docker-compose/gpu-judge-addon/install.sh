#!/bin/bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PROJECT="${GPU_JUDGE_COMPOSE_PROJECT:-jjdguard-gpu-judge}"
ENV_FILE="$ROOT/runtime.env"
TLS_DIR="$ROOT/tls"

fail() { echo "[error] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }
compose() {
  docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$ROOT/compose.yml" -f "$ROOT/compose.instances.yml" "$@"
}
MODEL_FILE="models/jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf"
JUDGE_IMAGE="jjdguard/llm-judge-gpu:2.1.0"
LB_IMAGE="jjdguard/judge-lb-nginx:2.1.0"
valid_uint() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }
valid_ipv4() {
  local a b c d
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$1"
  (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 ))
}
read_env() {
  local key="$1" value count
  count="$(grep -c "^${key}=" "$ENV_FILE" || true)"
  [[ "$count" == 1 ]] || fail "runtime.env must contain exactly one $key"
  value="$(sed -n "s/^${key}=//p" "$ENV_FILE")"
  printf '%s' "$value"
}
[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || fail 'invalid Compose project name'

[[ "$(uname -m)" =~ ^(x86_64|amd64)$ ]] || fail 'only Linux amd64/x86_64 is supported'
need sha256sum
need docker
need nvidia-smi
need openssl
need tee
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable to the current user'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'
nvidia-smi -L >/dev/null 2>&1 || fail 'NVIDIA GPU is unavailable in the Ubuntu VM'

[[ -f manifest.sha256 && ! -L manifest.sha256 ]] || fail 'manifest.sha256 is missing'
sha256sum -c manifest.sha256 || fail 'bundle integrity verification failed'
[[ -f images/llm-judge-gpu.tar && ! -L images/llm-judge-gpu.tar ]] || fail 'GPU image archive is missing'
[[ -f images/judge-lb-nginx.tar && ! -L images/judge-lb-nginx.tar ]] || fail 'load balancer image archive is missing'
[[ -f "$MODEL_FILE" && ! -L "$MODEL_FILE" ]] || fail 'bundled Judge model is missing'
# Customer extraction can preserve the packager's restrictive umask. The model is
# public release content and must be traversable/readable by the non-root Judge user.
chmod 0755 "$(dirname "$MODEL_FILE")"
chmod 0444 "$MODEL_FILE"
docker load -i images/llm-judge-gpu.tar >/dev/null
docker load -i images/judge-lb-nginx.tar >/dev/null
docker image inspect "$JUDGE_IMAGE" >/dev/null || fail 'loaded GPU Judge image is missing'
docker image inspect "$LB_IMAGE" >/dev/null || fail 'loaded load balancer image is missing'
gpu_count="$(nvidia-smi --query-gpu=index --format=csv,noheader | grep -c . || true)"
(( gpu_count >= 1 )) || fail 'nvidia-smi reports no GPU'
all_gpu_ids="$(nvidia-smi --query-gpu=index --format=csv,noheader | tr -d ' ' | paste -sd, -)"

if [[ ! -f "$ENV_FILE" ]]; then
  [[ -n "${JUDGE_BIND_IP:-}" ]] || fail 'set JUDGE_BIND_IP to this VM internal IP (or 127.0.0.1 for same-host gateway)'
  valid_ipv4 "$JUDGE_BIND_IP" || fail 'JUDGE_BIND_IP must be a valid IPv4 address'
  [[ "$JUDGE_BIND_IP" != 0.0.0.0 ]] || fail 'JUDGE_BIND_IP cannot be 0.0.0.0'
  if [[ -z "${JUDGE_API_KEY:-}" ]]; then
    JUDGE_API_KEY="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  [[ "$JUDGE_API_KEY" =~ ^[A-Za-z0-9._~-]{32,256}$ ]] || fail 'JUDGE_API_KEY contains unsafe characters or has an invalid length'
  JUDGE_HOST_PORT="${JUDGE_HOST_PORT:-8094}"
  # Qualified 12 GiB GPU profile: one instance, two 8192-token slots, F16 KV.
  JUDGE_GPU_IDS="${JUDGE_GPU_IDS:-$all_gpu_ids}"
  JUDGE_INSTANCES_PER_GPU="${JUDGE_INSTANCES_PER_GPU:-1}"
  JUDGE_PARALLEL="${JUDGE_PARALLEL:-2}"
  JUDGE_CTX="${JUDGE_CTX:-$(( ${JUDGE_PARALLEL} * 8192 ))}"
  JUDGE_THREADS="${JUDGE_THREADS:-4}"
  JUDGE_GPU_LAYERS="${JUDGE_GPU_LAYERS:-99}"
  JUDGE_FLASH_ATTN="${JUDGE_FLASH_ATTN:-on}"
  JUDGE_KV_CACHE_TYPE="${JUDGE_KV_CACHE_TYPE:-f16}"
  valid_uint "$JUDGE_HOST_PORT" 1 65535 || fail 'JUDGE_HOST_PORT must be between 1 and 65535'
  valid_uint "$JUDGE_PARALLEL" 1 32 || fail 'JUDGE_PARALLEL must be between 1 and 32'
  valid_uint "$JUDGE_CTX" 2048 262144 || fail 'JUDGE_CTX must be between 2048 and 262144'
  valid_uint "$JUDGE_THREADS" 1 256 || fail 'JUDGE_THREADS must be between 1 and 256'
  valid_uint "$JUDGE_GPU_LAYERS" 1 999 || fail 'JUDGE_GPU_LAYERS must be between 1 and 999'
  [[ "$JUDGE_FLASH_ATTN" =~ ^(on|off|auto)$ ]] || fail 'JUDGE_FLASH_ATTN must be on, off, or auto'
  cat >"$ENV_FILE" <<EOF
JUDGE_API_KEY=$JUDGE_API_KEY
JUDGE_BIND_IP=$JUDGE_BIND_IP
JUDGE_HOST_PORT=$JUDGE_HOST_PORT
JUDGE_GPU_IDS=$JUDGE_GPU_IDS
JUDGE_INSTANCES_PER_GPU=$JUDGE_INSTANCES_PER_GPU
JUDGE_PARALLEL=$JUDGE_PARALLEL
JUDGE_CTX=$JUDGE_CTX
JUDGE_THREADS=$JUDGE_THREADS
JUDGE_GPU_LAYERS=$JUDGE_GPU_LAYERS
JUDGE_FLASH_ATTN=$JUDGE_FLASH_ATTN
JUDGE_KV_CACHE_TYPE=$JUDGE_KV_CACHE_TYPE
EOF
  chmod 0600 "$ENV_FILE"
  echo '[ok] created root-only runtime.env; API key was not printed'
else
  mode="$(stat -c '%a' "$ENV_FILE")"
  [[ "$mode" == 600 ]] || fail "runtime.env must have mode 0600, got $mode"
  # Preserve credentials and endpoint; migrate the recognized legacy defaults.
  if ! grep -q '^JUDGE_INSTANCES_PER_GPU=' "$ENV_FILE"; then
    cp -p "$ENV_FILE" "$ENV_FILE.pre-2.0.0"
    old_parallel="$(read_env JUDGE_PARALLEL)"
    old_ctx="$(read_env JUDGE_CTX)"
    if [[ "$old_parallel" == 4 && "$old_ctx" == 16384 ]]; then
      sed -i -e 's/^JUDGE_PARALLEL=.*/JUDGE_PARALLEL=2/' -e 's/^JUDGE_CTX=.*/JUDGE_CTX=16384/' "$ENV_FILE"
    fi
    printf 'JUDGE_GPU_IDS=%s\nJUDGE_INSTANCES_PER_GPU=%s\nJUDGE_KV_CACHE_TYPE=%s\n' \
      "${JUDGE_GPU_IDS:-$all_gpu_ids}" "${JUDGE_INSTANCES_PER_GPU:-1}" "${JUDGE_KV_CACHE_TYPE:-f16}" >>"$ENV_FILE"
    echo '[ok] upgraded runtime.env to the multi-instance layout; previous file kept as runtime.env.pre-2.0.0'
  else
    echo '[info] preserving existing runtime.env'
  fi
fi

JUDGE_API_KEY="$(read_env JUDGE_API_KEY)"
JUDGE_BIND_IP="$(read_env JUDGE_BIND_IP)"
JUDGE_HOST_PORT="$(read_env JUDGE_HOST_PORT)"
JUDGE_PARALLEL="$(read_env JUDGE_PARALLEL)"
JUDGE_CTX="$(read_env JUDGE_CTX)"
JUDGE_THREADS="$(read_env JUDGE_THREADS)"
JUDGE_GPU_LAYERS="$(read_env JUDGE_GPU_LAYERS)"
JUDGE_FLASH_ATTN="$(read_env JUDGE_FLASH_ATTN)"
[[ "$JUDGE_API_KEY" =~ ^[A-Za-z0-9._~-]{32,256}$ ]] || fail 'runtime.env contains invalid JUDGE_API_KEY'
valid_ipv4 "$JUDGE_BIND_IP" && [[ "$JUDGE_BIND_IP" != 0.0.0.0 ]] || fail 'runtime.env contains invalid JUDGE_BIND_IP'
valid_uint "$JUDGE_HOST_PORT" 1 65535 || fail 'runtime.env contains invalid JUDGE_HOST_PORT'
valid_uint "$JUDGE_PARALLEL" 1 32 || fail 'runtime.env contains invalid JUDGE_PARALLEL'
valid_uint "$JUDGE_CTX" 2048 262144 || fail 'runtime.env contains invalid JUDGE_CTX'
valid_uint "$JUDGE_THREADS" 1 256 || fail 'runtime.env contains invalid JUDGE_THREADS'
valid_uint "$JUDGE_GPU_LAYERS" 1 999 || fail 'runtime.env contains invalid JUDGE_GPU_LAYERS'
[[ "$JUDGE_FLASH_ATTN" =~ ^(on|off|auto)$ ]] || fail 'runtime.env contains invalid JUDGE_FLASH_ATTN'
JUDGE_KV_CACHE_TYPE="$(read_env JUDGE_KV_CACHE_TYPE)"
[[ "$JUDGE_KV_CACHE_TYPE" =~ ^(f16|q8_0)$ ]] || fail 'runtime.env contains invalid JUDGE_KV_CACHE_TYPE'
[[ "$JUDGE_KV_CACHE_TYPE" == f16 || "$JUDGE_FLASH_ATTN" != off ]] || fail 'JUDGE_KV_CACHE_TYPE=q8_0 requires Flash Attention'
JUDGE_GPU_IDS="$(read_env JUDGE_GPU_IDS)"
IFS=',' read -ra requested_gpus <<<"$JUDGE_GPU_IDS"
for g in "${requested_gpus[@]}"; do
  [[ ",$all_gpu_ids," == *",$g,"* ]] || fail "JUDGE_GPU_IDS lists GPU $g, but nvidia-smi only reports: $all_gpu_ids"
done
# 生成实例 compose 与 nginx 配置（内部同样校验全部拓扑键）。
bash "$ROOT/render-topology.sh" "$ENV_FILE" "$ROOT"

mkdir -p "$TLS_DIR"
chmod 0755 "$TLS_DIR"
provided=0
[[ -n "${JUDGE_TLS_CERT_INPUT:-}${JUDGE_TLS_KEY_INPUT:-}${JUDGE_TLS_CA_INPUT:-}" ]] && provided=1
if (( provided )); then
  [[ -f "${JUDGE_TLS_CERT_INPUT:-}" && ! -L "${JUDGE_TLS_CERT_INPUT:-}" ]] || fail 'JUDGE_TLS_CERT_INPUT must be a regular certificate file'
  [[ -f "${JUDGE_TLS_KEY_INPUT:-}" && ! -L "${JUDGE_TLS_KEY_INPUT:-}" ]] || fail 'JUDGE_TLS_KEY_INPUT must be a regular private key file'
  [[ -f "${JUDGE_TLS_CA_INPUT:-}" && ! -L "${JUDGE_TLS_CA_INPUT:-}" ]] || fail 'JUDGE_TLS_CA_INPUT must be a regular CA file'
  install -m 0644 "$JUDGE_TLS_CERT_INPUT" "$TLS_DIR/server.crt"
  install -m 0600 "$JUDGE_TLS_KEY_INPUT" "$TLS_DIR/server.key"
  install -m 0644 "$JUDGE_TLS_CA_INPUT" "$TLS_DIR/ca.crt"
elif [[ ! -f "$TLS_DIR/server.crt" || ! -f "$TLS_DIR/server.key" || ! -f "$TLS_DIR/ca.crt" ]]; then
  rm -f "$TLS_DIR/server.crt" "$TLS_DIR/server.key" "$TLS_DIR/ca.crt" "$TLS_DIR/ca.key" "$TLS_DIR/server.csr" "$TLS_DIR/server.ext" "$TLS_DIR/ca.srl"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" \
    -subj '/CN=JJDGuard GPU Judge Internal CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
  openssl req -newkey rsa:3072 -sha256 -nodes \
    -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" \
    -subj "/CN=$JUDGE_BIND_IP" >/dev/null 2>&1
  cat >"$TLS_DIR/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$JUDGE_BIND_IP
EOF
  openssl x509 -req -in "$TLS_DIR/server.csr" \
    -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -out "$TLS_DIR/server.crt" -days 825 -sha256 -extfile "$TLS_DIR/server.ext" >/dev/null 2>&1
  rm -f "$TLS_DIR/ca.key" "$TLS_DIR/server.csr" "$TLS_DIR/server.ext" "$TLS_DIR/ca.srl"
  echo '[ok] created a per-install TLS CA and server certificate; no private key was printed'
else
  echo '[info] preserving existing TLS certificate and key'
fi
for file in "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt" "$TLS_DIR/server.key"; do
  [[ -f "$file" && ! -L "$file" ]] || fail "invalid TLS file: $file"
done
openssl x509 -in "$TLS_DIR/server.crt" -checkend 86400 -noout >/dev/null || fail 'TLS server certificate expires within 24 hours'
openssl verify -CAfile "$TLS_DIR/ca.crt" -verify_ip "$JUDGE_BIND_IP" "$TLS_DIR/server.crt" >/dev/null ||
  fail 'TLS certificate chain or IP SAN verification failed'
cert_public="$(openssl x509 -in "$TLS_DIR/server.crt" -pubkey -noout | sha256sum | cut -d' ' -f1)"
key_public="$(openssl pkey -in "$TLS_DIR/server.key" -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)"
[[ "$cert_public" == "$key_public" ]] || fail 'TLS certificate and private key do not match'
chmod 0644 "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt"
chmod 0640 "$TLS_DIR/server.key"
docker run --pull=never --network=none --rm --user 0:0 \
  -v "$TLS_DIR:/tls" --entrypoint chown "$JUDGE_IMAGE" \
  "$(id -u):10001" /tls/server.key

# This catches the common failure where the VM has an A100 but Docker cannot allocate it.
docker run --rm --gpus all --entrypoint /opt/llama/llama-server \
  "$JUDGE_IMAGE" --version >/dev/null 2>&1 ||
  fail 'Docker cannot allocate the NVIDIA GPU; install/configure NVIDIA Container Toolkit first'

# 1.x 单实例服务（llm-judge-gpu）由 --remove-orphans 移除；模型与 runtime.env 保留。
compose up -d --remove-orphans
expected="$(compose config --services | grep -c .)"
health_timeout="${GPU_JUDGE_HEALTH_TIMEOUT:-300}"
valid_uint "$health_timeout" 1 3600 || fail 'GPU_JUDGE_HEALTH_TIMEOUT must be between 1 and 3600 seconds'
deadline=$((SECONDS + health_timeout))
healthy=0
while (( SECONDS < deadline )); do
  healthy="$(compose ps --format json 2>/dev/null | grep -o '"Health":"healthy"' | grep -c . || true)"
  (( healthy == expected )) && break
  sleep 1
done
(( healthy == expected )) || {
  compose ps >&2 || true
  compose logs --tail 60 >&2 || true
  compose down >&2 || true
  fail "GPU Judge did not become healthy (${healthy}/${expected} services); service was stopped"
}
echo "[ok] ${expected} services healthy (load balancer + judge instances)"

"$ROOT/verify.sh" | tee "$ROOT/acceptance-last.log"
chmod 0600 "$ROOT/acceptance-last.log"
echo '[ok] GPU Judge installed and verified; acceptance-last.log contains non-secret timing evidence'
echo '[next] trust tls/ca.crt on the JJDGuard host, then configure the HTTPS Judge URL from README.md'
