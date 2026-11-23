#!/bin/sh
set -eu

# 实例只在附加包内部网络监听明文 HTTP；TLS 由前端 judge-lb（nginx）终结。
# API Key 仍由每个实例校验：nginx 透传 Authorization，不在前端保存密钥。
MODEL="${JUDGE_MODEL_PATH:-/models/jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf}"
API_KEY="${JUDGE_API_KEY:-}"
[ -f "$MODEL" ] || { echo "[fatal] Judge GGUF missing: $MODEL" >&2; exit 1; }
[ -n "$API_KEY" ] || { echo '[fatal] JUDGE_API_KEY is required' >&2; exit 1; }

devices="$(/opt/llama/llama-server --list-devices 2>&1)"
printf '%s\n' "$devices"
case "$devices" in
  *"CUDA0:"*) ;;
  *) echo '[fatal] llama-server cannot see an NVIDIA CUDA device' >&2; exit 1 ;;
esac

case "${JUDGE_PARALLEL:-2}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_PARALLEL' >&2; exit 1;; esac
case "${JUDGE_CTX:-16384}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_CTX' >&2; exit 1;; esac
case "${JUDGE_THREADS:-4}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_THREADS' >&2; exit 1;; esac
case "${JUDGE_GPU_LAYERS:-99}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_GPU_LAYERS' >&2; exit 1;; esac

# Refuse the old 2048-token slot configuration before loading the model.
[ "${JUDGE_PARALLEL:-2}" -ge 1 ] && [ "${JUDGE_PARALLEL:-2}" -le 32 ] || exit 1
[ "$(( ${JUDGE_CTX:-16384} / ${JUDGE_PARALLEL:-2} ))" -ge 8192 ] || {
  echo '[fatal] JUDGE_CTX / JUDGE_PARALLEL must leave at least 8192 tokens per slot' >&2
  exit 1
}
for value in "${JUDGE_CACHE_RAM_MB:-1024}" "${JUDGE_BATCH_SIZE:-512}" "${JUDGE_UBATCH_SIZE:-128}"; do
  case "$value" in ''|*[!0-9]*) echo '[fatal] invalid cache or batch size' >&2; exit 1;; esac
done
export OMP_WAIT_POLICY="${OMP_WAIT_POLICY:-PASSIVE}"
mkdir -p /tmp/jjdguard
umask 077
printf '%s\n' "$API_KEY" >/tmp/jjdguard/api-key

set -- /opt/llama/llama-server \
  -m "$MODEL" \
  --host 0.0.0.0 --port 8080 \
  --alias "${JUDGE_ALIAS:-bundled-judge}" \
  --ctx-size "${JUDGE_CTX:-16384}" \
  --parallel "${JUDGE_PARALLEL:-2}" \
  --threads "${JUDGE_THREADS:-4}" \
  --threads-batch "${JUDGE_THREADS:-4}" \
  --n-gpu-layers "${JUDGE_GPU_LAYERS:-99}" \
  --cache-ram "${JUDGE_CACHE_RAM_MB:-1024}" \
  --batch-size "${JUDGE_BATCH_SIZE:-512}" \
  --ubatch-size "${JUDGE_UBATCH_SIZE:-128}" \
  --cont-batching \
  --offline \
  --metrics \
  --api-key-file /tmp/jjdguard/api-key

case "${JUDGE_FLASH_ATTN:-on}" in
  on|off|auto) set -- "$@" --flash-attn "${JUDGE_FLASH_ATTN:-on}" ;;
  *) echo '[fatal] JUDGE_FLASH_ATTN must be on, off, or auto' >&2; exit 1 ;;
esac

# F16 preserves the validated semantic and memory configuration.
case "${JUDGE_KV_CACHE_TYPE:-f16}" in
  f16) ;;
  q8_0) set -- "$@" --cache-type-k q8_0 --cache-type-v q8_0 ;;
  *) echo '[fatal] JUDGE_KV_CACHE_TYPE must be f16 or q8_0' >&2; exit 1 ;;
esac
if [ "${JUDGE_KV_CACHE_TYPE:-f16}" = q8_0 ] && [ "${JUDGE_FLASH_ATTN:-on}" = off ]; then
  echo '[fatal] JUDGE_KV_CACHE_TYPE=q8_0 requires Flash Attention' >&2
  exit 1
fi

echo "[info] starting GPU Judge instance: parallel=${JUDGE_PARALLEL:-2} ctx=${JUDGE_CTX:-16384} gpu_layers=${JUDGE_GPU_LAYERS:-99} flash_attn=${JUDGE_FLASH_ATTN:-on} kv=${JUDGE_KV_CACHE_TYPE:-f16}"
exec "$@"
