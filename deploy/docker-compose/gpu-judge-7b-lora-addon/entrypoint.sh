#!/bin/sh
set -eu

MODEL="${JUDGE_MODEL_PATH:-/models/judge-v4-Q4_K_M.gguf}"
API_KEY="${JUDGE_API_KEY:-}"
TLS_CERT="${JUDGE_TLS_CERT_PATH:-/tls/server.crt}"
TLS_KEY="${JUDGE_TLS_KEY_PATH:-/tls/server.key}"
[ -f "$MODEL" ] || { echo "[fatal] Judge GGUF missing: $MODEL" >&2; exit 1; }
# The addon serves the merged judge-v4 model only; a LoRA would change the
# verified model identity, so a leftover JUDGE_LORA_PATH is rejected.
[ -z "${JUDGE_LORA_PATH:-}" ] || { echo '[fatal] JUDGE_LORA_PATH is not supported; the addon serves judge-v4 without an adapter' >&2; exit 1; }
[ -n "$API_KEY" ] || { echo '[fatal] JUDGE_API_KEY is required' >&2; exit 1; }
[ -r "$TLS_CERT" ] || { echo '[fatal] TLS certificate is missing or unreadable' >&2; exit 1; }
[ -r "$TLS_KEY" ] || { echo '[fatal] TLS private key is missing or unreadable' >&2; exit 1; }

devices="$(/opt/llama/llama-server --list-devices 2>&1)"
printf '%s\n' "$devices"
case "$devices" in
  *"CUDA0:"*) ;;
  *) echo '[fatal] llama-server cannot see an NVIDIA CUDA device' >&2; exit 1 ;;
esac

case "${JUDGE_PARALLEL:-4}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_PARALLEL' >&2; exit 1;; esac
case "${JUDGE_CTX:-16384}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_CTX' >&2; exit 1;; esac
case "${JUDGE_THREADS:-4}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_THREADS' >&2; exit 1;; esac
case "${JUDGE_GPU_LAYERS:-99}" in ''|*[!0-9]*) echo '[fatal] invalid JUDGE_GPU_LAYERS' >&2; exit 1;; esac

set -- /opt/llama/llama-server \
  -m "$MODEL" \
  --host 0.0.0.0 --port 8080 \
  --alias "${JUDGE_ALIAS:-qwen2.5-7b-judge-v4}" \
  --ctx-size "${JUDGE_CTX:-16384}" \
  --parallel "${JUDGE_PARALLEL:-4}" \
  --threads "${JUDGE_THREADS:-4}" \
  --threads-batch "${JUDGE_THREADS:-4}" \
  --n-gpu-layers "${JUDGE_GPU_LAYERS:-99}" \
  --cont-batching \
  --offline \
  --metrics \
  --api-key "$API_KEY" \
  --ssl-cert-file "$TLS_CERT" \
  --ssl-key-file "$TLS_KEY"

case "${JUDGE_FLASH_ATTN:-on}" in
  on|off|auto) set -- "$@" --flash-attn "${JUDGE_FLASH_ATTN:-on}" ;;
  *) echo '[fatal] JUDGE_FLASH_ATTN must be on, off, or auto' >&2; exit 1 ;;
esac

echo "[info] starting GPU Judge with TLS: parallel=${JUDGE_PARALLEL:-4} ctx=${JUDGE_CTX:-16384} gpu_layers=${JUDGE_GPU_LAYERS:-99} flash_attn=${JUDGE_FLASH_ATTN:-on}"
exec "$@"
