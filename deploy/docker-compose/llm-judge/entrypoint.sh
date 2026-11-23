#!/bin/sh
# 启动 CPU llama-server 暴露 OpenAI 兼容 /v1/chat/completions。
# 全参数化（线程/上下文/并发/模型路径/api-key），env 覆盖。
set -eu

# Avoid active OpenMP waits contending with the gateway and security engine.
# Explicit operator policy and spin-count overrides remain authoritative.
export OMP_WAIT_POLICY="${OMP_WAIT_POLICY:-PASSIVE}"

MODEL="${JUDGE_MODEL_PATH:-/models/jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf}"
if [ ! -f "$MODEL" ]; then
  echo "[fatal] GGUF 未找到: $MODEL —— judge-models 卷未灌模型？" >&2
  exit 1
fi

exec /opt/llama/llama-server \
  -m "$MODEL" \
  --host 0.0.0.0 --port "${JUDGE_PORT:-8080}" \
  --alias "${JUDGE_ALIAS:-bundled-judge}" \
  -c "${JUDGE_CTX:-2048}" \
  -t "${JUDGE_THREADS:-6}" --threads-batch "${JUDGE_THREADS:-6}" \
  --parallel "${JUDGE_PARALLEL:-2}" \
  --cache-ram "${JUDGE_CACHE_RAM_MB:-1024}" \
  --batch-size "${JUDGE_BATCH_SIZE:-512}" \
  --ubatch-size "${JUDGE_UBATCH_SIZE:-128}" \
  --api-key "${JUDGE_API_KEY:-bundled-judge}"
