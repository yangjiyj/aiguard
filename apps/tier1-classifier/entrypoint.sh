#!/bin/sh
# 启动 Tier-1 分类器 HTTP 服务（uvicorn）。全参数化，env 覆盖。
# 服务自身用 TIER1_MODEL_DIR 加载 ONNX；端口 8000（与契约 /classify 端口一致）。
#
# 开机 fatal 守卫（plan E-2）：模型目录缺失/为空 → 当场 exit 1 暴露，不静默起一个永远 503 的服务。
# 这是构建期 build-tier1-image.sh 模型就绪校验之外的【运行期最后一道】防线：
# 镜像若被错灌空模型卷、或 COPY 失败/被外部 mount 覆盖，启动即 fail-fast。
set -eu

MODEL_DIR="${TIER1_MODEL_DIR:-/models/prompt-guard-2}"
if [ ! -d "$MODEL_DIR" ] || [ -z "$(ls -A "$MODEL_DIR" 2>/dev/null)" ]; then
  echo "[fatal] Tier-1 模型目录为空: $MODEL_DIR —— 镜像未 COPY 模型？" >&2
  exit 1
fi

exec python -m uvicorn app.main:app \
  --host 0.0.0.0 --port "${TIER1_PORT:-8000}" \
  --workers "${TIER1_WORKERS:-1}"
