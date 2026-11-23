FROM docker.1ms.run/library/python:3.11-slim@sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca

WORKDIR /app

# 正式包从 home 已验证的本地 Tier1 镜像抽取依赖快照；构建全程断网，
# 不访问 PyPI/Hugging Face 或任何其他包索引。
COPY python-deps/site-packages /usr/local/lib/python3.11/site-packages
RUN python -m pip check
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
RUN useradd --create-home --uid 10001 appuser

# 应用代码
COPY --chown=appuser:appuser app ./app

# 受控的用户自训 ONNX 输入已由发布构建校验锁定；镜像构建不下载或训练模型。
COPY --chown=appuser:appuser models/prompt-guard-2 /models/prompt-guard-2
# 构建期 fail-fast：坐实自训基线(融合 ONNX + config)确实进镜像，COPY 空目录不会自动失败。
RUN test -f /models/prompt-guard-2/model.onnx && test -f /models/prompt-guard-2/config.json \
    || { echo "[fatal] 基线模型未进镜像: /models/prompt-guard-2/model.onnx|config.json 缺失" >&2; exit 1; }
ENV TIER1_MODEL_DIR=/models/prompt-guard-2

# 启动脚本：含空模型目录开机 fatal 守卫（plan E-2），再 exec uvicorn app.main:app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER appuser

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
