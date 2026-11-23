FROM docker.1ms.run/library/python:3.11-slim@sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca

WORKDIR /app

# P1-A：构建期注入版本号（供 check-input 响应回带 engine_build，网关据此做指纹缓存键）
ARG SECURITY_ENGINE_BUILD=""
ENV SECURITY_ENGINE_BUILD=${SECURITY_ENGINE_BUILD}

# 正式离线构建只复制 home 当前 security-engine 镜像的已校验依赖快照。
COPY --from=release-security-python-deps /site-packages /usr/local/lib/python3.11/site-packages
RUN python -m pip check
COPY apps/security-engine/ocr-resources.lock.json /app/ocr-resources.lock.json
RUN useradd --create-home --uid 10001 appuser

# 复制应用代码
COPY --chown=appuser:appuser apps/security-engine/app ./app
COPY --chown=appuser:appuser apps/security-engine/tests/fixtures/file_detection /app/file-fixtures

RUN SECURITY_FILE_CONTENT_DLP_ENABLED=true python -m app.file_readiness --require-enabled

USER appuser

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
