#!/usr/bin/env bash
# 在 Playwright 官方镜像里跑 e2e 浏览器测试。
# 用法：bash run_browser_in_docker.sh
set -euo pipefail

cd "$(dirname "$0")"

IMG="mcr.microsoft.com/playwright/python:v1.40.0-jammy"
ROOT="/home/dev/jjdguard-src/tests/e2e"
TS=$(date +%Y%m%d-%H%M%S)
REPORTS_HOST="$ROOT/reports/browser-$TS"
mkdir -p "$REPORTS_HOST"

# 容器内：
# - mount 测试目录到 /work
# - host 网络（127.0.0.1 直通 web-console:3000 / control-plane:8081 / postgres:15432）
# - 装额外 py 依赖（httpx + psycopg），playwright/pytest 镜像自带
# - E2E_FORCE_BROWSER=1 跳过 skipif
# - 直接跑 smoke/test_pages_render.py

exec docker run --rm \
  --network host \
  -v "$ROOT":/work \
  -w /work \
  -e E2E_API_BASE=http://127.0.0.1:8081 \
  -e E2E_WEB_BASE=http://127.0.0.1:3000 \
  -e E2E_DB_DSN=postgresql://newapi:newapi@127.0.0.1:15432/newapi \
  -e E2E_ADMIN_USER=admin \
  -e E2E_ADMIN_PASS='NapiE2E#2026!' \
  -e E2E_REPORTS=/work/reports/browser-"$TS" \
  -e E2E_FORCE_BROWSER=1 \
  "$IMG" \
  bash -c '
    set -e
    pip install --quiet httpx "psycopg[binary]>=3.1" pytest-asyncio 2>&1 | tail -3 || true
    cd /work
    pytest smoke/test_pages_render.py -v --tb=short -p asyncio 2>&1 | tee "$E2E_REPORTS/pages_render.log"
  '
