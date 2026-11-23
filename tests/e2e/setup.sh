#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .
# Try to install Playwright chromium (may fail on unsupported distros)
if .venv/bin/python -m playwright install chromium 2>/dev/null; then
    echo "[setup] Playwright chromium installed natively."
else
    echo "[setup] WARN: Playwright native install failed (ubuntu26.04 not supported)."
    echo "[setup] Browser tests will use Docker fallback: mcr.microsoft.com/playwright/python:v1.40.0-jammy"
    echo "[setup] Run: docker pull mcr.microsoft.com/playwright/python:v1.40.0-jammy"
fi
echo "[setup] done. Activate: source tests/e2e/.venv/bin/activate"
