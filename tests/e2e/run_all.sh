#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$(dirname "$0")"

TS=$(date +%Y%m%d-%H%M%S)
export E2E_REPORTS="$(pwd)/reports/$TS"
mkdir -p "$E2E_REPORTS"
ln -sfn "$TS" reports/latest

# --with-coverage also runs per-language coverage collection
WITH_COV=0
for arg in "$@"; do
  [ "$arg" = "--with-coverage" ] && WITH_COV=1
done

if ! source .venv/bin/activate 2>/dev/null; then
  echo "[ERROR] .venv not found. Run: bash setup.sh first"
  exit 1
fi

echo ""
echo "=== E2E Test Suite: $TS ==="
echo "Reports: $E2E_REPORTS"
echo ""

echo "=== smoke ===" && \
  pytest smoke/ -v --tb=short 2>&1 | tee "$E2E_REPORTS/smoke.log" || true

echo ""
echo "=== scenarios ===" && \
  pytest scenarios/ -v --tb=short 2>&1 | tee "$E2E_REPORTS/scenarios.log" || true

if [ "$WITH_COV" = "1" ]; then
  echo ""
  echo "=== coverage: Go ==="
  bash coverage/run_go_coverage.sh || true
  echo ""
  echo "=== coverage: Python ==="
  bash coverage/run_python_coverage.sh || true
  echo ""
  echo "=== coverage: Frontend ==="
  bash coverage/run_frontend_coverage.sh || true
fi

echo ""
echo "=== Summary ==="
# Extract pass/fail counts from logs
smoke_pass=$(grep -c "PASSED" "$E2E_REPORTS/smoke.log" 2>/dev/null || echo 0)
smoke_fail=$(grep -c "FAILED" "$E2E_REPORTS/smoke.log" 2>/dev/null || echo 0)
scenario_pass=$(grep -c "PASSED" "$E2E_REPORTS/scenarios.log" 2>/dev/null || echo 0)
scenario_fail=$(grep -c "FAILED" "$E2E_REPORTS/scenarios.log" 2>/dev/null || echo 0)
echo "  Smoke:     pass=$smoke_pass fail=$smoke_fail"
echo "  Scenarios: pass=$scenario_pass fail=$scenario_fail"
echo ""
echo "Reports saved to: $E2E_REPORTS"
ls -la "$E2E_REPORTS"

echo ""
echo "=== development traffic precision gate ==="
bash "$ROOT/deploy/tests/test_development_traffic_precision.sh"
