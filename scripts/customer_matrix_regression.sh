#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/usr/local/go/bin:${PATH}"
export GOWORK=off

run() {
  echo
  echo "==> $*"
  "$@"
}

forbid_hardcoded_adapter_registry() {
  echo
  echo "==> checking adapter registry consumers stay manifest-driven"

  local violations
  violations="$(
    rg -n --glob '!packages/shared-go/aiadapters/adapters/**' --glob '!**/*_test.go' \
      'var[[:space:]]+[A-Za-z0-9_]*entries[A-Za-z0-9_]*[[:space:]]*=[[:space:]]*\[\]' \
      "${ROOT}/packages/shared-go" "${ROOT}/apps/proxy-server" "${ROOT}/apps/web-console/src" || true
    rg -n --glob '!packages/shared-go/aiadapters/adapters/**' --glob '!**/*_test.go' \
      '[=:][[:space:]]*\[\][A-Za-z0-9_.*]*Entry[[:space:]]*\{' \
      "${ROOT}/packages/shared-go" "${ROOT}/apps/proxy-server" "${ROOT}/apps/web-console/src" || true
    rg -n --glob '!packages/shared-go/aiadapters/adapters/**' --glob '!**/*_test.go' \
      'AGENT_DEFINITIONS[[:space:]]*=[[:space:]]*\[' \
      "${ROOT}/packages/shared-go" "${ROOT}/apps/proxy-server" "${ROOT}/apps/web-console/src" || true
  )"
  if [[ -n "${violations}" ]]; then
    echo "Adapter catalog/agent definitions must be loaded from packages/shared-go/aiadapters/adapters/*.json." >&2
    echo "${violations}" >&2
    return 1
  fi

  rg -n 'aiadapters\.CatalogEntries\(\)' "${ROOT}/packages/shared-go/llmcatalog/llmcatalog.go" >/dev/null
  rg -n 'aiadapters\.AgentRules\(\)' "${ROOT}/packages/shared-go/agentdetect/agentdetect.go" >/dev/null
  rg -n 'generatedAgentDefinitions' "${ROOT}/apps/web-console/src/utils/agents.ts" >/dev/null
}

forbid_hardcoded_adapter_registry

run python3 "${ROOT}/scripts/generate_ai_adapter_frontend.py" --check

cd "${ROOT}/packages/shared-go"
run go test ./llmcatalog ./agentdetect -count=1

cd "${ROOT}/apps/proxy-server"
run go test ./internal/handler -count=1

cd "${ROOT}/apps/control-plane"
run go test ./internal/handler -run 'TestEvalIntegrationAssurance|TestEvalIntegration' -count=1

cd "${ROOT}/apps/security-engine"
PYTHON_BIN="${PYTHON:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
  else
    PYTHON_BIN=python
  fi
fi
run "${PYTHON_BIN}" -m pytest \
  tests/test_api.py::TestCheckInput::test_check_input_with_secret \
  tests/test_api.py::TestCheckInput::test_check_input_with_id_card \
  tests/test_api.py::TestCheckInput::test_check_input_with_ai_ide_github_token \
  tests/test_detectors.py::TestSecretDetection::test_detect_aws_access_key \
  tests/test_detectors.py::TestSecretDetection::test_detect_openai_key \
  tests/test_detectors.py::TestSecretDetection::test_detect_github_token \
  -q

echo
run "${PYTHON_BIN}" "${ROOT}/apps/security-engine/tools/credential_regression_gate.py"

echo "Customer matrix regression passed."
