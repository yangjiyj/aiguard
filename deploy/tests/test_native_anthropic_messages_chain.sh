#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
jjdguard_root="$(cd "${script_dir}/../.." && pwd)"
boflow_root="${BOFLOW_SOURCE_DIR:-/home/dev/jjdflow}"
harness="${boflow_root}/deploy/tests/native_anthropic_chain_harness.ts"

if [[ ! -f "${harness}" ]]; then
  echo "BoFlow chain harness not found: ${harness}" >&2
  exit 1
fi

chain_tmp="$(mktemp -d)"
ready_file="${chain_tmp}/boflow.url"
harness_log="${chain_tmp}/boflow.log"
harness_pid=""

cleanup() {
  if [[ -n "${harness_pid}" ]] && kill -0 "${harness_pid}" 2>/dev/null; then
    kill "${harness_pid}" 2>/dev/null || true
    wait "${harness_pid}" 2>/dev/null || true
  fi
  rm -rf "${chain_tmp}"
}
trap cleanup EXIT

(
  cd "${boflow_root}/apps/api"
  CHAIN_READY_FILE="${ready_file}" MESSAGES_BODY_LIMIT_MB=64 \
    pnpm exec tsx "${harness}"
) >"${harness_log}" 2>&1 &
harness_pid="$!"

for _ in $(seq 1 200); do
  if [[ -s "${ready_file}" ]]; then
    break
  fi
  if ! kill -0 "${harness_pid}" 2>/dev/null; then
    sed -n '1,200p' "${harness_log}" >&2
    exit 1
  fi
  sleep 0.1
done

if [[ ! -s "${ready_file}" ]]; then
  sed -n '1,200p' "${harness_log}" >&2
  echo "BoFlow chain harness did not become ready" >&2
  exit 1
fi

IFS= read -r boflow_url <"${ready_file}"
(
  cd "${jjdguard_root}/apps/gateway-core"
  PATH="/usr/local/go/bin:${PATH}" GOWORK=off \
    JJD_NATIVE_CHAIN_BOFLOW_URL="${boflow_url}" \
    go test ./internal/handler -run TestNativeMessagesFortyMiBBoFlowChain -count=1 -v
)

if ! kill -0 "${harness_pid}" 2>/dev/null; then
  sed -n '1,200p' "${harness_log}" >&2
  exit 1
fi

echo "native Anthropic Messages chain passed: 40 MiB JSON, SSE, upstream 400"
