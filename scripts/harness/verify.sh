#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/harness/verify.sh <module>
       scripts/harness/verify.sh --list

Modules:
  harness
  control-plane
  gateway-core
  proxy-server
  worker
  shared-go
  security-engine
  web-console
USAGE
}

repo_root="${HARNESS_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null)}"
[[ -n "$repo_root" ]] || {
  echo "verify: not inside a git repository" >&2
  exit 1
}
cd "$repo_root"

module="${1:-}"
if [[ "$module" == "--help" || "$module" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "$module" == "--list" ]]; then
  cat <<'MODULES'
harness
control-plane
gateway-core
proxy-server
worker
shared-go
security-engine
web-console
MODULES
  exit 0
  git diff --cached --check
fi

[[ -n "$module" ]] || {
  usage >&2
  exit 1
}

go_env() {
  PATH=/usr/local/go/bin:$PATH GOWORK=off "$@"
}

verify_harness() {
  git diff --check
  for script in scripts/harness/*.sh; do
    bash -n "$script"
  done
  bash scripts/harness/tests/test_harness_scripts.sh
}

verify_control_plane() {
  (
    cd apps/control-plane
    go_env go test ./...
    go_env go vet ./...
    go_env go build -o /tmp/jjdguard-control-plane ./cmd/server
  )
}

verify_gateway_core() {
  (
    cd apps/gateway-core
    go_env go test ./...
    go_env go vet ./...
    go_env go build -o /tmp/jjdguard-gateway-core ./cmd/server
  )
}

verify_proxy_server() {
  (
    cd apps/proxy-server
    go_env go test ./...
    go_env go vet ./...
    go_env go build -o /tmp/jjdguard-proxy-server ./cmd/server
  )
}

verify_worker() {
  (
    cd apps/worker
    go_env go test ./...
    if [[ -d cmd/worker ]]; then
      go_env go build -o /tmp/jjdguard-worker ./cmd/worker
    fi
  )
}

verify_shared_go() {
  (
    cd packages/shared-go
    go_env go test ./...
    go_env go vet ./...
  )
}

verify_security_engine() {
  (
    cd apps/security-engine
    python3 -m compileall app
    python3 -m pytest
  )
}

verify_web_console() {
  (
    cd apps/web-console
    npm run lint
    npm run test
    npm run build
  )
}

case "$module" in
  harness) verify_harness ;;
  control-plane) verify_control_plane ;;
  gateway-core) verify_gateway_core ;;
  proxy-server) verify_proxy_server ;;
  worker) verify_worker ;;
  shared-go) verify_shared_go ;;
  security-engine) verify_security_engine ;;
  web-console) verify_web_console ;;
  *)
    echo "verify: unknown module: $module" >&2
    usage >&2
    exit 1
    ;;
esac
