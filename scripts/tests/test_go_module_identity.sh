#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

want=(
  github.com/yangjiyj/aiguard/apps/control-plane
  github.com/yangjiyj/aiguard/apps/gateway-core
  github.com/yangjiyj/aiguard/apps/proxy-server
  github.com/yangjiyj/aiguard/apps/worker
  github.com/yangjiyj/aiguard/packages/shared-go
)
dirs=(
  apps/control-plane
  apps/gateway-core
  apps/proxy-server
  apps/worker
  packages/shared-go
)
old=(
  github.com/newapi/enterprise/control-plane
  github.com/newapi/enterprise/gateway-core
  github.com/newapi/enterprise/proxy-server
  github.com/newapi/enterprise/worker
  github.com/newapi/enterprise/shared-go
)

failures=0
for index in "${!dirs[@]}"; do
  actual="$(cd "${dirs[$index]}" && GOWORK=off go list -m)"
  if [[ "$actual" != "${want[$index]}" ]]; then
    printf 'FAIL: %s module is %s, want %s\n' \
      "${dirs[$index]}" "$actual" "${want[$index]}" >&2
    failures=$((failures + 1))
  fi
done

for root in "${old[@]}"; do
  if git grep -nF "$root" -- ':(glob)**/*.go' ':(glob)**/go.mod'; then
    printf 'FAIL: active Go files still reference old module root: %s\n' "$root" >&2
    failures=$((failures + 1))
  fi
done

if ((failures != 0)); then
  printf 'FAIL: %d Go module identity checks failed\n' "$failures" >&2
  exit 1
fi

printf 'PASS: five JJDGuard Go module identities and imports are canonical\n'
