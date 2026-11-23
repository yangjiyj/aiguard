#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"

fail() {
  printf 'FAIL test_go_services_offline_dependency_contract: %s\n' "$*" >&2
  exit 1
}

for service in gateway-core control-plane proxy-server worker; do
  dockerfile="$ROOT/apps/$service/Dockerfile"
  grep -Fq 'COPY --from=release-go-cache /pkg/mod /go/pkg/mod' "$dockerfile" ||
    fail "$service must copy the explicit local Go module cache"
  grep -Fq 'GOPROXY=off GOSUMDB=off go mod download' "$dockerfile" ||
    fail "$service must validate modules without an outbound proxy"
  if grep -Eq '^[[:space:]]*RUN[[:space:]].*apk[[:space:]]+add' "$dockerfile"; then
    fail "$service must not install Alpine packages from a network repository"
  fi
  grep -Fq 'COPY --from=release-alpine-runtime /etc/ssl/certs /etc/ssl/certs' "$dockerfile" ||
    fail "$service must copy local CA certificates from the release input"
  grep -Fq 'COPY --from=release-alpine-runtime /usr/share/zoneinfo /usr/share/zoneinfo' "$dockerfile" ||
    fail "$service must copy local timezone data from the release input"
done

grep -Fq 'GO_BUILD_CACHE_INPUT=' "$BUILDER" ||
  fail 'offline builder must require an explicit Go module cache input'
grep -Fq 'ALPINE_RUNTIME_INPUT=' "$BUILDER" ||
  fail 'offline builder must require an explicit Alpine runtime input'
grep -Fq -- '--build-context "release-go-cache=$GO_BUILD_CACHE_INPUT"' "$BUILDER" ||
  fail 'offline builder must pass the local Go module cache context'
grep -Fq -- '--build-context "release-alpine-runtime=$ALPINE_RUNTIME_INPUT"' "$BUILDER" ||
  fail 'offline builder must pass the local Alpine runtime context'

printf 'PASS test_go_services_offline_dependency_contract\n'
