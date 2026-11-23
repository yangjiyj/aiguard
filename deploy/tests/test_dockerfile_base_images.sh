#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PARSER="$ROOT_DIR/deploy/docker-compose/dockerfile-base-images.py"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail() {
  printf '[fail] %s\n' "$*" >&2
  exit 1
}

expect_reject_contains() {
  local label=$1 needle=$2 output
  shift 2
  if output=$("$@" 2>&1); then
    fail "$label was accepted"
  fi
  [[ "$output" == *"$needle"* ]] ||
    fail "$label failed for the wrong reason: $output"
}

[[ -x "$PARSER" ]] || fail 'Dockerfile base image parser is missing or not executable'

cat >"$TMP_ROOT/pinned.Dockerfile" <<'DOCKERFILE'
ARG BASE_IMAGE=registry.example/build:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
FROM ${BASE_IMAGE} AS build
RUN true
FROM build AS test
RUN true
FROM registry.example/runtime:2@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
DOCKERFILE

actual=$(python3 "$PARSER" --dockerfile "$TMP_ROOT/pinned.Dockerfile")
expected=$(jq -cn '[
  {from_index:0,stage:"build",
   reference:"registry.example/build:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {from_index:2,stage:null,
   reference:"registry.example/runtime:2@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
   digest:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
]')
[[ "$(jq -cS . <<<"$actual")" == "$(jq -cS . <<<"$expected")" ]] ||
  fail "ordered external FROM parsing drifted: $actual"

printf '%s\n' 'FROM registry.example/base:latest' >"$TMP_ROOT/mutable.Dockerfile"
expect_reject_contains mutable-from 'not pinned to a sha256 digest' \
  python3 "$PARSER" --dockerfile "$TMP_ROOT/mutable.Dockerfile"

cat >"$TMP_ROOT/mutable-arg.Dockerfile" <<'DOCKERFILE'
ARG NODE_IMAGE=registry.example/node:22-alpine
FROM ${NODE_IMAGE} AS build
DOCKERFILE
expect_reject_contains mutable-arg-default 'not pinned to a sha256 digest' \
  python3 "$PARSER" --dockerfile "$TMP_ROOT/mutable-arg.Dockerfile"

cat >"$TMP_ROOT/unresolved-arg.Dockerfile" <<'DOCKERFILE'
ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS build
DOCKERFILE
expect_reject_contains unresolved-arg 'unresolved build argument' \
  python3 "$PARSER" --dockerfile "$TMP_ROOT/unresolved-arg.Dockerfile"

install -d -m 0700 "$TMP_ROOT/bin"
cat >"$TMP_ROOT/bin/docker" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
: >"${LOCAL_DOCKER_MARKER:?}"
printf '%s\n' '[{"RepoDigests":["registry.example/build@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]}]'
SH
chmod 0500 "$TMP_ROOT/bin/docker"
LOCAL_DOCKER_MARKER="$TMP_ROOT/local-docker-called" \
PATH="$TMP_ROOT/bin:$PATH" \
  python3 "$PARSER" --dockerfile "$TMP_ROOT/pinned.Dockerfile" >"$TMP_ROOT/polluted.json"
[[ ! -e "$TMP_ROOT/local-docker-called" ]] ||
  fail 'base digest was derived from the polluted local Docker tag'
[[ "$(jq -r '.[0].digest' "$TMP_ROOT/polluted.json")" == \
   sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]] ||
  fail 'Dockerfile digest was replaced by a local RepoDigest'

catalog="$ROOT_DIR/deploy/docker-compose/images.lst"
external_from_count=0
: >"$TMP_ROOT/selected-base-digests"
while read -r _image _profile kind component _digest dockerfile _context; do
  [[ "$kind" != third-party ]] || continue
  case "$kind:$component" in
    home-runtime:*|upstream-source:llm-judge)
      # These images intentionally start from a verified local runtime. Their
      # build functions provide a checked base_images override, so a generic
      # parser must not mistake the injected alias for an external image.
      grep -Fqx 'ARG LOCAL_RUNTIME_IMAGE' "$ROOT_DIR/$dockerfile" ||
        fail "$component must declare an explicit local runtime build argument"
      grep -Fq 'FROM ${LOCAL_RUNTIME_IMAGE}' "$ROOT_DIR/$dockerfile" ||
        fail "$component must use the explicit local runtime image as its base"
      continue
      ;;
  esac
  if ! parsed=$(python3 "$PARSER" --dockerfile "$ROOT_DIR/$dockerfile" 2>&1); then
    fail "selected Dockerfile base contract failed for $component: $parsed"
  fi
  count=$(jq -er 'length' <<<"$parsed")
  case "$component" in
    gateway-core|control-plane|proxy-server|worker)
      expected_count=2
      ;;
    web-console)
      expected_count=3
      ;;
    security-engine|tier1-classifier|enterprise-ai-portal)
      expected_count=1
      ;;
    *) fail "unexpected source-built component: $component" ;;
  esac
  [[ "$count" == "$expected_count" ]] ||
    fail "$component external FROM count drifted: expected=$expected_count actual=$count"
  jq -er '.[].digest' <<<"$parsed" >>"$TMP_ROOT/selected-base-digests" ||
    fail "$component base digest summary is invalid"
  external_from_count=$((external_from_count + count))
done < <(awk '!/^[[:space:]]*#/ && NF' "$catalog")
[[ "$external_from_count" == 14 ]] ||
  fail "selected external FROM total drifted: $external_from_count"

actual_base_digests=$(sort -u "$TMP_ROOT/selected-base-digests")
expected_base_digests=$(printf '%s\n' \
  sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b \
  sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 \
  sha256:ae52c5bef62a6bdd42cd1e8dffef86b9cd284bde9427da79839de7a4b983e7ca \
  sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd)
[[ "$actual_base_digests" == "$expected_base_digests" ]] ||
  fail "selected base digest set drifted: $actual_base_digests"

printf '[ok] Dockerfile base image parser rejects mutable and local-tag provenance\n'
