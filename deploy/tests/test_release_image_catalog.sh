#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_DIR="$ROOT_DIR/deploy/docker-compose"
IMAGES_LST="$COMPOSE_DIR/images.lst"
export IMAGES_LST
# shellcheck disable=SC1091
source "$COMPOSE_DIR/lib-images.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

expect_invalid() {
  local label="$1" fixture="$2"
  if IMAGES_LST="$fixture" validate_image_catalog >"$TMP_ROOT/$label.stdout" 2>"$TMP_ROOT/$label.stderr"; then
    fail "$label catalog was accepted"
  fi
}

declare -F validate_image_catalog >/dev/null || fail 'catalog validator is missing'
declare -F read_image_digests_for_profile >/dev/null || fail 'catalog digest reader is missing'
validate_image_catalog

row_count="$(awk '!/^[[:space:]]*#/ && NF { count++ } END { print count + 0 }' "$IMAGES_LST")"
[[ "$row_count" == 14 ]] || fail "full+chat catalog expected 14 rows, got $row_count"

while read -r image profile kind component expected_digest dockerfile context extra; do
  [[ -z "${extra:-}" ]] || fail "catalog row has extra fields: $image"
  [[ "$image" != *@sha256:* ]] || fail "runtime image contains a digest: $image"
  [[ "$dockerfile" != /* && "$context" != /* ]] || fail "source paths must be repository-relative: $component"
  case "$kind" in
    first-party|upstream-source|home-runtime)
      [[ "$expected_digest" == - ]] || fail "$kind image must not declare a registry digest: $component"
      [[ "$dockerfile" != - && -f "$ROOT_DIR/$dockerfile" ]] || fail "missing Dockerfile for $component"
      [[ "$context" != - && -d "$ROOT_DIR/$context" ]] || fail "missing build context for $component"
      ;;
    third-party)
      [[ "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "third-party digest is invalid: $component"
      [[ "$dockerfile" == - && "$context" == - ]] || fail "third-party image carries source paths: $component"
      ;;
    *) fail "unknown source kind for $component: $kind" ;;
  esac
done < <(awk '!/^[[:space:]]*#/ && NF { print }' "$IMAGES_LST")

[[ "$(awk '!/^[[:space:]]*#/ && NF { print $1 }' "$IMAGES_LST" | sort -u | wc -l | tr -d ' ')" == "$row_count" ]] ||
  fail 'runtime image tags are not unique'
[[ "$(awk '!/^[[:space:]]*#/ && NF { print $4 }' "$IMAGES_LST" | sort -u | wc -l | tr -d ' ')" == "$row_count" ]] ||
  fail 'component names are not unique'

awk '$4 == "portal-proxy" {
       ok = ($1 == "chat-portal/portal-proxy:0.1.0" && $2 == "chat" &&
             $3 == "home-runtime" && $5 == "-" &&
             $6 == "portal-proxy/Dockerfile.offline" && $7 == "portal-proxy")
     }
     END { exit !ok }' "$IMAGES_LST" || fail 'Portal Proxy is not cataloged as a home runtime rebuild'
awk '$4 == "llm-judge" {
       ok = ($1 == "docker-compose-llm-judge:latest" && $2 == "full" &&
             $3 == "upstream-source" && $5 == "-" &&
             $6 == "deploy/docker-compose/llm-judge/Dockerfile.offline")
     }
     END { exit !ok }' "$IMAGES_LST" || fail 'llm-judge is not cataloged as pinned upstream source'
[[ "$(sed -n 's/^llama_cpp_revision=//p' "$COMPOSE_DIR/release-toolchain.lock")" == \
  3653e6d6d547ec763317d9ecd0ace334a7e21359 ]] || fail 'llama.cpp catalog source revision is not fixed'
grep -Fq 'UPSTREAM_REMOTE=https://github.com/ggerganov/llama.cpp.git' \
  "$COMPOSE_DIR/prepare-upstream-sources.sh" || fail 'llama.cpp upstream remote is not fixed'
grep -Fq '"schema": "jjdguard-upstream-source/v1"' \
  "$COMPOSE_DIR/prepare-upstream-sources.sh" || fail 'llama.cpp source receipt schema is missing'
grep -Fq '"archive_sha256"' "$COMPOSE_DIR/prepare-upstream-sources.sh" ||
  fail 'llama.cpp source receipt does not bind the archive digest'

while read -r component expected; do
  actual="$(awk -v component="$component" '$4 == component { print $5 }' "$IMAGES_LST")"
  [[ "$actual" == "$expected" ]] || fail "$component digest mismatch: ${actual:-missing}"
done <<'DIGESTS'
postgres sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
redis sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507
keycloak sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba
caddy sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
DIGESTS

[[ "$(INCLUDE_CHAT=0 read_images_for_profile lite | wc -l | tr -d ' ')" == 8 ]] || fail 'lite catalog count changed'
[[ "$(INCLUDE_CHAT=0 read_images_for_profile full | wc -l | tr -d ' ')" == 10 ]] || fail 'full catalog count changed'
INCLUDE_CHAT=1
export INCLUDE_CHAT
catalog_images="$(read_images_for_profile full | sort -u)"
[[ "$(printf '%s\n' "$catalog_images" | wc -l | tr -d ' ')" == 14 ]] || fail 'full+chat catalog count changed'

compose_images="$(env \
  BOOTSTRAP_ADMIN_PASSWORD=test \
  JJD_INTERNAL_API_SECRET=test \
  JJD_PROVIDER_SECRET_KEY=test \
  JJD_RULE_PACK_ATTESTATION_TOKEN=test \
  JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY=test \
  JJD_TIER1_INTERNAL_TOKEN=test \
  KEYCLOAK_ADMIN_PASSWORD=test \
  POSTGRES_PASSWORD=test \
  REDIS_PASSWORD=test \
  UAG_AUDIT_HMAC_KEY=test \
  CHAT_OIDC_HOST=chat.test.invalid \
  docker compose --profile full --profile chat \
    -f "$COMPOSE_DIR/docker-compose.offline.yml" config --images | sort -u)"
[[ "$catalog_images" == "$compose_images" ]] || {
  diff -u <(printf '%s\n' "$compose_images") <(printf '%s\n' "$catalog_images") >&2 || true
  fail 'catalog does not match offline Compose images'
}

digest_rows="$(read_image_digests_for_profile full)"
[[ "$(printf '%s\n' "$digest_rows" | sed '/^$/d' | wc -l | tr -d ' ')" == 4 ]] ||
  fail 'full+chat digest reader must return four third-party images'

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

write_fixture() {
  local name="$1" row="$2"
  printf '%s\n' "$row" >"$TMP_ROOT/$name.lst"
}

write_fixture bad-fields 'example.invalid/app:1 common first-party app - Dockerfile'
expect_invalid bad-fields "$TMP_ROOT/bad-fields.lst"
write_fixture bad-profile 'example.invalid/app:1 unknown first-party app - Dockerfile .'
expect_invalid bad-profile "$TMP_ROOT/bad-profile.lst"
write_fixture bad-kind 'example.invalid/app:1 common opaque app - Dockerfile .'
expect_invalid bad-kind "$TMP_ROOT/bad-kind.lst"
write_fixture bad-runtime 'example.invalid/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa common third-party app sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa - -'
expect_invalid bad-runtime "$TMP_ROOT/bad-runtime.lst"
write_fixture bad-digest 'example.invalid/app:1 common third-party app - - -'
expect_invalid bad-digest "$TMP_ROOT/bad-digest.lst"
write_fixture bad-source 'example.invalid/app:1 common first-party app - - -'
expect_invalid bad-source "$TMP_ROOT/bad-source.lst"
printf '%s\n' \
  'example.invalid/one:1 common first-party duplicate - Dockerfile .' \
  'example.invalid/two:1 full first-party duplicate - Dockerfile .' \
  >"$TMP_ROOT/duplicate-component.lst"
expect_invalid duplicate-component "$TMP_ROOT/duplicate-component.lst"

echo '[ok] release image catalog is complete, unique, and source-bound'
