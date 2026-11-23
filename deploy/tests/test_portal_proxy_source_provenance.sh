#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROXY="$ROOT/portal-proxy"
BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"
CATALOG="$ROOT/deploy/docker-compose/images.lst"
ATTESTATION="$PROXY/SOURCE-ATTESTATION.json"
LICENSE_FILE="$PROXY/LICENSE"
VERIFIER="$ROOT/deploy/docker-compose/verify-portal-proxy-source.py"

fail() {
  printf '[portal-proxy-source-test] %s\n' "$*" >&2
  exit 1
}

for path in \
  package.json \
  pnpm-lock.yaml \
  tsconfig.json \
  Dockerfile \
  prisma/schema.prisma \
  src/server.ts \
  src/proxy.ts \
  src/jit.ts \
  src/mapping.ts \
  src/model-alias.ts \
  src/gateway-flags.ts \
  src/admin/router.ts \
  src/admin/public/index.html; do
  [[ -f "$PROXY/$path" ]] || fail "missing repository source: portal-proxy/$path"
done

[[ -f "$ATTESTATION" ]] ||
  fail 'Portal Proxy source ownership and recovery attestation is missing'
[[ -f "$LICENSE_FILE" ]] ||
  fail 'Portal Proxy source license and ownership notice is missing'
python3 -m json.tool "$ATTESTATION" >/dev/null ||
  fail 'Portal Proxy source attestation is not valid JSON'
for expected in \
  '"schema": "jjdguard-portal-proxy-source/v1"' \
  '"license": "Proprietary"' \
  '"repository": "git@github.com:yangjiyj/aiguard.git"' \
  '"former_workspace": "/home/dev/chat-portal/proxy"' \
  '"git_history": "unavailable"' \
  '"image": "chat-portal/portal-proxy:0.1.0"' \
  '"image_archive_sha256": "sha256:'; do
  grep -Fq "$expected" "$ATTESTATION" ||
    fail "Portal Proxy source attestation is missing: $expected"
done
grep -Eq '"id": "[0-9a-f-]{36}"' "$ATTESTATION" ||
  fail 'Portal Proxy source attestation has no retained source-session ID'
grep -Eq '"sha256": "[0-9a-f]{64}"' "$ATTESTATION" ||
  fail 'Portal Proxy source attestation has no retained source-session hash'
grep -Fq 'All rights reserved.' "$LICENSE_FILE" ||
  fail 'Portal Proxy license does not reserve proprietary rights'

[[ -d "$PROXY/test" ]] || fail 'missing recovered Portal Proxy tests'
find "$PROXY/test" -maxdepth 1 -type f -name '*.test.ts' -print -quit |
  grep -q . || fail 'Portal Proxy has no executable test files'

grep -Fq '"build": "tsc -p tsconfig.json' "$PROXY/package.json" ||
  fail 'Portal Proxy package has no TypeScript build'
grep -Fq 'AS build' "$PROXY/Dockerfile" ||
  fail 'Portal Proxy Dockerfile has no source build stage'
grep -Fq 'pnpm run build' "$PROXY/Dockerfile" ||
  fail 'Portal Proxy Dockerfile does not build repository source'

if grep -Eq 'PORTAL_PROXY_SEED_IMAGE|docker create .*portal-proxy|docker cp .*:/app/(package|pnpm|prisma|dist)' "$BUILDER"; then
  fail 'offline builder still repacks an opaque Portal Proxy seed image'
fi

awk '$4 == "portal-proxy" {
       ok = ($1 == "chat-portal/portal-proxy:0.1.0" && $3 == "home-runtime" &&
             $6 == "portal-proxy/Dockerfile.offline" && $7 == "portal-proxy")
     }
     END { exit !ok }' "$CATALOG" ||
  fail 'Portal Proxy home runtime Dockerfile/context is missing from the image catalog'
grep -Fq 'prepare_release_git_context' "$BUILDER" ||
  fail 'offline builder does not materialize a reviewed Git archive context'
grep -Fq '"$SOURCE_ROOT/$dockerfile" "$context_path"' "$BUILDER" ||
  fail 'offline builder does not build cataloged source from the Git archive context'
[[ -x "$VERIFIER" ]] ||
  fail 'Portal Proxy archive authority verifier is missing'
python3 - "$BUILDER" <<'PY'
import pathlib
import sys

script = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
source_root = script.find('SOURCE_ROOT="$TEMP_ROOT/git-context/source"')
gate = script.find('verify-portal-proxy-source.py', source_root)
catalog = script.find(
    'catalog_rows="$(read_image_catalog_for_profile "$BUNDLE_PROFILE")"', source_root
)
if source_root < 0 or gate < 0 or catalog < 0 or gate >= catalog:
    raise SystemExit('Portal Proxy archive authority is not checked before image construction')
PY
python3 "$VERIFIER" \
  --source-root "$ROOT" \
  --source-remote 'git@github.com:yangjiyj/aiguard.git'

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-portal-source-test.XXXXXX")"
cleanup_fixture() {
  rm -rf "$fixture_root"
}
trap cleanup_fixture EXIT HUP INT TERM
mkdir -p "$fixture_root/portal-proxy/test"
printf '%s\n' 'FROM scratch' >"$fixture_root/portal-proxy/Dockerfile"
printf '%s\n' 'lockfileVersion: 9.0' >"$fixture_root/portal-proxy/pnpm-lock.yaml"
printf '%s\n' 'test("source authority", () => {})' >"$fixture_root/portal-proxy/test/source.test.ts"
printf '%s\n' 'JJDGuard Portal Proxy' >"$fixture_root/portal-proxy/LICENSE"
cat >"$fixture_root/portal-proxy/SOURCE-ATTESTATION.json" <<'JSON'
{
  "schema": "jjdguard-portal-proxy-source/v1",
  "ownership": {
    "license": "Proprietary",
    "copyright_holder": "Huoxianbao / JJDGuard",
    "authority": "JJDGuard project owner"
  },
  "current_authoritative_source": {
    "repository": "git@github.com:yangjiyj/aiguard.git",
    "path": "portal-proxy",
    "dockerfile": "portal-proxy/Dockerfile",
    "build_context": "portal-proxy",
    "lockfile": "portal-proxy/pnpm-lock.yaml",
    "tests": "portal-proxy/test/*.test.ts"
  }
}
JSON
python3 "$VERIFIER" \
  --source-root "$fixture_root" \
  --source-remote 'git@github.com:yangjiyj/aiguard.git'
sed -i 's#agent-compute-gateway.git#wrong-source.git#' \
  "$fixture_root/portal-proxy/SOURCE-ATTESTATION.json"
if python3 "$VERIFIER" \
  --source-root "$fixture_root" \
  --source-remote 'git@github.com:yangjiyj/aiguard.git'; then
  fail 'Portal Proxy archive authority verifier accepted a remote mismatch'
fi

tracked_source_count="$(
  git -C "$ROOT" ls-files 'portal-proxy/src/*.ts' 'portal-proxy/src/admin/*.ts' |
    wc -l |
    tr -d ' '
)"
[[ "$tracked_source_count" -ge 30 ]] ||
  fail "expected at least 30 tracked source modules, got $tracked_source_count"

printf '[ok] Portal Proxy repository source provenance contract passed\n'
