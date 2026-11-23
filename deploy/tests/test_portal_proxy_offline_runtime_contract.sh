#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"
CATALOG="$ROOT/deploy/docker-compose/images.lst"
DOCKERFILE="$ROOT/portal-proxy/Dockerfile.offline"
RUNTIME_SOURCE_GATE="$ROOT/deploy/docker-compose/verify-portal-proxy-runtime-source.sh"

fail() {
  printf 'FAIL test_portal_proxy_offline_runtime_contract: %s\n' "$*" >&2
  exit 1
}

[[ -f "$DOCKERFILE" ]] || fail 'missing local Portal Proxy runtime Dockerfile'
grep -Fq 'ARG LOCAL_RUNTIME_IMAGE' "$DOCKERFILE" ||
  fail 'Portal Proxy offline Dockerfile must receive an explicit local runtime image'
grep -Fq 'FROM ${LOCAL_RUNTIME_IMAGE}' "$DOCKERFILE" ||
  fail 'Portal Proxy offline Dockerfile must use the local runtime image as its base'
if grep -Fq 'pnpm install' "$DOCKERFILE"; then
  fail 'Portal Proxy runtime reuse Dockerfile must not reinstall dependencies'
fi
if grep -Eq 'apk[[:space:]]+add|corepack[[:space:]]+prepare' "$DOCKERFILE"; then
  fail 'Portal Proxy offline Dockerfile must not acquire packages or pnpm from a network source'
fi

grep -Fq 'PORTAL_PROXY_RUNTIME_INPUT=' "$BUILDER" ||
  fail 'offline builder must require an explicit local Portal Proxy runtime input'
if grep -Fq 'PORTAL_PROXY_PNPM_STORE_INPUT=' "$BUILDER"; then
  fail 'offline builder must not require a discarded Portal Proxy pnpm store'
fi
grep -Fq 'io.jjdguard.source-tree' "$BUILDER" ||
  fail 'offline builder must support the verified legacy Portal Proxy source tree label'
grep -Fq 'Portal Proxy source tree labels disagree' "$BUILDER" ||
  fail 'offline builder must reject disagreeing canonical and legacy Portal Proxy source tree labels'
grep -Fq 'Portal Proxy runtime application source differs from release source' "$BUILDER" ||
  fail 'offline builder must reject a stale Portal Proxy application runtime'
grep -Fq 'verify-portal-proxy-runtime-source.sh' "$BUILDER" ||
  fail 'offline builder must run the Portal Proxy runtime application source gate'
grep -Fq 'Portal Proxy runtime Prisma engines do not match the reviewed release lock' "$BUILDER" ||
  fail 'offline builder must verify Prisma engines inside the reused runtime'
grep -Fq -- '--label "io.jjdguard.source-tree=$SOURCE_TREE"' "$BUILDER" ||
  fail 'offline builder must overwrite the inherited legacy Portal Proxy source tree label'
grep -Fq 'build_portal_proxy()' "$BUILDER" ||
  fail 'offline builder must provide a dedicated Portal Proxy offline build path'
grep -Fq 'Dockerfile.offline' "$BUILDER" ||
  fail 'offline builder must select the Portal Proxy offline Dockerfile'
if grep -Fq -- '--build-context "release-portal-proxy-pnpm-store=$PORTAL_PROXY_PNPM_STORE_INPUT"' "$BUILDER"; then
  fail 'offline builder must not pass a Portal Proxy pnpm store build context'
fi
grep -Fq -- '--build-arg "LOCAL_RUNTIME_IMAGE=$PORTAL_PROXY_RUNTIME_ALIAS"' "$BUILDER" ||
  fail 'offline builder must bind Portal Proxy to the verified local runtime alias'
grep -Fq 'home_runtime' "$BUILDER" ||
  fail 'offline builder must record the local Portal Proxy runtime in provenance'

awk '$4 == "portal-proxy" {
       ok = ($1 == "chat-portal/portal-proxy:0.1.0" && $2 == "chat" &&
             $3 == "home-runtime" && $5 == "-" &&
             $6 == "portal-proxy/Dockerfile.offline" && $7 == "portal-proxy")
     }
     END { exit !ok }' "$CATALOG" ||
  fail 'Portal Proxy catalog entry must be a home-runtime offline build'

if grep -Eq 'release-portal-proxy-(pnpm-store|prisma-engines)|pnpm prisma generate' "$DOCKERFILE"; then
  fail 'Portal Proxy runtime reuse Dockerfile must not reconstruct runtime dependencies'
fi

for verifier in \
  "$ROOT/deploy/docker-compose/verify-image-provenance.py" \
  "$ROOT/deploy/acceptance/verify-acceptance-receipt.py"; do
  python3 - "$verifier" "$DOCKERFILE" "$ROOT" <<'PY'
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

verifier_path = pathlib.Path(sys.argv[1])
dockerfile = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
repository = pathlib.Path(sys.argv[3])
spec = importlib.util.spec_from_file_location("home_runtime_verifier", verifier_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
original_git_output = module.git_output
module.git_output = lambda *_args: dockerfile
runtime_bases = module.validate_home_runtime_dockerfile(
    pathlib.Path("/fixture"), "a" * 40, "portal-proxy/Dockerfile.offline", "portal-proxy"
)
expected_runtime_bases = [(0, None)]
if runtime_bases != expected_runtime_bases:
    raise SystemExit(f"home runtime base locations drifted: {runtime_bases!r}")
image_id = "sha256:" + "b" * 64
expected_base_images = [
    {
        "from_index": from_index,
        "stage": stage,
        "reference": f"home-runtime@{image_id}",
        "digest": image_id,
    }
    for from_index, stage in expected_runtime_bases
]
if module.home_runtime_base_images({"source_image_id": image_id}, runtime_bases) != expected_base_images:
    raise SystemExit("home runtime provenance did not retain every local base edge")
external_from = dockerfile.replace(
    "FROM ${LOCAL_RUNTIME_IMAGE}",
    "FROM --platform=linux/amd64 registry.example/evil:1@sha256:" + "e" * 64,
)
module.git_output = lambda *_args: external_from
try:
    module.validate_home_runtime_dockerfile(
        pathlib.Path("/fixture"), "a" * 40, "portal-proxy/Dockerfile.offline", "portal-proxy"
    )
except SystemExit:
    pass
else:
    raise SystemExit("home runtime verifier accepted an external FROM with a platform option")

module.git_output = original_git_output
revision = subprocess.check_output(
    ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
).strip()
tree = subprocess.check_output(
    ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"], text=True
).strip()
pnpm_lock_path = "portal-proxy/pnpm-lock.yaml"
pnpm_lock = subprocess.check_output(
    ["git", "-C", str(repository), "cat-file", "blob", f"{revision}:{pnpm_lock_path}"]
)
prisma_lock_path = "deploy/docker-compose/release-prisma-engines.lock.json"
prisma_lock = subprocess.check_output(
    ["git", "-C", str(repository), "cat-file", "blob", f"{revision}:{prisma_lock_path}"]
)
prisma = json.loads(prisma_lock)
image_id = "sha256:" + "b" * 64
manifest = prisma["manifest"]
runtime = {
    "source_image": "chat-portal/portal-proxy:0.1.0",
    "source_image_id": image_id,
    "source_revision": revision,
    "source_tree": tree,
    "pnpm_version": "10.10.0",
    "pnpm_lock": {
        "path": pnpm_lock_path,
        "sha256": hashlib.sha256(pnpm_lock).hexdigest(),
        "blob": subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", f"{revision}:{pnpm_lock_path}"], text=True
        ).strip(),
    },
    "prisma_engines": {
        "schema": "jjdguard-release-prisma-runtime/v1",
        "origin": prisma["origin"],
        "expected_source_image": prisma["source_image"],
        "expected_source_image_id": prisma["source_image_id"],
        "approved_lock_sha256": hashlib.sha256(prisma_lock).hexdigest(),
        "runtime_image": "chat-portal/portal-proxy:0.1.0",
        "runtime_image_id": image_id,
        "content_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "manifest": manifest,
    },
}
expected_alias = (
    f"jjdguard-release-input/portal-proxy:{revision[:12]}-"
    f"{image_id.removeprefix('sha256:')[:12]}"
)
expected_portal_bases = [{
    "from_index": 0,
    "stage": None,
    "reference": f"home-runtime@{image_id}",
    "digest": image_id,
}]
actual_portal_bases = module.validate_home_runtime(
    runtime,
    "portal-proxy",
    repository,
    revision,
    "portal-proxy/Dockerfile.offline",
    {"LOCAL_RUNTIME_IMAGE": expected_alias},
)
if actual_portal_bases != expected_portal_bases:
    raise SystemExit(f"Portal Proxy runtime base provenance drifted: {actual_portal_bases!r}")
try:
    module.validate_home_runtime(
        runtime,
        "portal-proxy",
        repository,
        revision,
        "portal-proxy/Dockerfile.offline",
        {"LOCAL_RUNTIME_IMAGE": "jjdguard-release-input/portal-proxy:tampered"},
    )
except SystemExit:
    pass
else:
    raise SystemExit("Portal Proxy provenance verifier accepted a tampered local runtime alias")
PY
done

[[ -x "$RUNTIME_SOURCE_GATE" ]] ||
  fail 'Portal Proxy runtime application source gate is missing'

runtime_gate_root="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-portal-runtime-gate.XXXXXX")"
cleanup_runtime_gate() {
  rm -rf "$runtime_gate_root"
}
trap cleanup_runtime_gate EXIT HUP INT TERM

make_runtime_fixture() {
  local repo=$1
  mkdir -p "$repo/portal-proxy/src" "$repo/portal-proxy/prisma/migrations/20260812_init"
  printf '%s\n' 'export const handler = () => "baseline"' >"$repo/portal-proxy/src/server.ts"
  printf '%s\n' 'lockfileVersion: 9.0' >"$repo/portal-proxy/pnpm-lock.yaml"
  printf '%s\n' '-- baseline migration' >"$repo/portal-proxy/prisma/migrations/20260812_init/migration.sql"
  git -C "$repo" init -q
  git -C "$repo" config user.email 'runtime-gate@example.invalid'
  git -C "$repo" config user.name 'runtime gate test'
  git -C "$repo" add portal-proxy
  git -C "$repo" commit -qm 'fixture baseline'
  git -C "$repo" rev-parse HEAD
}

expect_runtime_source_rejection() {
  local label=$1 repo=$2 runtime_revision=$3 release_revision=$4 output
  if output=$("$RUNTIME_SOURCE_GATE" \
    --repo "$repo" \
    --runtime-revision "$runtime_revision" \
    --release-revision "$release_revision" 2>&1); then
    fail "runtime source gate accepted a changed $label input"
  fi
  [[ "$output" == *'Portal Proxy runtime application source differs from release source'* ]] ||
    fail "unexpected $label rejection: $output"
}

exact_repo="$runtime_gate_root/exact"
mkdir -p "$exact_repo"
exact_revision="$(make_runtime_fixture "$exact_repo")"
"$RUNTIME_SOURCE_GATE" \
  --repo "$exact_repo" \
  --runtime-revision "$exact_revision" \
  --release-revision "$exact_revision"

src_repo="$runtime_gate_root/src"
mkdir -p "$src_repo"
src_runtime_revision="$(make_runtime_fixture "$src_repo")"
printf '%s\n' 'export const handler = () => "changed"' >"$src_repo/portal-proxy/src/server.ts"
git -C "$src_repo" add portal-proxy/src/server.ts
git -C "$src_repo" commit -qm 'change source'
expect_runtime_source_rejection src "$src_repo" "$src_runtime_revision" "$(git -C "$src_repo" rev-parse HEAD)"

lock_repo="$runtime_gate_root/lock"
mkdir -p "$lock_repo"
lock_runtime_revision="$(make_runtime_fixture "$lock_repo")"
printf '%s\n' 'lockfileVersion: 9.1' >"$lock_repo/portal-proxy/pnpm-lock.yaml"
git -C "$lock_repo" add portal-proxy/pnpm-lock.yaml
git -C "$lock_repo" commit -qm 'change lock'
expect_runtime_source_rejection lock "$lock_repo" "$lock_runtime_revision" "$(git -C "$lock_repo" rev-parse HEAD)"

migration_repo="$runtime_gate_root/migration"
mkdir -p "$migration_repo"
migration_runtime_revision="$(make_runtime_fixture "$migration_repo")"
printf '%s\n' '-- changed migration' >"$migration_repo/portal-proxy/prisma/migrations/20260812_init/migration.sql"
git -C "$migration_repo" add portal-proxy/prisma/migrations/20260812_init/migration.sql
git -C "$migration_repo" commit -qm 'change migration'
expect_runtime_source_rejection migration "$migration_repo" "$migration_runtime_revision" "$(git -C "$migration_repo" rev-parse HEAD)"

printf 'PASS test_portal_proxy_offline_runtime_contract\n'
