#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"
DOCKERFILE="$ROOT/deploy/docker-compose/llm-judge/Dockerfile.offline"
COMPOSE_FILE="$ROOT/deploy/docker-compose/docker-compose.offline.yml"
BENCHMARK="$ROOT/deploy/docker-compose/judge-benchmark.sh"

fail() {
  printf 'FAIL test_llm_judge_local_runtime_contract: %s\n' "$*" >&2
  exit 1
}

[[ -f "$DOCKERFILE" ]] || fail 'missing local Judge runtime Dockerfile'
if grep -Eq '^#[[:space:]]*syntax=' "$DOCKERFILE"; then
  fail 'Judge offline Dockerfile must not resolve an external Dockerfile frontend'
fi
grep -Fq 'ARG LOCAL_RUNTIME_IMAGE' "$DOCKERFILE" ||
  fail 'Judge offline Dockerfile must receive an explicit local runtime image'
grep -Fq 'FROM ${LOCAL_RUNTIME_IMAGE}' "$DOCKERFILE" ||
  fail 'Judge offline Dockerfile must use the local runtime image as its base'
grep -Fq 'COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh' "$DOCKERFILE" ||
  fail 'Judge offline Dockerfile must bind the release source entrypoint'
grep -Fq 'ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]' "$DOCKERFILE" ||
  fail 'Judge offline Dockerfile must execute the release source entrypoint'
grep -Fq 'test: ["CMD", "/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080"]' "$COMPOSE_FILE" ||
  fail 'Judge healthcheck must use the bundled Bash TCP probe instead of an unavailable network client'
grep -Fq 'mem_limit: ${JUDGE_MEMORY_LIMIT:-6g}' "$COMPOSE_FILE" ||
  fail 'Judge must have a configurable 6GiB default memory limit'
grep -Fq 'memswap_limit: ${JUDGE_MEMORY_SWAP_LIMIT:-7g}' "$COMPOSE_FILE" ||
  fail 'Judge must have a bounded memory plus swap limit'
grep -Fq 'JUDGE_CACHE_RAM_MB=${JUDGE_CACHE_RAM_MB:-1024}' "$COMPOSE_FILE" ||
  fail 'Judge reusable prompt cache must default to 1024MiB'
grep -Fq -- '--cache-ram "${JUDGE_CACHE_RAM_MB:-1024}"' "$ROOT/deploy/docker-compose/llm-judge/entrypoint.sh" ||
  fail 'Judge entrypoint must enforce the configured reusable prompt cache limit'
grep -Fq -- '--batch-size "${JUDGE_BATCH_SIZE:-512}"' "$ROOT/deploy/docker-compose/llm-judge/entrypoint.sh" ||
  fail 'Judge entrypoint must bound the logical batch size'
grep -Fq -- '--ubatch-size "${JUDGE_UBATCH_SIZE:-128}"' "$ROOT/deploy/docker-compose/llm-judge/entrypoint.sh" ||
  fail 'Judge entrypoint must bound the physical batch size'
grep -Fq "exec -T llm-judge /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080'" "$BENCHMARK" ||
  fail 'Judge benchmark readiness probe must use the bundled Bash TCP probe'
if grep -Fq 'exec -T llm-judge wget' "$BENCHMARK"; then
  fail 'Judge benchmark must not depend on unavailable wget in the offline runtime'
fi
if grep -Eq 'apt-get|apt[[:space:]]+install' "$DOCKERFILE"; then
  fail 'Judge offline Dockerfile must not install packages from Ubuntu repositories'
fi

grep -Fq 'LLM_JUDGE_RUNTIME_INPUT=' "$BUILDER" ||
  fail 'offline builder must require an explicit local Judge runtime input'
grep -Fq 'LLM_JUDGE_RUNTIME_ALIAS=' "$BUILDER" ||
  fail 'offline builder must bind the Judge runtime to a private local alias'
grep -Fq 'Dockerfile.offline' "$BUILDER" ||
  fail 'offline builder must select the local Judge runtime Dockerfile'
grep -Fq -- '--build-arg "LOCAL_RUNTIME_IMAGE=$LLM_JUDGE_RUNTIME_ALIAS"' "$BUILDER" ||
  fail 'offline builder must build Judge from the verified local runtime alias'
grep -Fq 'entrypoint_sha256' "$BUILDER" ||
  fail 'offline builder must record the verified Judge entrypoint hash'

for verifier in \
  "$ROOT/deploy/docker-compose/verify-image-provenance.py" \
  "$ROOT/deploy/acceptance/verify-acceptance-receipt.py"; do
  grep -Fq '"build_mode"' "$verifier" ||
    fail 'Judge provenance verifier must require an explicit local runtime build mode'
  grep -Fq '"home-runtime-reuse"' "$verifier" ||
    fail 'Judge provenance verifier must reject an unexpected local runtime build mode'
  python3 - "$verifier" "$DOCKERFILE" <<'PY'
import importlib.util
import pathlib
import sys

verifier_path = pathlib.Path(sys.argv[1])
dockerfile = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
spec = importlib.util.spec_from_file_location("judge_runtime_verifier", verifier_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
module.git_output = lambda *_args: dockerfile
revision = "a" * 40
image_id = "sha256:" + "b" * 64
runtime = {
    "source_image": "docker-compose-llm-judge:latest",
    "source_image_id": image_id,
    "entrypoint_sha256": "c" * 64,
}
expected_alias = f"jjdguard-release-input/llm-judge:{revision[:12]}-{image_id.removeprefix('sha256:')[:12]}"
expected = [{
    "from_index": 0,
    "stage": None,
    "reference": f"home-runtime@{image_id}",
    "digest": image_id,
}]
actual = module.validate_home_runtime(
    runtime,
    "llm-judge",
    pathlib.Path("/fixture"),
    revision,
    "deploy/docker-compose/llm-judge/Dockerfile.offline",
    {"LOCAL_RUNTIME_IMAGE": expected_alias},
)
if actual != expected:
    raise SystemExit(f"Judge runtime base provenance drifted: {actual!r}")
try:
    module.validate_home_runtime(
        runtime,
        "llm-judge",
        pathlib.Path("/fixture"),
        revision,
        "deploy/docker-compose/llm-judge/Dockerfile.offline",
        {"LOCAL_RUNTIME_IMAGE": "jjdguard-release-input/llm-judge:wrong"},
    )
except SystemExit:
    pass
else:
    raise SystemExit("Judge provenance verifier accepted an unbound local runtime alias")
PY
done

printf 'PASS test_llm_judge_local_runtime_contract\n'
