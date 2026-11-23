#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_IMAGE_PARSER="$ROOT_DIR/deploy/docker-compose/dockerfile-base-images.py"
readonly OWNED_TIER1_MODEL_LOCK_PATH='deploy/docker-compose/owned-tier1-model.lock.json'
readonly PRISMA_ENGINE_LOCK_PATH='deploy/docker-compose/release-prisma-engines.lock.json'
readonly PRISMA_ENGINE_ARM64_LOCK_PATH='deploy/docker-compose/release-prisma-engines.arm64.lock.json'
readonly PRISMA_ENGINE_VERIFIER_PATH='deploy/docker-compose/verify-release-prisma-engines.py'
readonly TIER1_PYTHON_DEPS_VERIFIER_PATH='deploy/docker-compose/verify-tier1-python-deps.py'
# shellcheck disable=SC1091
source "$ROOT_DIR/deploy/docker-compose/lib-build-identity.sh"

die() {
  printf '[task4-build] %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

canonical_receipt_sha() {
  jq -cS 'del(.revision)' "$1" | sha256sum | awk '{print $1}'
}

write_json() {
  local target=$1
  shift
  local tmp="${target}.tmp.$$"
  "$@" | jq -cS . >"$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$target"
}

candidate_tree=
candidate_revision=
receipt_dir=
portal_image=
tier1_image=
tier1_model_input=
tier1_python_deps_input=
npm_cache_context=
npm_cache_sha256=
npm_cache_archive=
prisma_engine_input=
build_network_mode=default
target_arch=amd64
source_root=
source_archive_sha256=
repo=
docker_cmd=docker
if [[ ${JJD_TASK4_DOCKER+x} ]]; then
  [[ "${JJD_TASK4_TESTING:-0}" == 1 ]] ||
    die 'JJD_TASK4_DOCKER requires JJD_TASK4_TESTING=1'
  docker_cmd=$JJD_TASK4_DOCKER
fi
while (($#)); do
  case "$1" in
    --candidate-revision) candidate_revision=$2; shift 2 ;;
    --candidate-tree) candidate_tree=$2; shift 2 ;;
    --receipt-dir) receipt_dir=$2; shift 2 ;;
    --portal-image) portal_image=$2; shift 2 ;;
    --tier1-image) tier1_image=$2; shift 2 ;;
    --tier1-model-input) tier1_model_input=$2; shift 2 ;;
    --tier1-python-deps-input) tier1_python_deps_input=$2; shift 2 ;;
    --npm-cache-context) npm_cache_context=$2; shift 2 ;;
    --npm-cache-sha256) npm_cache_sha256=$2; shift 2 ;;
    --prisma-engine-input) prisma_engine_input=$2; shift 2 ;;
    --network-mode) build_network_mode=$2; shift 2 ;;
    --target-arch) target_arch=$2; shift 2 ;;
    --source-root) source_root=$2; shift 2 ;;
    --source-archive-sha256) source_archive_sha256=$2; shift 2 ;;
    --repo) repo=$2; shift 2 ;;
    --docker-command)
      [[ "${JJD_TASK4_TESTING:-0}" == 1 ]] ||
        die '--docker-command requires JJD_TASK4_TESTING=1'
      docker_cmd=$2
      shift 2
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

repo=${repo:-$(git -C "$ROOT_DIR" rev-parse --show-toplevel)}

case "$build_network_mode" in
  default|none) ;;
  *) die '--network-mode must be default or none' ;;
esac
case "$target_arch" in
  amd64|arm64) ;;
  *) die '--target-arch must be amd64 or arm64' ;;
esac

billing_enabled=${BILLING_ENABLED:-false}
case "$billing_enabled" in
  true|false) ;;
  *) die 'BILLING_ENABLED must be true or false' ;;
esac
[[ "$candidate_revision" =~ ^[0-9a-f]{40}$ ]] || die 'invalid --candidate-revision'
[[ "$candidate_tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid --candidate-tree'
[[ -n "$receipt_dir" &&
   ( -n "$portal_image" || -n "$tier1_image" ) ]] ||
  die '--receipt-dir and at least one Task4 image are required'
[[ "$source_root" == /* && -d "$source_root" && ! -L "$source_root" ]] ||
  die '--source-root must be an absolute real directory'
[[ "$(realpath -e "$source_root")" == "$source_root" ]] ||
  die '--source-root must be canonical'
[[ "$(stat -c %a "$source_root")" == 700 ]] ||
  die '--source-root must be mode 0700'
[[ -z "$(find -P "$source_root" -mindepth 1 ! -type d ! -type f -print -quit)" ]] ||
  die '--source-root contains a link or special file'
[[ "$source_archive_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die 'invalid --source-archive-sha256'
[[ "$portal_image" != chat-portal/portal-proxy:* &&
   "$tier1_image" != chat-portal/portal-proxy:* ]] ||
  die 'opaque chat-portal/portal-proxy image is forbidden'
[[ -z "$tier1_image" || -n "$tier1_model_input" ]] ||
  die '--tier1-model-input is required when --tier1-image is set'
[[ -z "$tier1_model_input" || -n "$tier1_image" ]] ||
  die '--tier1-model-input is only valid with --tier1-image'
[[ -z "$tier1_image" || -n "$tier1_python_deps_input" ]] ||
  die '--tier1-python-deps-input is required when --tier1-image is set'
[[ -z "$tier1_python_deps_input" || -n "$tier1_image" ]] ||
  die '--tier1-python-deps-input is only valid with --tier1-image'
[[ -z "$npm_cache_context" || -n "$portal_image" ]] ||
  die '--npm-cache-context is only valid with --portal-image'
[[ -z "$npm_cache_sha256" || -n "$portal_image" ]] ||
  die '--npm-cache-sha256 is only valid with --portal-image'
[[ -z "$prisma_engine_input" || -n "$portal_image" ]] ||
  die '--prisma-engine-input is only valid with --portal-image'
if [[ -n "$portal_image" ]]; then
  [[ "$npm_cache_context" == /* && -d "$npm_cache_context" && ! -L "$npm_cache_context" ]] ||
    die '--npm-cache-context must be an absolute real directory when --portal-image is set'
  [[ "$(realpath -e "$npm_cache_context")" == "$npm_cache_context" ]] ||
    die '--npm-cache-context must be canonical'
  [[ "$(stat -c %a "$npm_cache_context")" == 700 ]] ||
    die '--npm-cache-context must be mode 0700'
  npm_cache_archive="$npm_cache_context/npm-cache.tar"
  [[ -f "$npm_cache_archive" && ! -L "$npm_cache_archive" && \
     "$(realpath -e "$npm_cache_archive")" == "$npm_cache_archive" && \
     "$(stat -c %a "$npm_cache_archive")" == 400 ]] ||
    die '--npm-cache-context must contain a real mode 0400 npm-cache.tar'
  [[ "$(find -P "$npm_cache_context" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" == npm-cache.tar ]] ||
    die '--npm-cache-context must contain only npm-cache.tar'
  [[ "$npm_cache_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    die 'invalid --npm-cache-sha256'
  [[ "$(sha256_file "$npm_cache_archive")" == "$npm_cache_sha256" ]] ||
    die 'local NPM cache archive hash mismatch'
  [[ "$prisma_engine_input" == /* && -d "$prisma_engine_input" && ! -L "$prisma_engine_input" ]] ||
    die '--prisma-engine-input must be an absolute real directory when --portal-image is set'
  [[ "$(realpath -e "$prisma_engine_input")" == "$prisma_engine_input" ]] ||
    die '--prisma-engine-input must be canonical'
fi
if [[ -n "$tier1_model_input" ]]; then
  [[ "$tier1_model_input" == /* && -d "$tier1_model_input" && ! -L "$tier1_model_input" ]] ||
    die '--tier1-model-input must be an absolute real directory'
  [[ "$(realpath -e "$tier1_model_input")" == "$tier1_model_input" ]] ||
    die '--tier1-model-input must be canonical'
  [[ "$(stat -c %a "$tier1_model_input")" == 700 ]] ||
    die '--tier1-model-input must be mode 0700'
  [[ -z "$(find -P "$tier1_model_input" -mindepth 1 ! -type d ! -type f -print -quit)" ]] ||
    die '--tier1-model-input contains a link or special file'
  for path in model.onnx config.json tokenizer.json tokenizer_config.json special_tokens_map.json; do
    [[ -f "$tier1_model_input/$path" && ! -L "$tier1_model_input/$path" ]] ||
      die "owned Tier-1 model input missing: $path"
  done
fi
if [[ -n "$tier1_python_deps_input" ]]; then
  [[ "$tier1_python_deps_input" == /* && -d "$tier1_python_deps_input" && ! -L "$tier1_python_deps_input" ]] ||
    die '--tier1-python-deps-input must be an absolute real directory'
  [[ "$(realpath -e "$tier1_python_deps_input")" == "$tier1_python_deps_input" ]] ||
    die '--tier1-python-deps-input must be canonical'
  [[ "$(stat -c %a "$tier1_python_deps_input")" == 700 ]] ||
    die '--tier1-python-deps-input must be mode 0700'
  [[ -z "$(find -P "$tier1_python_deps_input" -mindepth 1 ! -type d ! -type f -print -quit)" ]] ||
    die '--tier1-python-deps-input contains a link or special file'
  [[ -f "$tier1_python_deps_input/source.json" && ! -L "$tier1_python_deps_input/source.json" ]] ||
    die '--tier1-python-deps-input is missing source metadata'
  [[ -d "$tier1_python_deps_input/site-packages" && ! -L "$tier1_python_deps_input/site-packages" ]] ||
    die '--tier1-python-deps-input is missing site-packages'
fi
git -C "$repo" cat-file -e "$candidate_tree^{tree}"
[[ "$(git -C "$repo" rev-parse "$candidate_revision^{commit}")" == "$candidate_revision" ]] ||
  die 'candidate revision is unavailable'
[[ "$(git -C "$repo" rev-parse "$candidate_revision^{tree}")" == "$candidate_tree" ]] ||
  die 'candidate revision/tree mismatch'
install -d -m 0700 "$receipt_dir"
[[ "$(stat -c %a "$receipt_dir")" == 700 ]] || die 'receipt directory must be mode 0700'

assert_npm_cache_context_unchanged() {
  [[ -n "$npm_cache_archive" && -n "$npm_cache_sha256" && \
     -d "$npm_cache_context" && ! -L "$npm_cache_context" && \
     "$(realpath -e "$npm_cache_context")" == "$npm_cache_context" && \
     "$(stat -c %a "$npm_cache_context")" == 700 ]] ||
    die 'local NPM cache context changed during Portal construction'
  [[ -f "$npm_cache_archive" && ! -L "$npm_cache_archive" && \
     "$(realpath -e "$npm_cache_archive")" == "$npm_cache_archive" && \
     "$(stat -c %a "$npm_cache_archive")" == 400 ]] ||
    die 'local NPM cache archive changed during Portal construction'
  [[ "$(find -P "$npm_cache_context" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" == npm-cache.tar ]] ||
    die 'local NPM cache context changed during Portal construction'
  [[ "$(sha256_file "$npm_cache_archive")" == "$npm_cache_sha256" ]] ||
    die 'local NPM cache archive changed during Portal construction'
}

assert_candidate_unchanged() {
  [[ "$(git -C "$repo" write-tree)" == "$candidate_tree" ]] ||
    die 'candidate index tree changed after review'
  git -C "$repo" diff --quiet ||
    die 'tracked worktree differs from candidate index'
  [[ -z "$(git -C "$repo" ls-files --others --exclude-standard --     enterprise-ai-portal apps/tier1-classifier apps/security-engine/bench)" ]] ||
    die 'included untracked source is forbidden'
}
assert_candidate_unchanged

source_remote="$(git -C "$repo" remote get-url origin)"
source_labels=(
  --label "org.opencontainers.image.revision=$candidate_revision"
  --label "org.opencontainers.image.source=$source_remote"
  --label "com.jjdguard.source.tree=$candidate_tree"
)
TASK4_BUILD_ENGINE="$(docker_daemon_engine_json "$docker_cmd")" ||
  die 'unable to capture Docker daemon identity before Task4 construction'

tmp=$(mktemp -d)
chmod 0700 "$tmp"
trap "rm -rf -- '$tmp'" EXIT
archive_sha256=$source_archive_sha256

blob_oid() {
  git -C "$repo" rev-parse "$candidate_tree:$1"
}

assert_source_file() {
  local path=$1 file oid
  file="$source_root/$path"
  [[ -f "$file" && ! -L "$file" ]] || die "candidate input missing: $path"
  oid=$(git -C "$repo" hash-object --no-filters "$file")
  [[ "$oid" == "$(blob_oid "$path")" ]] ||
    die "unified source root differs from candidate blob: $path"
}

model_manifest_json() {
  local root=$1 tsv=$2 path mode size
  : >"$tsv"
  find -P "$root" -type f -printf '%P\t%m\t%s\n' | LC_ALL=C sort |
  while IFS=$'\t' read -r path mode size; do
    printf '%s\t%s\t%s\t%s\n' "$path" "$mode" "$size" \
      "$(sha256_file "$root/$path")"
  done >"$tsv"
  [[ -s "$tsv" ]] || die 'owned Tier-1 model manifest is empty'
  jq -cS -Rn '[inputs | split("\t") |
    {path:.[0],mode:.[1],size:(.[2]|tonumber),sha256:.[3]}]' <"$tsv"
}

approved_model_manifest_json() {
  local lock=$1
  [[ -f "$lock" && ! -L "$lock" ]] ||
    die 'approved owned Tier-1 model lock is missing or unsafe'
  jq -e '
    (keys | sort) == ["license","manifest","model_id","origin","schema","upstream"] and
    .schema == "jjdguard-owned-tier1-model-lock/v1" and
    .model_id == "jjdguard-tier1-e5small-lr" and
    .license == "MIT" and
    .upstream == {"repo":"intfloat/multilingual-e5-small","revision":"614241f622f53c4eeff9890bdc4f31cfecc418b3"} and
    .origin == "user-trained" and
    (.manifest | type == "array" and length == 5) and
    ([.manifest[].path] | sort) == [
      "config.json",
      "model.onnx",
      "special_tokens_map.json",
      "tokenizer.json",
      "tokenizer_config.json"
    ] and
    all(.manifest[];
      (keys | sort) == ["path","sha256","size"] and
      (.path | type == "string" and test("^[A-Za-z0-9._-]+$")) and
      (.size | type == "number" and . > 0 and . == floor) and
      (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))
  ' "$lock" >/dev/null ||
    die 'approved owned Tier-1 model lock is invalid'
  jq -cS '.manifest | sort_by(.path)' "$lock"
}

model_content_manifest_json() {
  jq -cS '[.[] | {path,size,sha256}] | sort_by(.path)' <<<"$1"
}

base_images() {
  local dockerfile=$1
  python3 "$BASE_IMAGE_PARSER" --dockerfile "$dockerfile" ||
    die "unable to parse pinned base images: $dockerfile"
}

single_base_ref() {
  local encoded=$1
  jq -er 'if length == 1 then .[0].reference else error("expected one external base image") end' \
    <<<"$encoded" || die 'Task4 Dockerfile must have exactly one external base image'
}

if [[ -n "$portal_image" ]]; then
portal_dockerfile=enterprise-ai-portal/Dockerfile
portal_lock=enterprise-ai-portal/package-lock.json
if [[ "$target_arch" == arm64 ]]; then
  portal_prisma_lock=$PRISMA_ENGINE_ARM64_LOCK_PATH
else
  portal_prisma_lock=$PRISMA_ENGINE_LOCK_PATH
fi
portal_prisma_verifier=$PRISMA_ENGINE_VERIFIER_PATH
for path in "$portal_dockerfile" "$portal_lock" "$portal_prisma_lock" "$portal_prisma_verifier"; do
  assert_source_file "$path"
done
prisma_engine_receipt=$(python3 "$source_root/$portal_prisma_verifier" \
  --lock "$source_root/$portal_prisma_lock" \
  --target-arch "$target_arch" \
  --input "$prisma_engine_input") ||
  die 'local Prisma engine input does not match the reviewed release lock'
prisma_engine_context="$tmp/prisma-engines"
install -d -m 0700 "$prisma_engine_context"
while IFS= read -r path; do
  cp --preserve=mode "$prisma_engine_input/$path" "$prisma_engine_context/$path"
done < <(jq -r '.manifest[].path' <<<"$prisma_engine_receipt")
chmod 0500 "$prisma_engine_context"/*
prisma_engine_receipt=$(python3 "$source_root/$portal_prisma_verifier" \
  --lock "$source_root/$portal_prisma_lock" \
  --target-arch "$target_arch" \
  --input "$prisma_engine_context") ||
  die 'local Prisma engine snapshot does not match the reviewed release lock'
portal_base_images=$(base_images "$source_root/$portal_dockerfile")
opaque_before=$("$docker_cmd" image inspect chat-portal/portal-proxy:0.1.0   --format '{{.Id}}' 2>/dev/null || true)

  assert_npm_cache_context_unchanged
  "$docker_cmd" buildx build --load --platform "linux/$target_arch" --no-cache --pull=false --network "$build_network_mode" \
  --build-context "release-npm-cache=$npm_cache_context" \
  --build-context "release-prisma-engine=$prisma_engine_context" "${source_labels[@]}" \
  --build-arg "NEXT_PUBLIC_BILLING_ENABLED=$billing_enabled" --tag "$portal_image" \
  "$source_root/enterprise-ai-portal"
assert_docker_daemon_identity_unchanged "$TASK4_BUILD_ENGINE" "$docker_cmd" ||
  die 'Docker daemon identity drifted during Portal construction'
assert_npm_cache_context_unchanged
assert_candidate_unchanged
portal_id=$("$docker_cmd" image inspect "$portal_image" --format '{{.Id}}')
[[ "$portal_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'invalid Portal image ID'
portal_config=$portal_id

portal_blobs=$(jq -n   --arg prisma_lock_path "$portal_prisma_lock"   --arg dockerfile "$(blob_oid "$portal_dockerfile")"   --arg lock "$(blob_oid "$portal_lock")"   --arg prisma_lock "$(blob_oid "$portal_prisma_lock")"   --arg prisma_verifier "$(blob_oid "$portal_prisma_verifier")"   '{("enterprise-ai-portal/Dockerfile"):$dockerfile,
    ("enterprise-ai-portal/package-lock.json"):$lock,
    ($prisma_lock_path):$prisma_lock,
    ("deploy/docker-compose/verify-release-prisma-engines.py"):$prisma_verifier}')
write_json "$receipt_dir/portal-image-receipt.json" jq -n   --arg schema jjdguard-task4-image-receipt/v1   --arg component portal   --arg revision "$candidate_revision"   --arg tree "$candidate_tree"   --arg archive "$archive_sha256"   --arg image "$portal_image"   --arg image_id "$portal_id"   --arg config "$portal_config"   --argjson base_images "$portal_base_images"   --argjson blobs "$portal_blobs"   --argjson engine "$TASK4_BUILD_ENGINE"   --argjson prisma_engines "$prisma_engine_receipt"   --arg billing "$billing_enabled"   '{schema:$schema,component:$component,revision:$revision,candidate_tree:$tree,
    archive_sha256:$archive,image:$image,image_id:$image_id,
    oci_config_digest:$config,
    base_images:$base_images,source_blobs:$blobs,build_engine:$engine,
    prisma_engines:$prisma_engines,build_args:{NEXT_PUBLIC_BILLING_ENABLED:$billing}}'
fi

if [[ -n "$tier1_image" ]]; then
tier1_paths=(
  apps/tier1-classifier/Dockerfile
  apps/tier1-classifier/requirements.lock
  apps/tier1-classifier/entrypoint.sh
  apps/tier1-classifier/app/__init__.py
  apps/tier1-classifier/app/classifier.py
  apps/tier1-classifier/app/header_compat.py
  apps/tier1-classifier/app/latency_stats.py
  apps/tier1-classifier/app/main.py
  apps/tier1-classifier/app/model.py
  apps/security-engine/bench/__init__.py
  apps/security-engine/bench/run_bench.py
  apps/security-engine/bench/scorers.py
  apps/security-engine/bench/metrics.py
  apps/security-engine/bench/gate_artifact.py
  apps/security-engine/bench/data/zh_jailbreak.jsonl
  apps/security-engine/bench/data/zh_benign.jsonl
  "$OWNED_TIER1_MODEL_LOCK_PATH"
  "$TIER1_PYTHON_DEPS_VERIFIER_PATH"
)
source_tsv="$tmp/tier1-source.tsv"
: >"$source_tsv"
for path in "${tier1_paths[@]}"; do
  assert_source_file "$path"
  printf '%s\t%s\n' "$path" "$(blob_oid "$path")" >>"$source_tsv"
done
tier1_blobs=$(jq -Rn '[inputs | split("\t") | {(.[0]):.[1]}] | add' <"$source_tsv")
tier1_base_images=$(base_images "$source_root/apps/tier1-classifier/Dockerfile")
tier1_model_lock="$source_root/$OWNED_TIER1_MODEL_LOCK_PATH"
tier1_deps_verifier="$source_root/$TIER1_PYTHON_DEPS_VERIFIER_PATH"
approved_model_manifest=$(approved_model_manifest_json "$tier1_model_lock")
approved_model_lock_sha256=$(sha256_file "$tier1_model_lock")
tier_tmp="$tmp/tier1"
install -d -m 0700 "$tier_tmp"
input_model_tsv="$tmp/tier1-owned-model.tsv"
model_manifest=$(model_manifest_json "$tier1_model_input" "$input_model_tsv")
model_content_manifest=$(model_content_manifest_json "$model_manifest")
[[ "$model_content_manifest" == "$approved_model_manifest" ]] ||
  die 'owned Tier-1 model input does not match approved user-trained model lock'
model_manifest_sha256=$(jq -cS . <<<"$model_manifest" | sha256sum | awk '{print $1}')
owned_model=$(jq -cn \
  --arg schema jjdguard-owned-tier1-model/v1 \
  --arg origin user-trained-locked-input \
  --arg lock_sha "$approved_model_lock_sha256" \
  --arg digest "$model_manifest_sha256" \
  --argjson manifest "$model_manifest" \
  '{schema:$schema,origin:$origin,approved_lock_sha256:$lock_sha,
    content_sha256:$digest,manifest:$manifest}')
tier1_deps_receipt=$(python3 "$tier1_deps_verifier" \
  --requirements-lock "$source_root/apps/tier1-classifier/requirements.lock" \
  --target-arch "$target_arch" \
  --input "$tier1_python_deps_input") ||
  die 'local Tier1 Python dependency input does not match requirements.lock'
tier1_context="$tmp/tier1_context"
install -d -m 0700 "$tier1_context"
cp -a "$source_root/apps/tier1-classifier/." "$tier1_context/"
model_root="$tier1_context/models/prompt-guard-2"
install -d -m 0700 "$model_root"
cp -a "$tier1_model_input/." "$model_root/"
context_model_tsv="$tmp/tier1-context-model.tsv"
context_model_manifest=$(model_manifest_json "$model_root" "$context_model_tsv")
[[ "$context_model_manifest" == "$model_manifest" ]] ||
  die 'Tier-1 build context model differs from the owned local input'
tier1_deps_context="$tier1_context/python-deps"
install -d -m 0700 "$tier1_deps_context"
cp -a "$tier1_python_deps_input/." "$tier1_deps_context/"
tier1_deps_context_receipt=$(python3 "$tier1_deps_verifier" \
  --requirements-lock "$tier1_context/requirements.lock" \
  --target-arch "$target_arch" \
  --input "$tier1_deps_context") ||
  die 'Tier1 Python dependency snapshot does not match requirements.lock'
[[ "$(jq -cS . <<<"$tier1_deps_context_receipt")" == "$(jq -cS . <<<"$tier1_deps_receipt")" ]] ||
  die 'Tier1 Python dependency build context differs from the local input'
"$docker_cmd" buildx build --load --platform "linux/$target_arch" --no-cache --pull=false --network "$build_network_mode" "${source_labels[@]}" --tag "$tier1_image" \
  "$tier1_context"
assert_docker_daemon_identity_unchanged "$TASK4_BUILD_ENGINE" "$docker_cmd" ||
  die 'Docker daemon identity drifted during Tier-1 construction'
assert_candidate_unchanged
tier1_id=$("$docker_cmd" image inspect "$tier1_image" --format '{{.Id}}')
[[ "$tier1_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'invalid Tier-1 image ID'
tier1_config=$tier1_id
bench_report="$tier_tmp/tier1_bench_gate_report.json"
# 构建期 benchmark 同时读取 0600 的受控模型输入和 0700 的源码快照；
# 仅该一次性验收容器使用 root，生成的运行镜像仍固定为非 root appuser。
"$docker_cmd" run --platform "linux/$target_arch" --pull=never --network=none --rm --user 0:0 \
  --mount "type=bind,src=$source_root/apps/security-engine,dst=/candidate/security-engine,readonly" \
  --mount "type=bind,src=$tier_tmp,dst=/work" \
  --entrypoint sh "$tier1_image" -ec '
    export PYTHONPATH=/candidate/security-engine
    python -m bench.run_bench --mode fused \
      --model /models/prompt-guard-2/model.onnx \
      --tokenizer /models/prompt-guard-2 \
      --json-out /work/tier1_bench_gate_report.json
  '
[[ -s "$bench_report" ]] || die 'Tier-1 benchmark report is missing'
install -m 0600 "$bench_report" "$receipt_dir/tier1-bench-gate-report.json"
bench_sha=$(sha256_file "$receipt_dir/tier1-bench-gate-report.json")

write_json "$receipt_dir/tier1-image-receipt.json" jq -n   --arg schema jjdguard-task4-image-receipt/v1   --arg component tier1   --arg revision "$candidate_revision"   --arg tree "$candidate_tree"   --arg archive "$archive_sha256"   --arg image "$tier1_image"   --arg image_id "$tier1_id"   --arg config "$tier1_config"   --argjson base_images "$tier1_base_images"   --argjson blobs "$tier1_blobs"   --argjson engine "$TASK4_BUILD_ENGINE"   --argjson owned_model "$owned_model"   --argjson models "$model_manifest"   --argjson python_deps "$tier1_deps_receipt"   --arg bench_path tier1-bench-gate-report.json   --arg bench_sha "$bench_sha"   '{schema:$schema,component:$component,revision:$revision,candidate_tree:$tree,
    archive_sha256:$archive,image:$image,image_id:$image_id,
    oci_config_digest:$config,
    base_images:$base_images,source_blobs:$blobs,build_engine:$engine,
    owned_model:$owned_model,
    model_manifest:$models,
    python_dependencies:$python_deps,
    bench:{path:$bench_path,sha256:$bench_sha,passed:true}}'
fi

components_json='[]'
receipts_json='{}'
if [[ -n "$portal_image" ]]; then
  portal_receipt_sha=$(canonical_receipt_sha "$receipt_dir/portal-image-receipt.json")
  components_json=$(jq -cn --argjson current "$components_json" '$current+["portal"]')
  receipts_json=$(jq -cn --argjson current "$receipts_json" \
    --arg sha "$portal_receipt_sha" '$current+{portal:$sha}')
fi
if [[ -n "$tier1_image" ]]; then
  tier1_receipt_sha=$(canonical_receipt_sha "$receipt_dir/tier1-image-receipt.json")
  components_json=$(jq -cn --argjson current "$components_json" '$current+["tier1"]')
  receipts_json=$(jq -cn --argjson current "$receipts_json" \
    --arg sha "$tier1_receipt_sha" '$current+{tier1:$sha}')
fi
write_json "$receipt_dir/build-set-receipt.json" jq -n \
  --arg schema jjdguard-task4-build-set-receipt/v2 \
  --arg revision "$candidate_revision" --arg tree "$candidate_tree" \
  --arg archive "$archive_sha256" --argjson components "$components_json" \
  --argjson receipts "$receipts_json" \
  '{schema:$schema,revision:$revision,candidate_tree:$tree,
    archive_sha256:$archive,components:$components,receipts:$receipts}'

assert_candidate_unchanged
assert_docker_daemon_identity_unchanged "$TASK4_BUILD_ENGINE" "$docker_cmd" ||
  die 'Docker daemon identity drifted after Task4 construction'
if [[ -n "$portal_image" ]]; then
  [[ "$("$docker_cmd" image inspect "$portal_image" --format '{{.Id}}')" == "$portal_id" ]] ||
    die 'Portal tag was retagged during build'
  opaque_after=$("$docker_cmd" image inspect chat-portal/portal-proxy:0.1.0 \
    --format '{{.Id}}' 2>/dev/null || true)
  [[ "$opaque_after" == "$opaque_before" ]] ||
    die 'opaque chat-portal/portal-proxy:0.1.0 changed'
fi
if [[ -n "$tier1_image" ]]; then
  [[ "$("$docker_cmd" image inspect "$tier1_image" --format '{{.Id}}')" == "$tier1_id" ]] ||
    die 'Tier-1 tag was retagged during build'
fi
printf '[task4-build] receipts written for %s\n' "$candidate_tree"
