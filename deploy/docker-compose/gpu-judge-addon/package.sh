#!/bin/bash
set -Eeuo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT_INPUT="${1:-$ROOT/deploy/docker-compose/offline-release}"
MODEL_INPUT="${JUDGE_OWNED_MODEL_INPUT:-}"
IMAGE="jjdguard/llm-judge-gpu:2.1.0"
LB_IMAGE="jjdguard/judge-lb-nginx:2.1.0"
# nginx 前端基础镜像按 digest 锁定；本地缓存缺失即失败（不在打包时联网拉取）。
NGINX_BASE_IMAGE="nginx@sha256:abe47724e466aeab9a345d8e46a221c2fa8953c7848bb4a3bd9976a7199f8cf2"
MODEL_FILE="jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf"
SOURCE_GATE="$ROOT/deploy/docker-compose/release-source-gate.sh"
LOCK="$ROOT/deploy/docker-compose/release-toolchain.lock"
MODEL_LOCK="$ROOT/deploy/docker-compose/owned-judge-model.lock.json"
MODEL_VERIFY="$ROOT/deploy/docker-compose/verify-owned-judge-model.py"
TEST="$ROOT/deploy/tests/test_gpu_judge_addon.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-gpu-judge.XXXXXX")"
CID=''
cleanup() {
  if [[ -n "$CID" ]]; then
    docker rm -f "$CID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

fail() { echo "[error] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }
for cmd in docker git python3 sha256sum tar gzip ldconfig readlink openssl cuobjdump; do need "$cmd"; done
[[ "$(uname -m)" =~ ^(x86_64|amd64)$ ]] || fail 'GPU Judge package supports amd64 only'
[[ -n "$MODEL_INPUT" ]] || fail 'JUDGE_OWNED_MODEL_INPUT is required'

git -C "$ROOT" diff --quiet && git -C "$ROOT" diff --cached --quiet || fail 'refusing package from dirty source tree'
[[ -z "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]] || fail 'refusing package with untracked source files'
[[ "$(git -C "$ROOT" branch --show-current)" == main ]] || fail 'customer package must be built from main'
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$(git -C "$ROOT" rev-parse origin/main)" ]] || fail 'main must equal origin/main'
bash "$SOURCE_GATE" "$ROOT" "$TMP/release-source.json" 'git@github.com:yangjiyj/aiguard.git'

"$TEST"
python3 "$MODEL_VERIFY" --lock "$MODEL_LOCK" --input "$MODEL_INPUT"
LLAMA_REV="$(sed -n 's/^llama_cpp_revision=//p' "$LOCK")"
[[ "$LLAMA_REV" =~ ^[0-9a-f]{40}$ ]] || fail 'invalid locked llama.cpp revision'
CACHE="/home/dev/tool-cache/llama.cpp-$LLAMA_REV"
"$ROOT/deploy/docker-compose/prepare-upstream-sources.sh" verify
COMMIT_COUNT="$(python3 - "$CACHE/receipt.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["commit_count"])
PY
)"
SOURCE_REV="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"

# Reuse the sealed core and the already validated SM86 extension. Never compile here.
[[ -n "${JUDGE_GPU_CORE_INPUT:-}" && -n "${JUDGE_GPU_EXTENSION_RECEIPT:-}" ]] ||
  fail 'JUDGE_GPU_CORE_INPUT and JUDGE_GPU_EXTENSION_RECEIPT are required'
python3 "$HERE/prepare-runtime-input.py" --core "$JUDGE_GPU_CORE_INPUT" \
  --extension-receipt "$JUDGE_GPU_EXTENSION_RECEIPT" --output "$TMP/runtime-input"
BASE_RUNTIME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_image"])' "$HERE/runtime-input.lock.json")"
docker image inspect "$BASE_RUNTIME" >/dev/null || fail 'locked base runtime is not cached'
BASE_ALIAS="jjdguard-release-input/gpu-core:${SOURCE_REV:0:12}-${BASE_RUNTIME:7:12}"
docker image tag "$BASE_RUNTIME" "$BASE_ALIAS"
[[ "$(docker image inspect "$BASE_ALIAS" --format '{{.Id}}')" == "$BASE_RUNTIME" ]] || fail 'base alias drift'
docker buildx build --platform linux/amd64 --load --pull=false --no-cache --network=none \
  --build-context "gpu-runtime-input=$TMP/runtime-input" \
  --build-arg "LOCAL_RUNTIME_IMAGE=$BASE_ALIAS" --build-arg "RELEASE_REVISION=$SOURCE_REV" \
  -t "$IMAGE" -f "$HERE/Dockerfile.runtime" "$HERE"
LIBCUDA="$(ldconfig -p | awk '$1 == "libcuda.so.1" { print $NF; exit }')"
[[ -n "$LIBCUDA" && -e "$LIBCUDA" ]] || fail 'host libcuda.so.1 is required for version validation'
LIBCUDA="$(readlink -f "$LIBCUDA")"
version="$(docker run --pull=never --network=none --rm \
  -v "$LIBCUDA:/opt/jjdguard/cuda-lib/libcuda.so.1:ro" \
  --entrypoint /opt/llama/llama-server "$IMAGE" --version 2>&1)"
grep -q "${LLAMA_REV:0:7}" <<<"$version" || fail 'runtime does not report the locked llama.cpp revision'
[[ "$(docker image inspect "$IMAGE" --format '{{ index .Config.Labels "com.jjdguard.cuda_architectures" }}')" == '86' ]] || fail 'CUDA architecture label mismatch'
CUDA_ARCHES="$(cuobjdump --list-elf "$TMP/runtime-input/llama/libggml-cuda.so" |
  sed -n 's/.*\.sm_\([0-9][0-9]*\)\.cubin.*/sm_\1/p' | sort -u | paste -sd, -)"
[[ "$CUDA_ARCHES" == 'sm_86' ]] || fail "unexpected CUDA architectures: ${CUDA_ARCHES:-none}"
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
python3 "$HERE/verify-runtime-image.py" --image "$IMAGE_ID" --receipt "$TMP/runtime-input/receipt.json" \
  --source "$HERE" --revision "$SOURCE_REV" >"$TMP/image-verification.json"

docker image inspect "$NGINX_BASE_IMAGE" >/dev/null ||
  fail 'locked nginx base image is not cached'
mkdir -p "$TMP/lb"
printf 'FROM %s\nLABEL org.opencontainers.image.title="JJDGuard GPU Judge load balancer" org.opencontainers.image.revision="%s"\n' \
  "$NGINX_BASE_IMAGE" "$SOURCE_REV" >"$TMP/lb/Dockerfile"
docker build --pull=false --no-cache -t "$LB_IMAGE" "$TMP/lb"
LB_IMAGE_ID="$(docker image inspect "$LB_IMAGE" --format '{{.Id}}')"
# 用真实 nginx 校验生成的配置语法（2 GPU x 3 实例拓扑，证书为一次性自签）。
mkdir -p "$TMP/lbcheck/tls"
printf 'JUDGE_GPU_IDS=0,1\nJUDGE_INSTANCES_PER_GPU=3\nJUDGE_PARALLEL=16\nJUDGE_CTX=131072\n' >"$TMP/lbcheck/runtime.env"
bash "$HERE/render-topology.sh" "$TMP/lbcheck/runtime.env" "$TMP/lbcheck" >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=check' \
  -keyout "$TMP/lbcheck/tls/server.key" -out "$TMP/lbcheck/tls/server.crt" >/dev/null 2>&1
chmod 0644 "$TMP/lbcheck/tls/server.key"
hosts=()
for h in $(grep -oE 'judge-g[0-9]+-i[0-9]+' "$TMP/lbcheck/nginx/nginx.conf" | sort -u); do hosts+=(--add-host "$h:127.0.0.1"); done
docker run --pull=never --network=none --rm "${hosts[@]}" \
  -v "$TMP/lbcheck/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$TMP/lbcheck/tls:/tls:ro" \
  "$LB_IMAGE" nginx -t -c /etc/nginx/nginx.conf || fail 'generated nginx configuration is invalid'

STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="JJDGuard-GPU-Judge-2.1.0-amd64-$STAMP"
BUNDLE="$TMP/$NAME"
mkdir -p "$BUNDLE/images" "$BUNDLE/models"
cp "$TMP/runtime-input/receipt.json" "$BUNDLE/gpu-runtime-input.json"
cp "$TMP/image-verification.json" "$BUNDLE/gpu-image-verification.json"
cp "$HERE/runtime-input.lock.json" "$BUNDLE/gpu-runtime-input.lock.json"
cp "$HERE/compose.yml" "$HERE/install.sh" "$HERE/verify.sh" "$HERE/rollback.sh" "$HERE/render-topology.sh" "$HERE/README.md" "$BUNDLE/"
cp "$MODEL_LOCK" "$BUNDLE/owned-judge-model.lock.json"
cp "$MODEL_INPUT" "$BUNDLE/models/$MODEL_FILE"
chmod 0755 "$BUNDLE/models"
chmod 0444 "$BUNDLE/models/$MODEL_FILE"
docker save "$IMAGE" -o "$BUNDLE/images/llm-judge-gpu.tar"
docker save "$LB_IMAGE" -o "$BUNDLE/images/judge-lb-nginx.tar"
MODEL_SIZE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["size"])' "$MODEL_LOCK")"
MODEL_SHA="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$MODEL_LOCK")"
[[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["file"])' "$MODEL_LOCK")" == "$MODEL_FILE" ]] ||
  fail 'model lock file name does not match the GPU addon model file'

python3 - "$BUNDLE/manifest.json" "$SOURCE_REV" "$SOURCE_TREE" "$LLAMA_REV" "$IMAGE_ID" "not-used-no-compilation" "$BASE_RUNTIME" "$LB_IMAGE_ID" "$NGINX_BASE_IMAGE" "$MODEL_FILE" "$MODEL_SIZE" "$MODEL_SHA" <<'PY'
import json, pathlib, sys
out, source, tree, llama, image, cuda_devel, cuda_runtime, lb_image, nginx_base, model_file, model_size, model_sha = sys.argv[1:]
payload = {
  "schema": "jjdguard-gpu-judge-addon/v2",
  "component_version": "2.1.0",
  "compatible_jjdguard_versions": ["2.6.15", "2.7.1", "2.9.6", "2.9.7", "2.9.8"],
  "source_revision": source,
  "source_tree": tree,
  "llama_cpp_revision": llama,
  "image": "jjdguard/llm-judge-gpu:2.1.0",
  "image_id": image,
  "load_balancer": {
    "image": "jjdguard/judge-lb-nginx:2.1.0",
    "image_id": lb_image,
    "base_image": nginx_base,
    "algorithm": "least_conn"
  },
  "topology_defaults": {"instances_per_gpu": 1, "parallel": 2, "ctx": 16384, "flash_attn": "on", "kv_cache_type": "f16"},
  "model": {
    "id": "bundled-judge",
    "origin": "derived",
    "license": "apache-2.0",
    "file": model_file,
    "size": int(model_size),
    "sha256": model_sha
  },
  "cuda": {"version": "12.4", "architectures": [86]},
  "build_mode": "verified-runtime-reuse",
  "original33_recompiled": False,
  "base_images": {
    "verified_core_runtime": cuda_runtime
  },
  "delivery_scope": "standalone-gpu-judge; no database or gateway policy mutation"
}
pathlib.Path(out).write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
PY

(
  cd "$BUNDLE"
  find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256
  sha256sum -c manifest.sha256 >/dev/null
)
chmod 0755 "$BUNDLE/install.sh" "$BUNDLE/verify.sh" "$BUNDLE/rollback.sh" "$BUNDLE/render-topology.sh"
chmod 0444 "$BUNDLE/manifest.json" "$BUNDLE/manifest.sha256" "$BUNDLE/owned-judge-model.lock.json"
mkdir -p "$OUT_INPUT"
OUT="$(cd "$OUT_INPUT" && pwd)"
tar --format=ustar --owner=0 --group=0 --numeric-owner -C "$TMP" -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256")
echo "[ok] GPU Judge customer artifact: $OUT/$NAME.tar.gz"
echo "[ok] SHA-256: $(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256")"
