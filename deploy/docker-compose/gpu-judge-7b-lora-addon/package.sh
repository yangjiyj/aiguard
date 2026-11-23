#!/bin/bash
set -Eeuo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT_INPUT="${1:-$ROOT/deploy/docker-compose/offline-release}"
BASE_INPUT="${JUDGE_7B_BASE_INPUT:-}"
IMAGE="jjdguard/llm-judge-gpu:1.2.0-7b-v4"
CUDA_DEVEL_IMAGE="nvidia/cuda@sha256:520292dbb4f755fd360766059e62956e9379485d9e073bbd2f6e3c20c270ed66"
CUDA_RUNTIME_IMAGE="nvidia/cuda@sha256:ebef3c171eeef0298e4eb2e4be843105edf3b8b0ac45e0b43acee358e8046867"
SOURCE_GATE="$ROOT/deploy/docker-compose/release-source-gate.sh"
LOCK="$ROOT/deploy/docker-compose/release-toolchain.lock"
MODEL_LOCK="$ROOT/deploy/docker-compose/owned-judge-7b-lora.lock.json"
MODEL_VERIFY="$ROOT/deploy/docker-compose/verify-owned-judge-7b-lora.py"
TEST="$ROOT/deploy/tests/test_gpu_judge_7b_lora_addon.sh"
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
for cmd in docker git python3 sha256sum tar gzip ldconfig readlink; do need "$cmd"; done
[[ "$(uname -m)" =~ ^(x86_64|amd64)$ ]] || fail 'GPU Judge package supports amd64 only'
[[ -n "$BASE_INPUT" ]] || fail 'JUDGE_7B_BASE_INPUT is required'
[[ -z "${JUDGE_7B_LORA_INPUT:-}" ]] || fail 'JUDGE_7B_LORA_INPUT is no longer accepted; the addon ships judge-v4 without an adapter'

git -C "$ROOT" diff --quiet && git -C "$ROOT" diff --cached --quiet || fail 'refusing package from dirty source tree'
[[ -z "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]] || fail 'refusing package with untracked source files'
[[ "$(git -C "$ROOT" branch --show-current)" == main ]] || fail 'customer package must be built from main'
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$(git -C "$ROOT" rev-parse origin/main)" ]] || fail 'main must equal origin/main'
bash "$SOURCE_GATE" "$ROOT" "$TMP/release-source.json" 'git@github.com:yangjiyj/aiguard.git'

"$TEST"
python3 "$MODEL_VERIFY" --lock "$MODEL_LOCK" --model "$BASE_INPUT"
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

mkdir -p "$TMP/source"
tar -xf "$CACHE/llama.cpp.tar" -C "$TMP/source" --strip-components=1
docker image inspect "$CUDA_DEVEL_IMAGE" >/dev/null ||
  fail 'locked CUDA devel image is not cached'
docker image inspect "$CUDA_RUNTIME_IMAGE" >/dev/null ||
  fail 'locked CUDA runtime image is not cached'

docker buildx build --platform linux/amd64 --load --pull=false --no-cache \
  --build-context "llama-src=$TMP/source" \
  --build-arg "LLAMA_CPP_REVISION=$LLAMA_REV" \
  --build-arg "LLAMA_CPP_COMMIT_COUNT=$COMMIT_COUNT" \
  --build-arg "RELEASE_REVISION=$SOURCE_REV" \
  -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE"

LIBCUDA="$(ldconfig -p | awk '$1 == "libcuda.so.1" { print $NF; exit }')"
[[ -n "$LIBCUDA" && -e "$LIBCUDA" ]] || fail 'host libcuda.so.1 is required to validate the CUDA binary'
LIBCUDA="$(readlink -f "$LIBCUDA")"
version="$(docker run --pull=never --network=none --rm \
  -v "$LIBCUDA:/usr/lib/x86_64-linux-gnu/libcuda.so.1:ro" \
  --entrypoint /opt/llama/llama-server "$IMAGE" --version 2>&1)"
grep -q "${LLAMA_REV:0:7}" <<<"$version" || fail 'built image does not report the locked llama.cpp revision'
[[ "$(docker image inspect "$IMAGE" --format '{{ index .Config.Labels "com.jjdguard.cuda_architectures" }}')" == '80,90' ]] ||
  fail 'built image CUDA architecture label is missing'
CID="$(docker create "$IMAGE")"
docker cp "$CID:/opt/llama/libggml-cuda.so.0.19.0" "$TMP/libggml-cuda.so"
docker rm "$CID" >/dev/null
CID=''
CUDA_ARCHES="$(docker run --pull=never --network=none --rm \
  -v "$TMP/libggml-cuda.so:/work/libggml-cuda.so:ro" \
  --entrypoint /usr/local/cuda/bin/cuobjdump "$CUDA_DEVEL_IMAGE" \
  --list-elf /work/libggml-cuda.so |
  sed -n 's/.*\.sm_\([0-9][0-9]*\)\.cubin.*/sm_\1/p' |
  sort -u | paste -sd, -)"
[[ "$CUDA_ARCHES" == 'sm_80,sm_90' ]] ||
  fail "built CUDA binary has unexpected architectures: ${CUDA_ARCHES:-none}"
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"

STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="JJDGuard-GPU-Judge-7B-v4-1.2.0-amd64-$STAMP"
BUNDLE="$TMP/$NAME"
mkdir -p "$BUNDLE/images" "$BUNDLE/models"
cp "$HERE/compose.yml" "$HERE/install.sh" "$HERE/verify.sh" "$HERE/rollback.sh" "$HERE/README.md" "$BUNDLE/"
cp "$MODEL_LOCK" "$BUNDLE/owned-judge-7b-lora.lock.json"
cp "$BASE_INPUT" "$BUNDLE/models/judge-v4-Q4_K_M.gguf"
docker save "$IMAGE" -o "$BUNDLE/images/llm-judge-gpu.tar"

python3 - "$BUNDLE/manifest.json" "$SOURCE_REV" "$SOURCE_TREE" "$LLAMA_REV" "$IMAGE_ID" "$CUDA_DEVEL_IMAGE" "$CUDA_RUNTIME_IMAGE" <<'PY'
import json, pathlib, sys
out, source, tree, llama, image, cuda_devel, cuda_runtime = sys.argv[1:]
payload = {
  "schema": "jjdguard-gpu-judge-7b-addon/v2",
  "component_version": "1.2.0",
  "compatible_jjdguard_versions": ["2.6.12", "2.6.15", "2.7.1"],
  "source_revision": source,
  "source_tree": tree,
  "llama_cpp_revision": llama,
  "image": "jjdguard/llm-judge-gpu:1.2.0-7b-v4",
  "image_id": image,
  "model": {
    "id": "qwen2.5-7b-judge-v4",
    "origin": "user-trained",
    "file": "judge-v4-Q4_K_M.gguf", "size": 4683073408, "sha256": "65f5e861b9abe9e63438f6aab4362c8c46536c2fc85cd88d7cf54856c7ec7a4a"
  },
  "cuda": {"version": "12.8.1", "architectures": [80, 90]},
  "base_images": {
    "cuda_devel": cuda_devel,
    "cuda_runtime": cuda_runtime
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
chmod 0755 "$BUNDLE/install.sh" "$BUNDLE/verify.sh" "$BUNDLE/rollback.sh"
chmod 0444 "$BUNDLE/manifest.json" "$BUNDLE/manifest.sha256" "$BUNDLE/owned-judge-7b-lora.lock.json"
mkdir -p "$OUT_INPUT"
OUT="$(cd "$OUT_INPUT" && pwd)"
tar --format=ustar --owner=0 --group=0 --numeric-owner -C "$TMP" -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256")
echo "[ok] GPU Judge customer artifact: $OUT/$NAME.tar.gz"
echo "[ok] SHA-256: $(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256")"
