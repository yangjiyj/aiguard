#!/bin/bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADDON="$ROOT/docker-compose/gpu-judge-7b-lora-addon"
PACKAGER="$ROOT/docker-compose/package-offline-bundle.sh"
LOCK="$ROOT/docker-compose/owned-judge-7b-lora.lock.json"
VERIFY="$ROOT/docker-compose/verify-owned-judge-7b-lora.py"
fail() { echo "[fail] $*" >&2; exit 1; }
for file in Dockerfile entrypoint.sh compose.yml install.sh verify.sh rollback.sh README.md package.sh; do
  [[ -f "$ADDON/$file" ]] || fail "missing $file"
done
for file in install.sh verify.sh rollback.sh package.sh; do bash -n "$ADDON/$file"; done
sh -n "$ADDON/entrypoint.sh"
python3 -m py_compile "$VERIFY"
grep -Fq 'gpu-judge-7b-lora-addon/package.sh' "$PACKAGER" || fail 'official package route is missing'
grep -Fq 'bash "$SOURCE_GATE"' "$ADDON/package.sh" || fail 'source gate is missing'
grep -Fq 'verify-owned-judge-7b-lora.py' "$ADDON/package.sh" || fail 'model lock verifier is missing'
grep -Fq -- '--model "$BASE_INPUT"' "$ADDON/package.sh" || fail 'judge-v4 model must be verified against the lock'
grep -Fq 'JUDGE_7B_LORA_INPUT is no longer accepted' "$ADDON/package.sh" || fail 'packager must reject a LoRA input'
grep -Fq 'JUDGE_LORA_PATH is not supported' "$ADDON/entrypoint.sh" || fail 'entrypoint must reject a LoRA path'
grep -Fq 'JUDGE_ALIAS: qwen2.5-7b-judge-v4' "$ADDON/compose.yml" || fail 'compose alias must be judge-v4'
grep -Fq 'jjdguard/llm-judge-gpu:1.2.0-7b-v4' "$ADDON/compose.yml" || fail 'compose image must be 1.2.0-7b-v4'
grep -Fq 'jjdguard/llm-judge-gpu:1.2.0-7b-v4' "$ADDON/install.sh" || fail 'install image must be 1.2.0-7b-v4'
# The v5 LoRA candidate is NO-GO; nothing shipped may load or reference it.
if grep -nE -- '--lora|jjdguard-v5-|judge-v5' \
    "$ADDON/Dockerfile" "$ADDON/entrypoint.sh" "$ADDON/compose.yml" "$ADDON/verify.sh" \
    "$ADDON/package.sh" "$LOCK" "$VERIFY"; then
  fail 'v5 LoRA reference found in shipped addon files'
fi
grep -Fq 'gpus: all' "$ADDON/compose.yml" || fail 'GPU allocation is missing'
grep -Fq 'sha256sum -c manifest.sha256' "$ADDON/install.sh" || fail 'bundle integrity check is missing'
grep -Fq 'compatible_jjdguard_versions": ["2.6.12", "2.6.15", "2.7.1"]' "$ADDON/package.sh" || fail 'version compatibility is missing'
grep -Fq '"schema": "jjdguard-gpu-judge-7b-addon/v2"' "$ADDON/package.sh" || fail 'manifest schema is missing'
grep -Fq 'sm_80,sm_90' "$ADDON/package.sh" || fail 'CUDA architecture gate is missing'
python3 - "$LOCK" <<'PY'
import json, pathlib, sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(lock) == {"schema", "model_id", "origin", "model"}, sorted(lock)
assert lock["schema"] == "jjdguard-owned-judge-7b-lock/v2"
assert lock["model_id"] == "qwen2.5-7b-judge-v4"
assert lock["origin"] == "user-trained"
assert lock["model"] == {
    "file": "judge-v4-Q4_K_M.gguf",
    "size": 4683073408,
    "sha256": "65f5e861b9abe9e63438f6aab4362c8c46536c2fc85cd88d7cf54856c7ec7a4a",
}
PY
tmp="$(mktemp -d)"
tmp="$(cd "$tmp" && pwd -P)"
trap 'rm -rf "$tmp"' EXIT

# Verifier behaviour: a small fixture model stands in for the real GGUF.
# The verifier's EXPECTED identity is fixed, so fixtures reuse it and only
# swap size/sha256 for the fixture content.
printf 'fixture-judge-v4' >"$tmp/judge-v4-Q4_K_M.gguf"
python3 - "$tmp" <<'PY'
import hashlib, json, pathlib, sys
d = pathlib.Path(sys.argv[1])
data = (d / "judge-v4-Q4_K_M.gguf").read_bytes()
model = {"file": "judge-v4-Q4_K_M.gguf", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
base = {"schema": "jjdguard-owned-judge-7b-lock/v2", "model_id": "qwen2.5-7b-judge-v4", "origin": "user-trained"}
(d / "good.json").write_text(json.dumps(dict(base, model=model)))
(d / "with-adapter.json").write_text(json.dumps(dict(base, model=model, adapter=model)))
(d / "bad-hash.json").write_text(json.dumps(dict(base, model=dict(model, sha256="0" * 64))))
(d / "v5-id.json").write_text(json.dumps(dict(base, model_id="qwen2.5-7b-judge-v5-full-lora", model=model)))
PY
python3 "$VERIFY" --lock "$tmp/good.json" --model "$tmp/judge-v4-Q4_K_M.gguf" >/dev/null ||
  fail 'verifier rejected a matching judge-v4 model'
for bad in with-adapter bad-hash v5-id; do
  if python3 "$VERIFY" --lock "$tmp/$bad.json" --model "$tmp/judge-v4-Q4_K_M.gguf" >/dev/null 2>&1; then
    fail "verifier accepted $bad lock"
  fi
done
if python3 "$VERIFY" --lock "$tmp/good.json" --model "$tmp/judge-v4-Q4_K_M.gguf" --adapter "$tmp/judge-v4-Q4_K_M.gguf" >/dev/null 2>&1; then
  fail 'verifier accepted an --adapter argument'
fi
ln -s "$tmp/judge-v4-Q4_K_M.gguf" "$tmp/link.gguf"
if python3 "$VERIFY" --lock "$tmp/good.json" --model "$tmp/link.gguf" >/dev/null 2>&1; then
  fail 'verifier accepted a symlinked model'
fi

cp "$ADDON/compose.yml" "$tmp/compose.yml"
cat >"$tmp/runtime.env" <<'EOF'
JUDGE_API_KEY=test-only
JUDGE_BIND_IP=127.0.0.1
JUDGE_HOST_PORT=18094
JUDGE_PARALLEL=4
JUDGE_CTX=16384
JUDGE_THREADS=4
JUDGE_GPU_LAYERS=99
JUDGE_FLASH_ATTN=on
EOF
docker compose --env-file "$tmp/runtime.env" -f "$tmp/compose.yml" config >/dev/null
echo '[ok] 7B judge-v4 addon static and Compose contracts passed'
