#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-owned-judge-model.py"

fail() {
  printf '[owned-judge-input] %s\n' "$*" >&2
  exit 1
}

tmp=$(mktemp -d)
chmod 0700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT

model="$tmp/jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf"
lock="$tmp/owned-judge-model.lock.json"
printf 'bundled-judge-weights' >"$model"

# write_lock [key=json-value ...]: v3 lock for $model, with optional overrides
# (value "DELETE" drops the key) so each negative case changes one thing.
write_lock() {
  python3 - "$model" "$lock" "$@" <<'PY'
import hashlib
import json
import os
import sys

model, lock, *overrides = sys.argv[1:]
with open(model, "rb") as handle:
    digest = hashlib.sha256(handle.read()).hexdigest()
data = {
    "schema": "jjdguard-owned-judge-model-lock/v3",
    "model_id": "bundled-judge",
    "origin": "derived",
    "base": {"repo": "Qwen/Qwen3-4B-Instruct-2507", "revision": "cdbee75f17c01a7cc42f958dc650907174af0554", "license": "apache-2.0"},
    "adapter_sha256": "276ed0c65060ac6961eef33eaf1bf0f74db24b935d86c0bd878a61f79ebf78ae",
    "training": "JJDGuard LoRA merged into the base",
    "license": "apache-2.0",
    "file": os.path.basename(model),
    "size": os.path.getsize(model),
    "sha256": digest,
}
for item in overrides:
    key, value = item.split("=", 1)
    if value == "DELETE":
        data.pop(key, None)
    else:
        data[key] = json.loads(value)
with open(lock, "w", encoding="utf-8") as handle:
    json.dump(data, handle, sort_keys=True)
    handle.write("\n")
os.chmod(lock, 0o600)
PY
}

expect_failure() {
  local label=$1
  shift
  if "$@" >"$tmp/$label.stdout" 2>"$tmp/$label.stderr"; then
    fail "$label was accepted"
  fi
}

verify() { python3 "$VERIFIER" --lock "$lock" --input "$model"; }

# The repository lock itself must satisfy the verifier's schema (content is
# checked at release time against the real GGUF).
python3 - "$VERIFIER" "$ROOT_DIR/deploy/docker-compose/owned-judge-model.lock.json" <<'PY' ||
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("v", sys.argv[1]); v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
lock = v.read_lock(pathlib.Path(sys.argv[2]))
assert lock["file"] == v.MODEL_FILE and lock["origin"] == "derived"
PY
  fail 'repository owned-judge-model.lock.json does not pass the verifier schema'

write_lock
verify >"$tmp/ok.stdout" || fail 'matching bundled Judge model was rejected'
grep -q 'derived from Qwen/Qwen3-4B-Instruct-2507@cdbee75f17c0' "$tmp/ok.stdout" ||
  fail 'verifier output must name the base model and revision'

printf 'tampered' >"$model"
expect_failure content-tamper verify
printf 'bundled-judge-weights' >"$model"

# Older schemas (v1 "user-trained", v2 "upstream" unmodified release) are rejected.
write_lock 'schema="jjdguard-owned-judge-model-lock/v2"'
expect_failure legacy-v2-schema verify
write_lock 'origin="upstream"'
expect_failure origin-upstream verify
write_lock 'origin="user-trained"'
expect_failure origin-user-trained verify

# Non-commercial licenses (e.g. Qwen Research License of Qwen2.5-3B) are refused,
# for the result and for the base.
write_lock 'license="qwen-research"'
expect_failure license verify
write_lock 'base={"repo":"Qwen/Qwen2.5-3B-Instruct","revision":"cdbee75f17c01a7cc42f958dc650907174af0554","license":"qwen-research"}'
expect_failure base-license verify
write_lock 'base={"repo":"Qwen/Qwen3-4B-Instruct-2507","revision":"main","license":"apache-2.0"}'
expect_failure base-revision verify
write_lock 'base={"repo":"","revision":"cdbee75f17c01a7cc42f958dc650907174af0554","license":"apache-2.0"}'
expect_failure base-repo verify
write_lock 'adapter_sha256="abc"'
expect_failure adapter-sha verify
write_lock 'training=""'
expect_failure training verify
write_lock 'adapter_sha256=DELETE'
expect_failure missing-key verify
write_lock 'upstream="unsloth/Qwen3-4B-Instruct-2507-GGUF"'
expect_failure extra-key verify

cp "$model" "$tmp/Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
write_lock
expect_failure old-file-name python3 "$VERIFIER" --lock "$lock" --input "$tmp/Qwen3-4B-Instruct-2507-Q4_K_M.gguf"

ln -s "$model" "$tmp/judge-link.gguf"
expect_failure symlink python3 "$VERIFIER" --lock "$lock" --input "$tmp/judge-link.gguf"

printf '[owned-judge-input] PASS\n'
