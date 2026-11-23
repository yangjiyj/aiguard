#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
VERIFIER="$ROOT/deploy/docker-compose/verify-tier1-python-deps.py"
DOCKERFILE="$ROOT/apps/tier1-classifier/Dockerfile"
TASK4="$ROOT/deploy/tests/build_jjdguard_task4_images.sh"
OFFLINE_BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"

fail() {
  printf 'FAIL test_tier1_offline_python_deps_contract: %s\n' "$*" >&2
  exit 1
}

expect_reject() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    fail "expected rejection: $label"
  fi
}

[[ -x "$VERIFIER" ]] || fail "missing Tier1 local Python dependency verifier"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

input="$tmp/input"
site_packages="$input/site-packages"
dist_info="$site_packages/fixture_pkg-1.0.dist-info"
lock="$tmp/requirements.lock"
install -d -m 0700 "$dist_info"

printf '%s\n' \
  '{"schema":"jjdguard-tier1-python-deps-source/v1","origin":"home-existing-tier1-image","source_image":"docker-compose-tier1-classifier:latest","source_image_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
  >"$input/source.json"
printf '%s\n' \
  'Metadata-Version: 2.1' \
  'Name: fixture-pkg' \
  'Version: 1.0' \
  >"$dist_info/METADATA"
printf '%s\n' 'VALUE = "fixture"' >"$site_packages/fixture_pkg.py"
python3 - "$site_packages/fixture_native.so" 62 <<'PY'
import pathlib, sys
header = bytearray(20)
header[:6] = bytes([127]) + b"ELF" + bytes([2, 1])
header[18:20] = int(sys.argv[2]).to_bytes(2, "little")
pathlib.Path(sys.argv[1]).write_bytes(header)
PY
printf '%s\n' \
  'fixture-pkg==1.0 \' \
  '    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  >"$lock"

receipt="$(python3 "$VERIFIER" --requirements-lock "$lock" --input "$input")" ||
  fail 'valid local Python dependency snapshot was rejected'
jq -e '
  .schema == "jjdguard-tier1-python-deps/v1" and
  .origin == "home-existing-tier1-image" and
  .source_image == "docker-compose-tier1-classifier:latest" and
  .source_image_id == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  (.requirements_lock_sha256 | test("^[0-9a-f]{64}$")) and
  (.content_sha256 | test("^[0-9a-f]{64}$")) and
  (.packages == [{name:"fixture-pkg",version:"1.0"}])
' <<<"$receipt" >/dev/null || fail 'valid dependency receipt shape is incorrect'
printf '%s\n' '{"schema":"jjdguard-tier1-python-deps-source/v1","origin":"home-arm64-python-dependency-image","source_image":"jjdguard-tier1-python-deps:arm64","source_image_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' >"$input/source.json"
expect_reject 'amd64 native extension cannot be used for arm64' \
  python3 "$VERIFIER" --target-arch arm64 --requirements-lock "$lock" --input "$input"
python3 - "$site_packages/fixture_native.so" 183 <<'PY'
import pathlib, sys
header = bytearray(20)
header[:6] = bytes([127]) + b"ELF" + bytes([2, 1])
header[18:20] = int(sys.argv[2]).to_bytes(2, "little")
pathlib.Path(sys.argv[1]).write_bytes(header)
PY
python3 "$VERIFIER" --target-arch arm64 --requirements-lock "$lock" --input "$input" >/dev/null ||
  fail 'arm64 native extension was rejected for arm64'
python3 - "$site_packages/fixture_native.so" 62 <<'PY'
import pathlib, sys
header = bytearray(20)
header[:6] = bytes([127]) + b"ELF" + bytes([2, 1])
header[18:20] = int(sys.argv[2]).to_bytes(2, "little")
pathlib.Path(sys.argv[1]).write_bytes(header)
PY

printf '%s\n' \
  'Metadata-Version: 2.1' \
  'Name: fixture-pkg' \
  'Version: 9.9' \
  >"$dist_info/METADATA"
printf '%s\n' '{"schema":"jjdguard-tier1-python-deps-source/v1","origin":"home-existing-tier1-image","source_image":"docker-compose-tier1-classifier:latest","source_image_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' >"$input/source.json"
expect_reject 'installed package version differs from requirements lock' \
  python3 "$VERIFIER" --requirements-lock "$lock" --input "$input"

grep -Fq 'COPY python-deps/site-packages /usr/local/lib/python3.11/site-packages' "$DOCKERFILE" ||
  fail 'Tier1 Dockerfile must copy the local dependency snapshot'
grep -Fq 'RUN python -m pip check' "$DOCKERFILE" ||
  fail 'Tier1 Dockerfile must validate copied dependencies'
grep -Fq 'ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1' "$DOCKERFILE" ||
  fail 'Tier1 Dockerfile must force Transformers and Hugging Face clients offline'
if grep -Eq '^[[:space:]]*RUN[[:space:]].*pip[[:space:]]+install' "$DOCKERFILE"; then
  fail 'Tier1 Dockerfile must not install Python dependencies from a network index'
fi
grep -Fq -- '--tier1-python-deps-input)' "$TASK4" ||
  fail 'Task4 must require an explicit local Tier1 Python dependency input'
grep -Fq -- '--tier1-python-deps-input "$TIER1_PYTHON_DEPS_INPUT"' "$OFFLINE_BUILDER" ||
  fail 'offline builder must pass the local Tier1 Python dependency input to Task4'

printf 'PASS test_tier1_offline_python_deps_contract\n'
