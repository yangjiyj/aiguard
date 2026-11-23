#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
DOCKERFILE="$ROOT/apps/security-engine/Dockerfile"
BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"
PREPARE="$ROOT/deploy/docker-compose/prepare-security-engine-python-deps-input.sh"
VERIFY="$ROOT/deploy/docker-compose/verify-security-engine-python-deps.py"

fail() {
  printf 'FAIL test_security_engine_offline_python_deps_contract: %s\n' "$*" >&2
  exit 1
}

expect_reject() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    fail "expected rejection: $label"
  fi
}

[[ -x "$PREPARE" ]] || fail 'missing local security-engine dependency snapshot preparer'
[[ -x "$VERIFY" ]] || fail 'missing local security-engine dependency snapshot verifier'

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
input="$tmp/input"
site_packages="$input/site-packages"
dist_info="$site_packages/fixture_pkg-1.0.dist-info"
lock="$tmp/requirements.lock"
install -d -m 0700 "$dist_info"
printf '%s\n' \
  '{"schema":"jjdguard-security-engine-python-deps-source/v1","origin":"home-existing-security-engine-image","source_image":"docker-compose-security-engine:latest","source_image_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
  >"$input/source.json"
printf '%s\n' \
  'Metadata-Version: 2.1' \
  'Name: fixture-pkg' \
  'Version: 1.0' \
  >"$dist_info/METADATA"
printf '%s\n' 'VALUE = "fixture"' >"$site_packages/fixture_pkg.py"
printf '%s\n' 'fixture-pkg==1.0' >"$lock"
assets_lock="$tmp/ocr-resources.lock.json"
python3 - "$site_packages/jjdguard_ocr_data" "$assets_lock" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]); root.mkdir()
items = []
for name in ("chi_sim.traineddata", "eng.traineddata", "LICENSE"):
    data = ("synthetic-asset-" + name).encode()
    (root / name).write_bytes(data)
    items.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
pathlib.Path(sys.argv[2]).write_text(json.dumps({"files": items}))
PY
receipt="$(python3 "$VERIFY" --ocr-resources-lock "$assets_lock" --requirements-lock "$lock" --input "$input")" ||
  fail 'valid security-engine local Python dependency snapshot was rejected'
jq -e '
  .schema == "jjdguard-security-engine-python-deps/v1" and
  .origin == "home-existing-security-engine-image" and
  .source_image == "docker-compose-security-engine:latest" and
  (.requirements_lock_sha256 | test("^[0-9a-f]{64}$")) and
  (.content_sha256 | test("^[0-9a-f]{64}$")) and
  (.packages == [{name:"fixture-pkg",version:"1.0"}])
' <<<"$receipt" >/dev/null || fail 'security-engine dependency receipt shape is incorrect'

for verifier in \
  "$ROOT/deploy/docker-compose/verify-image-provenance.py" \
  "$ROOT/deploy/acceptance/verify-acceptance-receipt.py"; do
  python3 - "$verifier" "$lock" "$receipt" <<'PY'
import copy
import importlib.util
import json
import pathlib
import sys

verifier_path = pathlib.Path(sys.argv[1])
lock = pathlib.Path(sys.argv[2]).read_bytes()
receipt = json.loads(sys.argv[3])
spec = importlib.util.spec_from_file_location("security_engine_provenance", verifier_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
module.git_blob_bytes = lambda *_args: lock
module.validate_security_engine_python_deps(
    receipt, pathlib.Path("/fixture"), "a" * 40
)
home_snapshot = copy.deepcopy(receipt)
home_snapshot["source_image"] = home_snapshot["source_image_id"]
module.validate_security_engine_python_deps(
    home_snapshot, pathlib.Path("/fixture"), "a" * 40
)
revision = "a" * 40
valid_build = {"SECURITY_ENGINE_BUILD": revision}
module.validate_security_engine_build_identity(valid_build, revision)
module.validate_security_engine_build_identity(valid_build, revision, ["SECURITY_ENGINE_BUILD=" + revision])
for args, env in (
    ({}, None),
    ({"SECURITY_ENGINE_BUILD": "b" * 40}, None),
    (valid_build, ["SECURITY_ENGINE_BUILD="]),
    (valid_build, ["SECURITY_ENGINE_BUILD=" + revision, "SECURITY_ENGINE_BUILD=" + revision]),
):
    try:
        module.validate_security_engine_build_identity(args, revision, env)
    except SystemExit:
        pass
    else:
        raise SystemExit("security-engine build provenance accepted missing or mismatched identity")
module.git_output = lambda *_args: module.SECURITY_ENGINE_BUILD_CONTRACT
module.git_blob_bytes = lambda *_args: b"source-revision-v1\n"
assert module.security_engine_build_identity_required(pathlib.Path("/fixture"), revision)
module.git_output = lambda *_args: ""
assert not module.security_engine_build_identity_required(pathlib.Path("/fixture"), revision)
module.git_output = lambda *_args: module.SECURITY_ENGINE_BUILD_CONTRACT
module.git_blob_bytes = lambda *_args: b"invalid\n"
try:
    module.security_engine_build_identity_required(pathlib.Path("/fixture"), revision)
except SystemExit:
    pass
else:
    raise SystemExit("security-engine build contract accepted invalid content")
module.git_blob_bytes = lambda *_args: lock
tampered = copy.deepcopy(receipt)
tampered["packages"][0]["version"] = "9.9"
try:
    module.validate_security_engine_python_deps(
        tampered, pathlib.Path("/fixture"), "a" * 40
    )
except SystemExit:
    pass
else:
    raise SystemExit("security-engine provenance verifier accepted a package-version mismatch")
forged_source = copy.deepcopy(receipt)
forged_source["source_image"] = "docker-compose-security-engine:unreviewed"
try:
    module.validate_security_engine_python_deps(
        forged_source, pathlib.Path("/fixture"), "a" * 40
    )
except SystemExit:
    pass
else:
    raise SystemExit("security-engine provenance verifier accepted an unreviewed source image")
PY
done

mv "$site_packages/jjdguard_ocr_data/chi_sim.traineddata" "$tmp/chi_sim.saved"
expect_reject 'missing Chinese OCR language' python3 "$VERIFY" --ocr-resources-lock "$assets_lock" --requirements-lock "$lock" --input "$input"
printf 'tampered' > "$site_packages/jjdguard_ocr_data/chi_sim.traineddata"
expect_reject 'tampered OCR language' python3 "$VERIFY" --ocr-resources-lock "$assets_lock" --requirements-lock "$lock" --input "$input"
mv "$tmp/chi_sim.saved" "$site_packages/jjdguard_ocr_data/chi_sim.traineddata"

printf '%s\n' \
  'Metadata-Version: 2.1' \
  'Name: fixture-pkg' \
  'Version: 9.9'  \
  >"$dist_info/METADATA"
expect_reject 'installed package version differs from the offline lock' \
  python3 "$VERIFY" --ocr-resources-lock "$assets_lock" --requirements-lock "$lock" --input "$input"

grep -Fq 'COPY --from=release-security-python-deps /site-packages /usr/local/lib/python3.11/site-packages' "$DOCKERFILE" ||
  fail 'security-engine Dockerfile must copy the explicit local dependency snapshot'
grep -Fq 'CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]' "$DOCKERFILE" ||
  fail 'security-engine Dockerfile must launch Uvicorn from the reviewed Python dependency snapshot'
grep -Fq 'RUN python -m pip check' "$DOCKERFILE" ||
  fail 'security-engine Dockerfile must validate copied dependencies'
if grep -Eq '^[[:space:]]*RUN[[:space:]].*pip[[:space:]]+install' "$DOCKERFILE"; then
  fail 'security-engine Dockerfile must not install Python dependencies from a network index'
fi
grep -Fq 'SECURITY_ENGINE_PYTHON_DEPS_INPUT=' "$BUILDER" ||
  fail 'offline builder must require an explicit security-engine Python dependency input'
grep -Fq -- '--build-context "release-security-python-deps=$SECURITY_ENGINE_PYTHON_DEPS_INPUT"' "$BUILDER" ||
  fail 'offline builder must pass the local security-engine dependency context'
grep -Fq -- '--build-arg "SECURITY_ENGINE_BUILD=$SOURCE_REVISION"' "$BUILDER" ||
  fail 'offline builder must bind the security-engine build identity to the source revision'

printf 'PASS test_security_engine_offline_python_deps_contract\n'
