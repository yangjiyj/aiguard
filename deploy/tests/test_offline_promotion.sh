#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY="$ROOT/deploy/acceptance/verify-acceptance-receipt.py"
PROMOTE="$ROOT/deploy/docker-compose/promote-offline-release.sh"
HEADER="$ROOT/deploy/offline-installer/self-extracting-header.sh"
TRUST_VERIFIER="$ROOT/deploy/offline-installer/verify-promoted-release.py"
AUTHORITATIVE_GITEE_REMOTE='git@github.com:yangjiyj/aiguard.git'

# This fixture intentionally puts a fake git binary on PATH later. Start from
# the standard system tool path so an inherited test wrapper cannot recurse.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
REAL_GIT="$(command -v git)"
[[ -x "$REAL_GIT" ]] || { echo '[fail] system git is unavailable' >&2; exit 1; }
REAL_MV="$(command -v mv)"
[[ -x "$REAL_MV" ]] || { echo '[fail] system mv is unavailable' >&2; exit 1; }
REAL_RM="$(command -v rm)"
[[ -x "$REAL_RM" ]] || { echo '[fail] system rm is unavailable' >&2; exit 1; }
REAL_STAT="$(command -v stat)"
[[ -x "$REAL_STAT" ]] || { echo '[fail] system stat is unavailable' >&2; exit 1; }

fail() { echo "[fail] $*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }
b64() { openssl base64 -A <"$1"; }

for file in "$VERIFY" "$PROMOTE" "$HEADER" "$TRUST_VERIFIER"; do
  [[ -f "$file" ]] || fail "missing: $file"
done
grep -Fqx "EMBEDDED_HEADER_SIGNATURE='__EMBEDDED_HEADER_SIGNATURE__'" "$HEADER" ||
  fail 'self-extracting header must reserve its sealed header signature'
grep -Fq 'outer.getmembers()' "$VERIFY" &&
  fail 'acceptance verifier must stream outer tar members instead of materializing them all'
grep -Fq 'member.issparse()' "$VERIFY" ||
  fail 'acceptance verifier must reject sparse outer tar members'
grep -Fq 'MAX_PAYLOAD_BYTES' "$VERIFY" ||
  fail 'acceptance verifier must bound the outer payload before materializing it'
grep -Fq 'run.read_bytes()' "$PROMOTE" &&
  fail 'promotion must not load a complete GiB-scale candidate into memory'
if grep -Eq 'JJD_(RELEASE_TESTING|TEST_GITEE_REMOTE)' "$PROMOTE"; then
  fail 'promotion must not permit test environment to override the authoritative Gitee remote'
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
priv="$tmp/release-private.pem"
pub="$tmp/release-public.pem"
openssl genpkey -algorithm Ed25519 -out "$priv" >/dev/null 2>&1
openssl pkey -in "$priv" -pubout -out "$pub" >/dev/null 2>&1
chmod 0400 "$priv"
pub_b64="$(b64 "$pub")"

image_id=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_image_id=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
syft_sha="$(awk -F= '$1 == "syft_binary_sha256" {print $2}' "$ROOT/deploy/docker-compose/release-toolchain.lock")"
[[ "$syft_sha" =~ ^[0-9a-f]{64}$ ]] || fail 'fixed Syft lock is invalid'
fixture_remote="$tmp/gitee-release.git"
release_remote="$AUTHORITATIVE_GITEE_REMOTE"
source_checkout="$tmp/gitee-source"
source_repository="$tmp/gitee-cache.git"
git init -q "$source_checkout"
git -C "$source_checkout" checkout -q -b main
mkdir -p "$source_checkout/deploy/docker-compose" "$source_checkout/enterprise-ai-portal"
printf 'syft_binary_sha256=%s\n' "$syft_sha" >"$source_checkout/deploy/docker-compose/release-toolchain.lock"
printf '%s\n' \
  'fixture/dependency:1 common third-party fixture sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb - -' \
  'fixture/application:1 full first-party enterprise-ai-portal - enterprise-ai-portal/Dockerfile .' \
  >"$source_checkout/deploy/docker-compose/images.lst"
printf '%s\n' \
  'def parse_dockerfile(text, source):' \
  '    if text != "FROM scratch":' \
  '        raise ValueError(f"unexpected Dockerfile: {source}")' \
  '    return []' \
  >"$source_checkout/deploy/docker-compose/dockerfile-base-images.py"
printf '%s\n' 'FROM scratch' >"$source_checkout/enterprise-ai-portal/Dockerfile"
git -C "$source_checkout" add deploy/docker-compose/release-toolchain.lock deploy/docker-compose/images.lst \
  deploy/docker-compose/dockerfile-base-images.py enterprise-ai-portal/Dockerfile
git -C "$source_checkout" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit -q -m 'fixture source identity'
source_revision="$(git -C "$source_checkout" rev-parse HEAD)"
source_tree="$(git -C "$source_checkout" rev-parse 'HEAD^{tree}')"
fixture_dockerfile_blob="$(git -C "$source_checkout" rev-parse 'HEAD:enterprise-ai-portal/Dockerfile')"
git -C "$source_checkout" archive --format=tar --prefix=source/ HEAD >"$tmp/source.tar"
source_archive_sha="$(sha "$tmp/source.tar")"
git clone -q --bare "$source_checkout" "$fixture_remote"
git init -q --bare "$source_repository"
git -C "$source_repository" remote add origin "$release_remote"
git -C "$source_repository" fetch -q --no-tags "$fixture_remote" refs/heads/main:refs/remotes/origin/main

python3 - "$ROOT/deploy/acceptance/receipt-schema.json" <<'PY'
import json
import pathlib
import sys

required = {
    "n1-install", "clean-install", "offline-reboot", "upgrade-n1-r7", "rollback-r7-n1",
    "reupgrade-n1-r7", "tamper-run", "tamper-manifest", "tamper-sbom", "tamper-provenance",
    "tamper-receipt", "browser-login", "model-api", "model-stream", "security-benign",
    "security-block", "security-audit", "portal-proxy-idp-chat",
}
schema = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
scenarios = schema["properties"]["scenarios"]
if scenarios.get("additionalProperties") is not False:
    raise SystemExit("receipt schema scenarios must reject undeclared entries")
if set(scenarios.get("required", [])) != required:
    raise SystemExit("receipt schema scenarios must require the promotion matrix")
if set(scenarios.get("properties", {})) != required:
    raise SystemExit("receipt schema scenarios must declare the promotion matrix")
if any(value != {"const": "PASS"} for value in scenarios["properties"].values()):
    raise SystemExit("receipt schema scenarios must require PASS")
PY

write_inventory() {
  local bundle="$1" rel
  chmod u+w "$bundle/offline-inventory.tsv" 2>/dev/null || true
  {
    printf '%s\t%s\n' schema jjdguard-offline-inventory/v1
    while IFS= read -r rel; do
      printf '%s\t%s\t%s\t%s\n' file "$(printf '%s' "$rel" | openssl base64 -A | tr '+/' '-_' | tr -d '=')" \
        "$(stat -c '%s' "$bundle/$rel")" "$(sha "$bundle/$rel")"
    done < <(cd "$bundle" && find . -type f ! -name offline-inventory.tsv -printf '%P\n' | LC_ALL=C sort)
  } >"$bundle/offline-inventory.tsv"
  chmod 0444 "$bundle/offline-inventory.tsv"
}

make_bundle() {
  local bundle="$1" base_images_json="${2:-[]}" sbom_bundle_sha sbom_image_sha source_image_sbom_sha
  local manifest fixture_digest toolchain_json task4_engine_json task4_sha
  mkdir -p "$bundle/deploy/docker-compose" "$bundle/sbom/images" "$bundle/task4"
  printf '%s\n' '077_request_logs_proxy_access_type_resolved.sql' >"$bundle/deploy/docker-compose/upgrade-min-data-version"
  printf '%s\n' '137_enterprise_identity_department.sql' >"$bundle/deploy/docker-compose/upgrade-bridge-target-version"
  printf '%s\n' "{\"schema\":\"jjdguard-release-source/v1\",\"remote\":\"$release_remote\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\"}" >"$bundle/release-source.json"
  printf '%s\n' '{"spdxVersion":"SPDX-2.3","creationInfo":{"creators":["Tool: syft-1.44.0"]},"packages":[{"name":"fixture"}]}' >"$bundle/sbom/bundle.spdx.json"
  cp "$bundle/sbom/bundle.spdx.json" "$bundle/sbom/images/fixture.spdx.json"
  cp "$bundle/sbom/bundle.spdx.json" "$bundle/sbom/images/enterprise-ai-portal.spdx.json"
  sbom_bundle_sha="$(sha "$bundle/sbom/bundle.spdx.json")"
  sbom_image_sha="$(sha "$bundle/sbom/images/fixture.spdx.json")"
  source_image_sbom_sha="$(sha "$bundle/sbom/images/enterprise-ai-portal.spdx.json")"
  fixture_digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  toolchain_json='{"docker_client_version":"Docker fixture","docker_server_version":"Docker server fixture","buildx_version":"buildx fixture","buildx_builder":"fixture-builder","buildx_nodes":[{"name":"fixture-node","endpoint":"fixture://builder","status":"running","buildkit_version":"BuildKit fixture"}]}'
  task4_engine_json='{"kind":"docker-daemon","docker_client_version":"Docker fixture","docker_server_version":"Docker server fixture"}'
  printf '%s\n' "{\"schema\":\"jjdguard-task4-image-receipt/v1\",\"component\":\"portal\",\"revision\":\"$source_revision\",\"candidate_tree\":\"$source_tree\",\"archive_sha256\":\"$source_archive_sha\",\"image\":\"fixture/application:1\",\"image_id\":\"$source_image_id\",\"oci_config_digest\":\"$source_image_id\",\"base_images\":$base_images_json,\"source_blobs\":{\"enterprise-ai-portal/Dockerfile\":\"$fixture_dockerfile_blob\"},\"build_engine\":$task4_engine_json,\"build_args\":{\"NEXT_PUBLIC_BILLING_ENABLED\":\"false\"}}" >"$bundle/task4/portal-image-receipt.json"
  task4_sha="$(sha "$bundle/task4/portal-image-receipt.json")"
  printf '%s\n' "{\"schema\":\"jjdguard-image-provenance/v1\",\"generated_at\":\"2026-08-08T00:00:00Z\",\"platform\":\"linux/amd64\",\"selection\":{\"profile\":\"full\",\"include_chat\":true},\"source\":{\"remote\":\"$release_remote\",\"revision\":\"$source_revision\",\"tree\":\"$source_tree\",\"archive_sha256\":\"$source_archive_sha\"},\"toolchain\":$toolchain_json,\"images\":[{\"runtime_tag\":\"fixture/dependency:1\",\"profile\":\"common\",\"kind\":\"third-party\",\"component\":\"fixture\",\"expected_digest\":\"$fixture_digest\",\"actual_digest\":\"$fixture_digest\",\"dockerfile\":null,\"context\":null,\"platform\":\"linux/amd64\",\"image_id\":\"$image_id\",\"oci_config_digest\":\"$image_id\",\"build_args\":{},\"sbom\":{\"path\":\"sbom/images/fixture.spdx.json\",\"sha256\":\"$sbom_image_sha\"}},{\"runtime_tag\":\"fixture/application:1\",\"profile\":\"full\",\"kind\":\"first-party\",\"component\":\"enterprise-ai-portal\",\"expected_digest\":null,\"actual_digest\":null,\"dockerfile\":\"enterprise-ai-portal/Dockerfile\",\"context\":\".\",\"platform\":\"linux/amd64\",\"image_id\":\"$source_image_id\",\"oci_config_digest\":\"$source_image_id\",\"source\":{\"remote\":\"$release_remote\",\"revision\":\"$source_revision\",\"tree\":\"$source_tree\",\"archive_sha256\":\"$source_archive_sha\"},\"source_blobs\":{\"enterprise-ai-portal/Dockerfile\":\"$fixture_dockerfile_blob\"},\"base_images\":$base_images_json,\"toolchain\":$toolchain_json,\"build_engine\":$task4_engine_json,\"build_args\":{\"NEXT_PUBLIC_BILLING_ENABLED\":\"false\"},\"legacy_receipt\":{\"path\":\"task4/portal-image-receipt.json\",\"sha256\":\"$task4_sha\"},\"sbom\":{\"path\":\"sbom/images/enterprise-ai-portal.spdx.json\",\"sha256\":\"$source_image_sbom_sha\"}}]}" >"$bundle/image-provenance.json"
  provenance_sha="$(sha "$bundle/image-provenance.json")"
  printf '%s\n' "{\"schema\":\"jjdguard-release-sbom-index/v1\",\"syft\":{\"version\":\"1.44.0\",\"binary_sha256\":\"$syft_sha\"},\"bundle\":{\"path\":\"sbom/bundle.spdx.json\",\"sha256\":\"$sbom_bundle_sha\"},\"images\":[{\"component\":\"fixture\",\"image_id\":\"$image_id\",\"path\":\"sbom/images/fixture.spdx.json\",\"sha256\":\"$sbom_image_sha\"},{\"component\":\"enterprise-ai-portal\",\"image_id\":\"$source_image_id\",\"path\":\"sbom/images/enterprise-ai-portal.spdx.json\",\"sha256\":\"$source_image_sbom_sha\"}]}" >"$bundle/sbom/index.json"
  sbom_sha="$(sha "$bundle/sbom/index.json")"
  manifest="{\"schema\":\"offline-manifest/v2\",\"product\":\"jjdguard-enterprise\",\"version\":\"fixture\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"target_arch\":\"amd64\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"min_data_version\":\"077_request_logs_proxy_access_type_resolved.sql\",\"manifest_signature\":\"ed25519-domain-v2\",\"built_at\":\"2026-08-08T00:00:00Z\",\"bundle\":\"$(basename "$bundle")\"}"
  printf '%s\n' "$manifest" >"$bundle/manifest.json"
  printf '%s\n' "$manifest" >"$bundle/deploy/docker-compose/manifest.json"
  printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' \
    'stamp="$(dirname "$0")/.jjdguard-offline-verified.tsv"' \
    'grep -Fqx $'"'"'schema\tjjdguard-offline-verified/v2'"'"' "$stamp"' \
    '[[ -n "${INSTALL_MARKER:-}" ]] && : >"$INSTALL_MARKER"' >"$bundle/install.sh"
  chmod 0755 "$bundle/install.sh"
  { printf '%s\0' jjdguard-offline-manifest/v2; cat "$bundle/manifest.json"; } >"$bundle/manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$bundle/manifest.payload" -out "$bundle/manifest.sig"
  rm -f "$bundle/manifest.payload"
  chmod 0444 "$bundle/manifest.sig"
  write_inventory "$bundle"
}

write_run() {
  local bundle="$1" output="$2" work payload payload_sha payload_size header_sig_b64
  work="$tmp/outer-$(basename "$output")"
  mkdir -p "$work"
  payload="$work/payload.tar.gz"
  tar -C "$(dirname "$bundle")" -czf "$payload" "$(basename "$bundle")"
  payload_sha="$(sha "$payload")"
  payload_size="$(stat -c '%s' "$payload")"
  fixture_inner_sha="$payload_sha"
  printf '%s\n' "{\"schema\":\"jjdguard-offline-run-manifest/v2\",\"product\":\"JJDGuard\",\"version\":\"fixture\",\"target_arch\":\"amd64\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"payload_sha256\":\"$payload_sha\",\"payload_size\":$payload_size,\"built_at\":\"2026-08-08T00:00:00Z\"}" >"$work/run-manifest.json"
  { printf '%s\0' jjdguard-offline-run-manifest/v2; cat "$work/run-manifest.json"; } >"$work/run-manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$work/run-manifest.payload" -out "$work/run-manifest.sig"
  tar -C "$work" -cf "$work/outer.tar" payload.tar.gz run-manifest.json run-manifest.sig
  sed "s|__EMBEDDED_PUBLIC_KEY__|$pub_b64|" "$HEADER" >"$output"
  grep -Fqx "EMBEDDED_HEADER_SIGNATURE='__EMBEDDED_HEADER_SIGNATURE__'" "$output" ||
    fail 'fixture header signature placeholder is missing'
  { printf '%s\0' jjdguard-offline-run-header/v1; cat "$output"; } >"$work/header.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$work/header.payload" -out "$work/header.sig"
  header_sig_b64="$(b64 "$work/header.sig")"
  [[ "${#header_sig_b64}" == 88 ]] || fail 'fixture header signature has an unexpected encoding length'
  sed -i "s|__EMBEDDED_HEADER_SIGNATURE__|$header_sig_b64|" "$output"
  grep -Fqx "EMBEDDED_HEADER_SIGNATURE='$header_sig_b64'" "$output" ||
    fail 'fixture header signature injection failed'
  dd if="$work/outer.tar" of="$output" bs=1M oflag=append conv=notrunc status=none
  chmod 0755 "$output"
}

write_payload_run() {
  local input_payload="$1" output="$2" work payload payload_sha payload_size header_sig_b64
  work="$tmp/outer-$(basename "$output")"
  mkdir -p "$work"
  payload="$work/payload.tar.gz"
  cp -- "$input_payload" "$payload"
  payload_sha="$(sha "$payload")"
  payload_size="$(stat -c '%s' "$payload")"
  fixture_inner_sha="$payload_sha"
  printf '%s\n' "{\"schema\":\"jjdguard-offline-run-manifest/v2\",\"product\":\"JJDGuard\",\"version\":\"fixture\",\"target_arch\":\"amd64\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"payload_sha256\":\"$payload_sha\",\"payload_size\":$payload_size,\"built_at\":\"2026-08-08T00:00:00Z\"}" >"$work/run-manifest.json"
  { printf '%s\0' jjdguard-offline-run-manifest/v2; cat "$work/run-manifest.json"; } >"$work/run-manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$work/run-manifest.payload" -out "$work/run-manifest.sig"
  tar -C "$work" -cf "$work/outer.tar" payload.tar.gz run-manifest.json run-manifest.sig
  sed "s|__EMBEDDED_PUBLIC_KEY__|$pub_b64|" "$HEADER" >"$output"
  grep -Fqx "EMBEDDED_HEADER_SIGNATURE='__EMBEDDED_HEADER_SIGNATURE__'" "$output" ||
    fail 'fixture header signature placeholder is missing'
  { printf '%s\0' jjdguard-offline-run-header/v1; cat "$output"; } >"$work/header.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$work/header.payload" -out "$work/header.sig"
  header_sig_b64="$(b64 "$work/header.sig")"
  [[ "${#header_sig_b64}" == 88 ]] || fail 'fixture header signature has an unexpected encoding length'
  sed -i "s|__EMBEDDED_HEADER_SIGNATURE__|$header_sig_b64|" "$output"
  dd if="$work/outer.tar" of="$output" bs=1M oflag=append conv=notrunc status=none
  chmod 0755 "$output"
}

tamper_sealed_header() {
  python3 - "$1" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
old = b"# shellcheck disable=SC2317\n"
new = b"# sealed fixture header mutation\n"
if raw.count(old) != 1:
    raise SystemExit("fixture header mutation target is ambiguous")
path.write_bytes(raw.replace(old, new, 1))
PY
}

copy_sealed_header() {
  local source="$1" output="$2" marker_line
  marker_line="$(grep -a -n '^__JJDGUARD_ARCHIVE_BELOW__$' "$source" | cut -d: -f1)"
  [[ "$marker_line" =~ ^[0-9]+$ ]] || fail 'fixture run marker is ambiguous'
  head -n "$marker_line" "$source" >"$output"
}

resign_inner_manifest() {
  local bundle="$1"
  chmod u+w "$bundle/manifest.sig"
  { printf '%s\0' jjdguard-offline-manifest/v2; cat "$bundle/manifest.json"; } >"$bundle/manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$bundle/manifest.payload" -out "$bundle/manifest.sig"
  rm -f "$bundle/manifest.payload"
  chmod 0444 "$bundle/manifest.sig"
  write_inventory "$bundle"
}

rebind_bundle_provenance() {
  local bundle="$1"
  provenance_sha="$(sha "$bundle/image-provenance.json")"
  python3 - "$bundle" "$provenance_sha" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = sys.argv[2]
for relative in ("manifest.json", "deploy/docker-compose/manifest.json"):
    path = root / relative
    data = json.loads(path.read_text(encoding="utf-8"))
    data["image_provenance_sha256"] = digest
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  resign_inner_manifest "$bundle"
}

write_home_migration_baseline() {
  local output="$1" run="$2" inner="$3"
  python3 - "$output" "$run" "$inner" "$provenance_sha" "$sbom_sha" "$source_revision" "$source_tree" <<'PY'
import hashlib, json, pathlib, sys

output = pathlib.Path(sys.argv[1])
run = pathlib.Path(sys.argv[2])
inner, provenance, sbom, revision, tree = sys.argv[3:]
data = {
    "schema": "jjdguard-home-migration-baseline/v1",
    "artifact": {
        "run_sha256": hashlib.sha256(run.read_bytes()).hexdigest(),
        "run_size": run.stat().st_size,
        "inner_tar_sha256": inner,
    },
    "release": {
        "source_revision": revision,
        "source_tree": tree,
        "image_provenance_sha256": provenance,
        "sbom_index_sha256": sbom,
    },
    "ledgers": [
        {
            "name": "schema_migrations_before",
            "entries": [{"version": "001_fixture.sql", "checksum": "1" * 64}],
        },
        {
            "name": "schema_migrations_after",
            "entries": [
                {"version": "001_fixture.sql", "checksum": "1" * 64},
                {"version": "002_fixture.sql", "checksum": "2" * 64},
            ],
        },
    ],
}
output.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

write_evidence_index() {
  local output="$1" run="$2" inner="$3" include_migration_baseline="${4:-true}" evidence_log baseline=""
  evidence_log="$(dirname "$output")/logs/acceptance-summary.txt"
  mkdir -p "$(dirname "$evidence_log")"
  printf '%s\n' 'fixture acceptance evidence: sanitized' >"$evidence_log"
  case "$include_migration_baseline" in
    true)
      baseline="$(dirname "$output")/home-migration-baseline.json"
      write_home_migration_baseline "$baseline" "$run" "$inner"
      ;;
    false) ;;
    *) fail "unknown migration baseline fixture mode: $include_migration_baseline" ;;
  esac
  python3 - "$output" "$run" "$inner" "$evidence_log" "$baseline" "$provenance_sha" "$sbom_sha" "$source_revision" "$source_tree" <<'PY'
import hashlib, json, pathlib, sys
output = pathlib.Path(sys.argv[1])
run = pathlib.Path(sys.argv[2])
inner, evidence_log, baseline, provenance, sbom, revision, tree = sys.argv[3:]
evidence_log = pathlib.Path(evidence_log)
run_sha = hashlib.sha256(run.read_bytes()).hexdigest()
entries = [{
    "path": "logs/acceptance-summary.txt",
    "sha256": hashlib.sha256(evidence_log.read_bytes()).hexdigest(),
}]
if baseline:
    baseline_path = pathlib.Path(baseline)
    entries.append({
        "path": "home-migration-baseline.json",
        "sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
    })
data = {
    "schema": "jjdguard-acceptance-evidence-index/v1",
    "artifact": {"run_sha256": run_sha, "run_size": run.stat().st_size, "inner_tar_sha256": inner},
    "release": {"source_revision": revision, "source_tree": tree, "image_provenance_sha256": provenance, "sbom_index_sha256": sbom},
    "entries": entries,
}
output.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

mutate_home_migration_baseline() {
  local baseline_path="$1" evidence_index_path="$2" mode="$3"
  python3 - "$baseline_path" "$evidence_index_path" "$mode" <<'PY'
import hashlib
import json
import pathlib
import sys

baseline_path = pathlib.Path(sys.argv[1])
index_path = pathlib.Path(sys.argv[2])
mode = sys.argv[3]
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
ledgers = {ledger["name"]: ledger["entries"] for ledger in baseline["ledgers"]}
after = ledgers["schema_migrations_after"]
if mode == "checksum-rewrite":
    for entry in after:
        if entry["version"] == "001_fixture.sql":
            entry["checksum"] = "3" * 64
            break
    else:
        raise SystemExit("fixture migration checksum rewrite target is missing")
elif mode == "version-deletion":
    after[:] = [entry for entry in after if entry["version"] != "001_fixture.sql"]
    if not after:
        raise SystemExit("fixture migration version deletion emptied the after ledger")
else:
    raise SystemExit("unknown migration baseline mutation")
baseline_path.write_text(
    json.dumps(baseline, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
index = json.loads(index_path.read_text(encoding="utf-8"))
for entry in index["entries"]:
    if entry["path"] == "home-migration-baseline.json":
        entry["sha256"] = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
        break
else:
    raise SystemExit("fixture migration baseline index entry is missing")
index_path.write_text(
    json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
PY
}

write_receipt() {
  local output="$1" run="$2" inner="$3" evidence="$4"
  python3 - "$output" "$run" "$inner" "$evidence" "$provenance_sha" "$sbom_sha" "$source_revision" "$source_tree" <<'PY'
import hashlib, json, pathlib, sys
output = pathlib.Path(sys.argv[1])
run = pathlib.Path(sys.argv[2])
inner = sys.argv[3]
evidence = pathlib.Path(sys.argv[4])
provenance, sbom, revision, tree = sys.argv[5:]
required = (
    "n1-install", "clean-install", "offline-reboot", "upgrade-n1-r7", "rollback-r7-n1",
    "reupgrade-n1-r7", "tamper-run", "tamper-manifest", "tamper-sbom", "tamper-provenance",
    "tamper-receipt", "browser-login", "model-api", "model-stream", "security-benign",
    "security-block", "security-audit", "portal-proxy-idp-chat",
)
data = {
    "schema": "jjdguard-acceptance-receipt/v1",
    "status": "PASS",
    "artifact": {
        "run_sha256": hashlib.sha256(run.read_bytes()).hexdigest(),
        "run_size": run.stat().st_size,
        "inner_tar_sha256": inner,
    },
    "release": {"source_revision": revision, "source_tree": tree, "image_provenance_sha256": provenance, "sbom_index_sha256": sbom},
    "scenarios": {scenario: "PASS" for scenario in required},
    "evidence_index_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
    "non_promotable_reasons": [],
    "completed_at": "2026-08-08T00:00:00Z",
}
output.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

mutate_receipt() {
  local mode="$1" target="$2"
  python3 - "$receipt" "$target" "$mode" <<'PY'
import json, pathlib, sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
mode = sys.argv[3]
data = json.loads(source.read_text(encoding="utf-8"))
if mode == "artifact": data["artifact"]["run_sha256"] = "0" * 64
elif mode == "inner": data["artifact"]["inner_tar_sha256"] = "0" * 64
elif mode == "tree": data["release"]["source_tree"] = "f" * 40
elif mode == "scenario": del data["scenarios"]["browser-login"]
elif mode == "status": data["status"] = "FAIL"
elif mode == "evidence": data["evidence_index_sha256"] = "0" * 64
elif mode == "reasons": data["non_promotable_reasons"] = ["fixture reason"]
else: raise SystemExit("unknown mutation")
target.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

expect_failure() {
  local label="$1"; shift
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "$label unexpectedly succeeded"
  [[ -n "$output" ]] || fail "$label did not report a rejection"
  printf '%s' "$output"
}

mkdir -p "$tmp/fake-bin"
cat >"$tmp/fake-bin/git" <<'EOF'
#!/bin/sh
if [ "${1:-}" = '-C' ] && [ "${3:-}" = 'fetch' ] && \
   [ "${4:-}" = '--quiet' ] && [ "${5:-}" = '--no-tags' ] && \
   [ "${6:-}" = 'origin' ] && [ -n "${FAKE_GIT_LOCAL_RELEASE_REMOTE:-}" ]; then
  exec "$REAL_GIT" -C "$2" fetch --quiet --no-tags \
    "$FAKE_GIT_LOCAL_RELEASE_REMOTE" "${7:?missing refspec}"
fi
case " $* " in
  *' ls-remote '*)
    if [ -n "${FAKE_GIT_MUTATE_CANDIDATE:-}" ]; then
      printf X >>"$FAKE_GIT_MUTATE_CANDIDATE"
    fi
    if [ -n "${FAKE_GIT_MUTATE_FILE:-}" ]; then
      printf X >>"$FAKE_GIT_MUTATE_FILE"
    fi
    if [ "${FAKE_GIT_REQUIRE_GITEE_REMOTE:-0}" = 1 ]; then
      case " $* " in
        *" ${FAKE_GIT_RELEASE_REMOTE:?} refs/heads/main "*) ;;
        *) echo "promotion did not query the authoritative Gitee remote: $*" >&2; exit 91 ;;
      esac
    fi
    if [ -n "${FAKE_GIT_MAIN:-}" ]; then
      printf '%s\trefs/heads/main\n' "$FAKE_GIT_MAIN"
    else
      exec "$REAL_GIT" "$@"
    fi
    ;;
  *) exec "$REAL_GIT" "$@" ;;
esac
EOF
chmod 0755 "$tmp/fake-bin/git"

cat >"$tmp/fake-bin/mv" <<'EOF'
#!/bin/sh
"$REAL_MV" "$@"
status=$?
if [ "$status" -eq 0 ] && [ -n "${FAKE_MV_TAMPER_PUBLISHED_RUN:-}" ]; then
  printf X >>"$FAKE_MV_TAMPER_PUBLISHED_RUN"
fi
exit "$status"
EOF
chmod 0755 "$tmp/fake-bin/mv"

cat >"$tmp/fake-bin/rm" <<'EOF'
#!/bin/sh
if [ -n "${FAKE_RM_FAIL_ONCE_FILE:-}" ] && [ -n "${FAKE_RM_FAIL_TARGET_PREFIX:-}" ]; then
  for argument in "$@"; do
    case "$argument" in
      "$FAKE_RM_FAIL_TARGET_PREFIX"*)
        if [ ! -e "$FAKE_RM_FAIL_ONCE_FILE" ]; then
          : >"$FAKE_RM_FAIL_ONCE_FILE"
          echo 'fixture verification workspace cleanup failure' >&2
          exit 91
        fi
        ;;
    esac
  done
fi
exec "$REAL_RM" "$@"
EOF
chmod 0755 "$tmp/fake-bin/rm"

cat >"$tmp/fake-bin/stat" <<'EOF'
#!/bin/sh
if [ -n "${FAKE_STAT_FOREIGN_OWNER_TARGET:-}" ] && \
  [ "$1" = '-c' ] && [ "$2" = '%u' ] && \
  [ "${3:-}" = "$FAKE_STAT_FOREIGN_OWNER_TARGET" ]; then
  printf '%s\n' "$FAKE_STAT_FOREIGN_OWNER_VALUE"
  exit 0
fi
exec "$REAL_STAT" "$@"
EOF
chmod 0755 "$tmp/fake-bin/stat"

run_promotion() {
  local candidate="$1" receipt_path="$2" evidence_path="$3" key="$4" output="$5" main="${6:-$source_revision}"
  PATH="$tmp/fake-bin:$PATH" FAKE_GIT_MAIN="$main" \
    REAL_GIT="$REAL_GIT" REAL_MV="$REAL_MV" REAL_RM="$REAL_RM" REAL_STAT="$REAL_STAT" \
    FAKE_GIT_RELEASE_REMOTE="$AUTHORITATIVE_GITEE_REMOTE" FAKE_GIT_LOCAL_RELEASE_REMOTE="$fixture_remote" \
    JJD_RELEASE_TESTING=1 JJD_TEST_GITEE_REMOTE="$fixture_remote" \
    FAKE_GIT_REQUIRE_GITEE_REMOTE=1 \
    FAKE_GIT_MUTATE_CANDIDATE="${FAKE_GIT_MUTATE_CANDIDATE:-}" \
    FAKE_GIT_MUTATE_FILE="${FAKE_GIT_MUTATE_FILE:-}" \
    FAKE_MV_TAMPER_PUBLISHED_RUN="${FAKE_MV_TAMPER_PUBLISHED_RUN:-}" \
    FAKE_RM_FAIL_TARGET_PREFIX="${FAKE_RM_FAIL_TARGET_PREFIX:-}" \
    FAKE_RM_FAIL_ONCE_FILE="${FAKE_RM_FAIL_ONCE_FILE:-}" \
    FAKE_STAT_FOREIGN_OWNER_TARGET="${FAKE_STAT_FOREIGN_OWNER_TARGET:-}" \
    FAKE_STAT_FOREIGN_OWNER_VALUE="${FAKE_STAT_FOREIGN_OWNER_VALUE:-}" \
    bash "$PROMOTE" --candidate "$candidate" --receipt "$receipt_path" \
      --evidence-index "$evidence_path" --signing-key "$key" --output "$output"
}

trust_root="$tmp/trust-root"
mkdir -p "$trust_root"
install -m 0644 "$pub" "$trust_root/release-public.pem"

trust_verify() {
  JJD_RELEASE_TESTING=1 "$TRUST_VERIFIER" --trust-root "$trust_root" \
    --release-dir "$1" --verify
}

trust_install_probe="$tmp/trust-install-probe"
cat >"$trust_install_probe" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
  "$JJD_TRUST_ROOT_EXPECTED"/.verify-promoted-*/*) ;;
  *) echo "installer did not receive a private trusted staging copy: $1" >&2; exit 91 ;;
esac
[ -f "$1" ] && [ ! -L "$1" ]
sha256sum "$1" | awk '{print $1}' >"$JJD_TRUST_INSTALL_MARKER"
EOF
chmod 0755 "$trust_install_probe"

trust_install() {
  local release="$1" marker="$2"
  JJD_RELEASE_TESTING=1 JJD_TRUST_TEST_INSTALL_COMMAND="$trust_install_probe" \
    JJD_TRUST_INSTALL_MARKER="$marker" JJD_TRUST_ROOT_EXPECTED="$trust_root" \
    "$TRUST_VERIFIER" --trust-root "$trust_root" --release-dir "$release" --install
}

resign_promoted_sidecar() {
  local release="$1" run_name sidecar signature payload
  run_name="$(basename "$run")"
  sidecar="$release/$run_name.promotion.json"
  signature="$release/$run_name.promotion.sig"
  payload="$tmp/promotion-sidecar.payload"
  chmod u+w "$sidecar" "$signature"
  python3 - "$release" "$run_name" <<'PY'
import hashlib
import json
import pathlib
import sys

release = pathlib.Path(sys.argv[1])
run_name = sys.argv[2]
sidecar_path = release / f"{run_name}.promotion.json"
sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
sidecar["acceptance_receipt_sha256"] = hashlib.sha256(
    (release / "acceptance-receipt.json").read_bytes()
).hexdigest()
sidecar["evidence_index_sha256"] = hashlib.sha256(
    (release / "acceptance-evidence-index.json").read_bytes()
).hexdigest()
sidecar_path.write_text(
    json.dumps(sidecar, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
  { printf '%s\0' 'jjdguard-offline-promotion/v1'; cat "$sidecar"; } >"$payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$payload" -out "$signature" >/dev/null 2>&1 ||
    fail 'fixture promotion sidecar re-signing failed'
  openssl pkeyutl -verify -rawin -pubin -inkey "$pub" -sigfile "$signature" -in "$payload" >/dev/null 2>&1 ||
    fail 'fixture re-signed promotion sidecar is invalid'
  rm -f -- "$payload"
  chmod 0444 "$sidecar" "$signature"
}

rebind_promoted_receipt_evidence_hash() {
  local release="$1" receipt evidence
  receipt="$release/acceptance-receipt.json"
  evidence="$release/acceptance-evidence-index.json"
  chmod u+w "$receipt"
  python3 - "$receipt" "$evidence" <<'PY'
import hashlib
import json
import pathlib
import sys

receipt_path = pathlib.Path(sys.argv[1])
evidence_path = pathlib.Path(sys.argv[2])
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
receipt["evidence_index_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
receipt_path.write_text(
    json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}

expect_promotion_failure() {
  local label="$1" output status
  shift
  set +e
  output="$(run_promotion "$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "$label unexpectedly succeeded"
  [[ -n "$output" ]] || fail "$label did not report a rejection"
}

fixture_root="$tmp/payload/jjdguard-fixture"
make_bundle "$fixture_root"
run="$tmp/JJDGuard-offline-fixture-amd64.run"
write_run "$fixture_root" "$run"
base_fixture_inner_sha="$fixture_inner_sha"
evidence="$tmp/evidence-index.json"
receipt="$tmp/receipt.json"
write_evidence_index "$evidence" "$run" "$base_fixture_inner_sha" true
write_receipt "$receipt" "$run" "$base_fixture_inner_sha" "$evidence"

python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$run" --evidence-index "$evidence" \
  --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null

evidence_log="$tmp/logs/acceptance-summary.txt"
mv "$evidence_log" "$tmp/logs/acceptance-summary.missing"
expect_failure 'missing indexed evidence file' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$run" --evidence-index "$evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null
mv "$tmp/logs/acceptance-summary.missing" "$evidence_log"
printf X >>"$evidence_log"
expect_failure 'indexed evidence hash drift' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$run" --evidence-index "$evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null
printf '%s\n' 'fixture acceptance evidence: sanitized' >"$evidence_log"

# This receipt is otherwise fully valid: the candidate header and both
# manifests are signed, the source identity is trusted, and every required
# acceptance scenario is PASS. A home recovery baseline is nevertheless a
# mandatory part of a promotable formal receipt.
missing_baseline_evidence="$tmp/evidence-index-missing-migration-baseline.json"
missing_baseline_receipt="$tmp/receipt-missing-migration-baseline.json"
write_evidence_index "$missing_baseline_evidence" "$run" "$fixture_inner_sha" false
write_receipt "$missing_baseline_receipt" "$run" "$fixture_inner_sha" "$missing_baseline_evidence"
missing_baseline_final="$tmp/final-missing-migration-baseline"
set +e
missing_baseline_promotion_output="$(run_promotion "$run" "$missing_baseline_receipt" "$missing_baseline_evidence" "$priv" "$missing_baseline_final" 2>&1)"
missing_baseline_promotion_status=$?
set -e
if [[ "$missing_baseline_promotion_status" == 0 ]]; then
  set +e
  missing_baseline_trust_output="$(trust_verify "$missing_baseline_final" 2>&1)"
  missing_baseline_trust_status=$?
  set -e
  [[ "$missing_baseline_trust_status" != 0 ]] ||
    fail 'missing migration baseline was accepted by promotion and final trust verification'
  fail "missing migration baseline candidate was accepted by promotion: $missing_baseline_promotion_output"
fi
[[ "$missing_baseline_promotion_output" == *'home migration baseline'* ]] ||
  fail "missing migration baseline promotion was rejected for the wrong reason: $missing_baseline_promotion_output"
[[ ! -e "$missing_baseline_final" ]] ||
  fail 'missing migration baseline promotion left a final directory behind'

# The run, source identity, evidence hash and acceptance receipt are all valid
# here. Promotion must still reject a baseline that claims an impossible
# migration history: existing migration rows cannot be rewritten or removed.
for ledger_mutation in checksum-rewrite version-deletion; do
  ledger_evidence_root="$tmp/migration-ledger-$ledger_mutation"
  ledger_evidence="$ledger_evidence_root/evidence-index.json"
  ledger_receipt="$tmp/receipt-migration-ledger-$ledger_mutation.json"
  ledger_final="$tmp/final-migration-ledger-$ledger_mutation"
  mkdir -p "$ledger_evidence_root"
  write_evidence_index "$ledger_evidence" "$run" "$fixture_inner_sha" true
  mutate_home_migration_baseline "$ledger_evidence_root/home-migration-baseline.json" \
    "$ledger_evidence" "$ledger_mutation"
  write_receipt "$ledger_receipt" "$run" "$fixture_inner_sha" "$ledger_evidence"
  ledger_receipt_output="$(expect_failure "migration ledger $ledger_mutation receipt verification" \
    python3 "$VERIFY" --public-key "$pub" --receipt "$ledger_receipt" --artifact "$run" \
      --evidence-index "$ledger_evidence" --source-repository "$source_repository" \
      --authoritative-remote "$release_remote")"
  [[ "$ledger_receipt_output" == *'after ledger does not preserve before migration'* ]] ||
    fail "migration ledger $ledger_mutation receipt was rejected for the wrong reason: $ledger_receipt_output"
  ledger_promotion_output="$(expect_failure "migration ledger $ledger_mutation promotion" \
    run_promotion "$run" "$ledger_receipt" "$ledger_evidence" "$priv" "$ledger_final")"
  [[ "$ledger_promotion_output" == *'after ledger does not preserve before migration'* ]] ||
    fail "migration ledger $ledger_mutation promotion was rejected for the wrong reason: $ledger_promotion_output"
  [[ ! -e "$ledger_final" ]] ||
    fail "migration ledger $ledger_mutation promotion left a final directory behind"
done

snapshot_collision_root="$tmp/snapshot-collision"
mkdir -p "$snapshot_collision_root/logs"
printf '%s\n' 'pre-existing snapshot fixture' >"$snapshot_collision_root/logs/acceptance-summary.txt"
snapshot_collision_sha="$(sha "$snapshot_collision_root/logs/acceptance-summary.txt")"
snapshot_collision_probe="$tmp/snapshot-collision.py"
cat >"$snapshot_collision_probe" <<'PY'
import importlib.util
import os
import pathlib

spec = importlib.util.spec_from_file_location(
    "acceptance_receipt_verifier", os.environ["VERIFY_SCRIPT"]
)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load acceptance verifier fixture")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
source = pathlib.Path(os.environ["SNAPSHOT_SOURCE"])
snapshot_root = pathlib.Path(os.environ["SNAPSHOT_ROOT"])
module.snapshot_evidence_file(
    source,
    source.stat().st_size,
    snapshot_root,
    ("logs", "acceptance-summary.txt"),
    "fixture evidence",
)
raise SystemExit("snapshot collision unexpectedly succeeded")
PY
snapshot_collision_output="$(expect_failure 'pre-existing evidence snapshot file' \
  env VERIFY_SCRIPT="$VERIFY" SNAPSHOT_SOURCE="$evidence_log" SNAPSHOT_ROOT="$snapshot_collision_root" \
  python3 "$snapshot_collision_probe")"
if [[ "$snapshot_collision_output" == *'Traceback (most recent call last):'* ]]; then
  fail "snapshot collision raised a Python traceback instead of a standard rejection: $snapshot_collision_output"
fi
[[ "$snapshot_collision_output" == *'[error] acceptance receipt rejected: cannot create evidence snapshot file:'* ]] ||
  fail "snapshot collision did not report a standard rejection: $snapshot_collision_output"
[[ "$(sha "$snapshot_collision_root/logs/acceptance-summary.txt")" == "$snapshot_collision_sha" ]] ||
  fail 'snapshot collision changed the pre-existing destination file'

duplicate_evidence="$tmp/evidence-duplicate-path.json"
python3 - "$evidence" "$duplicate_evidence" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
data = json.loads(source.read_text(encoding="utf-8"))
data["entries"].append(dict(data["entries"][0]))
target.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
duplicate_evidence_output="$(expect_failure 'duplicate indexed evidence path' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$run" --evidence-index "$duplicate_evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote")"
[[ "$duplicate_evidence_output" == *'duplicate paths'* ]] ||
  fail "duplicate evidence path was not rejected before receipt binding: $duplicate_evidence_output"

alias_evidence="$tmp/evidence-alias-path.json"
python3 - "$evidence" "$alias_evidence" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
data = json.loads(source.read_text(encoding="utf-8"))
data["entries"][0]["path"] = "logs/./acceptance-summary.txt"
target.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
alias_evidence_output="$(expect_failure 'non-canonical indexed evidence path' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$run" --evidence-index "$alias_evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote")"
[[ "$alias_evidence_output" == *'not canonical'* ]] ||
  fail "non-canonical evidence path was not rejected before receipt binding: $alias_evidence_output"

saved_provenance_sha="$provenance_sha"
saved_fixture_inner_sha="$fixture_inner_sha"
bad_toolchain_root="$tmp/bad-provenance-toolchain/jjdguard-fixture"
mkdir -p "$(dirname "$bad_toolchain_root")"
cp -a "$fixture_root" "$bad_toolchain_root"
python3 - "$bad_toolchain_root/image-provenance.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["toolchain"] = {}
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_bundle_provenance "$bad_toolchain_root"
bad_toolchain_run="$tmp/JJDGuard-offline-bad-provenance-toolchain-amd64.run"
write_run "$bad_toolchain_root" "$bad_toolchain_run"
bad_toolchain_evidence="$tmp/evidence-bad-provenance-toolchain.json"
bad_toolchain_receipt="$tmp/receipt-bad-provenance-toolchain.json"
write_evidence_index "$bad_toolchain_evidence" "$bad_toolchain_run" "$fixture_inner_sha"
write_receipt "$bad_toolchain_receipt" "$bad_toolchain_run" "$fixture_inner_sha" "$bad_toolchain_evidence"
expect_promotion_failure 'promotion with an incomplete image build toolchain' \
  "$bad_toolchain_run" "$bad_toolchain_receipt" "$bad_toolchain_evidence" "$priv" "$tmp/final-bad-provenance-toolchain"

bad_catalog_root="$tmp/bad-provenance-catalog/jjdguard-fixture"
mkdir -p "$(dirname "$bad_catalog_root")"
cp -a "$fixture_root" "$bad_catalog_root"
python3 - "$bad_catalog_root/image-provenance.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["images"][0]["runtime_tag"] = "untrusted/fixture:1"
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_bundle_provenance "$bad_catalog_root"
bad_catalog_run="$tmp/JJDGuard-offline-bad-provenance-catalog-amd64.run"
write_run "$bad_catalog_root" "$bad_catalog_run"
bad_catalog_evidence="$tmp/evidence-bad-provenance-catalog.json"
bad_catalog_receipt="$tmp/receipt-bad-provenance-catalog.json"
write_evidence_index "$bad_catalog_evidence" "$bad_catalog_run" "$fixture_inner_sha"
write_receipt "$bad_catalog_receipt" "$bad_catalog_run" "$fixture_inner_sha" "$bad_catalog_evidence"
expect_promotion_failure 'promotion with provenance that drifts from the authoritative image catalog' \
  "$bad_catalog_run" "$bad_catalog_receipt" "$bad_catalog_evidence" "$priv" "$tmp/final-bad-provenance-catalog"

bad_source_blob_root="$tmp/bad-provenance-source-blob/jjdguard-fixture"
mkdir -p "$(dirname "$bad_source_blob_root")"
cp -a "$fixture_root" "$bad_source_blob_root"
python3 - "$bad_source_blob_root/image-provenance.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["images"][1]["source_blobs"]["enterprise-ai-portal/Dockerfile"] = "0" * 40
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_bundle_provenance "$bad_source_blob_root"
bad_source_blob_run="$tmp/JJDGuard-offline-bad-provenance-source-blob-amd64.run"
write_run "$bad_source_blob_root" "$bad_source_blob_run"
bad_source_blob_evidence="$tmp/evidence-bad-provenance-source-blob.json"
bad_source_blob_receipt="$tmp/receipt-bad-provenance-source-blob.json"
write_evidence_index "$bad_source_blob_evidence" "$bad_source_blob_run" "$fixture_inner_sha"
write_receipt "$bad_source_blob_receipt" "$bad_source_blob_run" "$fixture_inner_sha" "$bad_source_blob_evidence"
expect_promotion_failure 'promotion with source-built provenance that drifts from its Dockerfile blob' \
  "$bad_source_blob_run" "$bad_source_blob_receipt" "$bad_source_blob_evidence" "$priv" "$tmp/final-bad-provenance-source-blob"
provenance_sha="$saved_provenance_sha"
fixture_inner_sha="$saved_fixture_inner_sha"

saved_provenance_sha="$provenance_sha"
saved_fixture_inner_sha="$fixture_inner_sha"
bad_task4_root="$tmp/bad-task4-build-engine/jjdguard-fixture"
mkdir -p "$(dirname "$bad_task4_root")"
cp -a "$fixture_root" "$bad_task4_root"
python3 - "$bad_task4_root" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
receipt_path = root / "task4/portal-image-receipt.json"
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
receipt["build_engine"]["docker_client_version"] = "Docker Task4 mismatch"
receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

provenance_path = root / "image-provenance.json"
provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
portal = next(image for image in provenance["images"] if image["component"] == "enterprise-ai-portal")
portal["legacy_receipt"]["sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
provenance_path.write_text(
    json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
PY
rebind_bundle_provenance "$bad_task4_root"
bad_task4_run="$tmp/JJDGuard-offline-bad-task4-build-engine-amd64.run"
write_run "$bad_task4_root" "$bad_task4_run"
bad_task4_evidence="$tmp/evidence-bad-task4-build-engine.json"
bad_task4_receipt="$tmp/receipt-bad-task4-build-engine.json"
write_evidence_index "$bad_task4_evidence" "$bad_task4_run" "$fixture_inner_sha"
write_receipt "$bad_task4_receipt" "$bad_task4_run" "$fixture_inner_sha" "$bad_task4_evidence"
expect_promotion_failure 'promotion with a Task4 receipt build-engine mismatch' \
  "$bad_task4_run" "$bad_task4_receipt" "$bad_task4_evidence" "$priv" "$tmp/final-bad-task4-build-engine"
provenance_sha="$saved_provenance_sha"
fixture_inner_sha="$saved_fixture_inner_sha"

saved_fixture_remote="$fixture_remote"
saved_source_revision="$source_revision"
saved_source_tree="$source_tree"
saved_source_archive_sha="$source_archive_sha"
saved_fixture_dockerfile_blob="$fixture_dockerfile_blob"
saved_provenance_sha="$provenance_sha"
saved_sbom_sha="$sbom_sha"
saved_fixture_inner_sha="$fixture_inner_sha"
parser_source_checkout="$tmp/gitee-fetched-parser-source"
cp -a "$source_checkout" "$parser_source_checkout"
fetched_parser_marker="$tmp/fetched-parser-executed"
parser_base_digest="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
parser_base_images="$(jq -cn --arg digest "$parser_base_digest" \
  '[{from_index:0,stage:null,reference:("fixture/base:1@" + $digest),digest:$digest}]')"
python3 - "$parser_source_checkout" "$fetched_parser_marker" "$parser_base_digest" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
marker = pathlib.Path(sys.argv[2])
digest = sys.argv[3]
reference = f"fixture/base:1@{digest}"
(source / "enterprise-ai-portal/Dockerfile").write_text(
    f"FROM {reference}\n", encoding="utf-8"
)
(source / "deploy/docker-compose/dockerfile-base-images.py").write_text(
    "import pathlib\n"
    f"pathlib.Path({str(marker)!r}).write_text('executed', encoding='ascii')\n"
    "def parse_dockerfile(text, source):\n"
    f"    return [{{'from_index': 0, 'stage': None, 'reference': {reference!r}, 'digest': {digest!r}}}]\n",
    encoding="utf-8",
)
PY
git -C "$parser_source_checkout" add enterprise-ai-portal/Dockerfile deploy/docker-compose/dockerfile-base-images.py
git -C "$parser_source_checkout" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit -q -m 'fixture fetched Dockerfile parser'
fixture_remote="$tmp/gitee-fetched-parser-release.git"
git clone -q --bare "$parser_source_checkout" "$fixture_remote"
source_revision="$(git -C "$parser_source_checkout" rev-parse HEAD)"
source_tree="$(git -C "$parser_source_checkout" rev-parse 'HEAD^{tree}')"
fixture_dockerfile_blob="$(git -C "$parser_source_checkout" rev-parse 'HEAD:enterprise-ai-portal/Dockerfile')"
git -C "$parser_source_checkout" archive --format=tar --prefix=source/ HEAD >"$tmp/authoritative-parser-source.tar"
source_archive_sha="$(sha "$tmp/authoritative-parser-source.tar")"
parser_root="$tmp/fetched-parser-payload/jjdguard-fixture"
mkdir -p "$(dirname "$parser_root")"
make_bundle "$parser_root" "$parser_base_images"
parser_run="$tmp/JJDGuard-offline-fetched-parser-amd64.run"
write_run "$parser_root" "$parser_run"
parser_evidence="$tmp/evidence-fetched-parser.json"
parser_receipt="$tmp/receipt-fetched-parser.json"
write_evidence_index "$parser_evidence" "$parser_run" "$fixture_inner_sha"
write_receipt "$parser_receipt" "$parser_run" "$fixture_inner_sha" "$parser_evidence"
if ! run_promotion "$parser_run" "$parser_receipt" "$parser_evidence" "$priv" "$tmp/final-fetched-parser"; then
  fail 'promotion rejected the accepted revision Dockerfile base image contract'
fi
[[ ! -e "$fetched_parser_marker" ]] ||
  fail 'promotion executed the fetched Dockerfile parser source'
fixture_remote="$saved_fixture_remote"
source_revision="$saved_source_revision"
source_tree="$saved_source_tree"
source_archive_sha="$saved_source_archive_sha"
fixture_dockerfile_blob="$saved_fixture_dockerfile_blob"
provenance_sha="$saved_provenance_sha"
sbom_sha="$saved_sbom_sha"
fixture_inner_sha="$saved_fixture_inner_sha"

oversized_outer="$tmp/oversized-outer.tar"
python3 - "$oversized_outer" <<'PY'
import pathlib
import tarfile
import sys

output = pathlib.Path(sys.argv[1])
member = tarfile.TarInfo("payload.tar.gz")
member.mode = 0o644
member.size = 64 * 1024 * 1024 * 1024 + 1
output.write_bytes(member.tobuf(format=tarfile.GNU_FORMAT) + b"\0" * 1024)
PY
oversized_run="$tmp/JJDGuard-offline-oversized-outer-amd64.run"
copy_sealed_header "$run" "$oversized_run"
dd if="$oversized_outer" of="$oversized_run" bs=1M oflag=append conv=notrunc status=none
oversized_output="$(expect_failure 'oversized outer payload' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$oversized_run" --evidence-index "$evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote")"
[[ "$oversized_output" == *'run outer member is unsafe'* ]] ||
  fail "oversized outer payload was not rejected before streaming: $oversized_output"

sparse_outer_work="$tmp/sparse-outer-work"
mkdir -p "$sparse_outer_work"
truncate -s $((64 * 1024 * 1024 * 1024 + 1)) "$sparse_outer_work/payload.tar.gz"
printf X | dd of="$sparse_outer_work/payload.tar.gz" bs=1 count=1 conv=notrunc status=none
cp "$tmp/outer-$(basename "$run")/run-manifest.json" "$sparse_outer_work/run-manifest.json"
cp "$tmp/outer-$(basename "$run")/run-manifest.sig" "$sparse_outer_work/run-manifest.sig"
sparse_outer="$tmp/sparse-outer.tar"
tar --sparse -C "$sparse_outer_work" -cf "$sparse_outer" payload.tar.gz run-manifest.json run-manifest.sig
python3 - "$sparse_outer" <<'PY'
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:") as archive:
    member = archive.next()
    if member is None or not member.issparse():
        raise SystemExit("fixture did not encode a sparse outer payload")
PY
sparse_run="$tmp/JJDGuard-offline-sparse-outer-amd64.run"
copy_sealed_header "$run" "$sparse_run"
dd if="$sparse_outer" of="$sparse_run" bs=1M oflag=append conv=notrunc status=none
sparse_output="$(expect_failure 'sparse outer payload' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$sparse_run" --evidence-index "$evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote")"
[[ "$sparse_output" == *'tar extension records are forbidden'* ]] ||
  fail "sparse outer payload was not rejected before extension parsing: $sparse_output"

pax_outer="$tmp/pax-outer.tar"
python3 - "$tmp/outer-$(basename "$run")" "$pax_outer" <<'PY'
import io
import pathlib
import sys
import tarfile

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with tarfile.open(output, "w", format=tarfile.GNU_FORMAT) as archive:
    extension = tarfile.TarInfo("PaxHeader")
    extension.type = tarfile.XHDTYPE
    extension.mode = 0o644
    extension.size = 1024 * 1024
    archive.addfile(extension, io.BytesIO(b"\0" * extension.size))
    for name in ("payload.tar.gz", "run-manifest.json", "run-manifest.sig"):
        archive.add(source / name, arcname=name, recursive=False)
PY
pax_outer_run="$tmp/JJDGuard-offline-pax-outer-amd64.run"
copy_sealed_header "$run" "$pax_outer_run"
dd if="$pax_outer" of="$pax_outer_run" bs=1M oflag=append conv=notrunc status=none
pax_outer_evidence="$tmp/evidence-pax-outer.json"
pax_outer_receipt="$tmp/receipt-pax-outer.json"
write_evidence_index "$pax_outer_evidence" "$pax_outer_run" "$fixture_inner_sha"
write_receipt "$pax_outer_receipt" "$pax_outer_run" "$fixture_inner_sha" "$pax_outer_evidence"
pax_outer_output="$(expect_failure 'acceptance verifier outer PAX extension' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$pax_outer_receipt" --artifact "$pax_outer_run" \
    --evidence-index "$pax_outer_evidence" --source-repository "$source_repository" \
    --authoritative-remote "$release_remote")"
[[ "$pax_outer_output" == *'tar extension records are forbidden'* ]] ||
  fail "acceptance verifier did not reject a PAX extension before payload parsing: $pax_outer_output"

for mutation in artifact inner tree scenario status evidence reasons; do
  bad="$tmp/receipt-$mutation.json"
  mutate_receipt "$mutation" "$bad"
  expect_failure "receipt $mutation mutation" \
    python3 "$VERIFY" --public-key "$pub" --receipt "$bad" --artifact "$run" --evidence-index "$evidence" \
      --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null
done

original_inner_sha="$fixture_inner_sha"
python3 - "$fixture_root" "$tmp/acceptance-inner-alias.tar.gz" <<'PY'
import io
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with tarfile.open(output, "w:gz", format=tarfile.GNU_FORMAT) as archive:
    archive.add(root, arcname=root.name)
    payload = b"#!/usr/bin/env bash\necho overwritten\n"
    member = tarfile.TarInfo(f"{root.name}/./install.sh")
    member.mode = 0o755
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))
PY
acceptance_alias_run="$tmp/JJDGuard-offline-inner-alias-amd64.run"
write_payload_run "$tmp/acceptance-inner-alias.tar.gz" "$acceptance_alias_run"
acceptance_alias_evidence="$tmp/evidence-inner-alias.json"
acceptance_alias_receipt="$tmp/receipt-inner-alias.json"
write_evidence_index "$acceptance_alias_evidence" "$acceptance_alias_run" "$fixture_inner_sha"
write_receipt "$acceptance_alias_receipt" "$acceptance_alias_run" "$fixture_inner_sha" "$acceptance_alias_evidence"
acceptance_alias_output="$(expect_failure 'acceptance verifier inner path alias' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_alias_receipt" --artifact "$acceptance_alias_run" \
    --evidence-index "$acceptance_alias_evidence" --source-repository "$source_repository" \
    --authoritative-remote "$release_remote")"
[[ "$acceptance_alias_output" == *'inner bundle member is unsafe'* ]] ||
  fail "acceptance verifier did not reject the inner path alias explicitly: $acceptance_alias_output"

python3 - "$fixture_root" "$tmp/acceptance-inner-oversized.tar.gz" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
payload = io.BytesIO()
with tarfile.open(fileobj=payload, mode="w", format=tarfile.GNU_FORMAT) as archive:
    archive.add(root, arcname=root.name)
    member = tarfile.TarInfo(f"{root.name}/oversized-payload.bin")
    member.mode = 0o644
    member.size = 8 * 1024 * 1024 * 1024 + 1
raw = payload.getvalue()
while raw.endswith(b"\0" * 512):
    raw = raw[:-512]
if not raw:
    raise SystemExit("fixture tar lost its regular members")
raw += b"\0" * ((-len(raw)) % 512)
with gzip.open(output, "wb") as archive:
    archive.write(raw)
    archive.write(member.tobuf(format=tarfile.GNU_FORMAT))
    archive.write(b"\0" * 1024)
PY
acceptance_oversized_run="$tmp/JJDGuard-offline-inner-oversized-amd64.run"
write_payload_run "$tmp/acceptance-inner-oversized.tar.gz" "$acceptance_oversized_run"
acceptance_oversized_evidence="$tmp/evidence-inner-oversized.json"
acceptance_oversized_receipt="$tmp/receipt-inner-oversized.json"
write_evidence_index "$acceptance_oversized_evidence" "$acceptance_oversized_run" "$fixture_inner_sha"
write_receipt "$acceptance_oversized_receipt" "$acceptance_oversized_run" "$fixture_inner_sha" "$acceptance_oversized_evidence"
acceptance_oversized_output="$(expect_failure 'acceptance verifier oversized inner member' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_oversized_receipt" --artifact "$acceptance_oversized_run" \
    --evidence-index "$acceptance_oversized_evidence" --source-repository "$source_repository" \
    --authoritative-remote "$release_remote")"
[[ "$acceptance_oversized_output" == *'inner bundle member exceeds the size limit'* ]] ||
  fail "acceptance verifier did not reject the oversized member before extraction: $acceptance_oversized_output"

python3 - "$fixture_root" "$tmp/acceptance-inner-pax.tar.gz" <<'PY'
import io
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with tarfile.open(output, "w:gz", format=tarfile.GNU_FORMAT) as archive:
    extension = tarfile.TarInfo("PaxHeader")
    extension.type = tarfile.XHDTYPE
    extension.mode = 0o644
    extension.size = 1024 * 1024
    archive.addfile(extension, io.BytesIO(b"\0" * extension.size))
    archive.add(root, arcname=root.name)
PY
acceptance_pax_run="$tmp/JJDGuard-offline-inner-pax-amd64.run"
write_payload_run "$tmp/acceptance-inner-pax.tar.gz" "$acceptance_pax_run"
acceptance_pax_evidence="$tmp/evidence-inner-pax.json"
acceptance_pax_receipt="$tmp/receipt-inner-pax.json"
write_evidence_index "$acceptance_pax_evidence" "$acceptance_pax_run" "$fixture_inner_sha"
write_receipt "$acceptance_pax_receipt" "$acceptance_pax_run" "$fixture_inner_sha" "$acceptance_pax_evidence"
acceptance_pax_output="$(expect_failure 'acceptance verifier inner PAX extension' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_pax_receipt" --artifact "$acceptance_pax_run" \
    --evidence-index "$acceptance_pax_evidence" --source-repository "$source_repository" \
    --authoritative-remote "$release_remote")"
[[ "$acceptance_pax_output" == *'tar extension records are forbidden'* ]] ||
  fail "acceptance verifier did not reject an inner PAX extension before decompression: $acceptance_pax_output"
[[ "$acceptance_pax_output" != *Traceback* ]] ||
  fail "acceptance verifier inner PAX rejection leaked a traceback: $acceptance_pax_output"

# The accepted release verifier must not let tarfile r|gz prefetch a
# high-compression PAX body before the extension type gate rejects it.
gzip_guard="$tmp/acceptance-gzip-boundary-guard"
mkdir -p "$gzip_guard"
cat >"$gzip_guard/sitecustomize.py" <<'PY'
import gzip
import os
import pathlib

marker = os.environ.get("JJD_GZIP_BOUNDARY_MARKER")
original_gzip_file = gzip.GzipFile
original_read = gzip._GzipReader.read


class GuardedGzipFile(original_gzip_file):
    def __init__(self, *args, **kwargs):
        if marker:
            pathlib.Path(marker).write_text("gzip.GzipFile\n", encoding="ascii")
        super().__init__(*args, **kwargs)


def bounded_read(self, size=-1):
    if size < 0 or size > 256 * 1024:
        raise OSError(f"gzip reader request exceeds boundary: {size}")
    return original_read(self, size)


gzip.GzipFile = GuardedGzipFile
gzip._GzipReader.read = bounded_read
PY

python3 - "$fixture_root" "$tmp/acceptance-inner-pax-boundary.tar.gz" <<'PY'
import io
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with tarfile.open(output, "w:gz", format=tarfile.GNU_FORMAT) as archive:
    archive.add(root, arcname=root.name)
    extension = tarfile.TarInfo("PaxHeader")
    extension.type = tarfile.XHDTYPE
    extension.mode = 0o644
    extension.size = 32 * 1024 * 1024
    archive.addfile(extension, io.BytesIO(b"\0" * extension.size))
PY
acceptance_pax_boundary_run="$tmp/JJDGuard-offline-inner-pax-boundary-amd64.run"
write_payload_run "$tmp/acceptance-inner-pax-boundary.tar.gz" "$acceptance_pax_boundary_run"
acceptance_pax_boundary_evidence="$tmp/evidence-inner-pax-boundary.json"
acceptance_pax_boundary_receipt="$tmp/receipt-inner-pax-boundary.json"
write_evidence_index "$acceptance_pax_boundary_evidence" "$acceptance_pax_boundary_run" "$fixture_inner_sha"
write_receipt "$acceptance_pax_boundary_receipt" "$acceptance_pax_boundary_run" "$fixture_inner_sha" "$acceptance_pax_boundary_evidence"
gzip_marker="$tmp/acceptance-inner-pax-boundary.marker"
declare -a acceptance_gzip_boundary_failures=()
set +e
acceptance_pax_boundary_output="$(PYTHONPATH="$gzip_guard${PYTHONPATH:+:$PYTHONPATH}" \
  JJD_GZIP_BOUNDARY_MARKER="$gzip_marker" \
  python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_pax_boundary_receipt" \
    --artifact "$acceptance_pax_boundary_run" --evidence-index "$acceptance_pax_boundary_evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote" 2>&1)"
acceptance_pax_boundary_status=$?
set -e
[[ "$acceptance_pax_boundary_status" -ne 0 ]] ||
  acceptance_gzip_boundary_failures+=('high-compression acceptance PAX extension unexpectedly succeeded')
[[ "$acceptance_pax_boundary_output" == *'tar extension records are forbidden'* ]] ||
  acceptance_gzip_boundary_failures+=("high-compression acceptance PAX rejection drifted: $acceptance_pax_boundary_output")
[[ "$acceptance_pax_boundary_output" != *Traceback* ]] ||
  acceptance_gzip_boundary_failures+=("high-compression acceptance PAX rejection leaked a traceback: $acceptance_pax_boundary_output")
[[ -s "$gzip_marker" ]] ||
  acceptance_gzip_boundary_failures+=('acceptance PAX rejection bypassed gzip.GzipFile boundary reader')
if grep -Fq 'mode="r|gz"' "$VERIFY" ||
  ! grep -Fq 'gzip.GzipFile(fileobj=source, mode="rb")' "$VERIFY"; then
  acceptance_gzip_boundary_failures+=('acceptance verifier regressed to tarfile r|gz inner parsing')
fi

python3 - "$tmp/outer-$(basename "$run")/payload.tar.gz" "$tmp/acceptance-inner-gzip-zero-tail.tar.gz" <<'PY'
import gzip
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with gzip.open(source, "rb") as archive:
    payload = archive.read()
if len(payload) < 1024:
    raise SystemExit("fixture inner tar is unexpectedly short")
with gzip.open(output, "wb") as archive:
    archive.write(payload)
    archive.write(b"\0" * (32 * 1024 * 1024))
PY
acceptance_zero_tail_run="$tmp/JJDGuard-offline-inner-gzip-zero-tail-amd64.run"
write_payload_run "$tmp/acceptance-inner-gzip-zero-tail.tar.gz" "$acceptance_zero_tail_run"
acceptance_zero_tail_evidence="$tmp/evidence-inner-gzip-zero-tail.json"
acceptance_zero_tail_receipt="$tmp/receipt-inner-gzip-zero-tail.json"
write_evidence_index "$acceptance_zero_tail_evidence" "$acceptance_zero_tail_run" "$fixture_inner_sha"
write_receipt "$acceptance_zero_tail_receipt" "$acceptance_zero_tail_run" "$fixture_inner_sha" "$acceptance_zero_tail_evidence"
acceptance_zero_tail_output="$(expect_failure 'acceptance verifier inner zero tail' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_zero_tail_receipt" \
    --artifact "$acceptance_zero_tail_run" --evidence-index "$acceptance_zero_tail_evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote")"
[[ "$acceptance_zero_tail_output" == *'inner bundle is invalid: inner bundle trailing tar padding exceeds the size limit'* ]] ||
  fail "acceptance verifier inner zero-tail rejection drifted: $acceptance_zero_tail_output"
[[ "$acceptance_zero_tail_output" != *Traceback* ]] ||
  fail "acceptance verifier inner zero-tail rejection leaked a traceback: $acceptance_zero_tail_output"

python3 - "$tmp/outer-$(basename "$run")/payload.tar.gz" "$tmp/acceptance-inner-single-zero.tar.gz" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with gzip.open(source, "rb") as archive:
    raw = archive.read()
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
    data_end = 0
    for member in archive:
        data_end = max(data_end, member.offset_data + ((member.size + 511) // 512) * 512)
if raw[data_end:data_end + 1024] != b"\0" * 1024:
    raise SystemExit("fixture inner tar does not have a canonical end marker")
with gzip.open(output, "wb") as archive:
    archive.write(raw[:data_end] + b"\0" * 512)
PY
acceptance_single_zero_run="$tmp/JJDGuard-offline-inner-single-zero-amd64.run"
write_payload_run "$tmp/acceptance-inner-single-zero.tar.gz" "$acceptance_single_zero_run"
acceptance_single_zero_evidence="$tmp/evidence-inner-single-zero.json"
acceptance_single_zero_receipt="$tmp/receipt-inner-single-zero.json"
write_evidence_index "$acceptance_single_zero_evidence" "$acceptance_single_zero_run" "$fixture_inner_sha"
write_receipt "$acceptance_single_zero_receipt" "$acceptance_single_zero_run" "$fixture_inner_sha" "$acceptance_single_zero_evidence"
acceptance_single_zero_output_dir="$tmp/final-inner-single-zero"
set +e
acceptance_single_zero_output="$(run_promotion "$acceptance_single_zero_run" "$acceptance_single_zero_receipt" \
  "$acceptance_single_zero_evidence" "$priv" "$acceptance_single_zero_output_dir" 2>&1)"
acceptance_single_zero_status=$?
set -e
[[ "$acceptance_single_zero_status" -ne 0 ]] ||
  fail 'promotion accepted a single-zero inner tar end marker'
[[ "$acceptance_single_zero_output" == *'inner tar end marker is truncated'* ]] ||
  fail "single-zero promotion rejection did not reach strict inner tar parsing: $acceptance_single_zero_output"
[[ "$acceptance_single_zero_output" != *Traceback* ]] ||
  fail "single-zero promotion rejection leaked a traceback: $acceptance_single_zero_output"
[[ ! -e "$acceptance_single_zero_output_dir" ]] ||
  fail 'single-zero inner tar created a promoted output'

for gzip_mutation in crc trunc; do
  python3 - "$tmp/outer-$(basename "$run")/payload.tar.gz" "$tmp/acceptance-inner-gzip-$gzip_mutation.tar.gz" "$gzip_mutation" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
mutation = sys.argv[3]
payload = bytearray(source.read_bytes())
if len(payload) < 18:
    raise SystemExit("fixture gzip payload is too short")
if mutation == "crc":
    payload[-8] ^= 1
elif mutation == "trunc":
    del payload[-8:]
else:
    raise SystemExit(f"unknown gzip mutation: {mutation}")
output.write_bytes(payload)
PY
  acceptance_gzip_run="$tmp/JJDGuard-offline-inner-gzip-$gzip_mutation-amd64.run"
  write_payload_run "$tmp/acceptance-inner-gzip-$gzip_mutation.tar.gz" "$acceptance_gzip_run"
  acceptance_gzip_evidence="$tmp/evidence-inner-gzip-$gzip_mutation.json"
  acceptance_gzip_receipt="$tmp/receipt-inner-gzip-$gzip_mutation.json"
  write_evidence_index "$acceptance_gzip_evidence" "$acceptance_gzip_run" "$fixture_inner_sha"
  write_receipt "$acceptance_gzip_receipt" "$acceptance_gzip_run" "$fixture_inner_sha" "$acceptance_gzip_evidence"
  set +e
  acceptance_gzip_output="$(python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_gzip_receipt" \
    --artifact "$acceptance_gzip_run" --evidence-index "$acceptance_gzip_evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote" 2>&1)"
  acceptance_gzip_status=$?
  set -e
  [[ "$acceptance_gzip_status" -ne 0 ]] ||
    acceptance_gzip_boundary_failures+=("$gzip_mutation-corrupted acceptance gzip unexpectedly succeeded")
  [[ "$acceptance_gzip_output" == *'inner bundle is invalid:'* ]] ||
    acceptance_gzip_boundary_failures+=("$gzip_mutation-corrupted acceptance gzip did not use the failure contract: $acceptance_gzip_output")
  [[ "$acceptance_gzip_output" != *Traceback* ]] ||
    acceptance_gzip_boundary_failures+=("$gzip_mutation-corrupted acceptance gzip leaked a traceback: $acceptance_gzip_output")
done

python3 - "$tmp/acceptance-inner-gzip-deflate.tar.gz" <<'PY'
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
output.write_bytes(
    b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + b"\x07" + b"\x00" * 8
)
PY
acceptance_deflate_run="$tmp/JJDGuard-offline-inner-gzip-deflate-amd64.run"
write_payload_run "$tmp/acceptance-inner-gzip-deflate.tar.gz" "$acceptance_deflate_run"
acceptance_deflate_evidence="$tmp/evidence-inner-gzip-deflate.json"
acceptance_deflate_receipt="$tmp/receipt-inner-gzip-deflate.json"
write_evidence_index "$acceptance_deflate_evidence" "$acceptance_deflate_run" "$fixture_inner_sha"
write_receipt "$acceptance_deflate_receipt" "$acceptance_deflate_run" "$fixture_inner_sha" "$acceptance_deflate_evidence"
set +e
acceptance_deflate_output="$(python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_deflate_receipt" \
  --artifact "$acceptance_deflate_run" --evidence-index "$acceptance_deflate_evidence" \
  --source-repository "$source_repository" --authoritative-remote "$release_remote" 2>&1)"
acceptance_deflate_status=$?
set -e
[[ "$acceptance_deflate_status" -ne 0 ]] ||
  acceptance_gzip_boundary_failures+=(raw-DEFLATE-corrupted acceptance gzip unexpectedly succeeded)
[[ "$acceptance_deflate_output" == *'inner bundle is invalid: zlib error: Error -3 while decompressing data: invalid block type'* ]] ||
  acceptance_gzip_boundary_failures+=("raw-DEFLATE-corrupted acceptance gzip did not report the decompression failure: $acceptance_deflate_output")
[[ "$acceptance_deflate_output" != *Traceback* ]] ||
  acceptance_gzip_boundary_failures+=("raw-DEFLATE-corrupted acceptance gzip leaked a traceback: $acceptance_deflate_output")
[[ "${#acceptance_gzip_boundary_failures[@]}" -eq 0 ]] ||
  fail "acceptance gzip boundary regressions: ${acceptance_gzip_boundary_failures[*]}"

python3 - "$tmp/outer-$(basename "$run")/payload.tar.gz" "$tmp/acceptance-inner-complete-zero-tail.tar.gz" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
with gzip.open(source, "rb") as archive:
    raw = archive.read()
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
    data_end = 0
    for member in archive:
        data_end = max(data_end, member.offset_data + ((member.size + 511) // 512) * 512)
if raw[data_end:data_end + 1024] != b"\0" * 1024:
    raise SystemExit("fixture inner tar does not have a canonical end marker")
with gzip.open(output, "wb") as archive:
    archive.write(raw[:data_end] + b"\0" * 1024)
PY
acceptance_complete_zero_tail_run="$tmp/JJDGuard-offline-inner-complete-zero-tail-amd64.run"
write_payload_run "$tmp/acceptance-inner-complete-zero-tail.tar.gz" "$acceptance_complete_zero_tail_run"
acceptance_complete_zero_tail_inner_sha="$fixture_inner_sha"
acceptance_complete_zero_tail_evidence="$tmp/evidence-inner-complete-zero-tail.json"
acceptance_complete_zero_tail_receipt="$tmp/receipt-inner-complete-zero-tail.json"
write_evidence_index "$acceptance_complete_zero_tail_evidence" "$acceptance_complete_zero_tail_run" "$acceptance_complete_zero_tail_inner_sha"
write_receipt "$acceptance_complete_zero_tail_receipt" "$acceptance_complete_zero_tail_run" "$acceptance_complete_zero_tail_inner_sha" "$acceptance_complete_zero_tail_evidence"
python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_complete_zero_tail_receipt" \
  --artifact "$acceptance_complete_zero_tail_run" --evidence-index "$acceptance_complete_zero_tail_evidence" \
  --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null
acceptance_complete_zero_tail_output_dir="$tmp/final-inner-complete-zero-tail"
run_promotion "$acceptance_complete_zero_tail_run" "$acceptance_complete_zero_tail_receipt" \
  "$acceptance_complete_zero_tail_evidence" "$priv" "$acceptance_complete_zero_tail_output_dir" >/dev/null
trust_verify "$acceptance_complete_zero_tail_output_dir" >/dev/null

for acceptance_inner_tar_mutation in bad-header half-header nonzero-directory; do
  python3 - "$tmp/outer-$(basename "$run")/payload.tar.gz" \
    "$tmp/acceptance-inner-$acceptance_inner_tar_mutation.tar.gz" "$acceptance_inner_tar_mutation" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
mutation = sys.argv[3]
with gzip.open(source, "rb") as archive:
    raw = archive.read()
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
    data_end = 0
    root_name = None
    for member in archive:
        data_end = max(data_end, member.offset_data + ((member.size + 511) // 512) * 512)
        if root_name is None:
            root_name = member.name.rstrip("/").split("/", 1)[0]
if raw[data_end:data_end + 1024] != b"\0" * 1024:
    raise SystemExit("fixture inner tar does not have a canonical end marker")
if not root_name:
    raise SystemExit("fixture inner tar has no bundle root")
payload = raw[:data_end]
if mutation == "bad-header":
    payload += b"bad-checksum-header" + b"\0" * (512 - len(b"bad-checksum-header"))
elif mutation == "half-header":
    payload += b"truncated-header" * 16
elif mutation == "nonzero-directory":
    directory = tarfile.TarInfo(f"{root_name}/nonzero-directory/")
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    directory.size = 1536
    payload += directory.tobuf(format=tarfile.GNU_FORMAT)
    payload += b"D" * directory.size + b"\0" * 1024
else:
    raise SystemExit(f"unknown inner tar mutation: {mutation}")
with gzip.open(output, "wb") as archive:
    archive.write(payload)
PY
  acceptance_inner_run="$tmp/JJDGuard-offline-inner-$acceptance_inner_tar_mutation-amd64.run"
  write_payload_run "$tmp/acceptance-inner-$acceptance_inner_tar_mutation.tar.gz" "$acceptance_inner_run"
  acceptance_inner_sha="$fixture_inner_sha"
  acceptance_inner_evidence="$tmp/evidence-inner-$acceptance_inner_tar_mutation.json"
  acceptance_inner_receipt="$tmp/receipt-inner-$acceptance_inner_tar_mutation.json"
  write_evidence_index "$acceptance_inner_evidence" "$acceptance_inner_run" "$acceptance_inner_sha"
  write_receipt "$acceptance_inner_receipt" "$acceptance_inner_run" "$acceptance_inner_sha" "$acceptance_inner_evidence"
  acceptance_inner_expected='inner bundle is invalid:'
  if [[ "$acceptance_inner_tar_mutation" == nonzero-directory ]]; then
    acceptance_inner_expected='inner bundle member is unsafe'
  fi
  declare -a acceptance_inner_failures=()
  set +e
  acceptance_inner_direct_output="$(python3 "$VERIFY" --public-key "$pub" --receipt "$acceptance_inner_receipt" \
    --artifact "$acceptance_inner_run" --evidence-index "$acceptance_inner_evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote" 2>&1)"
  acceptance_inner_direct_status=$?
  set -e
  [[ "$acceptance_inner_direct_status" -ne 0 ]] ||
    acceptance_inner_failures+=("acceptance verifier accepted an $acceptance_inner_tar_mutation inner tar")
  [[ "$acceptance_inner_direct_output" == *"$acceptance_inner_expected"* ]] ||
    acceptance_inner_failures+=("acceptance verifier $acceptance_inner_tar_mutation rejection drifted: $acceptance_inner_direct_output")
  [[ "$acceptance_inner_direct_output" != *Traceback* ]] ||
    acceptance_inner_failures+=("acceptance verifier $acceptance_inner_tar_mutation leaked a traceback: $acceptance_inner_direct_output")
  acceptance_inner_output_dir="$tmp/final-inner-$acceptance_inner_tar_mutation"
  set +e
  acceptance_inner_promotion_output="$(run_promotion "$acceptance_inner_run" "$acceptance_inner_receipt" \
    "$acceptance_inner_evidence" "$priv" "$acceptance_inner_output_dir" 2>&1)"
  acceptance_inner_promotion_status=$?
  set -e
  [[ "$acceptance_inner_promotion_status" -ne 0 ]] ||
    acceptance_inner_failures+=("promotion accepted an $acceptance_inner_tar_mutation inner tar")
  [[ "$acceptance_inner_promotion_output" == *"$acceptance_inner_expected"* ]] ||
    acceptance_inner_failures+=("promotion $acceptance_inner_tar_mutation rejection drifted: $acceptance_inner_promotion_output")
  [[ "$acceptance_inner_promotion_output" != *Traceback* ]] ||
    acceptance_inner_failures+=("promotion $acceptance_inner_tar_mutation leaked a traceback: $acceptance_inner_promotion_output")
  [[ ! -e "$acceptance_inner_output_dir" ]] ||
    acceptance_inner_failures+=("promotion left an output for $acceptance_inner_tar_mutation inner tar")
  [[ "${#acceptance_inner_failures[@]}" -eq 0 ]] ||
    fail "acceptance $acceptance_inner_tar_mutation inner tar regressions: ${acceptance_inner_failures[*]}"
done
fixture_inner_sha="$original_inner_sha"

acceptance_evidence_probe="$tmp/acceptance-evidence-probe.py"
cat >"$acceptance_evidence_probe" <<'PY'
import hashlib
import importlib.util
import json
import os
import pathlib
import resource
import subprocess
import sys


def load_verifier(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("acceptance_evidence_probe", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load acceptance verifier probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def identity():
    return {
        "run_sha256": "a" * 64,
        "run_size": 1,
        "inner_tar_sha256": "b" * 64,
        "source_revision": "c" * 40,
        "source_tree": "d" * 40,
        "image_provenance_sha256": "e" * 64,
        "sbom_index_sha256": "f" * 64,
    }


def main() -> int:
    verifier = pathlib.Path(sys.argv[1])
    root = pathlib.Path(sys.argv[2])
    attack = sys.argv[3]
    if attack == "fifo":
        try:
            result = subprocess.run(
                [sys.executable, __file__, str(verifier), str(root), "fifo-worker"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("acceptance evidence FIFO probe timed out")
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    module = load_verifier(verifier)
    evidence_parent = root / "evidence-parent"
    evidence_root = evidence_parent / "evidence"
    logs = evidence_root / "logs"
    logs.mkdir(parents=True)
    snapshot_parent = root / "snapshot-parent"
    snapshot_root = snapshot_parent / "snapshot"
    snapshot_root.mkdir(parents=True)
    leaf = logs / "acceptance-summary.txt"
    content = b"acceptance evidence fixture\n"
    leaf.write_bytes(content)
    external = root / "external"
    external.mkdir()
    (external / leaf.name).write_bytes(content)
    external_leaf = external / "evidence" / "logs" / leaf.name
    external_leaf.parent.mkdir(parents=True)
    external_leaf.write_bytes(content)
    external_snapshot = root / "external-snapshot"
    (external_snapshot / "snapshot").mkdir(parents=True)
    expected_identity = identity()
    baseline = evidence_root / "home-migration-baseline.json"
    baseline.write_text(json.dumps({
        "schema": "jjdguard-home-migration-baseline/v1",
        "artifact": {key: expected_identity[key] for key in ("run_sha256", "run_size", "inner_tar_sha256")},
        "release": {key: expected_identity[key] for key in ("source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256")},
        "ledgers": [
            {"name": "schema_migrations_before", "entries": [{"version": "001_fixture.sql", "checksum": "1" * 64}]},
            {"name": "schema_migrations_after", "entries": [
                {"version": "001_fixture.sql", "checksum": "1" * 64},
                {"version": "002_fixture.sql", "checksum": "2" * 64},
            ]},
        ],
    }, sort_keys=True), encoding="utf-8")
    index = {
        "schema": "jjdguard-acceptance-evidence-index/v1",
        "artifact": {key: expected_identity[key] for key in ("run_sha256", "run_size", "inner_tar_sha256")},
        "release": {key: expected_identity[key] for key in ("source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256")},
        "entries": [
            {"path": "logs/acceptance-summary.txt", "sha256": hashlib.sha256(content).hexdigest()},
            {"path": "home-migration-baseline.json", "sha256": hashlib.sha256(baseline.read_bytes()).hexdigest()},
        ],
    }
    index_path = root / "acceptance-evidence-index.json"
    index_path.write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
    if attack == "migration-baseline-growth":
        original_read = module.os.read
        original_fail = module.fail
        failures = []
        grew = False

        def limited_fail(message):
            failures.append(message)
            raise SystemExit(1)

        def grow_after_first_read(descriptor, size):
            nonlocal grew
            value = original_read(descriptor, size)
            if value and not grew:
                grew = True
                with baseline.open("ab") as stream:
                    stream.write(b" " * module.MAX_HOME_MIGRATION_BASELINE_BYTES)
            return value

        module.fail = limited_fail
        module.os.read = grow_after_first_read
        try:
            try:
                module.validate_home_migration_baseline_evidence(
                    index["entries"][1]["sha256"], expected_identity, evidence_root, None
                )
            except SystemExit:
                pass
            else:
                raise SystemExit("grown home migration baseline was accepted")
        finally:
            module.os.read = original_read
            module.fail = original_fail
        if not grew:
            raise SystemExit("migration baseline growth probe did not reach the no-follow reader")
        if failures != ["home migration baseline exceeds the size limit while reading"]:
            raise SystemExit(
                "migration baseline growth used the wrong rejection: " + repr(failures)
            )
        return 0
    if attack == "deep-low-nofile":
        content = b"deep descriptor-budget acceptance evidence fixture\n"
        deep_parts = tuple(f"deep-{number:03d}" for number in range(80))
        deep_directory = evidence_root.joinpath(*deep_parts)
        deep_directory.mkdir(parents=True)
        deep_leaf = deep_directory / "acceptance-summary.txt"
        deep_leaf.write_bytes(content)
        relative = "/".join((*deep_parts, deep_leaf.name))
        index["entries"] = [
            {"path": relative, "sha256": hashlib.sha256(content).hexdigest()},
            {"path": "home-migration-baseline.json", "sha256": hashlib.sha256(baseline.read_bytes()).hexdigest()},
        ]
        index_path.write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard_limit < 64:
            raise SystemExit("acceptance evidence descriptor-budget probe cannot set a 64-fd soft limit")
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard_limit))
        try:
            module.validate_evidence_index(
                index_path, expected_identity, evidence_root, snapshot_root
            )
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))
        snapshot = snapshot_root.joinpath(*deep_parts, deep_leaf.name)
        if snapshot.read_bytes() != content:
            raise SystemExit("acceptance evidence deep descriptor-budget snapshot drifted")
        return 0
    evidence_root_for_validation = evidence_root
    if attack == "root-dotdot":
        redirect = evidence_parent / "redirect"
        redirect.mkdir()
        os.symlink(redirect, evidence_parent / "ancestor", target_is_directory=True)
        evidence_root_for_validation = evidence_parent / "ancestor" / ".." / "evidence"
    original_open = module.os.open
    triggered = False

    def attacked_open(path, flags, permissions=0o777, *, dir_fd=None):
        nonlocal triggered
        raw_path = os.fspath(path)
        old_root_open = dir_fd is None and pathlib.Path(raw_path) == evidence_root
        new_evidence_parent_open = raw_path == evidence_parent.name and dir_fd is not None
        old_leaf_open = dir_fd is None and pathlib.Path(raw_path) == leaf
        new_parent_open = raw_path == "logs" and dir_fd is not None
        new_leaf_open = raw_path == leaf.name and dir_fd is not None
        old_snapshot_root_open = dir_fd is None and pathlib.Path(raw_path) == snapshot_root
        new_snapshot_parent_open = raw_path == snapshot_parent.name and dir_fd is not None
        if attack == "ancestor" and not triggered and (old_root_open or new_evidence_parent_open):
            triggered = True
            os.rename(evidence_parent, evidence_parent.with_name("evidence-parent-original"))
            os.symlink(external, evidence_parent, target_is_directory=True)
        elif attack == "snapshot-ancestor" and not triggered and (
            old_snapshot_root_open or new_snapshot_parent_open
        ):
            triggered = True
            os.rename(snapshot_parent, snapshot_parent.with_name("snapshot-parent-original"))
            os.symlink(external_snapshot, snapshot_parent, target_is_directory=True)
        elif attack == "directory" and not triggered and (old_leaf_open or new_parent_open):
            triggered = True
            os.rename(logs, logs.with_name("logs-original"))
            os.symlink(external, logs, target_is_directory=True)
        elif attack == "fifo-worker" and not triggered and (old_leaf_open or new_leaf_open):
            triggered = True
            leaf.unlink()
            os.mkfifo(leaf)
        if dir_fd is None:
            return original_open(path, flags, permissions)
        return original_open(path, flags, permissions, dir_fd=dir_fd)

    module.os.open = attacked_open
    try:
        module.validate_evidence_index(
            index_path, expected_identity, evidence_root_for_validation, snapshot_root
        )
    finally:
        module.os.open = original_open
    if attack == "root-dotdot":
        raise SystemExit("acceptance evidence root symlink dotdot was accepted")
    if not triggered:
        raise SystemExit(f"acceptance evidence {attack} probe did not reach an open boundary")
    raise SystemExit(f"acceptance evidence {attack} attack was accepted")


if __name__ == "__main__":
    raise SystemExit(main())
PY

acceptance_evidence_fifo_output="$(expect_failure 'acceptance evidence FIFO TOCTOU' \
  python3 "$acceptance_evidence_probe" "$VERIFY" "$tmp/acceptance-evidence-fifo" fifo)"
[[ "$acceptance_evidence_fifo_output" == *'[error] acceptance receipt rejected:'* ]] ||
  fail "acceptance evidence FIFO rejection did not use the failure contract: $acceptance_evidence_fifo_output"
[[ "$acceptance_evidence_fifo_output" != *Traceback* ]] ||
  fail "acceptance evidence FIFO leaked a traceback: $acceptance_evidence_fifo_output"

set +e
migration_baseline_growth_output="$(python3 "$acceptance_evidence_probe" "$VERIFY" \
  "$tmp/acceptance-migration-baseline-growth" migration-baseline-growth 2>&1)"
migration_baseline_growth_status=$?
set -e
[[ "$migration_baseline_growth_status" == 0 ]] ||
  fail "migration baseline growth was not rejected during bounded reading: $migration_baseline_growth_output"

acceptance_evidence_directory_output="$(expect_failure 'acceptance evidence directory-swap TOCTOU' \
  python3 "$acceptance_evidence_probe" "$VERIFY" "$tmp/acceptance-evidence-directory" directory)"
[[ "$acceptance_evidence_directory_output" == *'[error] acceptance receipt rejected:'* ]] ||
  fail "acceptance evidence directory-swap rejection did not use the failure contract: $acceptance_evidence_directory_output"
[[ "$acceptance_evidence_directory_output" != *Traceback* ]] ||
  fail "acceptance evidence directory-swap leaked a traceback: $acceptance_evidence_directory_output"

acceptance_evidence_ancestor_output="$(expect_failure 'acceptance evidence ancestor-symlink TOCTOU' \
  python3 "$acceptance_evidence_probe" "$VERIFY" "$tmp/acceptance-evidence-ancestor" ancestor)"
[[ "$acceptance_evidence_ancestor_output" == *'[error] acceptance receipt rejected:'* ]] ||
  fail "acceptance evidence ancestor-symlink rejection did not use the failure contract: $acceptance_evidence_ancestor_output"
[[ "$acceptance_evidence_ancestor_output" != *Traceback* ]] ||
  fail "acceptance evidence ancestor-symlink leaked a traceback: $acceptance_evidence_ancestor_output"

acceptance_evidence_root_dotdot_output="$(expect_failure 'acceptance evidence root symlink dotdot' \
  python3 "$acceptance_evidence_probe" "$VERIFY" "$tmp/acceptance-evidence-root-dotdot" root-dotdot)"
[[ "$acceptance_evidence_root_dotdot_output" == *'[error] acceptance receipt rejected:'* ]] ||
  fail "acceptance evidence root symlink dotdot did not use the failure contract: $acceptance_evidence_root_dotdot_output"
[[ "$acceptance_evidence_root_dotdot_output" != *Traceback* ]] ||
  fail "acceptance evidence root symlink dotdot leaked a traceback: $acceptance_evidence_root_dotdot_output"

acceptance_snapshot_ancestor_output="$(expect_failure 'acceptance snapshot ancestor-symlink TOCTOU' \
  python3 "$acceptance_evidence_probe" "$VERIFY" "$tmp/acceptance-snapshot-ancestor" snapshot-ancestor)"
[[ "$acceptance_snapshot_ancestor_output" == *'[error] acceptance receipt rejected:'* ]] ||
  fail "acceptance snapshot ancestor-symlink rejection did not use the failure contract: $acceptance_snapshot_ancestor_output"
[[ "$acceptance_snapshot_ancestor_output" != *Traceback* ]] ||
  fail "acceptance snapshot ancestor-symlink leaked a traceback: $acceptance_snapshot_ancestor_output"

set +e
acceptance_evidence_deep_low_nofile_output="$(python3 "$acceptance_evidence_probe" "$VERIFY" \
  "$tmp/acceptance-evidence-deep-low-nofile" deep-low-nofile 2>&1)"
acceptance_evidence_deep_low_nofile_status=$?
set -e
[[ "$acceptance_evidence_deep_low_nofile_status" == 0 ]] ||
  fail "acceptance evidence deep path exhausted the descriptor budget: $acceptance_evidence_deep_low_nofile_output"

expect_failure 'missing acceptance receipt' \
  python3 "$VERIFY" --public-key "$pub" --receipt "$tmp/missing-receipt.json" --artifact "$run" --evidence-index "$evidence" \
    --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null

expect_failure 'promotion with Gitee main drift' \
  run_promotion "$run" "$receipt" "$evidence" "$priv" "$tmp/final-drift" ffffffffffffffffffffffffffffffffffffffff >/dev/null

chmod 0644 "$priv"
expect_failure 'promotion with unsafe private key mode' \
  run_promotion "$run" "$receipt" "$evidence" "$priv" "$tmp/final-unsafe-key" >/dev/null
chmod 0400 "$priv"

wrong_priv="$tmp/wrong-release-private.pem"
openssl genpkey -algorithm Ed25519 -out "$wrong_priv" >/dev/null 2>&1
chmod 0400 "$wrong_priv"
expect_promotion_failure 'promotion with a key that does not match the candidate public key' \
  "$run" "$receipt" "$evidence" "$wrong_priv" "$tmp/final-wrong-key"
[[ ! -e "$tmp/final-wrong-key" ]] || fail 'mismatched signing key left a final directory behind'

tampered_header_run="$tmp/JJDGuard-offline-header-tampered-amd64.run"
cp "$run" "$tampered_header_run"
tamper_sealed_header "$tampered_header_run"
tampered_header_evidence="$tmp/evidence-header-tampered.json"
tampered_header_receipt="$tmp/receipt-header-tampered.json"
write_evidence_index "$tampered_header_evidence" "$tampered_header_run" "$fixture_inner_sha"
write_receipt "$tampered_header_receipt" "$tampered_header_run" "$fixture_inner_sha" "$tampered_header_evidence"
expect_promotion_failure 'promotion with a modified sealed header' \
  "$tampered_header_run" "$tampered_header_receipt" "$tampered_header_evidence" "$priv" "$tmp/final-header-tampered"
[[ ! -e "$tmp/final-header-tampered" ]] || fail 'modified sealed header left a final directory behind'

saved_source_tree="$source_tree"
bad_source_tree=ffffffffffffffffffffffffffffffffffffffff
bad_tree_root="$tmp/bad-source-tree/jjdguard-fixture"
mkdir -p "$(dirname "$bad_tree_root")"
cp -a "$fixture_root" "$bad_tree_root"
python3 - "$bad_tree_root" "$bad_source_tree" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
tree = sys.argv[2]
for relative in ("manifest.json", "deploy/docker-compose/manifest.json", "release-source.json"):
    path = root / relative
    data = json.loads(path.read_text(encoding="utf-8"))
    data["source_tree"] = tree
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
source_tree="$bad_source_tree"
resign_inner_manifest "$bad_tree_root"
bad_tree_run="$tmp/JJDGuard-offline-bad-source-tree-amd64.run"
write_run "$bad_tree_root" "$bad_tree_run"
bad_tree_evidence="$tmp/evidence-bad-source-tree.json"
bad_tree_receipt="$tmp/receipt-bad-source-tree.json"
write_evidence_index "$bad_tree_evidence" "$bad_tree_run" "$fixture_inner_sha"
write_receipt "$bad_tree_receipt" "$bad_tree_run" "$fixture_inner_sha" "$bad_tree_evidence"
expect_promotion_failure 'promotion with a re-signed non-Gitee source tree' \
  "$bad_tree_run" "$bad_tree_receipt" "$bad_tree_evidence" "$priv" "$tmp/final-bad-source-tree"
source_tree="$saved_source_tree"

saved_sbom_sha="$sbom_sha"
bad_sbom_root="$tmp/bad-sbom/jjdguard-fixture"
mkdir -p "$(dirname "$bad_sbom_root")"
cp -a "$fixture_root" "$bad_sbom_root"
python3 - "$bad_sbom_root/sbom/index.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["syft"]["binary_sha256"] = "0" * 64
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
sbom_sha="$(sha "$bad_sbom_root/sbom/index.json")"
python3 - "$bad_sbom_root" "$sbom_sha" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = sys.argv[2]
for relative in ("manifest.json", "deploy/docker-compose/manifest.json"):
    path = root / relative
    data = json.loads(path.read_text(encoding="utf-8"))
    data["sbom_index_sha256"] = digest
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
resign_inner_manifest "$bad_sbom_root"
bad_sbom_run="$tmp/JJDGuard-offline-bad-sbom-amd64.run"
write_run "$bad_sbom_root" "$bad_sbom_run"
bad_sbom_evidence="$tmp/evidence-bad-sbom.json"
bad_sbom_receipt="$tmp/receipt-bad-sbom.json"
write_evidence_index "$bad_sbom_evidence" "$bad_sbom_run" "$fixture_inner_sha"
write_receipt "$bad_sbom_receipt" "$bad_sbom_run" "$fixture_inner_sha" "$bad_sbom_evidence"
expect_promotion_failure 'promotion with a re-signed SBOM that drifts from the trusted Syft lock' \
  "$bad_sbom_run" "$bad_sbom_receipt" "$bad_sbom_evidence" "$priv" "$tmp/final-bad-sbom"
sbom_sha="$saved_sbom_sha"

saved_provenance_sha="$provenance_sha"
bad_provenance_root="$tmp/bad-provenance/jjdguard-fixture"
mkdir -p "$(dirname "$bad_provenance_root")"
cp -a "$fixture_root" "$bad_provenance_root"
python3 - "$bad_provenance_root/image-provenance.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["images"][0]["image_id"] = "sha256:" + "c" * 64
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
provenance_sha="$(sha "$bad_provenance_root/image-provenance.json")"
python3 - "$bad_provenance_root" "$provenance_sha" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = sys.argv[2]
for relative in ("manifest.json", "deploy/docker-compose/manifest.json"):
    path = root / relative
    data = json.loads(path.read_text(encoding="utf-8"))
    data["image_provenance_sha256"] = digest
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
resign_inner_manifest "$bad_provenance_root"
bad_provenance_run="$tmp/JJDGuard-offline-bad-provenance-amd64.run"
write_run "$bad_provenance_root" "$bad_provenance_run"
bad_provenance_evidence="$tmp/evidence-bad-provenance.json"
bad_provenance_receipt="$tmp/receipt-bad-provenance.json"
write_evidence_index "$bad_provenance_evidence" "$bad_provenance_run" "$fixture_inner_sha"
write_receipt "$bad_provenance_receipt" "$bad_provenance_run" "$fixture_inner_sha" "$bad_provenance_evidence"
expect_promotion_failure 'promotion with SBOM image coverage that drifts from re-signed provenance' \
  "$bad_provenance_run" "$bad_provenance_receipt" "$bad_provenance_evidence" "$priv" "$tmp/final-bad-provenance"
provenance_sha="$saved_provenance_sha"

bad_provenance_schema_root="$tmp/bad-provenance-schema/jjdguard-fixture"
mkdir -p "$(dirname "$bad_provenance_schema_root")"
cp -a "$fixture_root" "$bad_provenance_schema_root"
python3 - "$bad_provenance_schema_root/image-provenance.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["schema"] = "untrusted-provenance/v1"
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
provenance_sha="$(sha "$bad_provenance_schema_root/image-provenance.json")"
python3 - "$bad_provenance_schema_root" "$provenance_sha" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = sys.argv[2]
for relative in ("manifest.json", "deploy/docker-compose/manifest.json"):
    path = root / relative
    data = json.loads(path.read_text(encoding="utf-8"))
    data["image_provenance_sha256"] = digest
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
resign_inner_manifest "$bad_provenance_schema_root"
bad_provenance_schema_run="$tmp/JJDGuard-offline-bad-provenance-schema-amd64.run"
write_run "$bad_provenance_schema_root" "$bad_provenance_schema_run"
bad_provenance_schema_evidence="$tmp/evidence-bad-provenance-schema.json"
bad_provenance_schema_receipt="$tmp/receipt-bad-provenance-schema.json"
write_evidence_index "$bad_provenance_schema_evidence" "$bad_provenance_schema_run" "$fixture_inner_sha"
write_receipt "$bad_provenance_schema_receipt" "$bad_provenance_schema_run" "$fixture_inner_sha" "$bad_provenance_schema_evidence"
expect_promotion_failure 'promotion with a re-signed invalid provenance schema' \
  "$bad_provenance_schema_run" "$bad_provenance_schema_receipt" "$bad_provenance_schema_evidence" "$priv" "$tmp/final-bad-provenance-schema"
provenance_sha="$saved_provenance_sha"

unsafe_output_parent="$tmp/group-writable-output-parent"
mkdir -p "$unsafe_output_parent"
chmod 0770 "$unsafe_output_parent"
unsafe_output="$unsafe_output_parent/final"
unsafe_output_result="$(expect_failure 'group-writable promotion output parent' \
  run_promotion "$run" "$receipt" "$evidence" "$priv" "$unsafe_output")"
[[ "$unsafe_output_result" == *'output parent must not be group or other writable'* ]] ||
  fail "group-writable output parent was rejected for the wrong reason: $unsafe_output_result"
[[ ! -e "$unsafe_output" ]] || fail 'group-writable output parent created a release directory'

foreign_owner_parent="$tmp/foreign-owned-output-parent"
mkdir -p "$foreign_owner_parent"
chmod 0700 "$foreign_owner_parent"
foreign_owner_output="$foreign_owner_parent/final"
foreign_owner_uid=1
[[ "$(id -u)" != 1 ]] || foreign_owner_uid=2
foreign_owner_result="$(FAKE_STAT_FOREIGN_OWNER_TARGET="$foreign_owner_parent" \
  FAKE_STAT_FOREIGN_OWNER_VALUE="$foreign_owner_uid" \
  expect_failure 'foreign-owned promotion output parent' \
  run_promotion "$run" "$receipt" "$evidence" "$priv" "$foreign_owner_output")"
[[ "$foreign_owner_result" == *'output parent must be owned by the invoking user'* ]] ||
  fail "foreign-owned output parent was rejected for the wrong reason: $foreign_owner_result"
[[ ! -e "$foreign_owner_output" ]] || fail 'foreign-owned output parent created a release directory'

foreign_ancestor="$tmp/foreign-owned-output-ancestor"
foreign_ancestor_parent="$foreign_ancestor/trusted-child"
mkdir -p "$foreign_ancestor_parent"
chmod 0700 "$foreign_ancestor" "$foreign_ancestor_parent"
foreign_ancestor_output="$foreign_ancestor_parent/final"
foreign_ancestor_result="$(FAKE_STAT_FOREIGN_OWNER_TARGET="$foreign_ancestor" \
  FAKE_STAT_FOREIGN_OWNER_VALUE="$foreign_owner_uid" \
  expect_failure 'foreign-owned promotion output ancestor' \
  run_promotion "$run" "$receipt" "$evidence" "$priv" "$foreign_ancestor_output")"
[[ "$foreign_ancestor_result" == *'output parent ancestor must be owned by the invoking user or root'* ]] ||
  fail "foreign-owned output ancestor was rejected for the wrong reason: $foreign_ancestor_result"
[[ ! -e "$foreign_ancestor_output" ]] || fail 'foreign-owned output ancestor created a release directory'

write_evidence_index "$evidence" "$run" "$base_fixture_inner_sha" true
write_receipt "$receipt" "$run" "$base_fixture_inner_sha" "$evidence"
python3 "$VERIFY" --public-key "$pub" --receipt "$receipt" --artifact "$run" --evidence-index "$evidence" \
  --source-repository "$source_repository" --authoritative-remote "$release_remote" >/dev/null
run_before="$(sha "$run")"
post_publish_output="$tmp/final-post-publish-tamper"
FAKE_MV_TAMPER_PUBLISHED_RUN="$post_publish_output/$(basename "$run")" \
  expect_promotion_failure 'promotion with a post-publish artifact mutation' \
  "$run" "$receipt" "$evidence" "$priv" "$post_publish_output"
[[ ! -e "$post_publish_output" ]] ||
  fail 'post-publish promotion checksum rejection left a final directory behind'

cleanup_failure_output="$tmp/final-post-publish-cleanup-failure"
cleanup_failure_marker="$tmp/post-publish-cleanup-failure.marker"
FAKE_RM_FAIL_TARGET_PREFIX="$tmp/.jjdguard-promotion-work." \
FAKE_RM_FAIL_ONCE_FILE="$cleanup_failure_marker" \
  expect_promotion_failure 'promotion cleanup failure after a verified publish' \
  "$run" "$receipt" "$evidence" "$priv" "$cleanup_failure_output"
[[ -f "$cleanup_failure_marker" ]] || fail 'cleanup failure fixture did not intercept the verification workspace cleanup'
[[ -d "$cleanup_failure_output" ]] ||
  fail 'verified promotion output was deleted when workspace cleanup failed'
trust_verify "$cleanup_failure_output" >/dev/null

evidence_toctou_probe="$tmp/evidence-toctou-probe.py"
cat >"$evidence_toctou_probe" <<'PY'
import hashlib
import importlib.util
import os
import pathlib
import resource
import subprocess
import sys


def load_verifier(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("verify_promoted_release_probe", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load promoted release verifier probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    verifier = pathlib.Path(sys.argv[1])
    root = pathlib.Path(sys.argv[2])
    attack = sys.argv[3]
    if attack == "fifo":
        try:
            result = subprocess.run(
                [sys.executable, __file__, str(verifier), str(root), "fifo-worker"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("evidence FIFO attack probe timed out")
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    module = load_verifier(verifier)
    if attack == "prefix":
        module.evidence_entries(
            {
                "schema": "jjdguard-acceptance-evidence-index/v1",
                "artifact": {},
                "release": {},
                "entries": [
                    {"path": "logs", "sha256": "a" * 64},
                    {"path": "logs/acceptance-summary.txt", "sha256": "b" * 64},
                ],
            }
        )
        raise SystemExit("evidence path prefix collision was accepted")

    root.mkdir(parents=True)
    release = root / "release"
    stage = root / "stage"
    logs = release / "evidence" / "logs"
    logs.mkdir(parents=True)
    stage.mkdir()
    leaf = logs / "acceptance-summary.txt"
    content = b"fixture evidence snapshot\n"
    expected_content = content
    if attack == "size":
        content = b"small"
        expected_content = b"validated evidence that exceeds the test total limit\n"
        module.MAX_EVIDENCE_BYTES = len(content) + 1
        module.STAGING_MARGIN_BYTES = 0
    leaf.write_bytes(content)
    external = root / "external"
    external.mkdir()
    (external / leaf.name).write_bytes(content)
    index = {
        "schema": "jjdguard-acceptance-evidence-index/v1",
        "artifact": {},
        "release": {},
        "entries": [{"path": "logs/acceptance-summary.txt", "sha256": hashlib.sha256(expected_content).hexdigest()}],
    }
    if attack == "deep-low-nofile":
        content = b"deep descriptor-budget promoted evidence fixture\n"
        deep_parts = tuple(f"deep-{number:03d}" for number in range(80))
        deep_directory = release / "evidence" / pathlib.Path(*deep_parts)
        deep_directory.mkdir(parents=True)
        deep_leaf = deep_directory / "acceptance-summary.txt"
        deep_leaf.write_bytes(content)
        relative = "/".join((*deep_parts, deep_leaf.name))
        index["entries"] = [
            {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}
        ]
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard_limit < 64:
            raise SystemExit("evidence deep descriptor-budget probe cannot set a 64-fd soft limit")
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard_limit))
        release_descriptor = -1
        try:
            release_descriptor = module.open_absolute_directory(
                release, "promoted evidence deep descriptor-budget release"
            )
            module.stage_promoted_evidence(release_descriptor, index, stage)
        finally:
            if release_descriptor >= 0:
                module.close_descriptor(release_descriptor)
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))
        snapshot = stage / "evidence" / pathlib.Path(*deep_parts) / deep_leaf.name
        if snapshot.read_bytes() != content:
            raise SystemExit("promoted evidence deep descriptor-budget snapshot drifted")
        return 0
    if attack == "low-nofile":
        content = b"descriptor-budget evidence fixture\n"
        entries = []
        for number in range(70):
            name = f"evidence-{number:03d}.txt"
            (logs / name).write_bytes(content)
            entries.append(
                {
                    "path": f"logs/{name}",
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        index["entries"] = entries
        _soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard_limit < 64:
            raise SystemExit("evidence descriptor-budget probe cannot set a 64-fd soft limit")
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard_limit))
        release_descriptor = -1
        try:
            release_descriptor = module.open_absolute_directory(
                release, "promoted evidence descriptor-budget release"
            )
            module.stage_promoted_evidence(release_descriptor, index, stage)
        finally:
            if release_descriptor >= 0:
                module.close_descriptor(release_descriptor)
        for entry in entries:
            snapshot = stage / "evidence" / entry["path"]
            if snapshot.read_bytes() != content:
                raise SystemExit(f"evidence descriptor-budget snapshot drifted: {entry['path']}")
        return 0
    destination = stage / "evidence" / "logs" / leaf.name
    original_open = module.os.open
    triggered = False
    leaf_opens = 0

    def attacked_open(path, flags, permissions=0o777, *, dir_fd=None):
        nonlocal triggered, leaf_opens
        raw_path = os.fspath(path)
        old_leaf_open = dir_fd is None and pathlib.Path(raw_path) == leaf
        new_parent_open = raw_path == "logs" and dir_fd is not None
        new_leaf_open = raw_path == leaf.name and dir_fd is not None
        stage_target_open = dir_fd is None and pathlib.Path(raw_path) == destination
        if attack == "size" and (old_leaf_open or new_leaf_open):
            descriptor = original_open(path, flags, permissions) if dir_fd is None else original_open(
                path, flags, permissions, dir_fd=dir_fd
            )
            leaf_opens += 1
            if leaf_opens == 1:
                triggered = True
                replacement = leaf.with_name("acceptance-summary-replacement.txt")
                replacement.write_bytes(expected_content)
                os.replace(replacement, leaf)
            return descriptor
        if attack == "directory" and not triggered and (old_leaf_open or new_parent_open):
            triggered = True
            original_logs = logs.with_name("logs-original")
            os.rename(logs, original_logs)
            os.symlink(external, logs, target_is_directory=True)
        elif attack == "fifo-worker" and not triggered and (old_leaf_open or new_leaf_open):
            triggered = True
            leaf.unlink()
            os.mkfifo(leaf)
        elif attack == "destination" and not triggered and stage_target_open and flags & module.os.O_CREAT:
            triggered = True
            pathlib.Path(raw_path).write_bytes(b"collision")
        if dir_fd is None:
            return original_open(path, flags, permissions)
        return original_open(path, flags, permissions, dir_fd=dir_fd)

    module.os.open = attacked_open
    release_descriptor = -1
    try:
        release_descriptor = module.open_absolute_directory(
            release, "promoted evidence probe release"
        )
        module.stage_promoted_evidence(release_descriptor, index, stage)
    finally:
        if release_descriptor >= 0:
            module.close_descriptor(release_descriptor)
        module.os.open = original_open
    if not triggered:
        raise SystemExit(f"evidence {attack} probe did not reach its open boundary")
    raise SystemExit(f"evidence {attack} attack was accepted")


if __name__ == "__main__":
    raise SystemExit(main())
PY

evidence_directory_output="$(expect_failure 'promoted evidence directory-swap TOCTOU' \
  python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" "$tmp/evidence-directory-probe" directory)"
[[ "$evidence_directory_output" == *'[error] promoted release rejected:'* ]] ||
  fail "directory-swap evidence rejection did not use the standard failure contract: $evidence_directory_output"
[[ "$evidence_directory_output" == *'promoted evidence logs/acceptance-summary.txt parent'* ]] ||
  fail "directory-swap evidence rejection did not reach the guarded parent open: $evidence_directory_output"
[[ "$evidence_directory_output" != *Traceback* ]] ||
  fail "directory-swap evidence rejection leaked a traceback: $evidence_directory_output"

evidence_fifo_output="$(expect_failure 'promoted evidence FIFO TOCTOU' \
  python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" "$tmp/evidence-fifo-probe" fifo)"
[[ "$evidence_fifo_output" == *'[error] promoted release rejected:'* ]] ||
  fail "FIFO evidence rejection did not use the standard failure contract: $evidence_fifo_output"
[[ "$evidence_fifo_output" == *'promoted evidence logs/acceptance-summary.txt is not a regular non-symlink file'* ]] ||
  fail "FIFO evidence rejection did not reach the guarded leaf open: $evidence_fifo_output"
[[ "$evidence_fifo_output" != *Traceback* ]] ||
  fail "FIFO evidence rejection leaked a traceback: $evidence_fifo_output"

evidence_prefix_output="$(expect_failure 'promoted evidence path prefix collision' \
  python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" "$tmp/evidence-prefix-probe" prefix)"
[[ "$evidence_prefix_output" == *'[error] promoted release rejected:'* ]] ||
  fail "evidence path prefix collision did not use the standard failure contract: $evidence_prefix_output"
[[ "$evidence_prefix_output" != *Traceback* ]] ||
  fail "evidence path prefix collision leaked a traceback: $evidence_prefix_output"

evidence_destination_output="$(expect_failure 'promoted evidence staging target collision' \
  python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" "$tmp/evidence-destination-probe" destination)"
[[ "$evidence_destination_output" == *'[error] promoted release rejected:'* ]] ||
  fail "evidence staging target collision did not use the standard failure contract: $evidence_destination_output"
[[ "$evidence_destination_output" == *'cannot snapshot promoted evidence logs/acceptance-summary.txt'* ]] ||
  fail "evidence staging target collision did not reach the guarded destination open: $evidence_destination_output"
[[ "$evidence_destination_output" != *Traceback* ]] ||
  fail "evidence staging target collision leaked a traceback: $evidence_destination_output"

evidence_size_output="$(expect_failure 'promoted evidence total-size TOCTOU' \
  python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" "$tmp/evidence-size-probe" size)"
[[ "$evidence_size_output" == *'[error] promoted release rejected:'* ]] ||
  fail "evidence total-size TOCTOU did not use the standard failure contract: $evidence_size_output"
[[ "$evidence_size_output" == *'promoted evidence hash drifted: logs/acceptance-summary.txt'* ]] ||
  fail "evidence total-size TOCTOU did not reach the guarded source fd: $evidence_size_output"
[[ "$evidence_size_output" != *Traceback* ]] ||
  fail "evidence total-size TOCTOU leaked a traceback: $evidence_size_output"

top_level_capacity_probe="$tmp/top-level-capacity-probe.py"
cat >"$top_level_capacity_probe" <<'PY'
import importlib.util
import os
import pathlib
import shutil
import sys
import types


def load_verifier(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("verify_promoted_release_capacity_probe", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load promoted release verifier capacity probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    verifier = pathlib.Path(sys.argv[1])
    source_release = pathlib.Path(sys.argv[2])
    trust_root = pathlib.Path(sys.argv[3])
    root = pathlib.Path(sys.argv[4])
    module = load_verifier(verifier)
    release = root / "release"
    shutil.copytree(source_release, release)
    runs = sorted(path.name for path in release.iterdir() if path.name.endswith(".run"))
    if len(runs) != 1:
        raise SystemExit("capacity probe release does not contain exactly one run artifact")
    files = module.release_files(runs[0])
    names = (files.run, files.checksum, files.sidecar, files.signature, files.receipt, files.evidence)
    initial_total = sum((release / name).stat().st_size for name in names)
    receipt = release / files.receipt
    evidence_size = (release / files.evidence).stat().st_size
    replacement_size = receipt.stat().st_size + evidence_size + 1
    original_statvfs = module.os.statvfs
    original_capacity = module.ensure_staging_capacity_at
    original_copy = module.copy_open_regular
    mutated = False
    copied_replacement = False

    def staged_bytes() -> int:
        return sum(
            path.stat().st_size
            for path in trust_root.glob(".verify-promoted-*/*")
            if path.is_file()
        )

    def constrained_statvfs(path):
        available = initial_total + module.STAGING_MARGIN_BYTES - staged_bytes()
        return types.SimpleNamespace(f_bavail=max(available, 0), f_frsize=1)

    def mutate_after_preflight(*args, **kwargs):
        nonlocal mutated
        result = original_capacity(*args, **kwargs)
        replacement = receipt.with_name("acceptance-receipt-replacement.json")
        replacement.write_bytes(b"x" * replacement_size)
        os.replace(replacement, receipt)
        mutated = True
        return result

    def record_copy(*args, **kwargs):
        nonlocal copied_replacement
        if args[3] == "receipt":
            copied_replacement = True
        return original_copy(*args, **kwargs)

    module.os.statvfs = constrained_statvfs
    module.ensure_staging_capacity_at = mutate_after_preflight
    module.copy_open_regular = record_copy
    descriptor = -1
    rejection = None
    try:
        descriptor = module.open_absolute_directory(release, "capacity probe release")
        try:
            module.verify_release(
                descriptor,
                trust_root,
                trust_root / "release-public.pem",
                False,
                True,
            )
        except SystemExit as error:
            rejection = str(error)
        else:
            raise SystemExit("capacity probe unexpectedly verified the resized receipt")
    finally:
        if descriptor >= 0:
            module.close_descriptor(descriptor)
        module.os.statvfs = original_statvfs
        module.ensure_staging_capacity_at = original_capacity
        module.copy_open_regular = original_copy
    if not mutated:
        raise SystemExit("capacity probe did not replace the receipt after preflight")
    if copied_replacement:
        raise SystemExit("top-level capacity guard copied the replacement receipt before rejecting it")
    if rejection is None or "trust-root staging space is insufficient" not in rejection:
        raise SystemExit(f"capacity probe used the wrong rejection: {rejection}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY

generic_copy_probe="$tmp/generic-copy-probe.py"
cat >"$generic_copy_probe" <<'PY'
import importlib.util
import os
import pathlib
import subprocess
import sys


def load_verifier(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("verify_promoted_release_generic_copy_probe", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load promoted release verifier generic copy probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def copy_with_missing_flag(module, root: pathlib.Path, flag: str) -> None:
    root.mkdir(parents=True)
    source = root / "source"
    destination = root / "destination"
    source.write_bytes(b"fixture generic copy\n")
    original = getattr(module.os, flag, None)
    if not isinstance(original, int):
        raise SystemExit(f"generic copy probe host lacks {flag}")
    delattr(module.os, flag)
    try:
        module.copy_regular(source, destination, "generic copy probe", 1024)
    finally:
        setattr(module.os, flag, original)
    raise SystemExit(f"generic copy silently accepted missing {flag}")


def copy_after_fifo_swap(module, root: pathlib.Path) -> None:
    root.mkdir(parents=True)
    source = root / "source"
    destination = root / "destination"
    source.write_bytes(b"fixture generic copy\n")
    original_open = module.os.open
    triggered = False

    def swapped_open(path, flags, permissions=0o777, *, dir_fd=None):
        nonlocal triggered
        if not triggered and pathlib.Path(os.fspath(path)) == source:
            triggered = True
            source.unlink()
            os.mkfifo(source)
        if dir_fd is None:
            return original_open(path, flags, permissions)
        return original_open(path, flags, permissions, dir_fd=dir_fd)

    module.os.open = swapped_open
    try:
        module.copy_regular(source, destination, "generic copy probe", 1024)
    finally:
        module.os.open = original_open
    if not triggered:
        raise SystemExit("generic copy FIFO probe did not reach its open boundary")
    raise SystemExit("generic copy accepted a regular-to-FIFO swap")


def main() -> int:
    verifier = pathlib.Path(sys.argv[1])
    root = pathlib.Path(sys.argv[2])
    attack = sys.argv[3]
    if attack == "fifo":
        try:
            result = subprocess.run(
                [sys.executable, __file__, str(verifier), str(root), "fifo-worker"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("generic copy FIFO probe timed out")
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    module = load_verifier(verifier)
    if attack == "missing-nonblock":
        copy_with_missing_flag(module, root, "O_NONBLOCK")
    if attack == "missing-nofollow":
        copy_with_missing_flag(module, root, "O_NOFOLLOW")
    if attack == "missing-readonly":
        copy_with_missing_flag(module, root, "O_RDONLY")
    if attack == "missing-cloexec":
        copy_with_missing_flag(module, root, "O_CLOEXEC")
    if attack == "fifo-worker":
        copy_after_fifo_swap(module, root)
    raise SystemExit(f"unknown generic copy probe attack: {attack}")


if __name__ == "__main__":
    raise SystemExit(main())
PY

generic_missing_nonblock_output="$(expect_failure 'generic copy missing O_NONBLOCK' \
  python3 "$generic_copy_probe" "$TRUST_VERIFIER" "$tmp/generic-copy-missing-nonblock" missing-nonblock)"
[[ "$generic_missing_nonblock_output" == *'[error] promoted release rejected:'* ]] ||
  fail "generic copy silently downgraded missing O_NONBLOCK: $generic_missing_nonblock_output"
[[ "$generic_missing_nonblock_output" == *'requires unsupported O_NONBLOCK'* ]] ||
  fail "generic copy missing O_NONBLOCK used the wrong rejection: $generic_missing_nonblock_output"
[[ "$generic_missing_nonblock_output" != *Traceback* ]] ||
  fail "generic copy missing O_NONBLOCK leaked a traceback: $generic_missing_nonblock_output"

generic_missing_nofollow_output="$(expect_failure 'generic copy missing O_NOFOLLOW' \
  python3 "$generic_copy_probe" "$TRUST_VERIFIER" "$tmp/generic-copy-missing-nofollow" missing-nofollow)"
[[ "$generic_missing_nofollow_output" == *'[error] promoted release rejected:'* ]] ||
  fail "generic copy silently downgraded missing O_NOFOLLOW: $generic_missing_nofollow_output"
[[ "$generic_missing_nofollow_output" == *'requires unsupported O_NOFOLLOW'* ]] ||
  fail "generic copy missing O_NOFOLLOW used the wrong rejection: $generic_missing_nofollow_output"
[[ "$generic_missing_nofollow_output" != *Traceback* ]] ||
  fail "generic copy missing O_NOFOLLOW leaked a traceback: $generic_missing_nofollow_output"

generic_missing_readonly_output="$(expect_failure 'generic copy missing O_RDONLY' \
  python3 "$generic_copy_probe" "$TRUST_VERIFIER" "$tmp/generic-copy-missing-readonly" missing-readonly)"
[[ "$generic_missing_readonly_output" == *'[error] promoted release rejected:'* ]] ||
  fail "generic copy silently downgraded missing O_RDONLY: $generic_missing_readonly_output"
[[ "$generic_missing_readonly_output" == *'requires unsupported O_RDONLY'* ]] ||
  fail "generic copy missing O_RDONLY used the wrong rejection: $generic_missing_readonly_output"
[[ "$generic_missing_readonly_output" != *Traceback* ]] ||
  fail "generic copy missing O_RDONLY leaked a traceback: $generic_missing_readonly_output"

generic_missing_cloexec_output="$(expect_failure 'generic copy missing O_CLOEXEC' \
  python3 "$generic_copy_probe" "$TRUST_VERIFIER" "$tmp/generic-copy-missing-cloexec" missing-cloexec)"
[[ "$generic_missing_cloexec_output" == *'[error] promoted release rejected:'* ]] ||
  fail "generic copy silently downgraded missing O_CLOEXEC: $generic_missing_cloexec_output"
[[ "$generic_missing_cloexec_output" == *'requires unsupported O_CLOEXEC'* ]] ||
  fail "generic copy missing O_CLOEXEC used the wrong rejection: $generic_missing_cloexec_output"
[[ "$generic_missing_cloexec_output" != *Traceback* ]] ||
  fail "generic copy missing O_CLOEXEC leaked a traceback: $generic_missing_cloexec_output"

generic_fifo_output="$(expect_failure 'generic copy regular-to-FIFO TOCTOU' \
  python3 "$generic_copy_probe" "$TRUST_VERIFIER" "$tmp/generic-copy-fifo" fifo)"
[[ "$generic_fifo_output" == *'[error] promoted release rejected:'* ]] ||
  fail "generic copy FIFO rejection did not use the standard failure contract: $generic_fifo_output"
[[ "$generic_fifo_output" == *'changed while it was being opened'* ]] ||
  fail "generic copy FIFO rejection used the wrong failure: $generic_fifo_output"
[[ "$generic_fifo_output" != *Traceback* ]] ||
  fail "generic copy FIFO rejection leaked a traceback: $generic_fifo_output"

final_baseline_probe="$tmp/final-baseline-probe.py"
cat >"$final_baseline_probe" <<'PY'
import importlib.util
import json
import os
import pathlib
import sys


def load_verifier(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("verify_promoted_release_baseline_probe", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load promoted release baseline probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def identity():
    return {
        "run_sha256": "a" * 64,
        "run_size": 1,
        "inner_tar_sha256": "b" * 64,
        "source_revision": "c" * 40,
        "source_tree": "d" * 40,
        "image_provenance_sha256": "e" * 64,
        "sbom_index_sha256": "f" * 64,
    }


def baseline_bytes(expected_identity: dict[str, object]) -> bytes:
    value = {
        "schema": "jjdguard-home-migration-baseline/v1",
        "artifact": {
            key: expected_identity[key]
            for key in ("run_sha256", "run_size", "inner_tar_sha256")
        },
        "release": {
            key: expected_identity[key]
            for key in (
                "source_revision",
                "source_tree",
                "image_provenance_sha256",
                "sbom_index_sha256",
            )
        },
        "ledgers": [
            {
                "name": "schema_migrations_before",
                "entries": [{"version": "001_fixture.sql", "checksum": "1" * 64}],
            },
            {
                "name": "schema_migrations_after",
                "entries": [
                    {"version": "001_fixture.sql", "checksum": "1" * 64},
                    {"version": "002_fixture.sql", "checksum": "2" * 64},
                ],
            },
        ],
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def expect_rejection(action, expected: str) -> None:
    try:
        action()
    except SystemExit as error:
        if str(error) != f"[error] promoted release rejected: {expected}":
            raise SystemExit(f"final baseline rejection drifted: {error}")
    else:
        raise SystemExit("final staged migration baseline attack was accepted")


def main() -> int:
    verifier = pathlib.Path(sys.argv[1])
    root = pathlib.Path(sys.argv[2])
    attack = sys.argv[3]
    module = load_verifier(verifier)
    expected_identity = identity()
    baseline = root / "stage" / "evidence" / "home-migration-baseline.json"
    baseline.parent.mkdir(parents=True)
    raw = baseline_bytes(expected_identity)
    baseline.write_bytes(raw)

    if attack == "inode-swap":
        original_require_regular = module.require_regular
        swapped = False

        def replace_after_lstat(path, label, maximum_size=None):
            nonlocal swapped
            metadata = original_require_regular(path, label, maximum_size)
            if pathlib.Path(path) == baseline and not swapped:
                replacement = baseline.with_name("home-migration-baseline-replacement.json")
                replacement.write_bytes(raw)
                os.replace(replacement, baseline)
                swapped = True
            return metadata

        module.require_regular = replace_after_lstat
        try:
            expect_rejection(
                lambda: module.load_home_migration_baseline(baseline, expected_identity),
                "home migration baseline changed while it was opened",
            )
        finally:
            module.require_regular = original_require_regular
        if not swapped:
            raise SystemExit("final baseline inode-swap probe did not reach lstat")
        return 0

    if attack == "growth":
        original_read = module.os.read
        original_fail = module.fail
        failures = []
        grew = False

        def limited_fail(message):
            failures.append(message)
            raise SystemExit(1)

        def grow_after_first_read(descriptor, size):
            nonlocal grew
            value = original_read(descriptor, size)
            if value and not grew:
                grew = True
                with baseline.open("ab") as stream:
                    stream.write(b" " * module.MAX_HOME_MIGRATION_BASELINE_BYTES)
            return value

        module.fail = limited_fail
        module.os.read = grow_after_first_read
        try:
            try:
                module.load_home_migration_baseline(baseline, expected_identity)
            except SystemExit:
                pass
            else:
                raise SystemExit("grown final staged migration baseline was accepted")
        finally:
            module.os.read = original_read
            module.fail = original_fail
        if not grew:
            raise SystemExit("final baseline growth probe did not reach the descriptor reader")
        if failures != ["home migration baseline exceeds the size limit while reading"]:
            raise SystemExit("final baseline growth used the wrong rejection: " + repr(failures))
        return 0

    raise SystemExit(f"unknown final baseline probe attack: {attack}")


if __name__ == "__main__":
    raise SystemExit(main())
PY

python3 "$final_baseline_probe" "$TRUST_VERIFIER" "$tmp/final-baseline-inode-swap" inode-swap
python3 "$final_baseline_probe" "$TRUST_VERIFIER" "$tmp/final-baseline-growth" growth

final="$tmp/final"
FAKE_GIT_REQUIRE_GITEE_REMOTE=1 run_promotion "$run" "$receipt" "$evidence" "$priv" "$final"
final_run="$final/$(basename "$run")"
[[ "$(sha "$final_run")" == "$run_before" ]] || fail 'promotion changed run bytes'
[[ -f "$final_run.sha256" ]] || fail 'promotion checksum is missing'
(cd "$final" && sha256sum -c "$(basename "$final_run").sha256" >/dev/null) ||
  fail 'promotion checksum does not verify the final run bytes'
[[ -f "$final_run.promotion.json" && -f "$final_run.promotion.sig" ]] || fail 'promotion sidecars are missing'
[[ "$(stat -c '%a' "$final_run.promotion.json")" == 444 ]] || fail 'promotion sidecar must be world-readable for release verification'
[[ "$(stat -c '%a' "$final_run.promotion.sig")" == 444 ]] || fail 'promotion signature must be world-readable for release verification'
[[ -f "$final/acceptance-receipt.json" && -f "$final/acceptance-evidence-index.json" ]] || fail 'promotion evidence copies are missing'
[[ -f "$final/evidence/logs/acceptance-summary.txt" ]] || fail 'promotion evidence snapshot is missing'
[[ "$(sha "$final/evidence/logs/acceptance-summary.txt")" == "$(sha "$evidence_log")" ]] ||
  fail 'promotion evidence snapshot bytes drifted from the validated evidence input'
trust_verify "$final" >/dev/null

missing_baseline_entry_final="$tmp/final-missing-migration-baseline-entry"
cp -a "$final" "$missing_baseline_entry_final"
chmod u+w "$missing_baseline_entry_final/acceptance-evidence-index.json"
python3 - "$missing_baseline_entry_final/acceptance-evidence-index.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
index = json.loads(path.read_text(encoding="utf-8"))
index["entries"] = [entry for entry in index["entries"] if entry["path"] != "home-migration-baseline.json"]
path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_promoted_receipt_evidence_hash "$missing_baseline_entry_final"
resign_promoted_sidecar "$missing_baseline_entry_final"
missing_baseline_entry_output="$(expect_failure 're-signed final without migration baseline entry' \
  trust_verify "$missing_baseline_entry_final")"
[[ "$missing_baseline_entry_output" == *'promoted evidence index is missing home migration baseline'* ]] ||
  fail "missing migration baseline entry was rejected for the wrong reason: $missing_baseline_entry_output"

missing_baseline_file_final="$tmp/final-missing-migration-baseline-file"
cp -a "$final" "$missing_baseline_file_final"
mv "$missing_baseline_file_final/evidence/home-migration-baseline.json" \
  "$missing_baseline_file_final/evidence/home-migration-baseline.json.missing"
missing_baseline_file_output="$(expect_failure 'final missing indexed migration baseline file' \
  trust_verify "$missing_baseline_file_final")"
[[ "$missing_baseline_file_output" == *'promoted evidence home-migration-baseline.json'* ]] ||
  fail "missing migration baseline file was rejected for the wrong reason: $missing_baseline_file_output"

tampered_baseline_final="$tmp/final-tampered-migration-baseline"
cp -a "$final" "$tampered_baseline_final"
chmod u+w "$tampered_baseline_final/evidence/home-migration-baseline.json"
printf X >>"$tampered_baseline_final/evidence/home-migration-baseline.json"
tampered_baseline_output="$(expect_failure 'tampered migration baseline evidence' \
  trust_verify "$tampered_baseline_final")"
[[ "$tampered_baseline_output" == *'promoted evidence hash drifted: home-migration-baseline.json'* ]] ||
  fail "tampered migration baseline was rejected for the wrong reason: $tampered_baseline_output"

identity_mismatch_baseline_final="$tmp/final-migration-baseline-identity-mismatch"
cp -a "$final" "$identity_mismatch_baseline_final"
chmod u+w "$identity_mismatch_baseline_final/evidence/home-migration-baseline.json" \
  "$identity_mismatch_baseline_final/acceptance-evidence-index.json"
python3 - "$identity_mismatch_baseline_final/evidence/home-migration-baseline.json" \
  "$identity_mismatch_baseline_final/acceptance-evidence-index.json" <<'PY'
import hashlib
import json
import pathlib
import sys

baseline_path = pathlib.Path(sys.argv[1])
index_path = pathlib.Path(sys.argv[2])
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
baseline["artifact"]["run_sha256"] = "0" * 64
baseline_path.write_text(json.dumps(baseline, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
index = json.loads(index_path.read_text(encoding="utf-8"))
for entry in index["entries"]:
    if entry["path"] == "home-migration-baseline.json":
        entry["sha256"] = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
        break
else:
    raise SystemExit("migration baseline index entry is missing")
index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_promoted_receipt_evidence_hash "$identity_mismatch_baseline_final"
resign_promoted_sidecar "$identity_mismatch_baseline_final"
identity_mismatch_baseline_output="$(expect_failure 're-signed migration baseline identity mismatch' \
  trust_verify "$identity_mismatch_baseline_final")"
[[ "$identity_mismatch_baseline_output" == *'home migration baseline artifact binding drifted: run_sha256'* ]] ||
  fail "migration baseline identity mismatch was rejected for the wrong reason: $identity_mismatch_baseline_output"

for ledger_mutation in checksum-rewrite version-deletion; do
  ledger_baseline_final="$tmp/final-migration-baseline-$ledger_mutation"
  cp -a "$final" "$ledger_baseline_final"
  chmod u+w "$ledger_baseline_final/evidence/home-migration-baseline.json" \
    "$ledger_baseline_final/acceptance-evidence-index.json"
  mutate_home_migration_baseline "$ledger_baseline_final/evidence/home-migration-baseline.json" \
    "$ledger_baseline_final/acceptance-evidence-index.json" "$ledger_mutation"
  rebind_promoted_receipt_evidence_hash "$ledger_baseline_final"
  resign_promoted_sidecar "$ledger_baseline_final"
  ledger_baseline_output="$(expect_failure "re-signed migration baseline $ledger_mutation" \
    trust_verify "$ledger_baseline_final")"
  [[ "$ledger_baseline_output" == *'after ledger does not preserve before migration'* ]] ||
    fail "re-signed migration baseline $ledger_mutation was rejected for the wrong reason: $ledger_baseline_output"
done

release_parent="$tmp/promoted-release-parent"
mkdir -p "$release_parent"
cp -a "$final" "$release_parent/release"
release_ancestor="$tmp/promoted-release-ancestor"
ln -s "$release_parent" "$release_ancestor"
release_ancestor_output="$(expect_failure 'promoted release ancestor symlink' \
  trust_verify "$release_ancestor/release")"
[[ "$release_ancestor_output" == *'[error] promoted release rejected:'* ]] ||
  fail "promoted release ancestor symlink did not use the standard failure contract: $release_ancestor_output"
[[ "$release_ancestor_output" != *Traceback* ]] ||
  fail "promoted release ancestor symlink leaked a traceback: $release_ancestor_output"

release_dotdot_parent="$tmp/promoted-release-dotdot-parent"
mkdir -p "$release_dotdot_parent/redirect"
cp -a "$final" "$release_dotdot_parent/release"
ln -s "$release_dotdot_parent/redirect" "$release_dotdot_parent/ancestor"
release_dotdot_output="$(expect_failure 'promoted release symlink dotdot ancestor' \
  trust_verify "$release_dotdot_parent/ancestor/../release")"
[[ "$release_dotdot_output" == *'[error] promoted release rejected:'* ]] ||
  fail "promoted release symlink dotdot ancestor did not use the standard failure contract: $release_dotdot_output"
[[ "$release_dotdot_output" != *Traceback* ]] ||
  fail "promoted release symlink dotdot ancestor leaked a traceback: $release_dotdot_output"

set +e
top_level_capacity_output="$(python3 "$top_level_capacity_probe" "$TRUST_VERIFIER" "$final" \
  "$trust_root" "$tmp/top-level-capacity-probe" 2>&1)"
top_level_capacity_status=$?
set -e
[[ "$top_level_capacity_status" == 0 ]] ||
  fail "top-level capacity TOCTOU was not rejected before copying: $top_level_capacity_output"

set +e
evidence_low_nofile_output="$(python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" \
  "$tmp/evidence-low-nofile-probe" low-nofile 2>&1)"
evidence_low_nofile_status=$?
set -e
[[ "$evidence_low_nofile_status" == 0 ]] ||
  fail "promoted evidence staging exhausted the descriptor budget: $evidence_low_nofile_output"

set +e
evidence_deep_low_nofile_output="$(python3 "$evidence_toctou_probe" "$TRUST_VERIFIER" \
  "$tmp/evidence-deep-low-nofile-probe" deep-low-nofile 2>&1)"
evidence_deep_low_nofile_status=$?
set -e
[[ "$evidence_deep_low_nofile_status" == 0 ]] ||
  fail "promoted evidence deep path exhausted the descriptor budget: $evidence_deep_low_nofile_output"

semantic_receipt_final="$tmp/final-semantic-receipt"
cp -a "$final" "$semantic_receipt_final"
chmod u+w "$semantic_receipt_final/acceptance-receipt.json"
python3 - "$semantic_receipt_final/acceptance-receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
receipt = json.loads(path.read_text(encoding="utf-8"))
receipt["status"] = "FAIL"
path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
resign_promoted_sidecar "$semantic_receipt_final"
semantic_receipt_output="$(expect_failure 're-signed promoted receipt status' trust_verify "$semantic_receipt_final")"
[[ "$semantic_receipt_output" == *'promoted acceptance receipt status is not promotable'* ]] ||
  fail "re-signed receipt status was rejected for the wrong reason: $semantic_receipt_output"

semantic_evidence_artifact_final="$tmp/final-semantic-evidence-artifact"
cp -a "$final" "$semantic_evidence_artifact_final"
chmod u+w "$semantic_evidence_artifact_final/acceptance-evidence-index.json"
python3 - "$semantic_evidence_artifact_final/acceptance-evidence-index.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
index = json.loads(path.read_text(encoding="utf-8"))
index["artifact"]["run_sha256"] = "0" * 64
path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_promoted_receipt_evidence_hash "$semantic_evidence_artifact_final"
resign_promoted_sidecar "$semantic_evidence_artifact_final"
semantic_evidence_artifact_output="$(expect_failure 're-signed promoted evidence artifact identity' trust_verify "$semantic_evidence_artifact_final")"
[[ "$semantic_evidence_artifact_output" == *'promoted evidence index artifact binding drifted: run_sha256'* ]] ||
  fail "re-signed evidence artifact was rejected for the wrong reason: $semantic_evidence_artifact_output"

semantic_evidence_release_final="$tmp/final-semantic-evidence-release"
cp -a "$final" "$semantic_evidence_release_final"
chmod u+w "$semantic_evidence_release_final/acceptance-evidence-index.json"
python3 - "$semantic_evidence_release_final/acceptance-evidence-index.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
index = json.loads(path.read_text(encoding="utf-8"))
index["release"]["source_tree"] = "f" * 40
path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rebind_promoted_receipt_evidence_hash "$semantic_evidence_release_final"
resign_promoted_sidecar "$semantic_evidence_release_final"
semantic_evidence_release_output="$(expect_failure 're-signed promoted evidence release identity' trust_verify "$semantic_evidence_release_final")"
[[ "$semantic_evidence_release_output" == *'promoted evidence index release binding drifted: source_tree'* ]] ||
  fail "re-signed evidence release was rejected for the wrong reason: $semantic_evidence_release_output"

install_marker="$tmp/trusted-install.sha256"
trust_install "$final" "$install_marker"
[[ "$(cat "$install_marker")" == "$(sha "$final_run")" ]] ||
  fail 'trusted install did not execute the verified private staging copy'
evidence_snapshot="$final/evidence/logs/acceptance-summary.txt"
mv "$evidence_snapshot" "$evidence_snapshot.missing"
expect_failure 'missing promoted evidence snapshot' trust_verify "$final" >/dev/null
mv "$evidence_snapshot.missing" "$evidence_snapshot"
printf X >>"$evidence_snapshot"
expect_failure 'tampered promoted evidence snapshot' trust_verify "$final" >/dev/null
printf '%s\n' 'fixture acceptance evidence: sanitized' >"$evidence_snapshot"
trust_verify "$final" >/dev/null
wrong_pub="$tmp/wrong-release-public.pem"
openssl pkey -in "$wrong_priv" -pubout -out "$wrong_pub" >/dev/null 2>&1
cp "$wrong_pub" "$trust_root/release-public.pem"
expect_failure 'untrusted replacement release key' trust_verify "$final" >/dev/null
cp "$pub" "$trust_root/release-public.pem"
bash "$final_run" --verify-only >/dev/null ||
  fail 'customer package self-verification must not require the trusted verifier'
mkdir -p "$tmp/no-sudo"
cat >"$tmp/no-sudo/sudo" <<'EOF'
#!/bin/sh
printf '%s\n' '[fixture] install requires root/sudo' >&2
exit 20
EOF
chmod 0755 "$tmp/no-sudo/sudo"
set +e
final_default="$(PATH="$tmp/no-sudo:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" bash "$final_run" 2>&1)"
final_default_status=$?
set -e
[[ "$final_default_status" -ne 0 && "$final_default" == *'install requires root/sudo'* ]] ||
  fail "customer install without root did not report the root requirement: $final_default"

race_run="$tmp/JJDGuard-offline-race-amd64.run"
cp "$run" "$race_run"
race_before="$(sha "$race_run")"
FAKE_GIT_REQUIRE_GITEE_REMOTE=1 FAKE_GIT_MUTATE_CANDIDATE="$race_run" \
  run_promotion "$race_run" "$receipt" "$evidence" "$priv" "$tmp/final-race"
[[ "$(sha "$race_run")" != "$race_before" ]] || fail 'race fixture did not mutate the candidate after validation'
race_final="$tmp/final-race/$(basename "$race_run")"
[[ "$(sha "$race_final")" == "$race_before" ]] || fail 'promotion did not preserve the validated candidate snapshot'
[[ "$(sha "$race_final")" != "$(sha "$race_run")" ]] || fail 'promotion signed bytes changed after validation'
trust_verify "$tmp/final-race" >/dev/null

race_receipt="$tmp/receipt-race.json"
cp "$receipt" "$race_receipt"
receipt_before_race="$(sha "$race_receipt")"
FAKE_GIT_MUTATE_FILE="$race_receipt" \
  run_promotion "$run" "$race_receipt" "$evidence" "$priv" "$tmp/final-receipt-race"
[[ "$(sha "$tmp/final-receipt-race/acceptance-receipt.json")" == "$receipt_before_race" ]] || \
  fail 'promotion did not preserve the validated receipt snapshot'

race_evidence="$tmp/evidence-race.json"
cp "$evidence" "$race_evidence"
evidence_before_race="$(sha "$race_evidence")"
FAKE_GIT_MUTATE_FILE="$race_evidence" \
  run_promotion "$run" "$receipt" "$race_evidence" "$priv" "$tmp/final-evidence-race"
[[ "$(sha "$tmp/final-evidence-race/acceptance-evidence-index.json")" == "$evidence_before_race" ]] || \
  fail 'promotion did not preserve the validated evidence snapshot'

receipt_before="$(sha "$final/acceptance-receipt.json")"
chmod u+w "$final/acceptance-receipt.json"
printf '\n' >>"$final/acceptance-receipt.json"
[[ "$(sha "$final/acceptance-receipt.json")" != "$receipt_before" ]] || fail 'receipt tamper fixture did not change bytes'
expect_failure 'tampered copied receipt' trust_verify "$final" >/dev/null
cp "$receipt" "$final/acceptance-receipt.json"
chmod u+w "$final_run.promotion.json"
printf '\n' >>"$final_run.promotion.json"
expect_failure 'tampered promotion sidecar' trust_verify "$final" >/dev/null
run_promotion "$run" "$receipt" "$evidence" "$priv" "$tmp/final-signature"
trust_verify "$tmp/final-signature" >/dev/null
signature_path="$tmp/final-signature/$(basename "$run").promotion.sig"
chmod u+w "$signature_path"
python3 - "$signature_path" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
before = path.read_bytes()
if len(before) != 64:
    raise SystemExit("promotion signature fixture has an unexpected length")
after = bytes((before[0] ^ 1,)) + before[1:]
if after == before:
    raise SystemExit("promotion signature fixture mutation did not change bytes")
path.write_bytes(after)
if path.read_bytes() != after:
    raise SystemExit("promotion signature fixture mutation was not persisted")
PY
chmod 0444 "$signature_path"
tampered_signature_output="$(expect_failure 'tampered promotion signature' \
  trust_verify "$tmp/final-signature")"
[[ "$tampered_signature_output" == *'promotion signature is invalid'* ]] ||
  fail "tampered promotion signature did not reach signature verification: $tampered_signature_output"
[[ "$tampered_signature_output" != *Traceback* ]] ||
  fail "tampered promotion signature leaked a traceback: $tampered_signature_output"

bad_inner_root="$tmp/bad-inner-payload/jjdguard-fixture"
mkdir -p "$(dirname "$bad_inner_root")"
cp -a "$fixture_root" "$bad_inner_root"
chmod u+w "$bad_inner_root/manifest.sig"
dd if=/dev/zero of="$bad_inner_root/manifest.sig" bs=64 count=1 conv=notrunc status=none
chmod 0444 "$bad_inner_root/manifest.sig"
write_inventory "$bad_inner_root"
bad_inner_run="$tmp/JJDGuard-offline-inner-signature-tampered-amd64.run"
write_run "$bad_inner_root" "$bad_inner_run"
bad_inner_evidence="$tmp/evidence-inner-signature-tampered.json"
bad_inner_receipt="$tmp/receipt-inner-signature-tampered.json"
write_evidence_index "$bad_inner_evidence" "$bad_inner_run" "$fixture_inner_sha"
write_receipt "$bad_inner_receipt" "$bad_inner_run" "$fixture_inner_sha" "$bad_inner_evidence"
expect_promotion_failure 'promotion with a tampered inner manifest signature' \
  "$bad_inner_run" "$bad_inner_receipt" "$bad_inner_evidence" "$priv" "$tmp/final-inner-signature-tampered"
[[ ! -e "$tmp/final-inner-signature-tampered" ]] || fail 'tampered inner signature left a final directory behind'

grep -Fq 'acceptance-gate.sh' "$ROOT/deploy/docker-compose/package-offline-bundle.sh" &&
  fail 'bundle packager still treats local acceptance as formal release validation'

echo '[ok] offline promotion receipt, sidecar, and candidate-install contract passed'
