#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFIER="$ROOT/deploy/docker-compose/verify-jjdguard-offline-archive.sh"
[[ -x "$VERIFIER" ]] || { echo '[offline-trust-test] verifier missing' >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
priv="$tmp/release-private.pem"
pub="$tmp/release-public.pem"
wrong_priv="$tmp/wrong-private.pem"
wrong_pub="$tmp/wrong-public.pem"
openssl genpkey -algorithm Ed25519 -out "$priv" >/dev/null 2>&1
openssl pkey -in "$priv" -pubout -out "$pub" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$wrong_priv" >/dev/null 2>&1
openssl pkey -in "$wrong_priv" -pubout -out "$wrong_pub" >/dev/null 2>&1
chmod 0400 "$priv" "$wrong_priv"
chmod 0444 "$pub" "$wrong_pub"

sha() { sha256sum "$1" | awk '{print $1}'; }
b64u() { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
source_revision=0123456789abcdef0123456789abcdef01234567
source_tree=89abcdef0123456789abcdef0123456789abcdef
image_id=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
syft_sha="$(awk -F= '$1 == "syft_binary_sha256" {print $2}' "$ROOT/deploy/docker-compose/release-toolchain.lock")"
[[ "$syft_sha" =~ ^[0-9a-f]{64}$ ]] || { echo '[offline-trust-test] fixed Syft lock is invalid' >&2; exit 1; }
sign_domain() {
  local domain="$1" input="$2" key="$3" output="$4" payload="$tmp/domain-$RANDOM.bin"
  { printf '%s\0' "$domain"; cat "$input"; } >"$payload"
  openssl pkeyutl -sign -rawin -inkey "$key" -in "$payload" -out "$output" >/dev/null 2>&1
  rm -f "$payload"
}

write_inventory() {
  local bundle inventory rel
  bundle="$1"
  inventory="$bundle/offline-inventory.tsv"
  printf '%s\t%s\n' schema jjdguard-offline-inventory/v1 >"$inventory"
  while IFS= read -r rel; do
    printf '%s\t%s\t%s\t%s\n' \
      file "$(b64u "$rel")" "$(stat -c '%s' "$bundle/$rel")" "$(sha "$bundle/$rel")" >>"$inventory"
  done < <(cd "$bundle" && find . -type f ! -name offline-inventory.tsv -printf '%P\n' | LC_ALL=C sort)
  chmod 0444 "$inventory"
}

write_handoff() {
  local archive="$1" bundle="$2" handoff="$3" signature="$4" key="$5"
  local bundle_name manifest inventory
  bundle_name="$(basename "$bundle")"
  manifest="$bundle/manifest.json"
  inventory="$bundle/offline-inventory.tsv"
  printf '%s\t%s\n' \
    schema jjdguard-offline-handoff/v2 \
    archive_file "$(b64u "$(basename "$archive")")" \
    bundle_root "$(b64u "$bundle_name")" \
    archive_sha256 "$(sha "$archive")" \
    manifest_sha256 "$(sha "$manifest")" \
    inventory_sha256 "$(sha "$inventory")" \
    product "$(b64u "${fixture_product:-jjdguard-enterprise}")" \
    version "$(b64u 0.0.0-test)" \
    source_revision "$(b64u "$source_revision")" \
    source_tree "$(b64u "$source_tree")" \
    image_provenance_sha256 "$(sha "$bundle/image-provenance.json")" \
    sbom_index_sha256 "$(sha "$bundle/sbom/index.json")" \
    target_arch "$(b64u amd64)" \
    bundle_profile "$(b64u full)" \
    include_chat "$(b64u 1)" \
    artifact_stage "$(b64u candidate)" >"$handoff"
  if [[ "${fixture_product:-jjdguard-enterprise}" == agent-platform ]]; then
    printf '%s\t%s\n' \
      product_profile "$(b64u agent-platform)" \
      product_name "$(b64u 'JJDGuard Agent Platform')" \
      product_version "$(b64u 1.0.0)" \
      product_slug "$(b64u agent-platform)" \
      agent_kit_sha256 "$fixture_kit_sha" >>"$handoff"
  fi
  chmod 0444 "$handoff"
  sign_domain jjdguard-offline-handoff/v2 "$handoff" "$key" "$signature"
  chmod 0444 "$signature"
}

build_archive() {
  local bundle="$1" archive="$2"
  tar -czf "$archive" -C "$(dirname "$bundle")" "$(basename "$bundle")"
}

make_bundle() {
  local bundle="$1"
  local provenance_sha sbom_bundle_sha sbom_image_sha sbom_index_sha manifest
  install -d -m 0700 "$bundle/deploy/docker-compose" "$bundle/sbom/images"
  printf '%s\n' "{\"schema\":\"jjdguard-release-source/v1\",\"remote\":\"git@github.com:yangjiyj/aiguard.git\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\"}" >"$bundle/release-source.json"
  printf '%s\n' "{\"images\":[{\"component\":\"fixture\",\"image_id\":\"$image_id\"}]}" >"$bundle/image-provenance.json"
  printf '%s\n' '{"spdxVersion":"SPDX-2.3","creationInfo":{"creators":["Tool: syft-1.44.0"]},"packages":[{"name":"fixture"}]}' >"$bundle/sbom/bundle.spdx.json"
  cp "$bundle/sbom/bundle.spdx.json" "$bundle/sbom/images/fixture.spdx.json"
  provenance_sha="$(sha "$bundle/image-provenance.json")"
  sbom_bundle_sha="$(sha "$bundle/sbom/bundle.spdx.json")"
  sbom_image_sha="$(sha "$bundle/sbom/images/fixture.spdx.json")"
  printf '%s\n' "{\"schema\":\"jjdguard-release-sbom-index/v1\",\"syft\":{\"version\":\"1.44.0\",\"binary_sha256\":\"$syft_sha\"},\"bundle\":{\"path\":\"sbom/bundle.spdx.json\",\"sha256\":\"$sbom_bundle_sha\"},\"images\":[{\"component\":\"fixture\",\"image_id\":\"$image_id\",\"path\":\"sbom/images/fixture.spdx.json\",\"sha256\":\"$sbom_image_sha\"}]}" >"$bundle/sbom/index.json"
  sbom_index_sha="$(sha "$bundle/sbom/index.json")"
  manifest="{\"schema\":\"offline-manifest/v2\",\"product\":\"${fixture_product:-jjdguard-enterprise}\",\"version\":\"0.0.0-test\",\"source_revision\":\"$source_revision\",\"source_tree\":\"$source_tree\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_index_sha\",\"target_arch\":\"amd64\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"min_data_version\":\"077_request_logs_proxy_access_type_resolved.sql\",\"manifest_signature\":\"ed25519-domain-v2\",\"built_at\":\"2026-08-08T00:00:00Z\",\"bundle\":\"$(basename "$bundle")\"}"
  if [[ "${fixture_product:-jjdguard-enterprise}" == agent-platform ]]; then
    mkdir -p "$bundle/deploy/docker-compose/agent-kit"
    printf 'agent kit test payload\n' >"$bundle/deploy/docker-compose/agent-kit/install.sh"
    fixture_kit_sha="$(python3 - "$bundle/deploy/docker-compose/agent-kit" <<'PY'
import hashlib
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*")):
    if path.is_file():
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(rel).to_bytes(4, "big") + rel)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
print(digest.hexdigest())
PY
)"
    manifest="${manifest%?},\"product_profile\":\"agent-platform\",\"product_name\":\"JJDGuard Agent Platform\",\"product_version\":\"1.0.0\",\"product_slug\":\"agent-platform\",\"agent_kit_sha256\":\"$fixture_kit_sha\"}"
  fi
  printf '%s\n' "$manifest" >"$bundle/manifest.json"
  printf '%s\n' "$manifest" >"$bundle/deploy/docker-compose/manifest.json"
  printf '%s\n' 'fixture payload' >"$bundle/deploy/docker-compose/payload.txt"
  printf '%s\n' '077_request_logs_proxy_access_type_resolved.sql' >"$bundle/deploy/docker-compose/upgrade-min-data-version"
  sign_domain jjdguard-offline-manifest/v2 "$bundle/manifest.json" "$priv" "$bundle/manifest.sig"
  chmod 0444 "$bundle/manifest.json" "$bundle/manifest.sig" "$bundle/deploy/docker-compose/manifest.json" "$bundle/deploy/docker-compose/upgrade-min-data-version" "$bundle/deploy/docker-compose/payload.txt" "$bundle/release-source.json" "$bundle/image-provenance.json" "$bundle/sbom/index.json" "$bundle/sbom/bundle.spdx.json" "$bundle/sbom/images/fixture.spdx.json"
  write_inventory "$bundle"
}

expect_reject() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "[offline-trust-test] expected rejection: $label" >&2
    exit 1
  fi
}

source_dir="$tmp/source"
bundle="$source_dir/jjdguard-test"
archive="$tmp/jjdguard-test.tar.gz"
handoff="$archive.handoff.tsv"
handoff_sig="$archive.handoff.sig"
make_bundle "$bundle"
build_archive "$bundle" "$archive"
write_handoff "$archive" "$bundle" "$handoff" "$handoff_sig" "$priv"
original_provenance_sha="$(sha "$bundle/image-provenance.json")"
original_sbom_sha="$(sha "$bundle/sbom/index.json")"

extract="$tmp/extracted"
"$VERIFIER" --archive "$archive" --handoff "$handoff" --signature "$handoff_sig" --public-key "$pub" --extract-to "$extract"
verified_root="$extract/jjdguard-test"
[[ -f "$verified_root/.jjdguard-offline-verified.tsv" ]]
grep -Fqx $'schema\tjjdguard-offline-verified/v2' "$verified_root/.jjdguard-offline-verified.tsv"
grep -Fqx $'archive_sha256\t'"$(sha "$archive")" "$verified_root/.jjdguard-offline-verified.tsv"

fixture_product=agent-platform
platform_bundle="$tmp/platform-source/agent-platform-test"
platform_archive="$tmp/agent-platform-test.tar.gz"
make_bundle "$platform_bundle"
build_archive "$platform_bundle" "$platform_archive"
write_handoff "$platform_archive" "$platform_bundle" "$platform_archive.handoff.tsv" "$platform_archive.handoff.sig" "$priv"
"$VERIFIER" --archive "$platform_archive" --handoff "$platform_archive.handoff.tsv" --signature "$platform_archive.handoff.sig" --public-key "$pub" --extract-to "$tmp/platform-extracted"
[[ -f "$tmp/platform-extracted/agent-platform-test/.jjdguard-offline-verified.tsv" ]]
platform_bad="$tmp/platform-bad/agent-platform-test"
mkdir -p "$(dirname "$platform_bad")"
cp -a "$platform_bundle" "$platform_bad"
chmod u+w "$platform_bad/offline-inventory.tsv" "$platform_bad/deploy/docker-compose/agent-kit/install.sh"
printf 'tampered agent kit\n' >"$platform_bad/deploy/docker-compose/agent-kit/install.sh"
write_inventory "$platform_bad"
build_archive "$platform_bad" "$tmp/platform-bad.tar.gz"
write_handoff "$tmp/platform-bad.tar.gz" "$platform_bad" "$tmp/platform-bad.tar.gz.handoff.tsv" "$tmp/platform-bad.tar.gz.handoff.sig" "$priv"
expect_reject platform-agent-kit-hash "$VERIFIER" --archive "$tmp/platform-bad.tar.gz" --handoff "$tmp/platform-bad.tar.gz.handoff.tsv" --signature "$tmp/platform-bad.tar.gz.handoff.sig" --public-key "$pub" --extract-to "$tmp/platform-bad-extract"
# 验收闸的平台前置验证必须先走受信 Ed25519 身份链；截断 Docker 运行阶段。
GATE="$ROOT/deploy/lib/acceptance-gate.sh"
# 截取进入镜像检查前的隔离 .env，不更改验收门及已验签产物。
gate_bin="$tmp/gate-bin"
mkdir -p "$gate_bin"
cat >"$gate_bin/ls" <<'GATE_LS'
#!/bin/sh
case "$1" in
  */offline-artifacts/jjdguard-offline-images-*.tar.gz)
    cp "$(dirname "$(dirname "$1")")/.env" "$GATE_CAPTURE_ENV" ;;
esac
exec /bin/ls "$@"
GATE_LS
chmod +x "$gate_bin/ls"
gate_preflight() {
  local gate_tmp="$tmp/gate-$RANDOM" output="$tmp/gate-output-$RANDOM" rc
  mkdir -p "$gate_tmp"
  if TMPDIR="$gate_tmp" GATE_CAPTURE_ENV="$gate_tmp/captured.env" PATH="$gate_bin:$PATH" OFFLINE_ACCEPTANCE_PUBLIC_KEY="${2:-}" \
    sh "$GATE" "$1" >"$output" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  if [[ "${3:-reject}" == verified ]]; then
    grep -Fq "[offline-verify] status=verified" "$output" || {
      echo "[offline-trust-test] valid platform did not verify in acceptance gate" >&2
      return 1
    }
    grep -Fq "[gate] 离线镜像引用检查" "$output" || {
      cat "$output" >&2
      echo "[offline-trust-test] platform gate did not continue after verification" >&2
      return 1
    }
    [[ "$rc" -eq 1 ]] || { echo "[offline-trust-test] expected image-stage exit 1, got $rc" >&2; return 1; }
    grep -Fxq 'PRODUCT_PROFILE=agent-platform' "$gate_tmp/captured.env"
    grep -Fxq "PRODUCT_NAME='JJDGuard Agent Platform'" "$gate_tmp/captured.env"
    grep -Fxq 'PRODUCT_VERSION=1.0.0' "$gate_tmp/captured.env"
    grep -Fxq 'GATEWAY_PORT=27080' "$gate_tmp/captured.env"
  else
    [[ "$rc" -eq 2 ]] || { echo "[offline-trust-test] expected preflight exit 2, got $rc" >&2; return 1; }
    [[ ! -e "$gate_tmp/captured.env" ]] || { echo '[offline-trust-test] rejected platform wrote isolation env' >&2; return 1; }
    ! grep -Fq "[gate] 离线镜像引用检查" "$output" || {
      echo "[offline-trust-test] rejected platform reached image-stage gate" >&2
      return 1
    }
  fi
}
gate_preflight "$platform_archive" "$pub" verified
legacy_gate_tmp="$tmp/gate-legacy"
mkdir -p "$legacy_gate_tmp"
if TMPDIR="$legacy_gate_tmp" GATE_CAPTURE_ENV="$legacy_gate_tmp/captured.env" PATH="$gate_bin:$PATH" \
  sh "$GATE" "$archive" >"$legacy_gate_tmp/output" 2>&1; then
  echo '[offline-trust-test] fixture without images unexpectedly passed gateway gate' >&2
  exit 1
fi
grep -Fxq 'GATEWAY_PORT=27080' "$legacy_gate_tmp/captured.env"
! grep -q '^PRODUCT_' "$legacy_gate_tmp/captured.env"
gate_preflight "$platform_archive"
gate_preflight "$platform_archive" "$wrong_pub"
gate_preflight "$tmp/platform-bad.tar.gz" "$pub"
cp "$platform_archive.handoff.sig" "$tmp/platform-unsigned.sig.copy"
chmod u+w "$platform_archive.handoff.sig"
printf "%s %s\n" "$(sha "$platform_archive.handoff.tsv")" "$(basename "$platform_archive.handoff.tsv")" >"$platform_archive.handoff.sig"
gate_preflight "$platform_archive" "$pub"
cp "$tmp/platform-unsigned.sig.copy" "$platform_archive.handoff.sig"

unset fixture_product fixture_kit_sha

# The following cases re-sign both the mutated inner manifest and the handoff.
# They prove the chain comparison itself, rather than a stale signature, rejects
# a revision/tree/provenance/SBOM identity disagreement before installation.
expect_chain_mismatch() {
  local field="$1" bad_root bad_archive bad_handoff bad_sig replacement
  bad_root="$tmp/chain-$field/jjdguard-test"
  mkdir -p "$(dirname "$bad_root")"
  cp -a "$bundle" "$bad_root"
  chmod -R u+w "$bad_root"
  replacement="ffffffffffffffffffffffffffffffffffffffff"
  python3 - "$bad_root" "$field" "$replacement" <<'PY'
import hashlib
import json
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
field = sys.argv[2]
replacement = sys.argv[3]
def load(path):
    return json.loads(path.read_text(encoding="utf-8"))
def dump(path, data):
    path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
manifest_paths = [bundle / "manifest.json", bundle / "deploy/docker-compose/manifest.json"]
manifest = load(manifest_paths[0])
if field in {"source_revision", "source_tree"}:
    for path in manifest_paths:
        data = load(path)
        data[field] = replacement
        dump(path, data)
    source = load(bundle / "release-source.json")
    source[field] = replacement
    dump(bundle / "release-source.json", source)
elif field == "image_provenance_sha256":
    provenance = bundle / "image-provenance.json"
    provenance.write_bytes(provenance.read_bytes() + b"\n")
    digest = hashlib.sha256(provenance.read_bytes()).hexdigest()
    for path in manifest_paths:
        data = load(path)
        data[field] = digest
        dump(path, data)
elif field == "sbom_index_sha256":
    index = bundle / "sbom/index.json"
    index.write_bytes(index.read_bytes() + b"\n")
    digest = hashlib.sha256(index.read_bytes()).hexdigest()
    for path in manifest_paths:
        data = load(path)
        data[field] = digest
        dump(path, data)
else:
    raise SystemExit("unknown field")
PY
  { printf '%s\0' jjdguard-offline-manifest/v2; cat "$bad_root/manifest.json"; } >"$bad_root/manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$priv" -in "$bad_root/manifest.payload" -out "$bad_root/manifest.sig"
  rm -f "$bad_root/manifest.payload"
  chmod 0444 "$bad_root/manifest.sig"
  write_inventory "$bad_root"
  bad_archive="$tmp/chain-$field.tar.gz"
  build_archive "$bad_root" "$bad_archive"
  bad_handoff="$bad_archive.handoff.tsv"
  bad_sig="$bad_archive.handoff.sig"
  write_handoff "$bad_archive" "$bad_root" "$bad_handoff" "$bad_sig" "$priv"
  # write_handoff intentionally emits the actual hash.  Restore the original
  # signed-chain value for the evidence cases, then sign that receipt again.
  case "$field" in
    image_provenance_sha256) replacement="$original_provenance_sha" ;;
    sbom_index_sha256) replacement="$original_sbom_sha" ;;
    *) replacement='' ;;
  esac
  if [[ -n "$replacement" ]]; then
    chmod u+w "$bad_handoff" "$bad_sig"
    awk -F '\t' -v field="$field" -v value="$replacement" 'BEGIN{OFS="\t"} $1==field {$2=value} {print}' "$bad_handoff" >"$bad_handoff.tmp"
    mv "$bad_handoff.tmp" "$bad_handoff"
    sign_domain jjdguard-offline-handoff/v2 "$bad_handoff" "$priv" "$bad_sig"
    chmod 0444 "$bad_handoff" "$bad_sig"
  fi
  expect_reject "signed-chain-$field-mismatch" "$VERIFIER" --archive "$bad_archive" --handoff "$bad_handoff" --signature "$bad_sig" --public-key "$pub" --extract-to "$tmp/chain-$field-extract"
  [[ ! -e "$tmp/chain-$field-extract" ]] || { echo "[offline-trust-test] failed extraction was not cleaned: $field" >&2; exit 1; }
}
for chain_field in source_revision source_tree image_provenance_sha256 sbom_index_sha256; do
  expect_chain_mismatch "$chain_field"
done

expect_reject wrong-key "$VERIFIER" --archive "$archive" --handoff "$handoff" --signature "$handoff_sig" --public-key "$wrong_pub" --extract-to "$tmp/wrong-key"
tampered_archive="$tmp/tampered.tar.gz"
cp "$archive" "$tampered_archive"
chmod 0600 "$tampered_archive"
printf x >>"$tampered_archive"
expect_reject archive-tamper "$VERIFIER" --archive "$tampered_archive" --handoff "$handoff" --signature "$handoff_sig" --public-key "$pub" --extract-to "$tmp/archive-tamper"

tampered_handoff="$tmp/tampered-handoff.tsv"
awk -F '\t' 'BEGIN{OFS="\t"} $1=="target_arch" {$2="YXJtNjQ"} {print}' "$handoff" >"$tampered_handoff"
expect_reject handoff-tamper "$VERIFIER" --archive "$archive" --handoff "$tampered_handoff" --signature "$handoff_sig" --public-key "$pub" --extract-to "$tmp/handoff-tamper"
for field in source_revision source_tree image_provenance_sha256 sbom_index_sha256; do
  tampered_chain_handoff="$tmp/tampered-$field.tsv"
  awk -F '\t' -v field="$field" 'BEGIN{OFS="\t"} $1==field {$2=(field ~ /sha256/ ? "0000000000000000000000000000000000000000000000000000000000000000" : "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg")} {print}' "$handoff" >"$tampered_chain_handoff"
  expect_reject "handoff-$field-tamper" "$VERIFIER" --archive "$archive" --handoff "$tampered_chain_handoff" --signature "$handoff_sig" --public-key "$pub" --extract-to "$tmp/$field-tamper"
  [[ ! -e "$tmp/$field-tamper" ]] || { echo "[offline-trust-test] failed extraction was not cleaned: $field" >&2; exit 1; }
done
raw_sig="$tmp/raw.sig"
openssl pkeyutl -sign -rawin -inkey "$priv" -in "$handoff" -out "$raw_sig" >/dev/null 2>&1
expect_reject cross-domain "$VERIFIER" --archive "$archive" --handoff "$handoff" --signature "$raw_sig" --public-key "$pub" --extract-to "$tmp/cross-domain"

payload_bad="$tmp/payload-bad/jjdguard-test"
install -d -m 0700 "$(dirname "$payload_bad")"
cp -a "$bundle" "$payload_bad"
chmod 0644 "$payload_bad/deploy/docker-compose/payload.txt"
printf '%s\n' tampered >"$payload_bad/deploy/docker-compose/payload.txt"
payload_archive="$tmp/payload-bad.tar.gz"
build_archive "$payload_bad" "$payload_archive"
write_handoff "$payload_archive" "$payload_bad" "$payload_archive.handoff.tsv" "$payload_archive.handoff.sig" "$priv"
expect_reject inventory-tamper "$VERIFIER" --archive "$payload_archive" --handoff "$payload_archive.handoff.tsv" --signature "$payload_archive.handoff.sig" --public-key "$pub" --extract-to "$tmp/payload-bad-extract"

manifest_bad="$tmp/manifest-bad/jjdguard-test"
install -d -m 0700 "$(dirname "$manifest_bad")"
cp -a "$bundle" "$manifest_bad"
chmod 0644 "$manifest_bad/manifest.json" "$manifest_bad/offline-inventory.tsv"
sed -i 's/0.0.0-test/0.0.1-test/' "$manifest_bad/manifest.json"
write_inventory "$manifest_bad"
manifest_archive="$tmp/manifest-bad.tar.gz"
build_archive "$manifest_bad" "$manifest_archive"
write_handoff "$manifest_archive" "$manifest_bad" "$manifest_archive.handoff.tsv" "$manifest_archive.handoff.sig" "$priv"
expect_reject manifest-signature "$VERIFIER" --archive "$manifest_archive" --handoff "$manifest_archive.handoff.tsv" --signature "$manifest_archive.handoff.sig" --public-key "$pub" --extract-to "$tmp/manifest-bad-extract"

unsafe_archive="$tmp/unsafe.tar.gz"
tar -czf "$unsafe_archive" -C "$source_dir" --transform='s#^jjdguard-test#../escape#' jjdguard-test
write_handoff "$unsafe_archive" "$bundle" "$unsafe_archive.handoff.tsv" "$unsafe_archive.handoff.sig" "$priv"
expect_reject unsafe-path "$VERIFIER" --archive "$unsafe_archive" --handoff "$unsafe_archive.handoff.tsv" --signature "$unsafe_archive.handoff.sig" --public-key "$pub" --extract-to "$tmp/unsafe-extract"

duplicate_archive="$tmp/duplicate.tar.gz"
tar -czf "$duplicate_archive" -C "$source_dir" jjdguard-test jjdguard-test
write_handoff "$duplicate_archive" "$bundle" "$duplicate_archive.handoff.tsv" "$duplicate_archive.handoff.sig" "$priv"
expect_reject duplicate-member "$VERIFIER" --archive "$duplicate_archive" --handoff "$duplicate_archive.handoff.tsv" --signature "$duplicate_archive.handoff.sig" --public-key "$pub" --extract-to "$tmp/duplicate-extract"

printf 'offline_archive_trust=ok external_key=1 domain_separated=2 inventory_bound=1 manifest_bound=1 archive_tamper_rejected=1 unsafe_members_rejected=2\n'
