#!/usr/bin/env bash
# Shared minimal signed v2 fixture for installer behavior tests.

jjd_v2_sha() { sha256sum "$1" | awk '{print $1}'; }
jjd_v2_b64u() { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
JJD_V2_SOURCE_REVISION=0123456789abcdef0123456789abcdef01234567
JJD_V2_SOURCE_TREE=89abcdef0123456789abcdef0123456789abcdef
JJD_V2_IMAGE_ID=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

jjd_v2_write_inventory() {
  local bundle="$1" rel
  chmod u+w "$bundle/offline-inventory.tsv" 2>/dev/null || true
  {
    printf '%s\t%s\n' schema jjdguard-offline-inventory/v1
    while IFS= read -r rel; do
      printf '%s\t%s\t%s\t%s\n' file "$(jjd_v2_b64u "$rel")" \
        "$(stat -c '%s' "$bundle/$rel")" "$(jjd_v2_sha "$bundle/$rel")"
    done < <(cd "$bundle" && find . -type f ! -name offline-inventory.tsv -printf '%P\n' | LC_ALL=C sort)
  } >"$bundle/offline-inventory.tsv"
  chmod 0444 "$bundle/offline-inventory.tsv"
}

jjd_v2_make_bundle() {
  local bundle="$1" private_key="$2" target_arch="$3" toolchain_lock="$4"
  local syft_sha provenance_sha sbom_bundle_sha sbom_image_sha sbom_sha manifest
  syft_sha="$(awk -F= '$1 == "syft_binary_sha256" {print $2}' "$toolchain_lock")"
  [[ "$syft_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  mkdir -p "$bundle/deploy/docker-compose" "$bundle/sbom/images"
  printf '%s\n' "{\"schema\":\"jjdguard-release-source/v1\",\"remote\":\"git@github.com:yangjiyj/aiguard.git\",\"source_revision\":\"$JJD_V2_SOURCE_REVISION\",\"source_tree\":\"$JJD_V2_SOURCE_TREE\"}" >"$bundle/release-source.json"
  printf '%s\n' "{\"images\":[{\"component\":\"fixture\",\"image_id\":\"$JJD_V2_IMAGE_ID\"}]}" >"$bundle/image-provenance.json"
  printf '%s\n' '{"spdxVersion":"SPDX-2.3","creationInfo":{"creators":["Tool: syft-1.44.0"]},"packages":[{"name":"fixture"}]}' >"$bundle/sbom/bundle.spdx.json"
  cp "$bundle/sbom/bundle.spdx.json" "$bundle/sbom/images/fixture.spdx.json"
  provenance_sha="$(jjd_v2_sha "$bundle/image-provenance.json")"
  sbom_bundle_sha="$(jjd_v2_sha "$bundle/sbom/bundle.spdx.json")"
  sbom_image_sha="$(jjd_v2_sha "$bundle/sbom/images/fixture.spdx.json")"
  printf '%s\n' "{\"schema\":\"jjdguard-release-sbom-index/v1\",\"syft\":{\"version\":\"1.44.0\",\"binary_sha256\":\"$syft_sha\"},\"bundle\":{\"path\":\"sbom/bundle.spdx.json\",\"sha256\":\"$sbom_bundle_sha\"},\"images\":[{\"component\":\"fixture\",\"image_id\":\"$JJD_V2_IMAGE_ID\",\"path\":\"sbom/images/fixture.spdx.json\",\"sha256\":\"$sbom_image_sha\"}]}" >"$bundle/sbom/index.json"
  sbom_sha="$(jjd_v2_sha "$bundle/sbom/index.json")"
  manifest="{\"schema\":\"offline-manifest/v2\",\"product\":\"jjdguard-enterprise\",\"version\":\"fixture\",\"source_revision\":\"$JJD_V2_SOURCE_REVISION\",\"source_tree\":\"$JJD_V2_SOURCE_TREE\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"target_arch\":\"$target_arch\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"min_data_version\":\"077_request_logs_proxy_access_type_resolved.sql\",\"manifest_signature\":\"ed25519-domain-v2\",\"built_at\":\"2026-08-08T00:00:00Z\",\"bundle\":\"$(basename "$bundle")\"}"
  printf '%s\n' "$manifest" >"$bundle/manifest.json"
  printf '%s\n' "$manifest" >"$bundle/deploy/docker-compose/manifest.json"
  printf '%s\n' '077_request_logs_proxy_access_type_resolved.sql' >"$bundle/deploy/docker-compose/upgrade-min-data-version"
  printf '%s\n' '137_enterprise_identity_department.sql' >"$bundle/deploy/docker-compose/upgrade-bridge-target-version"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$bundle/install.sh"
  chmod 0755 "$bundle/install.sh"
  { printf '%s\0' jjdguard-offline-manifest/v2; cat "$bundle/manifest.json"; } >"$bundle/manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$bundle/manifest.payload" -out "$bundle/manifest.sig"
  rm -f "$bundle/manifest.payload"
  chmod 0444 "$bundle/manifest.sig"
}

jjd_v2_seal_run() {
  local header="$1" private_key="$2" public_key="$3" bundle="$4" output="$5" work="$6" target_arch="$7"
  local payload_sha payload_size provenance_sha sbom_sha public_b64 header_sig_b64
  mkdir -p "$work"
  tar -C "$(dirname "$bundle")" -czf "$work/payload.tar.gz" "$(basename "$bundle")"
  payload_sha="$(jjd_v2_sha "$work/payload.tar.gz")"
  payload_size="$(stat -c '%s' "$work/payload.tar.gz")"
  provenance_sha="$(jjd_v2_sha "$bundle/image-provenance.json")"
  sbom_sha="$(jjd_v2_sha "$bundle/sbom/index.json")"
  printf '%s\n' "{\"schema\":\"jjdguard-offline-run-manifest/v2\",\"product\":\"JJDGuard\",\"version\":\"fixture\",\"target_arch\":\"$target_arch\",\"bundle_profile\":\"full\",\"include_chat\":\"1\",\"artifact_stage\":\"candidate\",\"source_revision\":\"$JJD_V2_SOURCE_REVISION\",\"source_tree\":\"$JJD_V2_SOURCE_TREE\",\"image_provenance_sha256\":\"$provenance_sha\",\"sbom_index_sha256\":\"$sbom_sha\",\"payload_sha256\":\"$payload_sha\",\"payload_size\":$payload_size,\"built_at\":\"2026-08-08T00:00:00Z\"}" >"$work/run-manifest.json"
  { printf '%s\0' jjdguard-offline-run-manifest/v2; cat "$work/run-manifest.json"; } >"$work/run-manifest.payload"
  openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$work/run-manifest.payload" -out "$work/run-manifest.sig"
  tar -C "$work" -cf "$work/outer.tar" payload.tar.gz run-manifest.json run-manifest.sig
  public_b64="$(openssl base64 -A <"$public_key")"
  sed "s|__EMBEDDED_PUBLIC_KEY__|$public_b64|" "$header" >"$output"
  grep -Fqx "EMBEDDED_HEADER_SIGNATURE='__EMBEDDED_HEADER_SIGNATURE__'" "$output" || return 1
  { printf '%s\0' jjdguard-offline-run-header/v1; cat "$output"; } >"$work/header.payload"
  openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$work/header.payload" -out "$work/header.sig"
  header_sig_b64="$(openssl base64 -A <"$work/header.sig")"
  [[ "${#header_sig_b64}" == 88 ]] || return 1
  sed -i "s|__EMBEDDED_HEADER_SIGNATURE__|$header_sig_b64|" "$output"
  grep -Fqx "EMBEDDED_HEADER_SIGNATURE='$header_sig_b64'" "$output" || return 1
  dd if="$work/outer.tar" of="$output" bs=1M oflag=append conv=notrunc status=none
  chmod 0755 "$output"
}
