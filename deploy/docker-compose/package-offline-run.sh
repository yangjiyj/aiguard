#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HEADER="$PROJECT_ROOT/deploy/offline-installer/self-extracting-header.sh"
BUNDLE_BUILDER="$SCRIPT_DIR/package-offline-bundle.sh"
FAILURE_EVIDENCE_COLLECTOR="$SCRIPT_DIR/collect-package-failure-evidence.sh"
PUBLIC_KEY_ANCHOR="$PROJECT_ROOT/deploy/offline-installer/release-public.sha256"
ARCH="${1:-}"
OUTPUT_DIR="${2:-$PROJECT_ROOT/dist/offline}"
SIGNING_KEY="${OFFLINE_MANIFEST_SIGNING_KEY_FILE:-}"
BUNDLE_PROFILE="${BUNDLE_PROFILE:-full}"
INCLUDE_CHAT="${INCLUDE_CHAT:-1}"

normalize_arch() {
  case "$1" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) echo '[error] JJDGuard offline bundle supports amd64/arm64 only' >&2; exit 2 ;;
  esac
}

validate_release_public_key_anchor() {
  local anchor_line expected_hash expected_name extra actual_hash
  [[ -f "$PUBLIC_KEY_ANCHOR" && ! -L "$PUBLIC_KEY_ANCHOR" ]] || {
    echo '[error] trusted release public-key anchor is unavailable' >&2
    exit 1
  }
  [[ "$(wc -l <"$PUBLIC_KEY_ANCHOR")" == 1 ]] || {
    echo '[error] trusted release public-key anchor is invalid' >&2
    exit 1
  }
  anchor_line="$(<"$PUBLIC_KEY_ANCHOR")"
  IFS=' ' read -r expected_hash expected_name extra <<<"$anchor_line"
  [[ "$expected_hash" =~ ^[0-9a-f]{64}$ && "$expected_name" == release-public.pem && -z "$extra" ]] || {
    echo '[error] trusted release public-key anchor is invalid' >&2
    exit 1
  }
  actual_hash="$(sha256sum "$work/release-public.pem" | awk '{print $1}')"
  [[ "$actual_hash" == "$expected_hash" ]] || {
    echo '[error] release signing key does not match the trusted public-key anchor' >&2
    exit 1
  }
}

read_bundle_manifest_identity() {
  python3 - "$1" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

bundle = pathlib.Path(sys.argv[1])
manifest_path = bundle / "manifest.json"
compose_manifest_path = bundle / "deploy/docker-compose/manifest.json"
source_path = bundle / "release-source.json"
provenance_path = bundle / "image-provenance.json"
sbom_index_path = bundle / "sbom/index.json"

def fail(message):
    raise SystemExit(f"[error] bundle manifest chain is invalid: {message}")

def load(path):
    if not path.is_file() or path.is_symlink():
        fail(f"required JSON file is not regular: {path.name}")
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.name}: {exc}")

manifest = load(manifest_path)
compose_manifest = load(compose_manifest_path)
if manifest != compose_manifest:
    fail("root and compose manifests differ")
required = {
    "schema", "product", "version", "source_revision", "source_tree",
    "image_provenance_sha256", "sbom_index_sha256", "target_arch",
    "bundle_profile", "include_chat", "artifact_stage", "min_data_version",
    "manifest_signature", "built_at", "bundle",
}
platform = isinstance(manifest, dict) and manifest.get("product") == "agent-platform"
platform_keys = {"product_profile", "product_name", "product_version", "product_slug", "agent_kit_sha256"}
if not isinstance(manifest, dict) or set(manifest) != (required | platform_keys if platform else required):
    fail("manifest keys do not exactly match v2")
if manifest["schema"] != "offline-manifest/v2" or manifest["product"] != ("agent-platform" if platform else "jjdguard-enterprise"):
    fail("manifest schema or product is invalid")
if platform:
    if (manifest["product_profile"] != "agent-platform" or
            not isinstance(manifest["product_name"], str) or
            not re.fullmatch(r"[0-9A-Za-z._ -]+", manifest["product_name"]) or
            not isinstance(manifest["product_version"], str) or
            not re.fullmatch(r"[0-9A-Za-z.-]+", manifest["product_version"]) or
            not isinstance(manifest["product_slug"], str) or
            not re.fullmatch(r"[a-z0-9-]+", manifest["product_slug"]) or
            not isinstance(manifest["agent_kit_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", manifest["agent_kit_sha256"])):
        fail("platform identity is invalid")
    kit = bundle / "deploy/docker-compose/agent-kit"
    if not kit.is_dir() or kit.is_symlink():
        fail("platform agent-kit is missing")
    digest = hashlib.sha256()
    files = sorted(kit.rglob("*"))
    if not any(path.is_file() and path.name != ".gitkeep" for path in files):
        fail("platform agent-kit has no payload")
    for path in files:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            fail("unsafe agent-kit member")
        if path.is_file():
            relative = path.relative_to(kit).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(4, "big") + relative)
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    if digest.hexdigest() != manifest["agent_kit_sha256"]:
        fail("agent-kit digest mismatch")
if manifest["artifact_stage"] != "candidate" or manifest["manifest_signature"] not in {"ed25519-domain-v2", "sha256-only"}:
    fail("manifest stage or signature contract is invalid")
if manifest["bundle"] != bundle.name or manifest["bundle_profile"] not in {"lite", "full"}:
    fail("manifest bundle binding is invalid")
if not re.fullmatch((r"agent-platform-" if platform else r"jjdguard-") + r"[A-Za-z0-9._-]+", bundle.name):
    fail("manifest bundle root is invalid")
if manifest["include_chat"] not in {"0", "1"} or manifest["target_arch"] not in {"amd64", "arm64", "armv7"}:
    fail("manifest selection binding is invalid")
if not isinstance(manifest["version"], str) or not re.fullmatch(r"[0-9A-Za-z.-]+", manifest["version"]):
    fail("manifest version is invalid")
if not isinstance(manifest["built_at"], str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", manifest["built_at"]):
    fail("manifest build time is invalid")
minimum_path = bundle / "deploy/docker-compose/upgrade-min-data-version"
if not minimum_path.is_file() or minimum_path.is_symlink():
    fail("minimum data version contract is missing")
minimum = minimum_path.read_text(encoding="utf-8").strip()
if not re.fullmatch(r"[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql", minimum):
    fail("minimum data version contract is invalid")
if manifest["min_data_version"] != minimum:
    fail("manifest minimum data version is invalid")
for key in ("source_revision", "source_tree"):
    if not isinstance(manifest[key], str) or not re.fullmatch(r"[0-9a-f]{40}", manifest[key]):
        fail(f"manifest {key} is invalid")
for key in ("image_provenance_sha256", "sbom_index_sha256"):
    if not isinstance(manifest[key], str) or not re.fullmatch(r"[0-9a-f]{64}", manifest[key]):
        fail(f"manifest {key} is invalid")
source = load(source_path)
if (not isinstance(source, dict) or set(source) != {"schema", "remote", "source_revision", "source_tree"}
        or source.get("schema") != "jjdguard-release-source/v1"
        or not isinstance(source.get("remote"), str) or not source["remote"]
        or source.get("source_revision") != manifest["source_revision"]
        or source.get("source_tree") != manifest["source_tree"]):
    fail("release source receipt does not match manifest")
for path, key in ((provenance_path, "image_provenance_sha256"), (sbom_index_path, "sbom_index_sha256")):
    if not path.is_file() or path.is_symlink():
        fail(f"required evidence is not regular: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != manifest[key]:
        fail(f"{key} does not match bundled evidence")
for key in ("version", "target_arch", "bundle_profile", "include_chat", "artifact_stage", "source_revision", "source_tree", "image_provenance_sha256", "sbom_index_sha256"):
    print(manifest[key])
PY
}

[[ -n "$ARCH" ]] || { echo "usage: $0 <amd64> [output-dir]" >&2; exit 2; }
ARCH="$(normalize_arch "$ARCH")"
HOST_ARCH="$(normalize_arch "$(uname -m)")"
if [[ "$HOST_ARCH" != "$ARCH" && "${OFFLINE_ALLOW_CROSS_ARCH:-0}" != 1 ]]; then
  echo "[error] packaging host architecture ($HOST_ARCH) != target ($ARCH); QEMU/multi-arch verification and OFFLINE_ALLOW_CROSS_ARCH=1 are required" >&2
  exit 2
fi
[[ "$HOST_ARCH" == amd64 ]] || {
  echo '[error] release packaging host must be Linux amd64 because the locked Syft toolchain is amd64' >&2
  exit 2
}
[[ -r "$HEADER" && -x "$BUNDLE_BUILDER" ]] || { echo '[error] packaging scripts are incomplete' >&2; exit 1; }
if [[ -n "$SIGNING_KEY" && ! -r "$SIGNING_KEY" ]]; then
  echo '[error] optional OFFLINE_MANIFEST_SIGNING_KEY_FILE is unreadable' >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
work=''
cleanup_package_work() {
  local status=$?
  trap - EXIT
  if [[ -n "$work" && -d "$work" && ! -L "$work" ]]; then
    if (( status != 0 )); then
      "$FAILURE_EVIDENCE_COLLECTOR" --output-dir "$OUTPUT_DIR" --work-dir "$work" --exit-code "$status" || \
        echo '[warn] failure evidence collection failed; work payload will still be removed' >&2
    fi
    rm -rf -- "$work"
  fi
  exit "$status"
}
trap cleanup_package_work EXIT
work="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-run.XXXXXX")"
mkdir -p "$work/bundle" "$work/outer"

if [[ "${JJD_RELEASE_TESTING:-0}" == 1 && "${JJD_TEST_FORCE_PACKAGE_FAILURE:-0}" == 1 ]]; then
  printf '%s\n' 'forced package failure for evidence cleanup regression' >"$work/forced-failure.log"
  exit 73
fi

echo "[step] building self-contained $ARCH bundle through package-offline-bundle.sh"
OFFLINE_TARGET_ARCH="$ARCH" \
OFFLINE_ALLOW_CROSS_ARCH="${OFFLINE_ALLOW_CROSS_ARCH:-0}" \
OFFLINE_MANIFEST_SIGNING_KEY_FILE="$SIGNING_KEY" \
BUNDLE_PROFILE="$BUNDLE_PROFILE" INCLUDE_CHAT="$INCLUDE_CHAT" \
PRODUCT_PROFILE="${PRODUCT_PROFILE:-gateway}" PRODUCT_NAME="${PRODUCT_NAME:-}" \
PRODUCT_VERSION="${PRODUCT_VERSION:-}" PRODUCT_SLUG="${PRODUCT_SLUG:-}" \
  sh "$BUNDLE_BUILDER" "$work/bundle"

bundle_prefix=jjdguard
if [[ "${PRODUCT_PROFILE:-gateway}" == agent-platform ]]; then
  bundle_prefix=agent-platform
fi
bundle="$(find "$work/bundle" -maxdepth 1 -type f -name "${bundle_prefix}-*-${ARCH}-*.tar.gz" | sort | tail -1)"
[[ -s "$bundle" ]] || { echo '[error] architecture bundle was not produced' >&2; exit 1; }
mkdir -p "$work/sbom-check"
tar -xzf "$bundle" -C "$work/sbom-check"
mapfile -t bundle_roots < <(find "$work/sbom-check" -mindepth 1 -maxdepth 1 -type d | sort)
[[ "${#bundle_roots[@]}" == 1 ]] || { echo '[error] bundle SBOM verification root is ambiguous' >&2; exit 1; }
bundle_root="${bundle_roots[0]}"
env -u JJD_RELEASE_TESTING -u JJD_TEST_SYFT_BIN -u JJD_TEST_SYFT_SHA256 \
  python3 "$SCRIPT_DIR/verify-sbom-index.py" \
  --bundle "$bundle_root" \
  --provenance "$bundle_root/image-provenance.json" \
  --index "$bundle_root/sbom/index.json"
bundle_identity="$(read_bundle_manifest_identity "$bundle_root")"
mapfile -t manifest_values <<<"$bundle_identity"
[[ "${#manifest_values[@]}" == 9 ]] || { echo '[error] bundle manifest identity is incomplete' >&2; exit 1; }
platform_product=''
if [[ "$bundle_prefix" == agent-platform ]]; then
  platform_product="$(python3 - "$bundle_root/manifest.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["product_name"])
PY
)"
fi
version="${manifest_values[0]}"
installer_version="$version"
if [[ "$bundle_prefix" == agent-platform ]]; then
  installer_version="$(python3 - "$bundle_root/manifest.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:/n    print(json.load(handle)["product_version"])
PY
)"
fi
bundle_arch="${manifest_values[1]}"
bundle_profile="${manifest_values[2]}"
bundle_include_chat="${manifest_values[3]}"
artifact_stage="${manifest_values[4]}"
source_revision="${manifest_values[5]}"
source_tree="${manifest_values[6]}"
image_provenance_sha256="${manifest_values[7]}"
sbom_index_sha256="${manifest_values[8]}"
[[ "$bundle_arch" == "$ARCH" && "$bundle_profile" == "$BUNDLE_PROFILE" && "$bundle_include_chat" == "$INCLUDE_CHAT" ]] || {
  echo '[error] generated bundle selection does not match requested .run selection' >&2
  exit 1
}
[[ ! -e "$OUTPUT_DIR/image-provenance.json" && ! -L "$OUTPUT_DIR/image-provenance.json" &&
   ! -e "$OUTPUT_DIR/sbom" && ! -L "$OUTPUT_DIR/sbom" ]] || {
  echo '[error] output already contains provenance or SBOM evidence' >&2
  exit 1
}
install -m 0444 "$bundle_root/image-provenance.json" "$OUTPUT_DIR/image-provenance.json"
cp -a "$bundle_root/sbom" "$OUTPUT_DIR/sbom"
payload_sha="$(sha256sum "$bundle" | awk '{print $1}')"
payload_size="$(stat -c %s "$bundle")"

cat >"$work/outer/run-manifest.json" <<EOF
{
  "schema": "jjdguard-offline-run-manifest/v2",
  "product": "${platform_product:-JJDGuard}",
  "version": "$version",
  "target_arch": "$ARCH",
  "bundle_profile": "$bundle_profile",
  "include_chat": "$bundle_include_chat",
  "artifact_stage": "$artifact_stage",
  "source_revision": "$source_revision",
  "source_tree": "$source_tree",
  "image_provenance_sha256": "$image_provenance_sha256",
  "sbom_index_sha256": "$sbom_index_sha256",
  "payload_sha256": "$payload_sha",
  "payload_size": $payload_size,
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
run_payload="$work/outer/run-manifest.payload"
{ printf "%s\0" "jjdguard-offline-run-manifest/v2"; cat "$work/outer/run-manifest.json"; } >"$run_payload"
if [[ -n "$SIGNING_KEY" ]]; then
  openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" -in "$run_payload" -out "$work/outer/run-manifest.sig"
  [ "$(stat -c %s "$work/outer/run-manifest.sig")" = 64 ] || { echo "[error] unexpected Ed25519 signature length" >&2; exit 1; }
else
  (cd "$work/outer" && sha256sum run-manifest.json >run-manifest.sig)
fi
cp "$bundle" "$work/outer/payload.tar.gz"
tar -C "$work/outer" -cf "$work/outer.tar" payload.tar.gz run-manifest.json run-manifest.sig

bootstrap="$work/header.sh"
if [[ -n "$SIGNING_KEY" ]]; then
  openssl pkey -in "$SIGNING_KEY" -pubout -out "$work/release-public.pem" >/dev/null 2>&1 || {
    echo '[error] failed to derive optional release public key' >&2
    exit 1
  }
  validate_release_public_key_anchor
  pub_b64="$(openssl base64 -A <"$work/release-public.pem")"
  [[ -n "$pub_b64" ]] || { echo '[error] failed to derive optional release public key' >&2; exit 1; }
  sed "s|__EMBEDDED_PUBLIC_KEY__|$pub_b64|" "$HEADER" >"$bootstrap"
else
  sed "s|__EMBEDDED_PUBLIC_KEY__|sha256-only|" "$HEADER" >"$bootstrap"
fi
grep -Fqx "EMBEDDED_HEADER_SIGNATURE='__EMBEDDED_HEADER_SIGNATURE__'" "$bootstrap" || {
  echo '[error] self-extracting header signature placeholder is missing' >&2
  exit 1
}
if [[ -n "$SIGNING_KEY" ]]; then
  header_payload="$work/header.payload"
  header_signature="$work/header.sig"
  { printf '%s\0' 'jjdguard-offline-run-header/v1'; cat "$bootstrap"; } >"$header_payload"
  openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" -in "$header_payload" -out "$header_signature"
  [ "$(stat -c %s "$header_signature")" = 64 ] || {
    echo '[error] unexpected optional header signature length' >&2
    exit 1
  }
  header_sig_b64="$(openssl base64 -A <"$header_signature")"
else
  header_sig_b64=sha256-only
fi

# Candidate audit inputs remain artifact-bound by SHA-256. An optional public
# key is emitted only when a signing key was explicitly supplied.
cp "$bundle" "$OUTPUT_DIR/"
cp "$bundle.handoff.tsv" "$OUTPUT_DIR/"
cp "$bundle.handoff.sig" "$OUTPUT_DIR/"
if [[ -n "$SIGNING_KEY" ]]; then
  install -m 0444 "$work/release-public.pem" "$OUTPUT_DIR/${bundle_prefix}-release-public-$version.pem"
fi

short_sha="${source_revision:0:8}"
installer_prefix=JJDGuard
if [[ "$bundle_prefix" == agent-platform ]]; then
  installer_prefix="$(python3 - "$bundle_root/manifest.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["product_slug"])
PY
)"
fi
output="$OUTPUT_DIR/${installer_prefix}-offline-$installer_version-$ARCH.run"
legacy_output="$OUTPUT_DIR/${installer_prefix}-offline-$installer_version-$short_sha-$ARCH.run"
if [[ "$bundle_prefix" == agent-platform ]]; then
  output="$OUTPUT_DIR/${installer_prefix}-offline-$installer_version-$short_sha-$ARCH.run"
  legacy_output="$output"
fi
sed "s|__EMBEDDED_HEADER_SIGNATURE__|$header_sig_b64|" "$bootstrap" >"$output"
grep -Fqx "EMBEDDED_HEADER_SIGNATURE='$header_sig_b64'" "$output" || {
  echo '[error] failed to inject self-extracting header signature' >&2
  exit 1
}
dd if="$work/outer.tar" of="$output" bs=4M oflag=append conv=notrunc status=none
chmod 755 "$output"
if [ "$legacy_output" != "$output" ]; then
  ln "$output" "$legacy_output"
fi
(cd "$OUTPUT_DIR" && sha256sum "${output##*/}" >"${output##*/}.sha256" && sha256sum "${legacy_output##*/}" >"${legacy_output##*/}.sha256")

bash "$output" --verify-only
echo '[ok] self-contained self-extracting installer created'
echo "[info] $output"
echo "[info] $output.sha256"
