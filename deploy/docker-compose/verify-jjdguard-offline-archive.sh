#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HANDOFF_DOMAIN='jjdguard-offline-handoff/v2'
MANIFEST_DOMAIN='jjdguard-offline-manifest/v2'

die() {
  printf '[offline-verify] %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'Usage: verify-jjdguard-offline-archive.sh --archive FILE --handoff FILE' \
    '       --signature FILE [--public-key FILE] --extract-to NEW_DIRECTORY'
}

for tool in openssl python3 sha256sum stat od tail mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "required command is missing: $tool"
done

archive=''
handoff=''
signature=''
public_key=''
extract_to=''
declare -A seen=()
set_option() {
  local name="$1" value="$2"
  [[ -z "${seen[$name]+x}" ]] || die "duplicate option: $name"
  [[ -n "$value" ]] || die "empty option: $name"
  seen[$name]=1
  printf -v "$name" '%s' "$value"
}
while (($#)); do
  case "$1" in
    --archive|--handoff|--signature|--public-key|--extract-to)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --archive) set_option archive "$2" ;;
        --handoff) set_option handoff "$2" ;;
        --signature) set_option signature "$2" ;;
        --public-key) set_option public_key "$2" ;;
        --extract-to) set_option extract_to "$2" ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
for required in archive handoff signature extract_to; do
  [[ -n "${!required}" ]] || die "missing required option: $required"
done
for input in archive handoff signature; do
  [[ -f "${!input}" && ! -L "${!input}" ]] || die "$input must be a regular non-symlink file"
done
[[ ! -e "$extract_to" && ! -L "$extract_to" ]] || die 'extraction destination must not already exist'
[[ "$extract_to" != / && -d "$(dirname "$extract_to")" ]] || die 'invalid extraction destination'

if [[ -n "$public_key" ]]; then
  [[ -f "$public_key" && ! -L "$public_key" ]] || die 'public key must be a regular non-symlink file'
  key_mode="$(stat -c '%a' "$public_key")"
  key_owner="$(stat -c '%u' "$public_key")"
  [[ "$key_mode" =~ ^[0-7]{3,4}$ ]] || die 'could not read public key mode'
  (( (8#$key_mode & 8#022) == 0 )) || die 'trusted public key must not be group/world writable'
  [[ "$key_owner" == 0 || "$key_owner" == "$(id -u)" ]] || die 'trusted public key must be owned by root or the invoking user'
  openssl pkey -pubin -in "$public_key" -text_pub -noout 2>/dev/null | grep -qi ED25519 || die 'trusted public key must be Ed25519'
fi

validate_ascii_receipt() {
  local file="$1" label="$2" last
  if ! od -An -v -tu1 "$file" | awk '
    { for (i=1; i<=NF; i++) if ($i != 9 && $i != 10 && ($i < 32 || $i > 126)) bad=1 }
    END { exit bad ? 1 : 0 }
  '; then
    die "$label contains non-canonical bytes"
  fi
  last="$(tail -c 1 "$file" | od -An -tu1 | tr -d '[:space:]')"
  [[ "$last" == 10 ]] || die "$label must end with LF"
}
validate_ascii_receipt "$handoff" 'handoff'
mapfile -t handoff_lines <"$handoff"
handoff_keys=(schema archive_file bundle_root archive_sha256 manifest_sha256 inventory_sha256 product version source_revision source_tree image_provenance_sha256 sbom_index_sha256 target_arch bundle_profile include_chat artifact_stage)
platform_keys=(product_profile product_name product_version product_slug agent_kit_sha256)
if [[ "${#handoff_lines[@]}" -eq $((${#handoff_keys[@]} + ${#platform_keys[@]})) ]]; then
  handoff_keys+=("${platform_keys[@]}")
fi
[[ "${#handoff_lines[@]}" -eq "${#handoff_keys[@]}" ]] || die 'handoff field count mismatch'
declare -A receipt=()
for i in "${!handoff_keys[@]}"; do
  IFS=$'\t' read -r key value extra <<<"${handoff_lines[$i]}"
  [[ "$key" == "${handoff_keys[$i]}" && -n "$value" && -z "$extra" ]] || die "handoff is not canonical at field ${handoff_keys[$i]}"
  [[ "${handoff_lines[$i]}" == "$key"$'\t'"$value" ]] || die 'handoff delimiter mismatch'
  receipt[$key]="$value"
done
[[ "${receipt[schema]}" == "$HANDOFF_DOMAIN" ]] || die 'handoff schema mismatch'
for hash_key in archive_sha256 manifest_sha256 inventory_sha256 image_provenance_sha256 sbom_index_sha256; do
  [[ "${receipt[$hash_key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid handoff hash: $hash_key"
done
if [[ -n "${receipt[agent_kit_sha256]+x}" ]]; then
  [[ "${receipt[agent_kit_sha256]}" =~ ^[0-9a-f]{64}$ ]] || die 'invalid agent-kit hash'
fi
for encoded_key in archive_file bundle_root product version source_revision source_tree target_arch bundle_profile include_chat artifact_stage; do
  [[ "${receipt[$encoded_key]}" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid base64url field: $encoded_key"
done

decode_b64u() {
  local value="$1" rem
  rem=$((${#value} % 4))
  [[ "$rem" -ne 1 ]] || return 1
  case "$rem" in 2) value="${value}==" ;; 3) value="${value}=" ;; esac
  printf '%s' "$value" | tr '_-' '/+' | openssl base64 -d -A
}
archive_file="$(decode_b64u "${receipt[archive_file]}")" || die 'invalid encoded archive filename'
bundle_root="$(decode_b64u "${receipt[bundle_root]}")" || die 'invalid encoded bundle root'
product="$(decode_b64u "${receipt[product]}")" || die 'invalid encoded product'
version="$(decode_b64u "${receipt[version]}")" || die 'invalid encoded version'
source_revision="$(decode_b64u "${receipt[source_revision]}")" || die 'invalid encoded source revision'
source_tree="$(decode_b64u "${receipt[source_tree]}")" || die 'invalid encoded source tree'
target_arch="$(decode_b64u "${receipt[target_arch]}")" || die 'invalid encoded target architecture'
bundle_profile="$(decode_b64u "${receipt[bundle_profile]}")" || die 'invalid encoded bundle profile'
include_chat="$(decode_b64u "${receipt[include_chat]}")" || die 'invalid encoded chat selection'
artifact_stage="$(decode_b64u "${receipt[artifact_stage]}")" || die 'invalid encoded artifact stage'
[[ "$archive_file" =~ ^[A-Za-z0-9._-]+\.tar\.gz$ && "$archive_file" == "$(basename "$archive")" ]] || die 'archive filename binding mismatch'
[[ "$bundle_root" =~ ^(jjdguard|agent-platform)-[A-Za-z0-9._-]+$ ]] || die 'invalid bundle root binding'
if [[ "$bundle_root" == agent-platform-* ]]; then
  [[ "$product" == agent-platform && -n "${receipt[product_profile]+x}" ]] || die 'platform product binding mismatch'
  for encoded_key in product_profile product_name product_version product_slug; do
    [[ "${receipt[$encoded_key]}" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid platform handoff field: $encoded_key"
  done
  [[ "$(decode_b64u "${receipt[product_profile]}")" == agent-platform ]] || die 'platform profile binding mismatch'
  platform_name="$(decode_b64u "${receipt[product_name]}")" || die 'invalid platform name'
  platform_version="$(decode_b64u "${receipt[product_version]}")" || die 'invalid platform version'
  platform_slug="$(decode_b64u "${receipt[product_slug]}")" || die 'invalid platform slug'
  [[ "$platform_name" =~ ^[0-9A-Za-z._\ -]+$ && "$platform_version" =~ ^[0-9A-Za-z.-]+$ && "$platform_slug" =~ ^[a-z0-9-]+$ ]] || die 'invalid platform identity'
else
  [[ "$product" == jjdguard-enterprise && -z "${receipt[product_profile]+x}" ]] || die 'product binding mismatch'
fi
[[ "$version" =~ ^[0-9A-Za-z.-]+$ && "$source_revision" =~ ^[0-9a-f]{40}$ && "$source_tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid release identity binding'
[[ "$target_arch" =~ ^(amd64|arm64|armv7)$ ]] || die 'invalid target architecture binding'
[[ "$bundle_profile" =~ ^(lite|full)$ && "$include_chat" =~ ^[01]$ && "$artifact_stage" == candidate ]] || die 'invalid release selection binding'

tmp_dir="$(mktemp -d)"
success=0
cleanup() {
  rm -rf "$tmp_dir"
  if [[ "$success" -ne 1 && -d "$extract_to" ]]; then
    rm -rf "$extract_to"
  fi
}
trap cleanup EXIT
if [[ "$(stat -c '%s' "$signature")" == 64 ]]; then
  [[ -n "$public_key" ]] || die 'signed handoff requires --public-key'
  { printf '%s\0' "$HANDOFF_DOMAIN"; cat "$handoff"; } >"$tmp_dir/handoff-domain.bin"
  openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" -sigfile "$signature" -in "$tmp_dir/handoff-domain.bin" >/dev/null 2>&1 || die 'external handoff signature verification failed'
else
  expected_line="$(sha256sum "$handoff" | awk '{print $1}')  $(basename "$handoff")"
  [[ "$(tr -d '\r\n' <"$signature")" == "$expected_line" ]] || die 'handoff SHA-256 identity failed'
fi
[[ "$(sha256sum "$archive" | awk '{print $1}')" == "${receipt[archive_sha256]}" ]] || die 'archive hash does not match handoff'

JJDGUARD_OFFLINE_MAX_EXTRACT_BYTES="${JJDGUARD_OFFLINE_MAX_EXTRACT_BYTES:-214748364800}"
[[ "$JJDGUARD_OFFLINE_MAX_EXTRACT_BYTES" =~ ^[0-9]+$ ]] || die 'invalid extraction size limit'
python3 - "$archive" "$extract_to" "$bundle_root" "$JJDGUARD_OFFLINE_MAX_EXTRACT_BYTES" <<'PY'
import os
import pathlib
import shutil
import sys
import tarfile

archive, destination, expected_root, max_bytes_raw = sys.argv[1:]
max_bytes = int(max_bytes_raw)
dest = pathlib.Path(destination)
if dest.exists() or dest.is_symlink():
    raise SystemExit("destination already exists")
seen: set[str] = set()
total = 0
with tarfile.open(archive, mode="r:gz") as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit("archive is empty")
    for member in members:
        name = member.name.rstrip("/")
        path = pathlib.PurePosixPath(name)
        if not name or name.startswith("/") or "\\" in name or any(part in ("", ".", "..") for part in path.parts):
            raise SystemExit("unsafe archive member")
        if any(ord(char) < 32 or ord(char) == 127 for char in name):
            raise SystemExit("control character in archive member")
        if path.parts[0] != expected_root:
            raise SystemExit("archive has an unexpected top-level root")
        if name in seen:
            raise SystemExit("duplicate archive member")
        seen.add(name)
        if not (member.isdir() or member.isfile()):
            raise SystemExit("archive links and special files are forbidden")
        if member.mode & 0o7000:
            raise SystemExit("archive member has privileged mode bits")
        if member.isfile():
            total += member.size
            if total > max_bytes:
                raise SystemExit("archive exceeds extraction size limit")
    dest.mkdir(mode=0o700)
    base = dest.resolve()
    for member in members:
        name = member.name.rstrip("/")
        target = dest.joinpath(*pathlib.PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if member.isdir():
            target.mkdir(exist_ok=True, mode=0o700)
            continue
        resolved_parent = target.parent.resolve()
        if base != resolved_parent and base not in resolved_parent.parents:
            raise SystemExit("archive member escapes destination")
        source = tf.extractfile(member)
        if source is None:
            raise SystemExit("archive member has no file body")
        with source, target.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        os.chmod(target, member.mode & 0o755)
PY

bundle="$extract_to/$bundle_root"
manifest="$bundle/manifest.json"
manifest_sig="$bundle/manifest.sig"
inventory="$bundle/offline-inventory.tsv"
compose_manifest="$bundle/deploy/docker-compose/manifest.json"
source_receipt="$bundle/release-source.json"
provenance="$bundle/image-provenance.json"
sbom_index="$bundle/sbom/index.json"
for required_file in manifest manifest_sig inventory compose_manifest source_receipt provenance sbom_index; do
  [[ -f "${!required_file}" && ! -L "${!required_file}" ]] || die "bundle is missing required file: $required_file"
done
[[ "$(sha256sum "$manifest" | awk '{print $1}')" == "${receipt[manifest_sha256]}" ]] || die 'manifest hash does not match signed handoff'
[[ "$(sha256sum "$inventory" | awk '{print $1}')" == "${receipt[inventory_sha256]}" ]] || die 'inventory hash does not match signed handoff'
[[ "$(sha256sum "$provenance" | awk '{print $1}')" == "${receipt[image_provenance_sha256]}" ]] || die 'image provenance hash does not match signed handoff'
[[ "$(sha256sum "$sbom_index" | awk '{print $1}')" == "${receipt[sbom_index_sha256]}" ]] || die 'SBOM index hash does not match signed handoff'

inventory_count="$(python3 - "$bundle" "$inventory" <<'PY'
import base64
import hashlib
import pathlib
import re
import sys

bundle = pathlib.Path(sys.argv[1])
inventory = pathlib.Path(sys.argv[2])
raw = inventory.read_bytes()
if not raw.endswith(b"\n") or b"\r" in raw or any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in raw):
    raise SystemExit("inventory is not canonical ASCII")
lines = raw.decode("ascii").splitlines()
if not lines or lines[0] != "schema\tjjdguard-offline-inventory/v1":
    raise SystemExit("inventory schema mismatch")
expected: dict[str, tuple[int, str]] = {}
ordered: list[bytes] = []
for line in lines[1:]:
    fields = line.split("\t")
    if len(fields) != 4 or fields[0] != "file":
        raise SystemExit("inventory row shape mismatch")
    encoded, size_raw, digest = fields[1:]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded) or not re.fullmatch(r"0|[1-9][0-9]*", size_raw) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("inventory row value mismatch")
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        path = decoded.decode("utf-8", "strict")
    except Exception as exc:
        raise SystemExit("invalid inventory path encoding") from exc
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != encoded:
        raise SystemExit("non-canonical inventory path encoding")
    pure = pathlib.PurePosixPath(path)
    if not path or path.startswith("/") or "\\" in path or any(part in ("", ".", "..") for part in pure.parts):
        raise SystemExit("unsafe inventory path")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise SystemExit("control character in inventory path")
    if path in ("offline-inventory.tsv", ".jjdguard-offline-verified.tsv") or path in expected:
        raise SystemExit("forbidden or duplicate inventory path")
    ordered.append(decoded)
    expected[path] = (int(size_raw), digest)
if ordered != sorted(ordered) or len(ordered) != len(set(ordered)):
    raise SystemExit("inventory paths are not byte-sorted and unique")
actual: dict[str, pathlib.Path] = {}
for item in bundle.rglob("*"):
    if item.is_symlink():
        raise SystemExit("symlink found after extraction")
    if item.is_file():
        rel = item.relative_to(bundle).as_posix()
        if rel not in ("offline-inventory.tsv", ".jjdguard-offline-verified.tsv"):
            actual[rel] = item
if set(actual) != set(expected):
    raise SystemExit("inventory file set mismatch")
for path, (size, digest) in expected.items():
    item = actual[path]
    if item.stat().st_size != size:
        raise SystemExit("inventory size mismatch")
    hasher = hashlib.sha256()
    with item.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    if hasher.hexdigest() != digest:
        raise SystemExit("inventory digest mismatch")
print(len(expected))
PY
)"
[[ "$inventory_count" =~ ^[0-9]+$ && "$inventory_count" -gt 0 ]] || die 'inventory verification did not produce a file count'

if [[ "$(stat -c '%s' "$manifest_sig")" == 64 ]]; then
  [[ -n "$public_key" ]] || die 'signed manifest requires --public-key'
  { printf '%s\0' "$MANIFEST_DOMAIN"; cat "$manifest"; } >"$tmp_dir/manifest-domain.bin"
  openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" -sigfile "$manifest_sig" -in "$tmp_dir/manifest-domain.bin" >/dev/null 2>&1 || die 'manifest signature verification failed against external trust key'
else
  expected_line="$(sha256sum "$manifest" | awk '{print $1}')  manifest.json"
  [[ "$(tr -d '\r\n' <"$manifest_sig")" == "$expected_line" ]] || die 'manifest SHA-256 identity failed'
fi
python3 "$SCRIPT_DIR/verify-sbom-index.py" \
  --bundle "$bundle" --provenance "$provenance" --index "$sbom_index" || die 'SBOM index verification failed'
python3 - "$manifest" "$compose_manifest" "$source_receipt" "$provenance" "$sbom_index" \
  "$bundle_root" "$product" "$version" "$source_revision" "$source_tree" \
  "${receipt[image_provenance_sha256]}" "${receipt[sbom_index_sha256]}" "$target_arch" \
  "$bundle_profile" "$include_chat" "$artifact_stage" \
  "${platform_name:-}" "${platform_version:-}" "${platform_slug:-}" "${receipt[agent_kit_sha256]:-}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

(
    path, compose_path, source_path, provenance_path, sbom_path, bundle_root,
    product, version, source_revision, source_tree, provenance_sha, sbom_sha,
    target_arch, bundle_profile, include_chat, artifact_stage,
    platform_name, platform_version, platform_slug, agent_kit_sha,
) = sys.argv[1:]
def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
def load(item):
    with open(item, "r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=no_duplicates)
data = load(path)
if data != load(compose_path):
    raise SystemExit("root and compose manifests differ")
expected = {
    "schema": "offline-manifest/v2",
    "product": product,
    "version": version,
    "source_revision": source_revision,
    "source_tree": source_tree,
    "image_provenance_sha256": provenance_sha,
    "sbom_index_sha256": sbom_sha,
    "target_arch": target_arch,
    "bundle_profile": bundle_profile,
    "include_chat": include_chat,
    "artifact_stage": artifact_stage,
    "min_data_version": (pathlib.Path(path).parent / "deploy/docker-compose/upgrade-min-data-version").read_text(encoding="utf-8").strip(),
    "bundle": bundle_root,
}
required = set(expected) | {"built_at", "manifest_signature"}
if product == "agent-platform":
    required |= {"product_profile", "product_name", "product_version", "product_slug", "agent_kit_sha256"}
if not isinstance(data, dict) or set(data) != required:
    raise SystemExit("manifest keys do not exactly match v2")
for key, value in expected.items():
    if data[key] != value:
        raise SystemExit(f"manifest binding mismatch: {key}")
if product == "agent-platform":
    if (data["product_profile"] != "agent-platform" or data["product_name"] != platform_name
            or data["product_version"] != platform_version or data["product_slug"] != platform_slug
            or data["agent_kit_sha256"] != agent_kit_sha):
        raise SystemExit("platform manifest and handoff differ")
    kit = pathlib.Path(path).parent / "deploy/docker-compose/agent-kit"
    if not kit.is_dir() or kit.is_symlink():
        raise SystemExit("platform agent-kit missing")
    digest = hashlib.sha256()
    files = sorted(kit.rglob("*"))
    if not any(member.is_file() and member.name != ".gitkeep" for member in files):
        raise SystemExit("platform agent-kit empty")
    for member in files:
        if member.is_symlink() or not (member.is_file() or member.is_dir()):
            raise SystemExit("unsafe agent-kit member")
        if member.is_file():
            relative = member.relative_to(kit).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(4, "big") + relative)
            digest.update(hashlib.sha256(member.read_bytes()).digest())
    if digest.hexdigest() != agent_kit_sha:
        raise SystemExit("platform agent-kit digest mismatch")
if data.get("manifest_signature") not in {"ed25519-domain-v2", "sha256-only"}:
    raise SystemExit("manifest identity mode is invalid")
if not isinstance(data["built_at"], str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", data["built_at"]):
    raise SystemExit("manifest built_at is invalid")
source = load(source_path)
if (not isinstance(source, dict) or set(source) != {"schema", "remote", "source_revision", "source_tree"}
        or source.get("schema") != "jjdguard-release-source/v1"
        or not isinstance(source.get("remote"), str) or not source["remote"]
        or source.get("source_revision") != source_revision or source.get("source_tree") != source_tree):
    raise SystemExit("release source receipt mismatch")
for item, expected_sha in ((provenance_path, provenance_sha), (sbom_path, sbom_sha)):
    digest = hashlib.sha256(pathlib.Path(item).read_bytes()).hexdigest()
    if digest != expected_sha:
        raise SystemExit("bundled evidence hash mismatch")
PY

stamp_tmp="$(mktemp "$bundle/.jjdguard-offline-verified.XXXXXX")"
printf '%s\t%s\n' \
  schema jjdguard-offline-verified/v2 \
  archive_sha256 "${receipt[archive_sha256]}" \
  handoff_sha256 "$(sha256sum "$handoff" | awk '{print $1}')" \
  manifest_sha256 "${receipt[manifest_sha256]}" \
  inventory_sha256 "${receipt[inventory_sha256]}" \
  source_revision "$source_revision" \
  source_tree "$source_tree" \
  image_provenance_sha256 "${receipt[image_provenance_sha256]}" \
  sbom_index_sha256 "${receipt[sbom_index_sha256]}" \
  artifact_stage "$artifact_stage" \
  public_key_sha256 "$(sha256sum "$public_key" | awk '{print $1}')" \
  verified_files "$inventory_count" \
  verified_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$stamp_tmp"
chmod 0400 "$stamp_tmp"
mv "$stamp_tmp" "$bundle/.jjdguard-offline-verified.tsv"
success=1
printf '[offline-verify] status=verified files=%s root=%s\n' "$inventory_count" "$bundle"
