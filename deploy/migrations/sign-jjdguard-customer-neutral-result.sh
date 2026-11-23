#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

DOMAIN='jjdguard-customer-evidence/v1'
EVIDENCE_SCHEMA='jjdguard-customer-neutral-evidence/v1'
NEUTRAL_SCHEMA='jjdguard-neutral-result/v1'
NEUTRAL_MARKER='jjdguard-neutral-baseline-v1'

die() {
  printf '[customer-evidence] %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'Usage:' \
    '  sign-jjdguard-customer-neutral-result.sh sign --private-key FILE --neutral-result FILE --output FILE --signature FILE BINDINGS' \
    '  sign-jjdguard-customer-neutral-result.sh verify --public-key FILE --neutral-result FILE --evidence FILE --signature FILE BINDINGS' \
    'Bindings: --site-id TEXT --challenge TEXT --compat-bundle-sha256 HEX --compat-payload-sha256 HEX' \
    '          --final-target REF --applied-manifest-sha256 HEX'
}

for tool in openssl awk cmp mktemp stat od tail install; do
  command -v "$tool" >/dev/null 2>&1 || die "required command is missing: $tool"
done

mode="${1:-}"
case "$mode" in
  sign|verify) shift ;;
  -h|--help|'') usage; exit 0 ;;
  *) die "unknown mode: $mode" ;;
esac

private_key=''
public_key=''
neutral_result=''
output=''
evidence=''
signature=''
site_id=''
challenge=''
compat_bundle_sha256=''
compat_payload_sha256=''
final_target=''
applied_manifest_sha256=''
declare -A seen=()
set_option() {
  local name="$1" value="$2"
  [[ -z "${seen[$name]+x}" ]] || die "duplicate option: $name"
  [[ -n "$value" ]] || die "empty option: $name"
  seen[$name]=1
  printf -v "$name" '%s' "$value"
}

while (($#)); do
  (($# >= 2)) || die "missing value for $1"
  case "$1" in
    --private-key) set_option private_key "$2" ;;
    --public-key) set_option public_key "$2" ;;
    --neutral-result) set_option neutral_result "$2" ;;
    --output) set_option output "$2" ;;
    --evidence) set_option evidence "$2" ;;
    --signature) set_option signature "$2" ;;
    --site-id) set_option site_id "$2" ;;
    --challenge) set_option challenge "$2" ;;
    --compat-bundle-sha256) set_option compat_bundle_sha256 "$2" ;;
    --compat-payload-sha256) set_option compat_payload_sha256 "$2" ;;
    --final-target) set_option final_target "$2" ;;
    --applied-manifest-sha256) set_option applied_manifest_sha256 "$2" ;;
    *) die "unknown option: $1" ;;
  esac
  shift 2
done

for required in neutral_result signature site_id challenge compat_bundle_sha256 compat_payload_sha256 final_target applied_manifest_sha256; do
  [[ -n "${!required}" ]] || die "missing required option: $required"
done
if [[ "$mode" == sign ]]; then
  [[ -n "$private_key" && -n "$output" ]] || die 'sign mode requires --private-key and --output'
  [[ -z "$public_key" && -z "$evidence" ]] || die 'sign mode received verify-only options'
else
  [[ -n "$public_key" && -n "$evidence" ]] || die 'verify mode requires --public-key and --evidence'
  [[ -z "$private_key" && -z "$output" ]] || die 'verify mode received sign-only options'
fi

[[ "$site_id" =~ ^[A-Za-z0-9._:-]{1,200}$ ]] || die 'site id contains unsupported characters'
[[ "$challenge" =~ ^[A-Za-z0-9._:-]{1,300}$ ]] || die 'challenge contains unsupported characters'
[[ "$final_target" =~ ^[A-Za-z0-9._/@:+-]{1,400}$ ]] || die 'final target contains unsupported characters'
for hash_name in compat_bundle_sha256 compat_payload_sha256 applied_manifest_sha256; do
  [[ "${!hash_name}" =~ ^[0-9a-f]{64}$ ]] || die "invalid SHA-256 binding: $hash_name"
done

validate_ascii_file() {
  local file="$1" label="$2" size last
  [[ -f "$file" && ! -L "$file" ]] || die "$label must be a regular non-symlink file"
  size="$(stat -c '%s' "$file")"
  [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 ]] || die "$label must not be empty"
  if ! od -An -v -tu1 "$file" | awk '
    { for (i=1; i<=NF; i++) if ($i != 9 && $i != 10 && ($i < 32 || $i > 126)) bad=1 }
    END { exit bad ? 1 : 0 }
  '; then
    die "$label contains non-canonical bytes"
  fi
  last="$(tail -c 1 "$file" | od -An -tu1 | tr -d '[:space:]')"
  [[ "$last" == 10 ]] || die "$label must end with one LF"
}

validate_ascii_file "$neutral_result" 'neutral result'
mapfile -t neutral_lines <"$neutral_result"
neutral_keys=(schema status neutral_marker manifest_sha256 inventory_sha256 payload_sha256 catalog_sha256 object_count row_count started_at finished_at)
[[ "${#neutral_lines[@]}" -eq "${#neutral_keys[@]}" ]] || die 'neutral result field count mismatch'
declare -A neutral=()
for i in "${!neutral_keys[@]}"; do
  IFS=$'\t' read -r key value extra <<<"${neutral_lines[$i]}"
  [[ "$key" == "${neutral_keys[$i]}" && -n "$value" && -z "$extra" ]] || die "neutral result is not canonical at field ${neutral_keys[$i]}"
  [[ "${neutral_lines[$i]}" == "$key"$'\t'"$value" ]] || die 'neutral result delimiter mismatch'
  neutral[$key]="$value"
done
[[ "${neutral[schema]}" == "$NEUTRAL_SCHEMA" ]] || die 'neutral result schema mismatch'
[[ "${neutral[status]}" == applied || "${neutral[status]}" == already-applied ]] || die 'neutral result is not an applied receipt'
[[ "${neutral[neutral_marker]}" == "$NEUTRAL_MARKER" ]] || die 'neutral marker mismatch'
for hash_key in manifest_sha256 inventory_sha256 payload_sha256 catalog_sha256; do
  [[ "${neutral[$hash_key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid neutral hash: $hash_key"
done
[[ "${neutral[object_count]}" =~ ^[0-9]+$ && "${neutral[row_count]}" =~ ^[0-9]+$ ]] || die 'invalid neutral counts'
timestamp_re='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
[[ "${neutral[started_at]}" =~ $timestamp_re && "${neutral[finished_at]}" =~ $timestamp_re ]] || die 'invalid neutral timestamps'
[[ "${neutral[started_at]}" == "${neutral[finished_at]}" || "${neutral[started_at]}" < "${neutral[finished_at]}" ]] || die 'neutral timestamps are reversed'
[[ "$compat_payload_sha256" == "${neutral[payload_sha256]}" ]] || die 'payload binding does not match neutral result'
[[ "$applied_manifest_sha256" == "${neutral[manifest_sha256]}" ]] || die 'manifest binding does not match neutral result'

encode_value() {
  printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

write_canonical_evidence() {
  local destination="$1"
  printf '%s\n' \
    "schema	$(encode_value "$EVIDENCE_SCHEMA")" \
    "site_id	$(encode_value "$site_id")" \
    "challenge	$(encode_value "$challenge")" \
    "compat_bundle_sha256	$(encode_value "$compat_bundle_sha256")" \
    "compat_payload_sha256	$(encode_value "$compat_payload_sha256")" \
    "final_target	$(encode_value "$final_target")" \
    "applied_manifest_sha256	$(encode_value "$applied_manifest_sha256")" \
    "neutral_marker	$(encode_value "${neutral[neutral_marker]}")" \
    "neutral_catalog_sha256	$(encode_value "${neutral[catalog_sha256]}")" \
    "object_count	$(encode_value "${neutral[object_count]}")" \
    "row_count	$(encode_value "${neutral[row_count]}")" \
    "started_at	$(encode_value "${neutral[started_at]}")" \
    "finished_at	$(encode_value "${neutral[finished_at]}")" >"$destination"
}

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
canonical="$tmp_dir/evidence.tsv"
domain_payload="$tmp_dir/domain.bin"
write_canonical_evidence "$canonical"
{
  printf '%s\0' "$DOMAIN"
  cat "$canonical"
} >"$domain_payload"

if [[ "$mode" == sign ]]; then
  [[ -f "$private_key" && ! -L "$private_key" ]] || die 'private key must be a regular non-symlink file'
  key_mode="$(stat -c '%a' "$private_key")"
  key_owner="$(stat -c '%u' "$private_key")"
  [[ "$key_mode" == 400 || "$key_mode" == 600 ]] || die 'private key mode must be 0400 or 0600'
  [[ "$key_owner" == "$(id -u)" ]] || die 'private key owner must be the invoking user'
  openssl pkey -in "$private_key" -pubout -out "$tmp_dir/key-check.pem" >/dev/null 2>&1 || die 'private key is not readable by OpenSSL'
  [[ ! -L "$output" && ! -L "$signature" ]] || die 'output paths must not be symlinks'
  [[ -d "$(dirname "$output")" && -d "$(dirname "$signature")" ]] || die 'output parent directory is missing'
  [[ "$output" != "$signature" && "$output" != "$neutral_result" && "$signature" != "$neutral_result" ]] || die 'output paths overlap input files'
  openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$domain_payload" -out "$tmp_dir/signature.bin" >/dev/null 2>&1 || die 'Ed25519 signing failed'
  [[ "$(stat -c '%s' "$tmp_dir/signature.bin")" == 64 ]] || die 'unexpected Ed25519 signature length'
  evidence_tmp="$(mktemp "$(dirname "$output")/.jjdguard-evidence.XXXXXX")"
  signature_tmp="$(mktemp "$(dirname "$signature")/.jjdguard-signature.XXXXXX")"
  install -m 0400 "$canonical" "$evidence_tmp"
  install -m 0400 "$tmp_dir/signature.bin" "$signature_tmp"
  mv -f "$signature_tmp" "$signature"
  mv -f "$evidence_tmp" "$output"
  printf '[customer-evidence] status=signed fields=13\n'
else
  [[ -f "$public_key" && ! -L "$public_key" ]] || die 'public key must be a regular non-symlink file'
  [[ -f "$signature" && ! -L "$signature" ]] || die 'signature must be a regular non-symlink file'
  validate_ascii_file "$evidence" 'customer evidence'
  cmp -s "$canonical" "$evidence" || die 'customer evidence does not match the canonical bound fields'
  [[ "$(stat -c '%s' "$signature")" == 64 ]] || die 'unexpected Ed25519 signature length'
  openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" -sigfile "$signature" -in "$domain_payload" >/dev/null 2>&1 || die 'customer evidence signature verification failed'
  printf '[customer-evidence] status=verified fields=13\n'
fi
