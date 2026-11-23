#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIGNER="$ROOT/deploy/migrations/sign-jjdguard-customer-neutral-result.sh"
[[ -x "$SIGNER" ]] || { echo '[evidence-test] signer missing' >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
priv="$tmp/test-private.pem"
pub="$tmp/test-public.pem"
wrong_priv="$tmp/wrong-private.pem"
wrong_pub="$tmp/wrong-public.pem"
openssl genpkey -algorithm Ed25519 -out "$priv" >/dev/null 2>&1
openssl pkey -in "$priv" -pubout -out "$pub" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$wrong_priv" >/dev/null 2>&1
openssl pkey -in "$wrong_priv" -pubout -out "$wrong_pub" >/dev/null 2>&1
chmod 0400 "$priv" "$wrong_priv"

compat_bundle="$(printf compat-bundle | sha256sum | awk '{print $1}')"
compat_payload="$(printf compat-payload | sha256sum | awk '{print $1}')"
applied_manifest="$(printf applied-manifest | sha256sum | awk '{print $1}')"
catalog="$(printf neutral-catalog | sha256sum | awk '{print $1}')"
neutral="$tmp/neutral.tsv"
printf '%s\t%s\n' \
  schema jjdguard-neutral-result/v1 \
  status applied \
  neutral_marker jjdguard-neutral-baseline-v1 \
  manifest_sha256 "$applied_manifest" \
  inventory_sha256 "$(printf inventory | sha256sum | awk '{print $1}')" \
  payload_sha256 "$compat_payload" \
  catalog_sha256 "$catalog" \
  object_count 12 \
  row_count 2 \
  started_at 2026-07-18T12:00:00Z \
  finished_at 2026-07-18T12:00:01Z >"$neutral"
chmod 0400 "$neutral"

evidence="$tmp/evidence.tsv"
signature="$tmp/evidence.sig"
common=(
  --site-id site-fixture-001
  --challenge challenge-fixture-001
  --compat-bundle-sha256 "$compat_bundle"
  --compat-payload-sha256 "$compat_payload"
  --final-target refs/tags/jjdguard-final-fixture
  --applied-manifest-sha256 "$applied_manifest"
)
"$SIGNER" sign --private-key "$priv" --neutral-result "$neutral" \
  --output "$evidence" --signature "$signature" "${common[@]}"
"$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" \
  --evidence "$evidence" --signature "$signature" "${common[@]}"

expected_fields=$'schema\nsite_id\nchallenge\ncompat_bundle_sha256\ncompat_payload_sha256\nfinal_target\napplied_manifest_sha256\nneutral_marker\nneutral_catalog_sha256\nobject_count\nrow_count\nstarted_at\nfinished_at'
test "$(cut -f1 "$evidence")" = "$expected_fields"
test "$(tail -c 1 "$evidence" | od -An -tuC | tr -d ' ')" = 10
! LC_ALL=C grep -n $'\r' "$evidence"
awk -F '\t' 'NF != 2 || $2 !~ /^[A-Za-z0-9_-]+$/ || $2 ~ /=/ {exit 1}' "$evidence"

expect_reject() {
  local label=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "[evidence-test] expected rejection: $label" >&2
    exit 1
  fi
}
expect_reject wrong-key "$SIGNER" verify --public-key "$wrong_pub" --neutral-result "$neutral" --evidence "$evidence" --signature "$signature" "${common[@]}"

for field in site challenge bundle payload target manifest; do
  args=("${common[@]}")
  case "$field" in
    site) args[1]=site-tampered ;;
    challenge) args[3]=challenge-tampered ;;
    bundle) args[5]="$(printf tampered | sha256sum | awk '{print $1}')" ;;
    payload) args[7]="$(printf tampered | sha256sum | awk '{print $1}')" ;;
    target) args[9]=refs/tags/tampered ;;
    manifest) args[11]="$(printf tampered | sha256sum | awk '{print $1}')" ;;
  esac
  expect_reject "$field-binding" "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$evidence" --signature "$signature" "${args[@]}"
done

for field in neutral_marker catalog_sha256 object_count row_count started_at finished_at; do
  changed="$tmp/neutral-$field.tsv"
  awk -F '\t' -v f="$field" 'BEGIN{OFS="\t"} $1==f {$2=$2 "-tampered"} {print}' "$neutral" >"$changed"
  chmod 0400 "$changed"
  expect_reject "neutral-$field-binding" "$SIGNER" verify --public-key "$pub" --neutral-result "$changed" --evidence "$evidence" --signature "$signature" "${common[@]}"
done

mutate="$tmp/mutate.tsv"
cp "$evidence" "$mutate"; chmod 0600 "$mutate"; printf '\n' >>"$mutate"
expect_reject extra-line "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
awk 'NR==1{first=$0;next} NR==2{print;print first;next} {print}' "$evidence" >"$mutate"
expect_reject reordered "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
{ cat "$evidence"; head -n1 "$evidence"; } >"$mutate"
expect_reject duplicate "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
{ cat "$evidence"; printf 'unknown\tdmFsdWU\n'; } >"$mutate"
expect_reject unknown "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
head -n -1 "$evidence" >"$mutate"
expect_reject missing "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
sed 's/$/\r/' "$evidence" >"$mutate"
expect_reject crlf "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
cp "$evidence" "$mutate"; printf '\377' >>"$mutate"
expect_reject invalid-utf8 "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"
awk -F '\t' 'BEGIN{OFS="\t"} NR==2 {$2="***="} {print}' "$evidence" >"$mutate"
expect_reject invalid-base64url "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$mutate" --signature "$signature" "${common[@]}"

other_sig="$tmp/other-domain.sig"
openssl pkeyutl -sign -rawin -inkey "$priv" -in "$evidence" -out "$other_sig" >/dev/null 2>&1
expect_reject cross-domain-replay "$SIGNER" verify --public-key "$pub" --neutral-result "$neutral" --evidence "$evidence" --signature "$other_sig" "${common[@]}"

if rg -n -i 'registry|nonce|generate.*private|genpkey' "$SIGNER" >/dev/null; then
  echo '[evidence-test] signer contains forbidden stateful trust or key generation behavior' >&2
  exit 1
fi
printf 'customer_neutral_evidence=ok bound_fields=12 malformed_rejected=7 domain_separated=1 stateless=1\n'
