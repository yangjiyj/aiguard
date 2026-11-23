#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERIFY="$PROJECT_ROOT/deploy/acceptance/verify-acceptance-receipt.py"
GITEE_RELEASE_REMOTE='git@github.com:yangjiyj/aiguard.git'

die() { echo "[promotion] $*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

read_live_main() {
  local remote="$1" lines revision
  lines="$(git ls-remote "$remote" refs/heads/main)" || die 'cannot query live Gitee main'
  [[ "$(printf '%s\n' "$lines" | awk 'NF { count++ } END { print count + 0 }')" == 1 ]] ||
    die 'live Gitee main is not unique'
  revision="$(printf '%s\n' "$lines" | awk '$2 == "refs/heads/main" && NF == 2 { print $1 }')"
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || die 'live Gitee main is invalid'
  printf '%s\n' "$revision"
}

require_secure_output_parent() {
  local directory="$1" invoking_uid="$2" is_parent=1 owner mode mode_value parent
  while :; do
    if [[ ! -d "$directory" || -L "$directory" ]]; then
      if [[ "$is_parent" == 1 ]]; then
        die 'output parent is unsafe'
      fi
      die 'output parent ancestor is unsafe'
    fi
    owner="$(stat -c '%u' "$directory")" || die 'cannot inspect output parent owner'
    [[ "$owner" =~ ^[0-9]+$ ]] || die 'output parent owner is invalid'
    if [[ "$is_parent" == 1 ]]; then
      [[ "$owner" == "$invoking_uid" ]] || die 'output parent must be owned by the invoking user'
    elif [[ "$owner" != "$invoking_uid" && "$owner" != 0 ]]; then
      die 'output parent ancestor must be owned by the invoking user or root'
    fi
    mode="$(stat -c '%a' "$directory")" || die 'cannot inspect output parent mode'
    case "$mode" in
      [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
      *) die 'output parent mode is invalid' ;;
    esac
    mode_value=$((8#$mode))
    if (( mode_value & 022 )) && (( !(mode_value & 01000) )); then
      if [[ "$is_parent" == 1 ]]; then
        die 'output parent must not be group or other writable'
      fi
      die 'output parent ancestor must not be group or other writable without sticky protection'
    fi
    [[ "$directory" == / ]] && return
    parent="$(dirname "$directory")"
    [[ "$parent" != "$directory" ]] || die 'output parent ancestry is invalid'
    directory="$parent"
    is_parent=0
  done
}

usage() {
  cat >&2 <<'EOF'
usage: promote-offline-release.sh \
  --candidate CANDIDATE.run \
  --receipt receipt.json \
  --evidence-index evidence-index.json \
  [--signing-key release-private.pem] \
  --output NEW-final-directory
EOF
  exit 64
}

require_value() {
  [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || usage
}

candidate=""
receipt=""
evidence_index=""
signing_key=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --candidate)
      require_value "$@"
      [[ -z "$candidate" ]] || die 'candidate was supplied more than once'
      candidate="$2"
      shift 2
      ;;
    --receipt)
      require_value "$@"
      [[ -z "$receipt" ]] || die 'receipt was supplied more than once'
      receipt="$2"
      shift 2
      ;;
    --evidence-index)
      require_value "$@"
      [[ -z "$evidence_index" ]] || die 'evidence index was supplied more than once'
      evidence_index="$2"
      shift 2
      ;;
    --signing-key)
      require_value "$@"
      [[ -z "$signing_key" ]] || die 'signing key was supplied more than once'
      signing_key="$2"
      shift 2
      ;;
    --output)
      require_value "$@"
      [[ -z "$output" ]] || die 'output was supplied more than once'
      output="$2"
      shift 2
      ;;
    --help|-h) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$candidate" && -n "$receipt" && -n "$evidence_index" && -n "$output" ]] || usage
for input in "$candidate" "$receipt" "$evidence_index" "$VERIFY"; do
  [[ -f "$input" && ! -L "$input" ]] || die "input is incomplete or unsafe: $input"
done

[[ "$output" == /* ]] || die 'output must be a new absolute directory'
output_name="$(basename "$output")"
output_parent="$(realpath -e -- "$(dirname "$output")")" || die 'output parent is unsafe'
output="$output_parent/$output_name"
[[ ! -e "$output" && ! -L "$output" ]] || die 'output must be a new absolute directory'
require_secure_output_parent "$output_parent" "$(id -u)"

if [[ -n "$signing_key" ]]; then
  [[ -f "$signing_key" && ! -L "$signing_key" ]] || die 'optional promotion key is unsafe'
  key_mode="$(stat -c '%a' "$signing_key")"
  key_owner="$(stat -c '%u' "$signing_key")"
  case "$key_mode" in 400|600) ;; *) die 'promotion key mode must be 0400 or 0600' ;; esac
  if [[ "$key_owner" != 0 && "$key_owner" != "$(id -u)" ]]; then
    die 'promotion key must be owned by root or the invoking user'
  fi
  openssl pkey -in "$signing_key" -text -noout 2>/dev/null | grep -q 'ED25519' ||
    die 'promotion key must be Ed25519'
fi

# Capture every promotable input in a private staging directory first. The
# caller can replace candidate/receipt/evidence paths while this script runs;
# promotion must bind only the exact bytes that passed all checks below.
stage_dir=""
work_dir=""
published_dir=""
cleanup_staging() {
  [[ -z "$stage_dir" ]] || rm -rf -- "$stage_dir"
  [[ -z "$work_dir" ]] || rm -rf -- "$work_dir"
  [[ -z "$published_dir" ]] || rm -rf -- "$published_dir"
}
trap cleanup_staging EXIT
stage_dir="$(mktemp -d "$output_parent/.jjdguard-promotion.XXXXXX")" ||
  die 'unable to create a private promotion staging directory'
work_dir="$(mktemp -d "$output_parent/.jjdguard-promotion-work.XXXXXX")" ||
  die 'unable to create a private promotion verification directory'

run_name="$(basename "$candidate")"
stage_run="$stage_dir/$run_name"
stage_receipt="$stage_dir/acceptance-receipt.json"
stage_evidence="$stage_dir/acceptance-evidence-index.json"
stage_evidence_root="$stage_dir/evidence"
install -m 0755 -- "$candidate" "$stage_run"
install -m 0444 -- "$receipt" "$stage_receipt"
install -m 0444 -- "$evidence_index" "$stage_evidence"

if [[ -n "$signing_key" ]]; then
  openssl pkey -in "$signing_key" -pubout -out "$work_dir/signing.pub" >/dev/null 2>&1 ||
    die 'promotion key public derivation failed'
fi
gitee_remote="$GITEE_RELEASE_REMOTE"
source_repository="$work_dir/gitee-main.git"
git init --bare --quiet "$source_repository" || die 'cannot create authoritative Gitee cache'
git -C "$source_repository" remote add origin "$gitee_remote" || die 'cannot configure authoritative Gitee cache'
main_before="$(read_live_main "$gitee_remote")"
git -C "$source_repository" fetch --quiet --no-tags origin \
  refs/heads/main:refs/remotes/origin/main || die 'cannot fetch authoritative Gitee main'
fetched_main="$(git -C "$source_repository" rev-parse --verify refs/remotes/origin/main)" ||
  die 'cannot resolve fetched Gitee main'
[[ "$fetched_main" == "$main_before" ]] || die 'Gitee main moved while the trusted source was fetched'
# Do not execute candidate shell code during promotion. The repository-owned
# verifier authenticates the signed header and both manifest layers against
# the public key derived from the controlled promotion key.
verify_args=(python3 "$VERIFY")
[[ -z "$signing_key" ]] || verify_args+=(--public-key "$work_dir/signing.pub")
identity="$("${verify_args[@]}" \
  --receipt "$stage_receipt" --artifact "$stage_run" --evidence-index "$stage_evidence" \
  --evidence-root "$(dirname "$evidence_index")" --snapshot-evidence-dir "$stage_evidence_root" \
  --source-repository "$source_repository" --authoritative-remote "$gitee_remote")" ||
  die 'acceptance receipt validation failed'

main_after="$(read_live_main "$gitee_remote")"
[[ "$main_after" == "$main_before" ]] || die 'live Gitee main moved during acceptance verification'
identity_fields="$(python3 - "$identity" <<'PY'
import json
import re
import sys
data = json.loads(sys.argv[1])
for key, pattern in (
    ("source_revision", r"[0-9a-f]{40}"),
    ("run_sha256", r"[0-9a-f]{64}"),
):
    value = data.get(key)
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise SystemExit(f"invalid verifier identity field: {key}")
run_size = data.get("run_size")
if not isinstance(run_size, int) or run_size < 1:
    raise SystemExit("invalid verifier identity field: run_size")
print(data["source_revision"])
print(data["run_sha256"])
print(run_size)
PY
)"
mapfile -t identity_values <<<"$identity_fields"
[[ "${#identity_values[@]}" == 3 ]] || die 'acceptance verifier identity is incomplete'
source_revision="${identity_values[0]}"
run_sha_before="${identity_values[1]}"
run_size="${identity_values[2]}"
[[ "$main_after" == "$source_revision" ]] || die 'live Gitee main drifted from the accepted artifact'

receipt_sha="$(sha256_file "$stage_receipt")"
evidence_index_sha="$(sha256_file "$stage_evidence")"
checksum_tmp="$stage_dir/$run_name.sha256"
sidecar_tmp="$stage_dir/$run_name.promotion.json"
payload_tmp="$work_dir/promotion.payload"
signature_tmp="$stage_dir/$run_name.promotion.sig"

printf '%s  %s\n' "$run_sha_before" "$run_name" >"$checksum_tmp" ||
  die 'promotion checksum creation failed'

python3 - "$identity" "$run_sha_before" "$run_size" "$receipt_sha" "$evidence_index_sha" >"$sidecar_tmp" <<'PY'
import datetime
import json
import sys

identity = json.loads(sys.argv[1])
run_sha, run_size, receipt_sha, evidence_sha = sys.argv[2:]
payload = {
    "schema": "jjdguard-offline-promotion/v1",
    "run_sha256": run_sha,
    "run_size": int(run_size),
    "inner_tar_sha256": identity["inner_tar_sha256"],
    "source_revision": identity["source_revision"],
    "source_tree": identity["source_tree"],
    "image_provenance_sha256": identity["image_provenance_sha256"],
    "sbom_index_sha256": identity["sbom_index_sha256"],
    "acceptance_receipt_sha256": receipt_sha,
    "evidence_index_sha256": evidence_sha,
    "promoted_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
PY

{ printf '%s\0' 'jjdguard-offline-promotion/v1'; cat "$sidecar_tmp"; } >"$payload_tmp"
if [[ -n "$signing_key" ]]; then
  openssl pkeyutl -sign -rawin -inkey "$signing_key" -in "$payload_tmp" -out "$signature_tmp" >/dev/null 2>&1 ||
    die 'promotion signature creation failed'
  [[ "$(stat -c '%s' "$signature_tmp")" == 64 ]] || die 'promotion signature length is invalid'
else
  printf '%s  promotion.payload\n' "$(sha256_file "$payload_tmp")" >"$signature_tmp"
fi
chmod 0444 "$checksum_tmp" "$sidecar_tmp" "$signature_tmp" "$stage_receipt" "$stage_evidence" ||
  die 'promotion artifacts cannot be made readable for release verification'

chmod 0755 "$stage_dir"
mv -T -- "$stage_dir" "$output" || die 'cannot publish the promoted artifact directory'
stage_dir=""
published_dir="$output"
final_run="$output/$run_name"
[[ "$(sha256_file "$final_run")" == "$run_sha_before" ]] || die 'run bytes changed while publishing final artifact'
(cd "$output" && sha256sum -c "$run_name.sha256" >/dev/null) ||
  die 'promotion checksum does not match final artifact'
published_dir=""
rm -rf -- "$work_dir"
work_dir=""
trap - EXIT

echo "[ok] promoted without repackaging: $final_run ($run_sha_before)"
