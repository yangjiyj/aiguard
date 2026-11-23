#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
JJD_INSTALLER_LIB_ONLY=1 source "$ROOT/deploy/offline-installer/installer.sh"
OPT_ROOT="$tmp/opt/jjdguard"; root="$OPT_ROOT/development-releases"; old="$root/dev-base"; console="$root/dev-console"; new="$OPT_ROOT/releases/new"
mkdir -p "$old/state" "$console/state" "$new/deploy/docker-compose/.upgrade"
printf '%s\n' '{"status":"deployed","release_id":"dev-base","version":"2.8.0","services":{"gateway-core":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}' > "$old/receipt.json"
old_sha="$(sha256sum "$old/receipt.json" | awk '{print $1}')"
# The real console publisher writes a JSON string with escaped newline bytes.
python3 - "$console/state/previous-current.json" "$old" "$old_sha" <<'PY'
import json,sys
open(sys.argv[1],'w').write(json.dumps(json.dumps({'release':sys.argv[2],'receipt_sha256':sys.argv[3]},indent=2)+'\n')+'\n')
PY
printf '{}\n' > "$console/state/before.json"; printf '{}\n' > "$console/state/after.json"
printf '%s\n' '{"version":"2.8.0","revision":"0123456789abcdef0123456789abcdef01234567"}' > "$console/manifest.json"
manifest_sha="$(sha256sum "$console/manifest.json" | awk '{print $1}')"; before_sha="$(sha256sum "$console/state/before.json" | awk '{print $1}')"; prev_sha="$(sha256sum "$console/state/previous-current.json" | awk '{print $1}')"
cat > "$console/receipt.json" <<EOF
{
 "schema": 1,
 "purpose": "console-only",
 "status": "deployed",
 "release_id": "dev-console",
 "revision": "0123456789abcdef0123456789abcdef01234567",
 "manifest_sha256": "$manifest_sha",
 "before_sha256": "$before_sha",
 "after_sha256": "$before_sha",
 "artifacts": {
  "previous-current.json": "$prev_sha"
 }
}
EOF
find "$root" -type f -exec chmod 0600 {} +
console_sha="$(sha256sum "$console/receipt.json" | awk '{print $1}')"
printf '{"release":"%s","receipt_sha256":"%s"}\n' "$console" "$console_sha" > "$root/current.json"
capture_development_receipt "$new"
target="$new/deploy/docker-compose/.upgrade/development-receipt"
[[ "$(cat "$target/receipt.sha256")" == "$old_sha" ]] || { echo 'wrong full-release anchor'; exit 1; }
source "$ROOT/deploy/offline-installer/lib/development-receipt-chain.sh"
development_receipt_chain_valid "$target/chain.tsv"
printf 'tampered\n' >> "$console/state/previous-current.json"
if development_receipt_chain_valid "$target/chain.tsv"; then echo 'tampered chain accepted';exit 1;fi
if (capture_development_receipt "$new") >/dev/null 2>&1;then echo 'tampered pointer accepted';exit 1;fi
echo '[ok] console manifest and predecessor receipt chain verified; tampering rejected'
