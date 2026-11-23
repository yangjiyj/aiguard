#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$BASH_SOURCE")/../.." && pwd)"
BUNDLE_BUILDER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"

fail() { echo "[offline-ustar-contract] $*" >&2; exit 1; }

[[ -f "$BUNDLE_BUILDER" ]] || fail "bundle builder is missing"
grep -Fq 'tar --format=ustar -czf "$ARCHIVE_FILE" "$BUNDLE_NAME"' "$BUNDLE_BUILDER" ||
  fail "bundle archive must be written in USTAR format"

tmp="$(mktemp -d /tmp/jjdguard-ustar-contract.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
bundle_name='jjdguard-2.0-offline-full-chat-amd64-20260811-061455'
long_member="$bundle_name/deploy/offline-installer/release-public-key-verification-contract.pem"
mkdir -p "$(dirname "$tmp/$long_member")"
printf 'fixture\n' >"$tmp/$long_member"
archive="$tmp/bundle.tar.gz"
tar --format=ustar -C "$tmp" -czf "$archive" "$bundle_name"

python3 - "$archive" "$long_member" <<'PY'
import gzip
import sys
import tarfile

archive_path, expected_member = sys.argv[1:]
safe_types = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
seen = set()

with gzip.open(archive_path, "rb") as archive:
    while True:
        block = archive.read(tarfile.BLOCKSIZE)
        if not block or block == bytes(tarfile.BLOCKSIZE):
            break
        if len(block) != tarfile.BLOCKSIZE:
            raise SystemExit("truncated USTAR fixture")
        member = tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
        if member.type not in safe_types:
            raise SystemExit(f"unexpected tar extension record: {member.type!r}")
        seen.add(member.name)
        archive.read(member.size + (-member.size) % tarfile.BLOCKSIZE)

if expected_member not in seen:
    raise SystemExit("USTAR prefix did not preserve the long fixture member")
PY

echo '[ok] offline bundle USTAR archive contract passed'
