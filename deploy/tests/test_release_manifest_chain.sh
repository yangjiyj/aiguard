#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
RUN="$ROOT_DIR/deploy/docker-compose/package-offline-run.sh"
ARCHIVE_VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-jjdguard-offline-archive.sh"
DEPLOY="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
HEADER="$ROOT_DIR/deploy/offline-installer/self-extracting-header.sh"

fail() { printf '[fail] %s\n' "$*" >&2; exit 1; }

# v2 must bind the full source and SBOM/provenance identity across the bundle,
# signed handoff, and self-extracting run manifest.  The following assertions
# intentionally fail until the v1 contract is upgraded.
for file in "$PACKAGE" "$RUN" "$ARCHIVE_VERIFIER" "$DEPLOY" "$HEADER"; do
  [[ -f "$file" ]] || fail "required release-chain file is missing: $file"
done
grep -Fq 'offline-manifest/v2' "$PACKAGE" || fail 'bundle manifest has not been upgraded to v2'
grep -Fq 'jjdguard-offline-handoff/v2' "$PACKAGE" || fail 'handoff has not been upgraded to v2'
grep -Fq 'jjdguard-offline-run-manifest/v2' "$RUN" || fail 'run manifest has not been upgraded to v2'
for field in source_revision source_tree image_provenance_sha256 sbom_index_sha256 artifact_stage; do
  grep -Fq "$field" "$PACKAGE" || fail "bundle/handoff does not bind $field"
  grep -Fq "$field" "$RUN" || fail "run manifest does not bind $field"
done
grep -Fq 'verify-sbom-index.py' "$ARCHIVE_VERIFIER" || fail 'archive verifier does not verify SBOM index'
grep -Fq 'source_revision' "$DEPLOY" || fail 'installer does not enforce source revision binding'
grep -Fq 'source_tree' "$HEADER" || fail 'self-extracting header does not enforce source tree binding'

echo '[ok] release manifest chain is v2 and binds source, provenance, and SBOM identity'
