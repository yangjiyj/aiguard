#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$ROOT/deploy/docker-compose/package-offline-bundle.sh"
RUN="$ROOT/deploy/docker-compose/package-offline-run.sh"
PROMOTE="$ROOT/deploy/docker-compose/promote-offline-release.sh"
ACCEPT="$ROOT/deploy/acceptance/verify-acceptance-receipt.py"
TRUST="$ROOT/deploy/offline-installer/verify-promoted-release.py"

! grep -Fq 'OFFLINE_MANIFEST_SIGNING_KEY_FILE is required' "$BUNDLE"
! grep -Fq 'OFFLINE_MANIFEST_SIGNING_KEY_FILE is required' "$RUN"
! grep -Fq 'OFFLINE_ALLOW_UNSIGNED_MANIFEST' "$BUNDLE"
! grep -Fq '[[' "$BUNDLE"
grep -Fq 'MANIFEST_SIGNATURE_STATUS=sha256-only' "$BUNDLE"
grep -Fq 'sha256sum run-manifest.json >run-manifest.sig' "$RUN"
grep -Fq 'promotion.payload' "$PROMOTE"
grep -Fq 'pathlib.Path | None' "$ACCEPT"
grep -Fq 'pathlib.Path | None' "$TRUST"

python3 - "$ACCEPT" "$TRUST" <<'PY'
import hashlib
import importlib.util
import pathlib
import sys
import tempfile

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

accept = load("jjd_acceptance", sys.argv[1])
trust = load("jjd_trust", sys.argv[2])
payload = b'{"fixture":true}\n'
line = (hashlib.sha256(payload).hexdigest() + "  run-manifest.json\n").encode()
accept.verify_signature_or_sha256(None, line, b"unused", payload, "run-manifest.json", "fixture")
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    data = root / "promotion.payload"
    evidence = root / "promotion.sig"
    data.write_bytes(payload)
    evidence.write_text(hashlib.sha256(payload).hexdigest() + "  promotion.payload\n")
    trust.verify_signature_or_sha256(None, evidence, data)
    evidence.write_text("0" * 64 + "  promotion.payload\n")
    try:
        trust.verify_signature_or_sha256(None, evidence, data)
    except SystemExit:
        pass
    else:
        raise AssertionError("tampered SHA-256 promotion identity was accepted")
PY

bash "$ROOT/deploy/tests/test_self_extracting_installer.sh"
printf 'sha256_packaging_contract=ok\n'
