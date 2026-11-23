#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENERATOR="$ROOT_DIR/deploy/docker-compose/generate-release-sbom.sh"
VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-sbom-index.py"
SELECTOR="$ROOT_DIR/deploy/docker-compose/select-offline-image-archive.py"
PACKAGE="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
RUN_PACKAGER="$ROOT_DIR/deploy/docker-compose/package-offline-run.sh"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

fail() {
  printf '[fail] %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

[[ -x "$GENERATOR" ]] || fail 'release SBOM generator is missing or not executable'
[[ -x "$VERIFIER" ]] || fail 'release SBOM verifier is missing or not executable'
[[ -x "$SELECTOR" ]] || fail 'offline image archive selector is missing or not executable'

BUNDLE="$TMP_ROOT/bundle"
PROVENANCE="$TMP_ROOT/image-provenance.json"
IMAGE_ARCHIVE_DIR="$BUNDLE/deploy/docker-compose/offline-artifacts"
mkdir -p "$IMAGE_ARCHIVE_DIR"
python3 - "$PROVENANCE" "$IMAGE_ARCHIVE_DIR/jjdguard-offline-images-fixture.tar.gz" <<'PY'
import gzip
import hashlib
import io
import json
import pathlib
import sys
import tarfile

provenance_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
rows = []
members = {}
images = []
for component, runtime_tag, image_id, arch in [
    ("alpha", "fixture/alpha:1", "sha256:" + "a" * 64, "amd64"),
    ("beta", "fixture/beta:2", "sha256:" + "b" * 64, "amd64"),
]:
    config = {
        "architecture": arch,
        "created": "2026-01-01T00:00:00Z",
        "os": "linux",
        "config": {"Env": [f"FIXTURE={component}"], "Labels": {}},
        "rootfs": {"type": "layers", "diff_ids": []},
        "history": [],
    }
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    config_name = config_digest.removeprefix("sha256:") + ".json"
    members[config_name] = config_bytes
    rows.append({"Config": config_name, "RepoTags": [runtime_tag], "Layers": []})
    images.append({"component": component, "runtime_tag": runtime_tag,
                   "image_id": image_id, "oci_config_digest": config_digest,
                   "platform": "linux/amd64"})
manifest = json.dumps(rows, separators=(",", ":")).encode() + b"\n"
with tarfile.open(archive_path, mode="w:gz") as output:
    for name, payload in [("manifest.json", manifest), *members.items()]:
        info = tarfile.TarInfo(name)
        info.mode = 0o444
        info.size = len(payload)
        output.addfile(info, io.BytesIO(payload))
provenance_path.write_text(json.dumps({"platform": "linux/amd64", "images": images},
                                      sort_keys=True) + "\n", encoding="utf-8")
PY
printf 'bundle payload\n' >"$BUNDLE/deploy/docker-compose/payload.txt"

FAKE_SYFT="$TMP_ROOT/syft"
cat >"$FAKE_SYFT" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == scan && "$3" == -o ]] || exit 64
source_ref=$2
output=${4#spdx-json=}
creator=${FAKE_SYFT_CREATOR:-Tool: syft-1.44.0}
python3 - "$output" "$creator" "$source_ref" <<'PY'
import json
import pathlib
import sys

output, creator, source = sys.argv[1:]
pathlib.Path(output).write_text(json.dumps({
    "spdxVersion": "SPDX-2.3",
    "creationInfo": {"creators": [creator]},
    "name": source,
    "packages": [{"SPDXID": "SPDXRef-Package", "name": "fixture"}],
}, sort_keys=True) + "\n", encoding="utf-8")
PY
SH
chmod 0500 "$FAKE_SYFT"
FAKE_SYFT_SHA="$(sha256_file "$FAKE_SYFT")"
export JJD_RELEASE_TESTING=1 JJD_TEST_SYFT_SHA256="$FAKE_SYFT_SHA"

JJD_RELEASE_TESTING=1 \
JJD_TEST_SYFT_BIN="$FAKE_SYFT" \
JJD_TEST_SYFT_SHA256="$FAKE_SYFT_SHA" \
bash "$GENERATOR" --bundle "$BUNDLE" --provenance "$PROVENANCE"

INDEX="$BUNDLE/sbom/index.json"
python3 "$VERIFIER" --bundle "$BUNDLE" --provenance "$PROVENANCE" --index "$INDEX"
SOURCE_TAR="$TMP_ROOT/offline-images.tar"
gzip -dc "$IMAGE_ARCHIVE_DIR/jjdguard-offline-images-fixture.tar.gz" >"$SOURCE_TAR"
if python3 "$SELECTOR" --archive "$SOURCE_TAR" --tag fixture/alpha:1 \
     --config-digest "sha256:$(printf '0%.0s' {1..64})" \
     --platform linux/amd64 --output "$TMP_ROOT/bad-digest.tar" >/dev/null 2>&1; then
  fail 'offline image selector accepted a config digest mismatch'
fi
if python3 "$SELECTOR" --archive "$SOURCE_TAR" --tag fixture/missing:1 \
     --config-digest "sha256:$(printf '0%.0s' {1..64})" \
     --platform linux/amd64 --output "$TMP_ROOT/missing-tag.tar" >/dev/null 2>&1; then
  fail 'offline image selector accepted a missing tag'
fi

BASE_BUNDLE="$TMP_ROOT/base-bundle"
cp -a "$BUNDLE" "$BASE_BUNDLE"

expect_verifier_failure() {
  local label=$1 candidate
  candidate="$TMP_ROOT/$label"
  cp -a "$BASE_BUNDLE" "$candidate"
  find "$candidate/sbom" -type f -exec chmod u+w {} +
  shift
  "$@" "$candidate"
  if python3 "$VERIFIER" --bundle "$candidate" --provenance "$PROVENANCE" \
      --index "$candidate/sbom/index.json" >/dev/null 2>&1; then
    fail "SBOM verifier accepted: $label"
  fi
}

mutate_index() {
  local expression=$1 bundle=$2
  python3 - "$bundle/sbom/index.json" "$expression" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
exec(sys.argv[2], {}, {"payload": payload})
path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY
}

expect_verifier_failure non-syft-creator bash -c '
  bundle=$1
  python3 - "$bundle/sbom/bundle.spdx.json" <<"PY"
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]); data = json.loads(path.read_text())
data["creationInfo"]["creators"] = ["Tool: something-else"]
path.write_text(json.dumps(data) + "\n")
PY
' bash
expect_verifier_failure empty-packages bash -c '
  bundle=$1
  python3 - "$bundle/sbom/images/alpha.spdx.json" <<"PY"
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]); data = json.loads(path.read_text())
data["packages"] = []
path.write_text(json.dumps(data) + "\n")
PY
' bash
expect_verifier_failure missing-image mutate_index 'payload["images"].pop()'
expect_verifier_failure duplicate-component mutate_index 'payload["images"].append(dict(payload["images"][0]))'
expect_verifier_failure hash-mismatch mutate_index 'payload["bundle"]["sha256"] = "0" * 64'
expect_verifier_failure missing-sbom-sentinel bash -c 'touch "$1/SBOM-MISSING.txt"' bash
expect_verifier_failure file-list-fallback bash -c '
  printf "{\"files\":[\"payload.txt\"]}\n" >"$1/sbom/images/beta.spdx.json"
' bash

mkdir -p "$TMP_ROOT/bad-syft"
if JJD_RELEASE_TESTING=1 \
   JJD_TEST_SYFT_BIN="$FAKE_SYFT" \
   JJD_TEST_SYFT_SHA256="$(printf '0%.0s' {1..64})" \
   bash "$GENERATOR" --bundle "$TMP_ROOT/bad-syft" --provenance "$PROVENANCE" \
     >/dev/null 2>&1; then
  fail 'generator accepted a Syft binary with the wrong hash'
fi

grep -Fq 'generate-release-sbom.sh' "$PACKAGE" ||
  fail 'bundle packager does not invoke the SBOM generator'
grep -Fq 'select-offline-image-archive.py' "$GENERATOR" ||
  fail 'SBOM generator does not select exact images from the verified archive'
grep -Fq 'env -u JJD_RELEASE_TESTING' "$PACKAGE" ||
  fail 'bundle packager permits Syft test-mode fallback'
grep -Fq 'verify-sbom-index.py' "$RUN_PACKAGER" ||
  fail 'run packager does not retain the SBOM verification chain'

echo '[ok] release SBOM rejects non-Syft, incomplete, duplicate, fallback, and hash-drift evidence'
