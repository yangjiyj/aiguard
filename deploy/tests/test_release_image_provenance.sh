#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT_DIR/deploy/docker-compose/lib-image-provenance.sh"
VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-image-provenance.py"
BASE_PARSER="$ROOT_DIR/deploy/docker-compose/dockerfile-base-images.py"
BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
PACKAGE="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
EXPORTER="$ROOT_DIR/deploy/docker-compose/export-offline-images.sh"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail() {
  echo "[fail] $*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$TMP_ROOT/$label.stdout" 2>"$TMP_ROOT/$label.stderr"; then
    fail "$label was accepted"
  fi
}

[[ -f "$LIB" ]] || fail 'image provenance library is missing'
[[ -x "$VERIFIER" ]] || fail 'image provenance verifier is missing or not executable'
# shellcheck disable=SC1090
source "$LIB"
declare -F prepare_release_git_context >/dev/null || fail 'Git archive context helper is missing'
declare -F image_provenance_repo_digest >/dev/null ||
  fail 'third-party RepoDigest parser is missing'

PARSED_DIGEST="$(image_provenance_repo_digest \
  registry.example/dependency:1 \
  '["registry.example/dependency@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]')"
[[ "$PARSED_DIGEST" == sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]] ||
  fail 'third-party actual digest was not parsed from RepoDigests'
expect_failure missing-repository-digest image_provenance_repo_digest \
  registry.example/dependency:1 \
  '["other.example/dependency@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]'

MULTIPLE_DIGESTS='["registry.example/dependency@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","registry.example/dependency@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]'
PARSED_PIN="$(image_provenance_repo_digest registry.example/dependency:1 "$MULTIPLE_DIGESTS" sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)"
[[ "$PARSED_PIN" == sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ]] || fail 'locked digest was not selected from same-image RepoDigests'
expect_failure missing-locked-digest image_provenance_repo_digest registry.example/dependency:1 "$MULTIPLE_DIGESTS" sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
expect_failure ambiguous-unpinned-digests image_provenance_repo_digest registry.example/dependency:1 "$MULTIPLE_DIGESTS"

REPO="$TMP_ROOT/repo"
mkdir -p "$REPO/app" "$REPO/judge"
git init -q "$REPO"
git -C "$REPO" config user.name 'Provenance Fixture'
git -C "$REPO" config user.email provenance-fixture@example.invalid
cat >"$REPO/app/Dockerfile" <<'DOCKERFILE'
FROM registry.example/app-base:1@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS base
FROM base AS runtime
DOCKERFILE
printf '%s\n' 'tracked payload' >"$REPO/app/payload.txt"
cat >"$REPO/judge/Dockerfile" <<'DOCKERFILE'
FROM registry.example/judge-base:1@sha256:2222222222222222222222222222222222222222222222222222222222222222 AS build
FROM registry.example/judge-base:1@sha256:2222222222222222222222222222222222222222222222222222222222222222
DOCKERFILE
printf '%s\n' '#!/bin/sh' 'exit 0' >"$REPO/judge/entrypoint.sh"
git -C "$REPO" add .
git -C "$REPO" commit -q -m initial
REVISION="$(git -C "$REPO" rev-parse HEAD)"
TREE="$(git -C "$REPO" rev-parse HEAD^{tree})"
APP_BLOB="$(git -C "$REPO" rev-parse HEAD:app/Dockerfile)"
JUDGE_BLOB="$(git -C "$REPO" rev-parse HEAD:judge/Dockerfile)"
ENTRYPOINT_BLOB="$(git -C "$REPO" rev-parse HEAD:judge/entrypoint.sh)"
REMOTE='git@gitee.com:example/fixture.git'
SOURCE_RECEIPT="$TMP_ROOT/release-source.json"
python3 - "$SOURCE_RECEIPT" "$REMOTE" "$REVISION" "$TREE" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "schema": "jjdguard-release-source/v1",
    "remote": sys.argv[2],
    "source_revision": sys.argv[3],
    "source_tree": sys.argv[4],
}, sort_keys=True) + "\n", encoding="utf-8")
PY
UPSTREAM_RECEIPT="$TMP_ROOT/upstream-receipt.json"
python3 - "$UPSTREAM_RECEIPT" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "schema": "jjdguard-upstream-source/v1",
    "component": "llama.cpp",
    "remote": "https://github.com/ggerganov/llama.cpp.git",
    "revision": "1" * 40,
    "tree": "2" * 40,
    "commit_count": 7,
    "archive_file": "llama.cpp.tar",
    "archive_sha256": "3" * 64,
    "archive_size": 123,
}, sort_keys=True) + "\n", encoding="utf-8")
PY

printf '%s\n' 'must stay outside the image context' >"$REPO/app/untracked.txt"
ARCHIVE_SHA_ONE="$(prepare_release_git_context "$REPO" "$SOURCE_RECEIPT" "$TMP_ROOT/context-one")"
ARCHIVE_SHA_TWO="$(prepare_release_git_context "$REPO" "$SOURCE_RECEIPT" "$TMP_ROOT/context-two")"
[[ "$ARCHIVE_SHA_ONE" =~ ^[0-9a-f]{64}$ && "$ARCHIVE_SHA_ONE" == "$ARCHIVE_SHA_TWO" ]] ||
  fail 'same source revision did not produce a deterministic archive'
[[ -f "$TMP_ROOT/context-one/source/app/payload.txt" ]] || fail 'tracked source is missing from archive context'
[[ ! -e "$TMP_ROOT/context-one/source/app/untracked.txt" ]] || fail 'untracked source entered archive context'
[[ "$(stat -c %a "$TMP_ROOT/context-one/source")" == 700 ]] ||
  fail 'source archive root is not mode 0700'

BAD_SOURCE="$TMP_ROOT/bad-source.json"
python3 - "$SOURCE_RECEIPT" "$BAD_SOURCE" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
data["source_tree"] = "f" * 40
pathlib.Path(sys.argv[2]).write_text(json.dumps(data) + "\n", encoding="utf-8")
PY
expect_failure source-tree-mismatch \
  prepare_release_git_context "$REPO" "$BAD_SOURCE" "$TMP_ROOT/context-bad"

CATALOG="$TMP_ROOT/images.lst"
cat >"$CATALOG" <<'CATALOG'
fixture/app:1 common first-party enterprise-ai-portal - app/Dockerfile app
fixture/judge:1 full upstream-source judge - judge/Dockerfile judge
registry.example/dependency:1 common third-party dependency sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb - -
CATALOG

CONFIG_DIR="$TMP_ROOT/docker-configs"
mkdir -p "$CONFIG_DIR"
python3 - "$CONFIG_DIR" "$REVISION" "$TREE" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
revision, tree = sys.argv[2:]
def write(name, labels):
    config = {
        "architecture": "amd64",
        "created": "2026-01-01T00:00:00Z",
        "os": "linux",
        "config": {"Labels": labels},
        "rootfs": {"type": "layers", "diff_ids": []},
        "history": [],
    }
    (root / name).write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
app_labels = {
    "org.opencontainers.image.revision": revision,
    "org.opencontainers.image.source": "git@gitee.com:example/fixture.git",
    "com.jjdguard.source.tree": tree,
}
write("app.json", app_labels)
write("retagged-app.json", {**app_labels, "com.jjdguard.source.tree": "f" * 40})
write("judge.json", app_labels)
write("dependency.json", {})
APP_ID = "sha256:" + "a" * 64
DEPENDENCY_ID = "sha256:" + "d" * 64
JUDGE_ID = "sha256:" + "c" * 64
(root / "ids.env").write_text(f"APP_ID={APP_ID}\nDEPENDENCY_ID={DEPENDENCY_ID}\nJUDGE_ID={JUDGE_ID}\n", encoding="utf-8")
PY
source <(cat "$CONFIG_DIR/ids.env")
TOOLCHAIN_JSON='{"docker_client_version":"Docker client fixture","docker_server_version":"Docker server fixture","buildx_version":"buildx fixture","buildx_builder":"fixture-builder","buildx_nodes":[{"name":"fixture-node","endpoint":"fixture://builder","status":"running","buildkit_version":"BuildKit fixture"}]}'
BUILDX_ENGINE_JSON='{"kind":"buildx","builder":"fixture-builder","nodes":[{"name":"fixture-node","endpoint":"fixture://builder","status":"running","buildkit_version":"BuildKit fixture"}]}'
DAEMON_ENGINE_JSON='{"kind":"docker-daemon","docker_client_version":"Docker client fixture","docker_server_version":"Docker server fixture"}'
APP_BASE_IMAGES="$(python3 "$BASE_PARSER" --dockerfile "$REPO/app/Dockerfile")"
JUDGE_BASE_IMAGES="$(python3 "$BASE_PARSER" --dockerfile "$REPO/judge/Dockerfile")"
expect_failure invalid-base-images \
  write_source_image_provenance_record \
  "$TMP_ROOT/invalid-base-images.json" fixture/app:1 common first-party enterprise-ai-portal \
  app/Dockerfile app linux/amd64 "$APP_ID" "$SOURCE_RECEIPT" \
  "$ARCHIVE_SHA_ONE" "$APP_BLOB" '{}' '{}' '{}'
grep -Fq 'base_images must be a JSON array' "$TMP_ROOT/invalid-base-images.stderr" ||
  fail 'invalid base_images failed for the wrong reason'
mkdir -p "$TMP_ROOT/task4"
printf '%s\n' \
  '{"schema":"fixture-task4-receipt/v1","build_args":{"NEXT_PUBLIC_BILLING_ENABLED":"false"},"build_engine":{"kind":"docker-daemon","docker_client_version":"Docker client fixture","docker_server_version":"Docker server fixture"},"base_images":[{"from_index":0,"stage":"base","reference":"registry.example/app-base:1@sha256:1111111111111111111111111111111111111111111111111111111111111111","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}]}' \
  >"$TMP_ROOT/task4/portal-image-receipt.json"
cp "$TMP_ROOT/task4/portal-image-receipt.json" "$TMP_ROOT/task4/tier1-image-receipt.json"
LEGACY_RECEIPT_SHA="$(sha256sum "$TMP_ROOT/task4/portal-image-receipt.json" | awk '{print $1}')"
PROVENANCE="$TMP_ROOT/image-provenance.json"
python3 - "$PROVENANCE" "$REMOTE" "$REVISION" "$TREE" "$ARCHIVE_SHA_ONE" \
  "$APP_ID" "$DEPENDENCY_ID" "$JUDGE_ID" "$APP_BLOB" "$JUDGE_BLOB" \
  "$ENTRYPOINT_BLOB" "$LEGACY_RECEIPT_SHA" "$TOOLCHAIN_JSON" \
  "$BUILDX_ENGINE_JSON" "$DAEMON_ENGINE_JSON" <<'PY'
import json
import pathlib
import sys

out, remote, revision, tree, archive_sha, app_id, dependency_id, judge_id, app_blob, judge_blob, entrypoint_blob, legacy_receipt_sha, toolchain_json, buildx_engine_json, daemon_engine_json = sys.argv[1:]
toolchain = json.loads(toolchain_json)
buildx_engine = json.loads(buildx_engine_json)
daemon_engine = json.loads(daemon_engine_json)
payload = {
    "schema": "jjdguard-image-provenance/v1",
    "generated_at": "2026-08-08T00:00:00Z",
    "platform": "linux/amd64",
    "selection": {"profile": "full", "include_chat": False},
    "source": {
        "remote": remote,
        "revision": revision,
        "tree": tree,
        "archive_sha256": archive_sha,
    },
    "toolchain": toolchain,
    "images": [
        {
            "runtime_tag": "fixture/app:1",
            "profile": "common",
            "kind": "first-party",
            "component": "enterprise-ai-portal",
            "expected_digest": None,
            "actual_digest": None,
            "dockerfile": "app/Dockerfile",
            "context": "app",
            "platform": "linux/amd64",
            "image_id": app_id,
            "oci_config_digest": app_id,
            "source": {"remote": remote, "revision": revision, "tree": tree,
                       "archive_sha256": archive_sha},
            "source_blobs": {"app/Dockerfile": app_blob},
            "base_images": [{
                "from_index": 0,
                "stage": "base",
                "reference": "registry.example/app-base:1@sha256:" + "1" * 64,
                "digest": "sha256:" + "1" * 64,
            }],
            "toolchain": toolchain,
            "build_engine": daemon_engine,
            "legacy_receipt": {
                "path": "task4/portal-image-receipt.json",
                "sha256": legacy_receipt_sha,
            },
            "build_args": {"NEXT_PUBLIC_BILLING_ENABLED": "false"},
            "sbom": {"path": None, "sha256": None},
        },
        {
            "runtime_tag": "fixture/judge:1",
            "profile": "full",
            "kind": "upstream-source",
            "component": "judge",
            "expected_digest": None,
            "actual_digest": None,
            "dockerfile": "judge/Dockerfile",
            "context": "judge",
            "platform": "linux/amd64",
            "image_id": judge_id,
            "oci_config_digest": judge_id,
            "source": {"remote": remote, "revision": revision, "tree": tree,
                       "archive_sha256": archive_sha},
            "source_blobs": {"judge/Dockerfile": judge_blob},
            "base_images": [
                {
                    "from_index": 0,
                    "stage": "build",
                    "reference": "registry.example/judge-base:1@sha256:" + "2" * 64,
                    "digest": "sha256:" + "2" * 64,
                },
                {
                    "from_index": 1,
                    "stage": None,
                    "reference": "registry.example/judge-base:1@sha256:" + "2" * 64,
                    "digest": "sha256:" + "2" * 64,
                },
            ],
            "wrapper_blobs": {"judge/entrypoint.sh": entrypoint_blob},
            "toolchain": toolchain,
            "build_engine": buildx_engine,
            "upstream": {
                "schema": "jjdguard-upstream-source/v1",
                "component": "llama.cpp",
                "remote": "https://github.com/ggerganov/llama.cpp.git",
                "revision": "1" * 40,
                "tree": "2" * 40,
                "commit_count": 7,
                "archive_file": "llama.cpp.tar",
                "archive_sha256": "3" * 64,
                "archive_size": 123,
            },
            "build_args": {"LLAMA_CPP_REVISION": "1" * 40, "LLAMA_CPP_COMMIT_COUNT": 7},
            "sbom": {"path": None, "sha256": None},
        },
        {
            "runtime_tag": "registry.example/dependency:1",
            "profile": "common",
            "kind": "third-party",
            "component": "dependency",
            "expected_digest": "sha256:" + "b" * 64,
            "actual_digest": "sha256:" + "b" * 64,
            "dockerfile": None,
            "context": None,
            "platform": "linux/amd64",
            "image_id": dependency_id,
            "oci_config_digest": dependency_id,
            "build_args": {},
            "sbom": {"path": None, "sha256": None},
        },
    ],
}
pathlib.Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

DOCKER_STATE="$TMP_ROOT/docker-state"
mkdir -p "$DOCKER_STATE"
python3 - "$DOCKER_STATE/app.json" "$APP_ID" "$CONFIG_DIR/app.json" <<'PY'
import json
import pathlib
import sys

path, image_id, config_path = sys.argv[1:]
config = json.loads(pathlib.Path(config_path).read_text(encoding="utf-8"))
pathlib.Path(path).write_text(json.dumps([{
    "Id": image_id,
    "architecture": config["architecture"],
    "os": config["os"],
    "Architecture": config["architecture"],
    "Os": config["os"],
    "Variant": None,
    "Created": config["created"],
    "Author": config.get("author"),
    "RepoDigests": [],
    "Config": config["config"],
    "RootFS": {"Type": config["rootfs"]["type"], "Layers": config["rootfs"]["diff_ids"]},
}]), encoding="utf-8")
PY
python3 - "$DOCKER_STATE/dependency.json" "$DEPENDENCY_ID" "$CONFIG_DIR/dependency.json" <<'PY'
import json
import pathlib
import sys

path, image_id, config_path = sys.argv[1:]
config = json.loads(pathlib.Path(config_path).read_text(encoding="utf-8"))
pathlib.Path(path).write_text(json.dumps([{
    "Id": image_id,
    "architecture": config["architecture"],
    "os": config["os"],
    "Architecture": config["architecture"],
    "Os": config["os"],
    "Variant": None,
    "Created": config["created"],
    "Author": config.get("author"),
    "RepoDigests": ["registry.example/dependency@sha256:" + "b" * 64],
    "Config": config["config"],
    "RootFS": {"Type": config["rootfs"]["type"], "Layers": config["rootfs"]["diff_ids"]},
}]), encoding="utf-8")
PY
python3 - "$DOCKER_STATE/judge.json" "$JUDGE_ID" "$CONFIG_DIR/judge.json" <<'PY'
import json
import pathlib
import sys

path, image_id, config_path = sys.argv[1:]
config = json.loads(pathlib.Path(config_path).read_text(encoding="utf-8"))
pathlib.Path(path).write_text(json.dumps([{
    "Id": image_id,
    "architecture": config["architecture"],
    "os": config["os"],
    "Architecture": config["architecture"],
    "Os": config["os"],
    "Variant": None,
    "Created": config["created"],
    "Author": config.get("author"),
    "RepoDigests": [],
    "Config": config["config"],
    "RootFS": {"Type": config["rootfs"]["type"], "Layers": config["rootfs"]["diff_ids"]},
}]), encoding="utf-8")
PY

FAKE_DOCKER="$TMP_ROOT/docker"
cat >"$FAKE_DOCKER" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-} ${2:-}" in
  'image inspect')
    if [[ "$3" == --platform ]]; then
      inspected_image="$5"
    else
      inspected_image="$3"
    fi
    case "$inspected_image" in
      fixture/app:1) cat "$FAKE_DOCKER_STATE/app.json" ;;
      fixture/judge:1) cat "$FAKE_DOCKER_STATE/judge.json" ;;
      registry.example/dependency:1) cat "$FAKE_DOCKER_STATE/dependency.json" ;;
      *)
        [[ "${FAKE_EXPORT_COMPAT:-0}" == 1 ]] || exit 1
        if [[ "${4:-}" == --format ]]; then
          case "$3" in
            postgres:16-alpine)
              printf '%s\n' '["postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"]'
              ;;
            valkey/valkey:8.1.10-alpine)
              printf '%s\n' '["valkey/valkey@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507"]'
              ;;
            *) printf '%s\n' '[]' ;;
          esac
        else
          printf '%s\n' '[{"Id":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]'
        fi
        ;;
    esac
    ;;
  save\ *)
    # The exporter passes all tags after "save"; match the first tag and build
    # a Docker archive from the selected fixture state.
    python3 - "$FAKE_DOCKER_CONFIG_DIR" "${FAKE_DOCKER_SAVE_MODE:-valid}" <<'PY'
import hashlib
import io
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
rows = [
    ["fixture/app:1", root / ("retagged-app.json" if mode == "retag" else "app.json")],
    ["fixture/judge:1", root / "judge.json"],
    ["registry.example/dependency:1", root / "dependency.json"],
]
if mode == "missing":
    rows.pop(0)
if mode == "duplicate":
    rows.append(list(rows[0]))
if mode == "extra":
    rows[0][0] = [rows[0][0], "fixture/extra:1"]

manifest = []
members = {}
for tags, path in rows:
    payload = path.read_bytes()
    name = hashlib.sha256(payload).hexdigest() + ".json"
    members[name] = payload
    manifest.append({
        "Config": name,
        "RepoTags": tags if isinstance(tags, list) else [tags],
        "Layers": [],
    })
if mode == "layer-sources":
    for item in manifest:
        item["LayerSources"] = {}
if mode == "bad-layer-sources":
    for item in manifest:
        item["LayerSources"] = []
members["manifest.json"] = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"

with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
    for name, payload in members.items():
        info = tarfile.TarInfo(name)
        info.mode = 0o444
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
PY
    ;;
  *) exit 64 ;;
esac
SH
chmod 0500 "$FAKE_DOCKER"

verify() {
  FAKE_DOCKER_STATE="$DOCKER_STATE" python3 "$VERIFIER" \
    --catalog "$CATALOG" \
    --receipt "$1" \
    --source-receipt "$SOURCE_RECEIPT" \
    --repository "$REPO" \
    --profile full \
    --include-chat 0 \
    --upstream-receipt "$UPSTREAM_RECEIPT" \
    --docker-command "$FAKE_DOCKER"
}

verify "$PROVENANCE"

GENERATED_RECORDS="$TMP_ROOT/generated-records"
mkdir -m 0700 "$GENERATED_RECORDS"
write_source_image_provenance_record \
  "$GENERATED_RECORDS/app.json" fixture/app:1 common first-party enterprise-ai-portal \
  app/Dockerfile app linux/amd64 "$APP_ID" "$SOURCE_RECEIPT" \
  "$ARCHIVE_SHA_ONE" "$APP_BLOB" "$APP_BASE_IMAGES" \
  '{"NEXT_PUBLIC_BILLING_ENABLED":"false"}' \
  "{\"legacy_receipt\":{\"path\":\"task4/portal-image-receipt.json\",\"sha256\":\"$LEGACY_RECEIPT_SHA\"},\"build_engine\":$DAEMON_ENGINE_JSON}"
write_third_party_image_provenance_record \
  "$GENERATED_RECORDS/dependency.json" registry.example/dependency:1 common dependency \
  sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  linux/amd64 "$DEPENDENCY_ID"
UPSTREAM_EXTRA="$(BUILDX_ENGINE_JSON="$BUILDX_ENGINE_JSON" python3 - "$ENTRYPOINT_BLOB" <<'PY'
import json
import sys

print(json.dumps({
    "build_engine": json.loads(__import__("os").environ["BUILDX_ENGINE_JSON"]),
    "wrapper_blobs": {"judge/entrypoint.sh": sys.argv[1]},
    "upstream": {
        "schema": "jjdguard-upstream-source/v1",
        "component": "llama.cpp",
        "remote": "https://github.com/ggerganov/llama.cpp.git",
        "revision": "1" * 40,
        "tree": "2" * 40,
        "commit_count": 7,
        "archive_file": "llama.cpp.tar",
        "archive_sha256": "3" * 64,
        "archive_size": 123,
    },
}, sort_keys=True))
PY
)"
write_source_image_provenance_record \
  "$GENERATED_RECORDS/judge.json" fixture/judge:1 full upstream-source judge \
  judge/Dockerfile judge linux/amd64 "$JUDGE_ID" "$SOURCE_RECEIPT" \
  "$ARCHIVE_SHA_ONE" "$JUDGE_BLOB" "$JUDGE_BASE_IMAGES" \
  '{"LLAMA_CPP_REVISION":"1111111111111111111111111111111111111111","LLAMA_CPP_COMMIT_COUNT":7}' \
  "$UPSTREAM_EXTRA"
GENERATED_PROVENANCE="$TMP_ROOT/generated-provenance.json"
finalize_image_provenance \
  "$GENERATED_PROVENANCE" "$GENERATED_RECORDS" "$SOURCE_RECEIPT" \
  "$ARCHIVE_SHA_ONE" linux/amd64 "$TOOLCHAIN_JSON" full 0
[[ "$(python3 - "$GENERATED_PROVENANCE" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["toolchain"]["buildx_nodes"][0]["buildkit_version"])
PY
)" == 'BuildKit fixture' ]] || fail 'generated provenance omits the BuildKit version'
verify "$GENERATED_PROVENANCE"

mutate() {
  local label="$1" expression="$2" expected_error="${3:-}"
  python3 - "$PROVENANCE" "$TMP_ROOT/$label.json" "$expression" <<'PY'
import json
import pathlib
import sys

source, target, expression = sys.argv[1:]
data = json.loads(pathlib.Path(source).read_text(encoding="utf-8"))
exec(expression, {}, {"data": data})
pathlib.Path(target).write_text(json.dumps(data) + "\n", encoding="utf-8")
PY
  expect_failure "$label" verify "$TMP_ROOT/$label.json"
  if [[ -n "$expected_error" ]]; then
    grep -Fq "$expected_error" "$TMP_ROOT/$label.stderr" ||
      fail "$label failed for the wrong reason"
  fi
}

mutate missing-image 'data["images"].pop()'
mutate missing-portal-billing \
  'data["images"][0]["build_args"] = {}' \
  'build argument key set drifted for enterprise-ai-portal'
mutate wrong-portal-billing-key \
  'data["images"][0]["build_args"] = {"VITE_BILLING_ENABLED": "false"}' \
  'build argument key set drifted for enterprise-ai-portal'
mutate portal-billing-receipt-mismatch \
  'data["images"][0]["build_args"]["NEXT_PUBLIC_BILLING_ENABLED"] = "true"' \
  'Task4 receipt build arguments drifted for enterprise-ai-portal'
mutate duplicate-component 'data["images"][1]["component"] = "enterprise-ai-portal"'
mutate source-revision 'data["source"]["revision"] = "d" * 40'
mutate dockerfile-drift 'data["images"][0]["dockerfile"] = "other/Dockerfile"'
mutate missing-dockerfile-blob \
  'data["images"][0]["source_blobs"].pop("app/Dockerfile")' \
  'Dockerfile blob identity is missing for enterprise-ai-portal'
mutate missing-base-images \
  'data["images"][0].pop("base_images")' \
  'image provenance fields do not exactly match the first-party schema for enterprise-ai-portal'
mutate extra-base-images \
  'data["images"][0]["base_images"].append({"from_index":9,"stage":None,"reference":"registry.example/extra:1@sha256:"+"e"*64,"digest":"sha256:"+"e"*64})' \
  'base image provenance drifted for enterprise-ai-portal'
mutate base-image-digest-drift \
  'data["images"][0]["base_images"][0]["digest"] = "sha256:" + "f" * 64' \
  'base image provenance drifted for enterprise-ai-portal'
mutate digest-drift \
  'data["images"][2]["actual_digest"] = "sha256:" + "d" * 64' \
  'third-party actual digest drifted for dependency'
mutate missing-label-contract 'data["images"][0]["source"]["tree"] = "e" * 40'
mutate upstream-archive 'data["images"][1]["upstream"]["archive_sha256"] = "4" * 64'
mutate missing-buildkit-version 'data["toolchain"]["buildx_nodes"][0].pop("buildkit_version")'
mutate missing-image-toolchain \
  'data["images"][0].pop("toolchain")' \
  'image provenance fields do not exactly match the first-party schema for enterprise-ai-portal'
mutate image-toolchain-drift \
  'data["images"][1]["toolchain"]["buildx_nodes"][0]["buildkit_version"] = "BuildKit drift"' \
  'image toolchain drifted for judge'
mutate legacy-receipt-hash \
  'data["images"][0]["legacy_receipt"]["sha256"] = "f" * 64' \
  'legacy receipt digest drifted for enterprise-ai-portal'
mutate missing-legacy-receipt \
  'data["images"][0].pop("legacy_receipt")' \
  'image provenance fields do not exactly match the first-party schema for enterprise-ai-portal'
mutate swapped-legacy-receipt \
  'data["images"][0]["legacy_receipt"]["path"] = "task4/tier1-image-receipt.json"' \
  'Task4 legacy receipt path drifted for enterprise-ai-portal'
mutate unknown-top-level-field 'data["unexpected"] = True' \
  'image provenance schema is invalid'
mutate unknown-first-party-field 'data["images"][0]["unknown"] = True' \
  'image provenance fields do not exactly match the first-party schema for enterprise-ai-portal'
mutate extra-source-blob \
  'data["images"][0]["source_blobs"]["app/extra.txt"] = "0" * 40'
mutate extra-wrapper-blob \
  'data["images"][1]["wrapper_blobs"]["judge/extra.sh"] = "0" * 40'
mutate extra-toolchain-key \
  'data["toolchain"]["extra"] = "forbidden"' \
  'build toolchain fields do not exactly match the schema'
mutate third-party-source-claim \
  'data["images"][2]["source"] = data["source"]' \
  'image provenance fields do not exactly match the third-party schema for dependency'

cp "$TMP_ROOT/task4/portal-image-receipt.json" \
  "$TMP_ROOT/task4/portal-image-receipt.good.json"
jq '.base_images[0].reference="registry.example/app-base:1@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
    .base_images[0].digest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$TMP_ROOT/task4/portal-image-receipt.good.json" \
  >"$TMP_ROOT/task4/portal-image-receipt.json"
TASK4_BASE_DRIFT_SHA="$(sha256sum "$TMP_ROOT/task4/portal-image-receipt.json" | awk '{print $1}')"
python3 - "$PROVENANCE" "$TMP_ROOT/task4-base-images-drift.json" "$TASK4_BASE_DRIFT_SHA" <<'PY'
import json
import pathlib
import sys

source, target, receipt_sha = sys.argv[1:]
data = json.loads(pathlib.Path(source).read_text(encoding="utf-8"))
data["images"][0]["legacy_receipt"]["sha256"] = receipt_sha
pathlib.Path(target).write_text(json.dumps(data) + "\n", encoding="utf-8")
PY
expect_failure task4-base-images-drift verify "$TMP_ROOT/task4-base-images-drift.json"
grep -Fq 'Task4 receipt base images drifted for enterprise-ai-portal' \
  "$TMP_ROOT/task4-base-images-drift.stderr" ||
  fail 'Task4 base image drift failed for the wrong reason'
mv "$TMP_ROOT/task4/portal-image-receipt.good.json" \
  "$TMP_ROOT/task4/portal-image-receipt.json"

cp "$DOCKER_STATE/app.json" "$DOCKER_STATE/app.good.json"
python3 - "$DOCKER_STATE/app.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data[0]["Id"] = "sha256:" + "9" * 64
path.write_text(json.dumps(data), encoding="utf-8")
PY
expect_failure retag verify "$PROVENANCE"
mv "$DOCKER_STATE/app.good.json" "$DOCKER_STATE/app.json"

cp "$DOCKER_STATE/app.json" "$DOCKER_STATE/app.good.json"
python3 - "$DOCKER_STATE/app.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data[0]["Config"]["Labels"].pop("com.jjdguard.source.tree")
path.write_text(json.dumps(data), encoding="utf-8")
PY
expect_failure missing-oci-label verify "$PROVENANCE"
mv "$DOCKER_STATE/app.good.json" "$DOCKER_STATE/app.json"

# A valid archive must cover every selected tag and atomically retain its
# checksum only after its config JSON identities have been verified.
EXPORT_VALID_DIR="$TMP_ROOT/export-valid"
mkdir -p "$EXPORT_VALID_DIR"
FAKE_DOCKER_STATE="$DOCKER_STATE" \
FAKE_DOCKER_CONFIG_DIR="$CONFIG_DIR" \
FAKE_DOCKER_SAVE_MODE=layer-sources \
FAKE_EXPORT_COMPAT=1 \
PATH="$TMP_ROOT:$PATH" \
PROVENANCE_CATALOG="$CATALOG" \
IMAGE_PROVENANCE_FILE="$PROVENANCE" \
SOURCE_ATTESTATION_FILE="$SOURCE_RECEIPT" \
PROVENANCE_REPOSITORY="$REPO" \
PROVENANCE_UPSTREAM_RECEIPT="$UPSTREAM_RECEIPT" \
BUNDLE_PROFILE=full INCLUDE_CHAT=0 \
JJDGUARD_IMAGE_STORE_LOCK_FILE="$TMP_ROOT/image-store.lock" \
bash "$EXPORTER" "$EXPORT_VALID_DIR" >/dev/null
find "$EXPORT_VALID_DIR" -maxdepth 1 -type f -name '*.tar.gz' -print -quit | grep -q . ||
  fail 'valid image export did not retain its archive'
find "$EXPORT_VALID_DIR" -maxdepth 1 -type f -name '*.tar.gz.sha256' -print -quit | grep -q . ||
  fail 'valid image export did not retain its checksum'
python3 - "$PROVENANCE" <<'PY'
import json, pathlib, sys
images = json.loads(pathlib.Path(sys.argv[1]).read_text())["images"]
assert images and all(image["oci_config_digest"] != image["image_id"] for image in images)
PY
verify "$PROVENANCE"

# The live tags pass verification, then docker save emits a retagged config.
# The exporter must reject the saved bytes and remove both archive and checksum.
EXPORT_DIR="$TMP_ROOT/export-retag"
mkdir -p "$EXPORT_DIR"
if FAKE_DOCKER_STATE="$DOCKER_STATE" \
   FAKE_DOCKER_CONFIG_DIR="$CONFIG_DIR" \
   FAKE_DOCKER_SAVE_MODE=retag \
   FAKE_EXPORT_COMPAT=1 \
   PATH="$TMP_ROOT:$PATH" \
   PROVENANCE_CATALOG="$CATALOG" \
   IMAGE_PROVENANCE_FILE="$PROVENANCE" \
   SOURCE_ATTESTATION_FILE="$SOURCE_RECEIPT" \
   PROVENANCE_REPOSITORY="$REPO" \
   PROVENANCE_UPSTREAM_RECEIPT="$UPSTREAM_RECEIPT" \
   BUNDLE_PROFILE=full INCLUDE_CHAT=0 \
   JJDGUARD_IMAGE_STORE_LOCK_FILE="$TMP_ROOT/image-store.lock" \
   bash "$EXPORTER" "$EXPORT_DIR" \
     >"$TMP_ROOT/retag-export.stdout" 2>"$TMP_ROOT/retag-export.stderr"; then
  fail 'retag-after-verification archive was accepted'
fi
grep -Fq 'archive image config drifted for fixture/app:1' \
  "$TMP_ROOT/retag-export.stderr" ||
  fail 'retagged archive failed for the wrong reason'
if find "$EXPORT_DIR" -maxdepth 1 -type f \
    \( -name '*.tar.gz' -o -name '*.tar.gz.sha256' \) -print -quit | grep -q .; then
  fail 'failed image export retained a bad archive or checksum'
fi

assert_bad_saved_archive() {
  local mode=$1 needle=$2 output
  output="$TMP_ROOT/export-$mode"
  mkdir -p "$output"
  if FAKE_DOCKER_STATE="$DOCKER_STATE" \
     FAKE_DOCKER_CONFIG_DIR="$CONFIG_DIR" \
     FAKE_DOCKER_SAVE_MODE="$mode" \
     FAKE_EXPORT_COMPAT=1 \
     PATH="$TMP_ROOT:$PATH" \
     PROVENANCE_CATALOG="$CATALOG" \
     IMAGE_PROVENANCE_FILE="$PROVENANCE" \
     SOURCE_ATTESTATION_FILE="$SOURCE_RECEIPT" \
     PROVENANCE_REPOSITORY="$REPO" \
     PROVENANCE_UPSTREAM_RECEIPT="$UPSTREAM_RECEIPT" \
     BUNDLE_PROFILE=full INCLUDE_CHAT=0 \
     JJDGUARD_IMAGE_STORE_LOCK_FILE="$TMP_ROOT/image-store.lock" \
     bash "$EXPORTER" "$output" >"$output/stdout" 2>"$output/stderr"; then
    fail "bad saved archive was accepted: $mode"
  fi
  grep -Fq "$needle" "$output/stderr" ||
    fail "bad saved archive failed for the wrong reason: $mode"
  if find "$output" -maxdepth 1 -type f \
      \( -name '*.tar.gz' -o -name '*.tar.gz.sha256' \) -print -quit | grep -q .; then
    fail "bad saved archive retained an artifact: $mode"
  fi
}

assert_bad_saved_archive missing 'archive is missing runtime tag: fixture/app:1'
assert_bad_saved_archive duplicate 'archive runtime tag is duplicated: fixture/app:1'
assert_bad_saved_archive extra 'archive contains an extra runtime tag: fixture/extra:1'
assert_bad_saved_archive bad-layer-sources 'archive LayerSources is malformed'

FAKE_BUILD_IDENTITY="$TMP_ROOT/build-identity-docker"
cat >"$FAKE_BUILD_IDENTITY" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
case "$1 $2" in
  'version --format')
    case "$3" in
      '{{.Client.Version}}') printf 'fixture-client\n' ;;
      '{{.Server.Version}}') printf '%s\n' "${BUILD_IDENTITY_SERVER:-fixture-server}" ;;
      *) exit 64 ;;
    esac
    ;;
  'buildx version') printf 'buildx fixture\n' ;;
  'buildx inspect')
    printf 'Name: fixture-builder\n\nNodes:\nName: fixture-node\nEndpoint: fixture://builder\nStatus: running\nBuildKit version: BuildKit fixture\n'
    ;;
  *) exit 65 ;;
esac
SH
chmod 0500 "$FAKE_BUILD_IDENTITY"
# shellcheck disable=SC1090
source "$ROOT_DIR/deploy/docker-compose/lib-build-identity.sh"
BUILD_IDENTITY="$(build_identity_json "$FAKE_BUILD_IDENTITY")" ||
  fail 'unable to capture fixture Buildx identity'
if BUILD_IDENTITY_SERVER=drifted-server \
  assert_build_identity_unchanged "$BUILD_IDENTITY" "$FAKE_BUILD_IDENTITY" >/dev/null 2>&1; then
  fail 'Buildx identity drift was accepted'
fi

grep -Fq 'prepare_release_git_context' "$BUILDER" || fail 'builder does not use the Git archive context helper'
grep -Fq 'org.opencontainers.image.revision' "$BUILDER" || fail 'builder does not label source revision'
grep -Fq 'com.jjdguard.source.tree' "$BUILDER" || fail 'builder does not label source tree'
grep -Fq 'prepare_locked_image_export' "$PACKAGE" || fail 'package does not prepare locked provenance export'
grep -Fq 'verify-image-provenance.py' "$EXPORTER" || fail 'exporter does not verify provenance under the lock'
grep -Fq 'verify-offline-image-archive.py' "$EXPORTER" || fail 'exporter does not verify saved archive bytes'
grep -Fq 'flock -x' "$EXPORTER" || fail 'exporter does not hold an image-store lock'
grep -Fq 'test_jjdguard_task4_image_provenance.sh' "$PACKAGE" ||
  fail 'package does not reverify the Task4 receipt chain'
grep -Fq -- '--expected-components "$task4_components"' "$PACKAGE" ||
  fail 'package does not pass the exact Task4 component selection'
! grep -Fq 'Portal and Tier1 must be selected together' "$PACKAGE" ||
  fail 'package still rejects independent Portal or Tier1 selection'
grep -Fq 'cp -a "$task4_receipt_dir" "$BUNDLE_DIR/task4"' "$PACKAGE" ||
  fail 'package does not retain the Task4 receipt chain'
task4_line="$(grep -n '^verify_task4_provenance$' "$PACKAGE" | tail -1 | cut -d: -f1)"
export_line="$(grep -n '^export_images$' "$PACKAGE" | tail -1 | cut -d: -f1)"
[[ -n "$task4_line" && -n "$export_line" && "$task4_line" -lt "$export_line" ]] ||
  fail 'package must prepare locked provenance export before docker save'

echo '[ok] release image provenance rejects source, image, and digest drift'
