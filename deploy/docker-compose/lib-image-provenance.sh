#!/bin/sh

image_provenance_fail() {
  echo "[error] image provenance failed: $1" >&2
  return 1
}

image_provenance_sha256() {
  sha256sum "$1" | awk '{print $1}'
}

read_release_source_identity() {
  _source_receipt="$1"
  python3 - "$_source_receipt" <<'PY'
import json
import pathlib
import re
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(data) != {"schema", "remote", "source_revision", "source_tree"}:
    raise SystemExit("source receipt fields do not match the schema")
if data["schema"] != "jjdguard-release-source/v1":
    raise SystemExit("source receipt schema is invalid")
if not isinstance(data["remote"], str) or not data["remote"]:
    raise SystemExit("source remote is invalid")
for key in ("source_revision", "source_tree"):
    if not isinstance(data[key], str) or not re.fullmatch(r"[0-9a-f]{40}", data[key]):
        raise SystemExit(f"{key} is invalid")
print(data["remote"])
print(data["source_revision"])
print(data["source_tree"])
PY
}

# Materialize only objects reachable from the source receipt revision. The caller
# receives <destination>/source as its build root and the archive SHA on stdout.
prepare_release_git_context() {
  _repo="$1"
  _source_receipt="$2"
  _destination="$3"

  [ -d "$_repo" ] && [ ! -L "$_repo" ] || {
    image_provenance_fail 'repository is not a real directory'
    return 1
  }
  [ -f "$_source_receipt" ] && [ ! -L "$_source_receipt" ] || {
    image_provenance_fail 'source receipt is not a regular file'
    return 1
  }
  [ ! -e "$_destination" ] && [ ! -L "$_destination" ] || {
    image_provenance_fail 'Git archive destination already exists'
    return 1
  }
  command -v git >/dev/null 2>&1 || {
    image_provenance_fail 'git is unavailable'
    return 1
  }
  command -v python3 >/dev/null 2>&1 || {
    image_provenance_fail 'python3 is unavailable'
    return 1
  }
  command -v sha256sum >/dev/null 2>&1 || {
    image_provenance_fail 'sha256sum is unavailable'
    return 1
  }

  _identity="$(python3 - "$_source_receipt" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
if set(data) != {"schema", "remote", "source_revision", "source_tree"}:
    raise SystemExit("source receipt fields do not match the schema")
if data["schema"] != "jjdguard-release-source/v1":
    raise SystemExit("source receipt schema is invalid")
if not isinstance(data["remote"], str) or not data["remote"]:
    raise SystemExit("source remote is invalid")
for key in ("source_revision", "source_tree"):
    if not isinstance(data[key], str) or not re.fullmatch(r"[0-9a-f]{40}", data[key]):
        raise SystemExit(f"{key} is invalid")
print(data["source_revision"])
print(data["source_tree"])
PY
  )" || {
    image_provenance_fail 'source receipt is invalid'
    return 1
  }
  _revision="$(printf '%s\n' "$_identity" | sed -n '1p')"
  _tree="$(printf '%s\n' "$_identity" | sed -n '2p')"
  _actual_revision="$(GIT_NO_LAZY_FETCH=1 git -C "$_repo" rev-parse --verify "$_revision^{commit}" 2>/dev/null)" || {
    image_provenance_fail 'source revision is unavailable in the repository'
    return 1
  }
  [ "$_actual_revision" = "$_revision" ] || {
    image_provenance_fail 'source revision resolves to a different commit'
    return 1
  }
  _actual_tree="$(GIT_NO_LAZY_FETCH=1 git -C "$_repo" rev-parse --verify "$_revision^{tree}" 2>/dev/null)" || {
    image_provenance_fail 'source tree is unavailable in the repository'
    return 1
  }
  [ "$_actual_tree" = "$_tree" ] || {
    image_provenance_fail 'source tree does not match the source revision'
    return 1
  }

  mkdir -m 0700 "$_destination" || return 1
  _archive="$_destination/.source.tar"
  if ! GIT_NO_LAZY_FETCH=1 git -C "$_repo" archive \
    --format=tar --prefix=source/ "$_revision" >"$_archive"; then
    rm -rf -- "$_destination"
    image_provenance_fail 'unable to create the source archive'
    return 1
  fi
  chmod 0600 "$_archive"
  _archive_sha="$(image_provenance_sha256 "$_archive")"
  if ! python3 - "$_archive" "$_destination" <<'PY'
import pathlib
import shutil
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2]).resolve()
with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("source archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit("source archive contains an unsafe path")
        if not path.parts or path.parts[0] != "source":
            raise SystemExit("source archive member is outside source/")
        if not (member.isdir() or member.isfile()):
            raise SystemExit("source archive contains links or special files")
    for member in members:
        target = destination.joinpath(*pathlib.PurePosixPath(member.name).parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(member.mode & 0o777)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit("unable to read source archive member")
        with source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(member.mode & 0o777)
PY
  then
    rm -rf -- "$_destination"
    image_provenance_fail 'source archive extraction failed'
    return 1
  fi
  rm -f -- "$_archive"
  [ -d "$_destination/source" ] || {
    rm -rf -- "$_destination"
    image_provenance_fail 'source archive root is missing'
    return 1
  }
  chmod 0700 "$_destination/source" || {
    rm -rf -- "$_destination"
    image_provenance_fail 'unable to secure source archive root'
    return 1
  }
  printf '%s\n' "$_archive_sha"
}

write_source_image_provenance_record() {
  _output="$1"
  _runtime_tag="$2"
  _profile="$3"
  _kind="$4"
  _component="$5"
  _dockerfile="$6"
  _context="$7"
  _platform="$8"
  _image_id="$9"
  shift 9
  _source_receipt="$1"
  _archive_sha="$2"
  _dockerfile_blob="$3"
  _base_images_json="$4"
  _build_args_json="$5"
  if [ "$#" -ge 6 ]; then
    _extra_json="$6"
  else
    _extra_json='{}'
  fi
  python3 - "$_output" "$_runtime_tag" "$_profile" "$_kind" "$_component" \
    "$_dockerfile" "$_context" "$_platform" "$_image_id" "$_source_receipt" \
    "$_archive_sha" "$_dockerfile_blob" "$_base_images_json" \
    "$_build_args_json" "$_extra_json" <<'PY'
import json
import os
import pathlib
import re
import sys

(output, runtime_tag, profile, kind, component, dockerfile, context, platform,
 image_id, source_receipt, archive_sha, dockerfile_blob, base_images_json,
 build_args_json, extra_json) = sys.argv[1:]
if kind not in {"first-party", "upstream-source", "home-runtime"}:
    raise SystemExit("source image record has an invalid kind")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    raise SystemExit("source image ID is invalid")
if not re.fullmatch(r"[0-9a-f]{64}", archive_sha):
    raise SystemExit("source archive digest is invalid")
if not re.fullmatch(r"[0-9a-f]{40}", dockerfile_blob):
    raise SystemExit("Dockerfile blob is invalid")
identity = json.loads(pathlib.Path(source_receipt).read_text(encoding="utf-8"))
source = {
    "remote": identity["remote"],
    "revision": identity["source_revision"],
    "tree": identity["source_tree"],
    "archive_sha256": archive_sha,
}
base_images = json.loads(base_images_json)
build_args = json.loads(build_args_json)
extra = json.loads(extra_json)
if not isinstance(base_images, list):
    raise SystemExit("base_images must be a JSON array")
if not isinstance(build_args, dict) or not isinstance(extra, dict):
    raise SystemExit("record extensions must be JSON objects")
previous_index = -1
for base in base_images:
    if not isinstance(base, dict) or set(base) != {"from_index", "stage", "reference", "digest"}:
        raise SystemExit("base image summary has invalid fields")
    if not isinstance(base["from_index"], int) or base["from_index"] <= previous_index:
        raise SystemExit("base image summary order is invalid")
    previous_index = base["from_index"]
    if base["stage"] is not None and not isinstance(base["stage"], str):
        raise SystemExit("base image stage is invalid")
    if (not isinstance(base["reference"], str)
            or not isinstance(base["digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", base["digest"])
            or not base["reference"].endswith("@" + base["digest"])):
        raise SystemExit("base image reference or digest is invalid")
reserved = {
    "runtime_tag", "profile", "kind", "component", "expected_digest",
    "actual_digest", "dockerfile", "context", "platform", "image_id",
    "oci_config_digest", "source", "source_blobs", "build_args", "sbom",
    "toolchain", "base_images",
}
if reserved.intersection(extra):
    raise SystemExit("record extension overrides a reserved field")
engine = extra.get("build_engine")
if not isinstance(engine, dict) or engine.get("kind") not in {"buildx", "docker-daemon"}:
    raise SystemExit("source image record build engine is invalid")
record = {
    "runtime_tag": runtime_tag,
    "profile": profile,
    "kind": kind,
    "component": component,
    "expected_digest": None,
    "actual_digest": None,
    "dockerfile": dockerfile,
    "context": context,
    "platform": platform,
    "image_id": image_id,
    "oci_config_digest": image_id,
    "source": source,
    "source_blobs": {dockerfile: dockerfile_blob},
    "base_images": base_images,
    "build_args": build_args,
    "sbom": {"path": None, "sha256": None},
}
record.update(extra)
target = pathlib.Path(output)
target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
with target.open("x", encoding="utf-8", newline="\n") as handle:
    json.dump(record, handle, ensure_ascii=True, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(target, 0o600)
PY
}

image_provenance_repo_digest() {
  _runtime_tag="$1"
  _repo_digests_json="$2"
  python3 - "$_runtime_tag" "$_repo_digests_json" "${3:-}" <<'PY'
import json
import re
import sys

runtime_tag, encoded, expected = sys.argv[1:]
colon = runtime_tag.rfind(":")
slash = runtime_tag.rfind("/")
repository = runtime_tag[:colon] if colon > slash else runtime_tag
try:
    repo_digests = json.loads(encoded)
except json.JSONDecodeError as error:
    raise SystemExit(f"invalid RepoDigests JSON: {error}")
if not isinstance(repo_digests, list) or not all(isinstance(item, str) for item in repo_digests):
    raise SystemExit("RepoDigests is not a string list")
prefix = f"{repository}@"
matches = {
    item[len(prefix):]
    for item in repo_digests
    if item.startswith(prefix) and re.fullmatch(r"sha256:[0-9a-f]{64}", item[len(prefix):])
}
if expected:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected) or expected not in matches:
        raise SystemExit("RepoDigests does not contain the locked repository digest")
    print(expected)
else:
    if len(matches) != 1:
        raise SystemExit("RepoDigests does not contain one matching repository digest")
    print(matches.pop())
PY
}

write_third_party_image_provenance_record() {
  _output="$1"
  _runtime_tag="$2"
  _profile="$3"
  _component="$4"
  _expected_digest="$5"
  _actual_digest="$6"
  _platform="$7"
  _image_id="$8"
  python3 - "$_output" "$_runtime_tag" "$_profile" "$_component" \
    "$_expected_digest" "$_actual_digest" "$_platform" "$_image_id" <<'PY'
import json
import os
import pathlib
import re
import sys

output, runtime_tag, profile, component, expected_digest, actual_digest, platform, image_id = sys.argv[1:]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
    raise SystemExit("third-party digest is invalid")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", actual_digest):
    raise SystemExit("third-party observed digest is invalid")
if actual_digest != expected_digest:
    raise SystemExit("third-party observed digest does not match expected")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    raise SystemExit("third-party image ID is invalid")
record = {
    "runtime_tag": runtime_tag,
    "profile": profile,
    "kind": "third-party",
    "component": component,
    "expected_digest": expected_digest,
    "actual_digest": actual_digest,
    "dockerfile": None,
    "context": None,
    "platform": platform,
    "image_id": image_id,
    "oci_config_digest": image_id,
    "build_args": {},
    "sbom": {"path": None, "sha256": None},
}
target = pathlib.Path(output)
target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
with target.open("x", encoding="utf-8", newline="\n") as handle:
    json.dump(record, handle, ensure_ascii=True, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(target, 0o600)
PY
}

finalize_image_provenance() {
  _output="$1"
  _records_dir="$2"
  _source_receipt="$3"
  _archive_sha="$4"
  _platform="$5"
  _toolchain_json="$6"
  _profile="$7"
  _include_chat="$8"
  python3 - "$_output" "$_records_dir" "$_source_receipt" "$_archive_sha" \
    "$_platform" "$_toolchain_json" "$_profile" "$_include_chat" <<'PY'
import datetime
import json
import os
import pathlib
import re
import sys
import tempfile

(output, records_dir, source_receipt, archive_sha, platform, toolchain_json,
 profile, include_chat) = sys.argv[1:]
if not re.fullmatch(r"[0-9a-f]{64}", archive_sha):
    raise SystemExit("source archive digest is invalid")
identity = json.loads(pathlib.Path(source_receipt).read_text(encoding="utf-8"))
records = []
for path in sorted(pathlib.Path(records_dir).glob("*.json")):
    records.append(json.loads(path.read_text(encoding="utf-8")))
if not records:
    raise SystemExit("no image provenance records were generated")
try:
    toolchain = json.loads(toolchain_json)
except json.JSONDecodeError as error:
    raise SystemExit(f"build toolchain JSON is invalid: {error}")
toolchain_keys = {
    "docker_client_version", "docker_server_version", "buildx_version",
    "buildx_builder", "buildx_nodes",
}
node_keys = {"name", "endpoint", "status", "buildkit_version"}
if not isinstance(toolchain, dict) or set(toolchain) != toolchain_keys:
    raise SystemExit("build toolchain schema is invalid")
if not all(isinstance(toolchain[key], str) and toolchain[key]
           for key in toolchain_keys - {"buildx_nodes"}):
    raise SystemExit("build toolchain identity is incomplete")
if (not isinstance(toolchain["buildx_nodes"], list) or not toolchain["buildx_nodes"]
        or any(not isinstance(node, dict) or set(node) != node_keys
               for node in toolchain["buildx_nodes"])):
    raise SystemExit("build toolchain nodes are invalid")
for record in records:
    kind = record.get("kind")
    if kind in {"first-party", "upstream-source", "home-runtime"}:
        if "toolchain" in record:
            raise SystemExit("source image record already carries a toolchain")
        record["toolchain"] = dict(toolchain)
    elif kind == "third-party":
        if "toolchain" in record:
            raise SystemExit("third-party image record carries a source build toolchain")
    else:
        raise SystemExit("image record has an invalid kind")
payload = {
    "schema": "jjdguard-image-provenance/v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "platform": platform,
    "selection": {"profile": profile, "include_chat": include_chat == "1"},
    "source": {
        "remote": identity["remote"],
        "revision": identity["source_revision"],
        "tree": identity["source_tree"],
        "archive_sha256": archive_sha,
    },
    "toolchain": toolchain,
    "images": records,
}
target = pathlib.Path(output)
target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
if target.is_symlink():
    raise SystemExit("provenance output is a symbolic link")
temporary = None
try:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", prefix=f".{target.name}.",
        dir=target.parent, delete=False,
    ) as handle:
        temporary = pathlib.Path(handle.name)
        json.dump(payload, handle, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o444)
    os.replace(temporary, target)
    temporary = None
finally:
    if temporary is not None:
        temporary.unlink(missing_ok=True)
PY
}
