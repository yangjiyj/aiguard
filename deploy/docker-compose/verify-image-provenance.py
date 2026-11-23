#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import runpy
import shlex
import subprocess
import sys
from typing import Any

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX256_RE = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_RE = re.compile(r"(?:api.?key|password|secret|token|cookie)", re.IGNORECASE)
ALLOWED_BUILD_ARGS = {
    "VITE_BILLING_ENABLED",
    "NEXT_PUBLIC_BILLING_ENABLED",
    "LLAMA_CPP_REVISION",
    "LLAMA_CPP_COMMIT_COUNT",
    "LOCAL_RUNTIME_IMAGE",
    "SECURITY_ENGINE_BUILD",
}
HOME_RUNTIME_COMPONENTS = frozenset({"llm-judge", "portal-proxy"})
PORTAL_PROXY_RUNTIME_IMAGE = "chat-portal/portal-proxy:0.1.0"
PORTAL_PROXY_PNPM_LOCK = "portal-proxy/pnpm-lock.yaml"
PRISMA_ENGINE_LOCK = "deploy/docker-compose/release-prisma-engines.lock.json"
PRISMA_ENGINE_ARM64_LOCK = "deploy/docker-compose/release-prisma-engines.arm64.lock.json"
SECURITY_ENGINE_PYTHON_DEPS_LOCK = "apps/security-engine/requirements.offline.lock"
SECURITY_ENGINE_BUILD_CONTRACT = "deploy/docker-compose/security-engine-build-identity.contract"
SECURITY_ENGINE_PYTHON_DEPS_SCHEMA = "jjdguard-security-engine-python-deps/v1"
SECURITY_ENGINE_PYTHON_DEPS_ORIGIN = "home-existing-security-engine-image"
SECURITY_ENGINE_PYTHON_DEPS_ARM64_ORIGIN = "home-arm64-python-dependency-image"
SECURITY_ENGINE_PYTHON_DEPS_ARM64_IMAGE = "jjdguard-security-engine-python-deps:arm64"
SECURITY_ENGINE_PYTHON_DEPS_IMAGE = "docker-compose-security-engine:latest"
REQUIREMENT_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\ ]+)")
TASK4_LEGACY_RECEIPTS = {
    "enterprise-ai-portal": "task4/portal-image-receipt.json",
    "tier1-classifier": "task4/tier1-image-receipt.json",
}
TOOLCHAIN_KEYS = {
    "docker_client_version", "docker_server_version", "buildx_version",
    "buildx_builder", "buildx_nodes",
}
BUILD_NODE_KEYS = {"name", "endpoint", "status", "buildkit_version"}
COMMON_IMAGE_KEYS = {
    "runtime_tag", "profile", "kind", "component", "expected_digest",
    "actual_digest", "dockerfile", "context", "platform", "image_id",
    "oci_config_digest", "build_args", "sbom",
}


def fail(message: str) -> None:
    raise SystemExit(f"[error] image provenance verification failed: {message}")


def load_json(path: pathlib.Path) -> Any:
    if not path.is_file() or path.is_symlink():
        fail(f"JSON input is not a regular file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON input {path}: {error}")


def parse_catalog(path: pathlib.Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen_tags: set[str] = set()
    seen_components: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 7:
            fail(f"catalog line {number} does not contain seven fields")
        runtime_tag, profile, kind, component, digest, dockerfile, context = fields
        if "@sha256:" in runtime_tag:
            fail(f"catalog line {number} uses a digest as a runtime tag")
        if profile not in {"common", "full", "chat"}:
            fail(f"catalog line {number} has an unknown profile")
        if kind not in {"first-party", "upstream-source", "home-runtime", "third-party"}:
            fail(f"catalog line {number} has an unknown source kind")
        if kind == "third-party":
            if not SHA256_RE.fullmatch(digest) or dockerfile != "-" or context != "-":
                fail(f"catalog line {number} has an invalid third-party source contract")
        elif digest != "-" or dockerfile == "-" or context == "-":
            fail(f"catalog line {number} has an invalid source-built contract")
        if runtime_tag in seen_tags or component in seen_components:
            fail(f"catalog line {number} duplicates a tag or component")
        seen_tags.add(runtime_tag)
        seen_components.add(component)
        rows.append({
            "runtime_tag": runtime_tag,
            "profile": profile,
            "kind": kind,
            "component": component,
            "expected_digest": digest,
            "dockerfile": dockerfile,
            "context": context,
        })
    if not rows:
        fail("catalog is empty")
    return rows


def selected_catalog(rows: list[dict[str, str]], profile: str, include_chat: bool) -> list[dict[str, str]]:
    return [row for row in rows if row["profile"] == "common"
            or (profile == "full" and row["profile"] == "full")
            or (include_chat and row["profile"] == "chat")]


def git_output(repository: pathlib.Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment["GIT_NO_LAZY_FETCH"] = "1"
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if result.returncode != 0:
        fail(f"Git object verification failed: {' '.join(arguments)}")
    return result.stdout.strip()


def source_archive_sha(repository: pathlib.Path, revision: str) -> str:
    environment = os.environ.copy()
    environment["GIT_NO_LAZY_FETCH"] = "1"
    process = subprocess.Popen(
        ["git", "-C", str(repository), "archive", "--format=tar", "--prefix=source/", revision],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    for block in iter(lambda: process.stdout.read(1024 * 1024), b""):
        digest.update(block)
    _, stderr = process.communicate()
    if process.returncode != 0:
        fail(f"unable to reproduce source archive: {stderr.decode('utf-8', errors='replace').strip()}")
    return digest.hexdigest()


def git_dockerfile_base_images(
        repository: pathlib.Path, revision: str, dockerfile: str, component: str) -> list[dict[str, object]]:
    parser_path = pathlib.Path(__file__).with_name("dockerfile-base-images.py")
    try:
        namespace = runpy.run_path(str(parser_path))
        parse_dockerfile = namespace["parse_dockerfile"]
        dockerfile_text = git_output(repository, "show", f"{revision}:{dockerfile}")
        result = parse_dockerfile(dockerfile_text, f"{revision}:{dockerfile}")
    except (OSError, KeyError, ValueError) as error:
        fail(f"Dockerfile base image contract is invalid for {component}: {error}")
    if not isinstance(result, list):
        fail(f"Dockerfile base image contract is invalid for {component}")
    return result


def git_blob_bytes(repository: pathlib.Path, revision: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "blob", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(f"Git blob verification failed for {path}")
    return result.stdout


def security_engine_build_identity_required(repository: pathlib.Path, revision: str) -> bool:
    path = git_output(repository, "ls-tree", "--name-only", revision, "--", SECURITY_ENGINE_BUILD_CONTRACT)
    if not path:
        return False
    if path != SECURITY_ENGINE_BUILD_CONTRACT or git_blob_bytes(repository, revision, path) != b"source-revision-v1\n":
        fail("security-engine build identity contract is invalid")
    return True


def validate_security_engine_build_identity(build_args: Any, revision: str, image_env: Any = None) -> None:
    if not SHA1_RE.fullmatch(revision) or build_args != {"SECURITY_ENGINE_BUILD": revision}:
        fail("security-engine build identity differs from the source revision")
    if image_env is not None and (
        not isinstance(image_env, list)
        or [item for item in image_env if isinstance(item, str) and item.startswith("SECURITY_ENGINE_BUILD=")]
        != ["SECURITY_ENGINE_BUILD=" + revision]
    ):
        fail("security-engine image build identity differs from the source revision")


def validate_security_engine_python_deps(
        value: Any, repository: pathlib.Path, revision: str) -> None:
    required = {
        "schema", "origin", "source_image", "source_image_id", "requirements_lock_sha256",
        "content_sha256", "file_count", "packages",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail("security-engine Python dependency provenance is invalid")
    lock_bytes = git_blob_bytes(repository, revision, SECURITY_ENGINE_PYTHON_DEPS_LOCK)
    try:
        lines = lock_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        fail("security-engine Python dependency lock is invalid")
    packages: dict[str, str] = {}
    for line in lines:
        match = REQUIREMENT_PIN.match(line)
        if match is None:
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        version = match.group(2)
        if name in packages and packages[name] != version:
            fail("security-engine Python dependency lock has conflicting packages")
        packages[name] = version
    expected_packages = [{"name": name, "version": packages[name]} for name in sorted(packages)]
    if (
        not expected_packages
        or value.get("schema") != SECURITY_ENGINE_PYTHON_DEPS_SCHEMA
        or not isinstance(value.get("source_image_id"), str)
        or not SHA256_RE.fullmatch(value["source_image_id"])
        or not (
            (
                value.get("origin") == SECURITY_ENGINE_PYTHON_DEPS_ORIGIN
                and value.get("source_image") in {
                    SECURITY_ENGINE_PYTHON_DEPS_IMAGE, value["source_image_id"]
                }
            )
            or (
                value.get("origin") == SECURITY_ENGINE_PYTHON_DEPS_ARM64_ORIGIN
                and value.get("source_image") == SECURITY_ENGINE_PYTHON_DEPS_ARM64_IMAGE
            )
        )
        or value.get("requirements_lock_sha256") != hashlib.sha256(lock_bytes).hexdigest()
        or not isinstance(value.get("content_sha256"), str)
        or not HEX256_RE.fullmatch(value["content_sha256"])
        or type(value.get("file_count")) is not int
        or value["file_count"] < 1
        or value.get("packages") != expected_packages
    ):
        fail("security-engine Python dependency provenance drifted from the reviewed lock")


def home_runtime_base_images(
        value: dict[str, Any], runtime_bases: list[tuple[int, str | None]]) -> list[dict[str, object]]:
    image_id = value.get("source_image_id")
    if not isinstance(image_id, str) or not SHA256_RE.fullmatch(image_id):
        fail("home runtime image ID is invalid")
    return [{
        "from_index": from_index,
        "stage": stage,
        "reference": f"home-runtime@{image_id}",
        "digest": image_id,
    } for from_index, stage in runtime_bases]


def validate_home_runtime_dockerfile(
        repository: pathlib.Path, revision: str, dockerfile: str, component: str) -> list[tuple[int, str | None]]:
    text = git_output(repository, "show", f"{revision}:{dockerfile}")
    if re.search(r"^ARG[ \t]+LOCAL_RUNTIME_IMAGE[ \t]*$", text, flags=re.MULTILINE) is None:
        fail(f"home runtime Dockerfile does not declare LOCAL_RUNTIME_IMAGE for {component}")
    stages: set[str] = set()
    runtime_bases: list[tuple[int, str | None]] = []
    from_bodies = re.findall(r"^FROM[ \t]+(.+?)\s*$", text, flags=re.MULTILINE | re.IGNORECASE)
    if not from_bodies:
        fail(f"home runtime Dockerfile base contract drifted for {component}")
    for from_index, body in enumerate(from_bodies):
        try:
            fields = shlex.split(body, posix=True)
        except ValueError:
            fail(f"home runtime Dockerfile base contract drifted for {component}")
        while fields and fields[0].startswith("--"):
            fields.pop(0)
        if len(fields) not in {1, 3} or (len(fields) == 3 and fields[1].upper() != "AS"):
            fail(f"home runtime Dockerfile base contract drifted for {component}")
        reference = fields[0]
        stage = fields[2] if len(fields) == 3 else None
        if reference == "${LOCAL_RUNTIME_IMAGE}":
            runtime_bases.append((from_index, stage))
        elif reference.lower() not in stages:
            fail(f"home runtime Dockerfile base contract drifted for {component}")
        if stage is not None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", stage):
            stages.add(stage.lower())
        elif stage is not None:
            fail(f"home runtime Dockerfile base contract drifted for {component}")
    if not runtime_bases:
        fail(f"home runtime Dockerfile base contract drifted for {component}")
    return runtime_bases


def validate_portal_proxy_prisma_engines(
        value: Any, repository: pathlib.Path, revision: str,
        runtime_image: str, runtime_image_id: str, target_platform: str) -> None:
    required = {
        "schema", "origin", "expected_source_image", "expected_source_image_id",
        "approved_lock_sha256", "runtime_image", "runtime_image_id", "content_sha256",
        "manifest",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail("Portal Proxy Prisma engine receipt is invalid")
    if target_platform == "linux/amd64":
        lock_path = PRISMA_ENGINE_LOCK
    elif target_platform == "linux/arm64":
        lock_path = PRISMA_ENGINE_ARM64_LOCK
    else:
        fail("Portal Proxy Prisma engine target platform is invalid")
    try:
        lock = json.loads(git_blob_bytes(repository, revision, lock_path))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Portal Proxy Prisma engine lock is invalid")
    lock_bytes = git_blob_bytes(repository, revision, lock_path)
    manifest = lock.get("manifest") if isinstance(lock, dict) else None
    if (
        value.get("schema") != "jjdguard-release-prisma-runtime/v1"
        or value.get("origin") != lock.get("origin")
        or value.get("expected_source_image") != lock.get("source_image")
        or value.get("expected_source_image_id") != lock.get("source_image_id")
        or value.get("approved_lock_sha256") != hashlib.sha256(lock_bytes).hexdigest()
        or value.get("runtime_image") != runtime_image
        or value.get("runtime_image_id") != runtime_image_id
        or value.get("manifest") != manifest
    ):
        fail("Portal Proxy Prisma engine receipt drifted from the release lock")
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if value.get("content_sha256") != hashlib.sha256(content).hexdigest():
        fail("Portal Proxy Prisma engine content digest is invalid")


def validate_home_runtime(
        value: Any, component: str, repository: pathlib.Path, revision: str,
        dockerfile: str, build_args: dict[str, Any], target_platform: str) -> list[dict[str, object]]:
    if component not in HOME_RUNTIME_COMPONENTS or not isinstance(value, dict):
        fail(f"home runtime provenance is invalid for {component}")
    if component == "llm-judge":
        required = {"source_image", "source_image_id", "entrypoint_sha256"}
        if set(value) != required:
            fail("Judge home runtime provenance fields are invalid")
        if (not isinstance(value["source_image"], str) or not value["source_image"]
                or not isinstance(value["source_image_id"], str)
                or not SHA256_RE.fullmatch(value["source_image_id"])
                or not isinstance(value["entrypoint_sha256"], str)
                or not HEX256_RE.fullmatch(value["entrypoint_sha256"])):
            fail("Judge home runtime provenance is invalid")
        expected_alias = (
            f"jjdguard-release-input/llm-judge:{revision[:12]}-"
            f"{value['source_image_id'].removeprefix('sha256:')[:12]}"
        )
        if build_args != {"LOCAL_RUNTIME_IMAGE": expected_alias}:
            fail("Judge home runtime build arguments are invalid")
    else:
        required = {
            "source_image", "source_image_id", "source_revision", "source_tree",
            "pnpm_version", "pnpm_lock", "prisma_engines",
        }
        if set(value) != required or value.get("source_image") != PORTAL_PROXY_RUNTIME_IMAGE:
            fail("Portal Proxy home runtime provenance fields are invalid")
        if (not isinstance(value.get("source_revision"), str)
                or not SHA1_RE.fullmatch(value["source_revision"])
                or not isinstance(value.get("source_tree"), str)
                or not SHA1_RE.fullmatch(value["source_tree"])
                or git_output(repository, "rev-parse", f"{value['source_revision']}^{{tree}}")
                != value["source_tree"]
                or value.get("pnpm_version") != "10.10.0"
                or not isinstance(value.get("source_image_id"), str)
                or not SHA256_RE.fullmatch(value["source_image_id"])):
            fail("Portal Proxy home runtime source binding is invalid")
        expected_alias = (
            f"jjdguard-release-input/portal-proxy:{revision[:12]}-"
            f"{value['source_image_id'].removeprefix('sha256:')[:12]}"
        )
        if build_args != {"LOCAL_RUNTIME_IMAGE": expected_alias}:
            fail("Portal Proxy home runtime build arguments are invalid")
        pnpm_lock = value.get("pnpm_lock")
        if not isinstance(pnpm_lock, dict) or set(pnpm_lock) != {"path", "sha256", "blob"}:
            fail("Portal Proxy pnpm lock provenance is invalid")
        lock_bytes = git_blob_bytes(repository, revision, PORTAL_PROXY_PNPM_LOCK)
        if (
            pnpm_lock.get("path") != PORTAL_PROXY_PNPM_LOCK
            or pnpm_lock.get("blob") != git_output(
                repository, "rev-parse", f"{revision}:{PORTAL_PROXY_PNPM_LOCK}")
            or pnpm_lock.get("sha256") != hashlib.sha256(lock_bytes).hexdigest()
        ):
            fail("Portal Proxy pnpm lock provenance drifted from the release source")
        validate_portal_proxy_prisma_engines(
            value.get("prisma_engines"), repository, revision,
            value["source_image"], value["source_image_id"], target_platform)
    runtime_bases = validate_home_runtime_dockerfile(repository, revision, dockerfile, component)
    return home_runtime_base_images(value, runtime_bases)


def inspect_image(command: list[str], runtime_tag: str, target_platform: str) -> dict[str, Any]:
    result = subprocess.run(
        [*command, "image", "inspect", "--platform", target_platform, runtime_tag],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(f"unable to inspect runtime tag: {runtime_tag}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(f"Docker returned invalid JSON for {runtime_tag}")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        fail(f"Docker inspect result is not singular for {runtime_tag}")
    return payload[0]


def repository_name(runtime_tag: str) -> str:
    colon = runtime_tag.rfind(":")
    slash = runtime_tag.rfind("/")
    return runtime_tag[:colon] if colon > slash else runtime_tag


def validate_source_receipt(data: Any) -> dict[str, str]:
    if not isinstance(data, dict) or set(data) != {"schema", "remote", "source_revision", "source_tree"}:
        fail("source receipt fields do not match the schema")
    if data.get("schema") != "jjdguard-release-source/v1":
        fail("source receipt schema is invalid")
    remote = data.get("remote")
    revision = data.get("source_revision")
    tree = data.get("source_tree")
    if not isinstance(remote, str) or not remote or not isinstance(revision, str) or not SHA1_RE.fullmatch(revision):
        fail("source receipt remote or revision is invalid")
    if not isinstance(tree, str) or not SHA1_RE.fullmatch(tree):
        fail("source receipt tree is invalid")
    return {"remote": remote, "revision": revision, "tree": tree}


def validate_sbom(value: Any, component: str) -> None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        fail(f"SBOM placeholder is invalid for {component}")
    path, digest = value["path"], value["sha256"]
    if path is None and digest is None:
        return
    if not isinstance(path, str) or not path or path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
        fail(f"SBOM path is invalid for {component}")
    if not isinstance(digest, str) or not HEX256_RE.fullmatch(digest):
        fail(f"SBOM digest is invalid for {component}")


def validate_toolchain(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TOOLCHAIN_KEYS:
        fail("build toolchain fields do not exactly match the schema")
    for key in TOOLCHAIN_KEYS - {"buildx_nodes"}:
        if not isinstance(value[key], str) or not value[key] or any(
                character in value[key] for character in "\r\n\x00"):
            fail("build toolchain identity is incomplete")
    nodes = value["buildx_nodes"]
    if not isinstance(nodes, list) or not nodes:
        fail("build toolchain nodes are incomplete")
    names: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict) or set(node) != BUILD_NODE_KEYS:
            fail("build toolchain node fields do not exactly match the schema")
        for field in BUILD_NODE_KEYS:
            candidate = node[field]
            if (not isinstance(candidate, str) or not candidate
                    or any(character in candidate for character in "\r\n\x00")):
                fail("build toolchain node identity is incomplete")
        if node["name"] in names:
            fail("build toolchain contains a duplicate node")
        names.add(node["name"])
    return value


def validate_build_engine(value: Any, toolchain: dict[str, Any], component: str) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        fail(f"build engine is invalid for {component}")
    if value["kind"] == "buildx":
        if set(value) != {"kind", "builder", "nodes"}:
            fail(f"build engine fields do not exactly match the Buildx schema for {component}")
        if (value["builder"] != toolchain["buildx_builder"]
                or value["nodes"] != toolchain["buildx_nodes"]):
            fail(f"build engine drifted from the build toolchain for {component}")
        return
    if value["kind"] == "docker-daemon":
        if set(value) != {"kind", "docker_client_version", "docker_server_version"}:
            fail(f"build engine fields do not exactly match the Docker daemon schema for {component}")
        if (value["docker_client_version"] != toolchain["docker_client_version"]
                or value["docker_server_version"] != toolchain["docker_server_version"]):
            fail(f"build engine drifted from the Docker daemon identity for {component}")
        return
    fail(f"build engine kind is invalid for {component}")


def validate_legacy_receipt(
        value: Any, evidence_root: pathlib.Path, component: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        fail(f"legacy receipt metadata is invalid for {component}")
    relative_path = value.get("path")
    expected_digest = value.get("sha256")
    if (not isinstance(relative_path, str) or not relative_path
            or pathlib.PurePosixPath(relative_path).is_absolute()
            or ".." in pathlib.PurePosixPath(relative_path).parts):
        fail(f"legacy receipt path is invalid for {component}")
    if not isinstance(expected_digest, str) or not HEX256_RE.fullmatch(expected_digest):
        fail(f"legacy receipt digest is invalid for {component}")
    target = evidence_root.joinpath(*pathlib.PurePosixPath(relative_path).parts)
    cursor = evidence_root
    for part in pathlib.PurePosixPath(relative_path).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail(f"legacy receipt path contains a symbolic link for {component}")
    try:
        target.resolve(strict=True).relative_to(evidence_root.resolve(strict=True))
    except (FileNotFoundError, ValueError):
        fail(f"legacy receipt path escapes or is missing for {component}")
    if not target.is_file():
        fail(f"legacy receipt is not a regular file for {component}")
    payload = target.read_bytes()
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        fail(f"legacy receipt digest drifted for {component}")
    try:
        receipt = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"legacy receipt JSON is invalid for {component}")
    if not isinstance(receipt, dict):
        fail(f"legacy receipt JSON is invalid for {component}")
    return receipt


def default_upstream_receipt(repository: pathlib.Path, revision: str) -> pathlib.Path:
    lock = git_output(repository, "show", f"{revision}:deploy/docker-compose/release-toolchain.lock")
    matches = re.findall(r"^llama_cpp_revision=([0-9a-f]{40})$", lock, flags=re.MULTILINE)
    if len(matches) != 1:
        fail("release toolchain lock does not identify one llama.cpp revision")
    return pathlib.Path(f"/home/dev/tool-cache/llama.cpp-{matches[0]}/receipt.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True, type=pathlib.Path)
    parser.add_argument("--receipt", required=True, type=pathlib.Path)
    parser.add_argument("--source-receipt", type=pathlib.Path)
    parser.add_argument("--repository", type=pathlib.Path)
    parser.add_argument("--profile", choices=("lite", "full"))
    parser.add_argument("--include-chat", choices=("0", "1"))
    parser.add_argument("--docker-command", default="docker")
    parser.add_argument("--upstream-receipt", type=pathlib.Path)
    args = parser.parse_args()

    receipt = load_json(args.receipt)
    expected_receipt_keys = {
        "schema", "generated_at", "platform", "selection", "source", "toolchain", "images",
    }
    if (not isinstance(receipt, dict) or set(receipt) != expected_receipt_keys
            or receipt.get("schema") != "jjdguard-image-provenance/v1"):
        fail("image provenance schema is invalid")
    if not isinstance(receipt.get("generated_at"), str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        receipt["generated_at"],
    ):
        fail("image provenance generation time is invalid")
    selection = receipt.get("selection")
    if not isinstance(selection, dict) or set(selection) != {"profile", "include_chat"}:
        fail("image selection is invalid")
    if selection.get("profile") not in ("lite", "full") or not isinstance(selection.get("include_chat"), bool):
        fail("image selection values are invalid")
    profile = args.profile or selection["profile"]
    include_chat = (args.include_chat == "1") if args.include_chat is not None else selection["include_chat"]
    if profile != selection["profile"] or include_chat != selection["include_chat"]:
        fail("requested image selection differs from the provenance receipt")
    source_receipt_path = args.source_receipt or args.receipt.parent / "release-source.json"
    repository = args.repository or args.catalog.resolve().parents[2]
    evidence_root = args.receipt.parent
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        fail("image provenance evidence root is not a real directory")

    source_identity = validate_source_receipt(load_json(source_receipt_path))
    revision = source_identity["revision"]
    tree = source_identity["tree"]
    if git_output(repository, "rev-parse", f"{revision}^{{commit}}") != revision:
        fail("source revision does not resolve to the receipt commit")
    if git_output(repository, "rev-parse", f"{revision}^{{tree}}") != tree:
        fail("source tree does not match the receipt revision")
    archive_sha = source_archive_sha(repository, revision)
    if receipt.get("platform") not in ("linux/amd64", "linux/arm64"):
        fail("release platform is invalid")
    top_source = receipt.get("source")
    expected_source = {**source_identity, "archive_sha256": archive_sha}
    if top_source != expected_source:
        fail("top-level source identity or archive digest does not match")
    toolchain = validate_toolchain(receipt.get("toolchain"))

    catalog = selected_catalog(parse_catalog(args.catalog), profile, include_chat)
    images = receipt.get("images")
    if not isinstance(images, list) or not all(isinstance(item, dict) for item in images):
        fail("image provenance entries are invalid")
    by_component: dict[str, dict[str, Any]] = {}
    for image in images:
        component = image.get("component")
        if not isinstance(component, str) or component in by_component:
            fail("image provenance contains a missing or duplicate component")
        by_component[component] = image
    expected_components = {row["component"] for row in catalog}
    if set(by_component) != expected_components:
        fail("image provenance component set does not match the selected catalog")

    docker_command = shlex.split(args.docker_command)
    if not docker_command:
        fail("Docker command is empty")
    expected_upstream: Any = None
    for row in catalog:
        component = row["component"]
        entry = by_component[component]
        if row["kind"] == "third-party":
            allowed_entry_keys = COMMON_IMAGE_KEYS
        elif row["kind"] == "first-party":
            allowed_entry_keys = COMMON_IMAGE_KEYS | {
                "source", "source_blobs", "base_images", "toolchain", "build_engine",
            }
            if component in TASK4_LEGACY_RECEIPTS:
                allowed_entry_keys = allowed_entry_keys | {"legacy_receipt"}
            if component == "security-engine":
                allowed_entry_keys = allowed_entry_keys | {"security_engine_python_deps"}
        elif row["kind"] == "home-runtime":
            allowed_entry_keys = COMMON_IMAGE_KEYS | {
                "source", "source_blobs", "base_images", "toolchain", "build_engine",
                "home_runtime",
            }
        else:
            allowed_entry_keys = COMMON_IMAGE_KEYS | {
                "source", "source_blobs", "base_images", "toolchain", "build_engine",
                "upstream", "wrapper_blobs",
            }
            if component in HOME_RUNTIME_COMPONENTS:
                allowed_entry_keys = allowed_entry_keys | {"home_runtime"}
            if component == "llm-judge":
                allowed_entry_keys = allowed_entry_keys | {"build_mode"}
        if set(entry) != allowed_entry_keys:
            fail(f"image provenance fields do not exactly match the {row['kind']} schema for {component}")
        if component == "llm-judge" and entry.get("build_mode") != "home-runtime-reuse":
            fail("Judge home runtime build mode is invalid")
        for key in ("runtime_tag", "profile", "kind", "component"):
            if entry.get(key) != row[key]:
                fail(f"catalog field {key} drifted for {component}")
        expected_digest = None if row["expected_digest"] == "-" else row["expected_digest"]
        expected_dockerfile = None if row["dockerfile"] == "-" else row["dockerfile"]
        expected_context = None if row["context"] == "-" else row["context"]
        if entry.get("expected_digest") != expected_digest:
            fail(f"expected digest drifted for {component}")
        if entry.get("dockerfile") != expected_dockerfile or entry.get("context") != expected_context:
            fail(f"Dockerfile or context drifted for {component}")
        if entry.get("platform") != receipt["platform"]:
            fail(f"platform drifted for {component}")
        image_id = entry.get("image_id")
        if not isinstance(image_id, str) or not SHA256_RE.fullmatch(image_id):
            fail(f"image ID is invalid for {component}")
        config_digest = entry.get("oci_config_digest")
        if not isinstance(config_digest, str) or not SHA256_RE.fullmatch(config_digest):
            fail(f"OCI config digest is invalid for {component}")
        build_args = entry.get("build_args")
        if (not isinstance(build_args, dict)
                or any(SENSITIVE_RE.search(str(key)) for key in build_args)
                or not set(build_args).issubset(ALLOWED_BUILD_ARGS)):
            fail(f"build argument summary is invalid or sensitive for {component}")
        expected_build_arg_keys: set[str]
        security_build_required = component == "security-engine" and security_engine_build_identity_required(repository, revision)
        if component == "enterprise-ai-portal":
            expected_build_arg_keys = {"NEXT_PUBLIC_BILLING_ENABLED"}
        elif component == "web-console":
            expected_build_arg_keys = {"VITE_BILLING_ENABLED"}
        elif security_build_required:
            expected_build_arg_keys = {"SECURITY_ENGINE_BUILD"}
        elif component in {"llm-judge", "portal-proxy"}:
            expected_build_arg_keys = {"LOCAL_RUNTIME_IMAGE"}
        elif row["kind"] == "upstream-source":
            expected_build_arg_keys = {"LLAMA_CPP_REVISION", "LLAMA_CPP_COMMIT_COUNT"}
        else:
            expected_build_arg_keys = set()
        if set(build_args) != expected_build_arg_keys:
            fail(f"build argument key set drifted for {component}")
        if security_build_required:
            validate_security_engine_build_identity(build_args, revision)
        for key, value in build_args.items():
            if key in {"VITE_BILLING_ENABLED", "NEXT_PUBLIC_BILLING_ENABLED"} and value not in {"true", "false"}:
                fail(f"billing build argument is invalid for {component}")
            if key == "LLAMA_CPP_REVISION" and (not isinstance(value, str) or not SHA1_RE.fullmatch(value)):
                fail(f"llama.cpp revision build argument is invalid for {component}")
            if key == "LLAMA_CPP_COMMIT_COUNT" and (not isinstance(value, int) or value < 1):
                fail(f"llama.cpp commit count build argument is invalid for {component}")
        if (component == "enterprise-ai-portal"
                and (set(build_args) != {"NEXT_PUBLIC_BILLING_ENABLED"}
                     or build_args["NEXT_PUBLIC_BILLING_ENABLED"] not in {"true", "false"})):
            fail(f"Portal billing build arguments drifted for {component}")
        validate_sbom(entry.get("sbom"), component)

        inspected = inspect_image(docker_command, row["runtime_tag"], receipt["platform"])
        if security_build_required:
            validate_security_engine_build_identity(build_args, revision, (inspected.get("Config") or {}).get("Env") or [])
        if inspected.get("Id") != image_id:
            fail(f"runtime tag was retargeted for {component}")
        if f"{inspected.get('Os')}/{inspected.get('Architecture')}" != receipt["platform"]:
            fail(f"Docker image platform drifted for {component}")

        if row["kind"] == "third-party":
            if entry.get("actual_digest") != expected_digest:
                fail(f"third-party actual digest drifted for {component}")
            wanted = f"{repository_name(row['runtime_tag'])}@{expected_digest}"
            if wanted not in (inspected.get("RepoDigests") or []):
                fail(f"third-party RepoDigest drifted for {component}")
            continue

        if entry.get("actual_digest") is not None:
            fail(f"source-built image has an unexpected registry digest for {component}")
        if entry.get("toolchain") != toolchain:
            fail(f"image toolchain drifted for {component}")
        validate_build_engine(entry.get("build_engine"), toolchain, component)
        source = entry.get("source")
        if source != expected_source:
            fail(f"source identity drifted for {component}")
        blobs = entry.get("source_blobs")
        if not isinstance(blobs, dict) or set(blobs) != {expected_dockerfile}:
            fail(f"Dockerfile blob identity is missing for {component}")
        expected_blob = git_output(repository, "rev-parse", f"{revision}:{expected_dockerfile}")
        if blobs.get(expected_dockerfile) != expected_blob:
            fail(f"Dockerfile blob identity drifted for {component}")
        if component == "security-engine":
            validate_security_engine_python_deps(
                entry.get("security_engine_python_deps"), repository, revision)
        home_runtime = entry.get("home_runtime")
        if row["kind"] == "home-runtime" and home_runtime is None:
            fail(f"home runtime provenance is missing for {component}")
        if home_runtime is None:
            expected_base_images = git_dockerfile_base_images(
                repository, revision, expected_dockerfile, component)
        else:
            expected_base_images = validate_home_runtime(
                home_runtime, component, repository, revision, expected_dockerfile, build_args,
                receipt["platform"])
        if entry.get("base_images") != expected_base_images:
            fail(f"base image provenance drifted for {component}")
        context_spec = f"{revision}^{{tree}}" if expected_context == "." else f"{revision}:{expected_context}"
        git_output(repository, "cat-file", "-e", context_spec)
        labels = ((inspected.get("Config") or {}).get("Labels") or {})
        expected_labels = {
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.source": source_identity["remote"],
            "com.jjdguard.source.tree": tree,
        }
        if any(labels.get(key) != value for key, value in expected_labels.items()):
            fail(f"OCI source labels drifted for {component}")
        legacy_receipt = entry.get("legacy_receipt")
        expected_legacy_path = TASK4_LEGACY_RECEIPTS.get(component)
        if expected_legacy_path is not None:
            if legacy_receipt is None:
                fail(f"Task4 legacy receipt is missing for {component}")
            if not isinstance(legacy_receipt, dict) or legacy_receipt.get("path") != expected_legacy_path:
                fail(f"Task4 legacy receipt path drifted for {component}")
            legacy_payload = validate_legacy_receipt(
                legacy_receipt, evidence_root, component)
            if legacy_payload.get("base_images") != entry.get("base_images"):
                fail(f"Task4 receipt base images drifted for {component}")
            if legacy_payload.get("build_engine") != entry.get("build_engine"):
                fail(f"Task4 receipt build engine drifted for {component}")
            if (component == "enterprise-ai-portal"
                    and legacy_payload.get("build_args") != build_args):
                fail(f"Task4 receipt build arguments drifted for {component}")
        elif legacy_receipt is not None:
            fail(f"unexpected legacy receipt for {component}")
        if row["kind"] == "upstream-source":
            upstream = entry.get("upstream")
            required_upstream = {
                "schema", "component", "remote", "revision", "tree", "commit_count",
                "archive_file", "archive_sha256", "archive_size",
            }
            if not isinstance(upstream, dict) or set(upstream) != required_upstream:
                fail(f"upstream receipt is invalid for {component}")
            if (upstream.get("schema") != "jjdguard-upstream-source/v1"
                    or upstream.get("component") != "llama.cpp"
                    or upstream.get("remote") != "https://github.com/ggerganov/llama.cpp.git"
                    or not SHA1_RE.fullmatch(str(upstream.get("revision", "")))
                    or not SHA1_RE.fullmatch(str(upstream.get("tree", "")))
                    or not isinstance(upstream.get("commit_count"), int)
                    or upstream["commit_count"] < 1
                    or not HEX256_RE.fullmatch(str(upstream.get("archive_sha256", "")))
                    or not isinstance(upstream.get("archive_size"), int)
                    or upstream["archive_size"] < 1
                    or upstream.get("archive_file") != "llama.cpp.tar"):
                fail(f"upstream identity is invalid for {component}")
            if expected_upstream is None:
                upstream_receipt_path = args.upstream_receipt or default_upstream_receipt(repository, revision)
                expected_upstream = load_json(upstream_receipt_path)
            if upstream != expected_upstream:
                fail(f"upstream receipt drifted for {component}")
            if (component != "llm-judge" and (
                    build_args.get("LLAMA_CPP_REVISION") != upstream["revision"]
                    or build_args.get("LLAMA_CPP_COMMIT_COUNT") != upstream["commit_count"])):
                fail(f"upstream build arguments drifted for {component}")
            wrapper_blobs = entry.get("wrapper_blobs")
            wrapper_path = f"{expected_context}/entrypoint.sh"
            if not isinstance(wrapper_blobs, dict) or set(wrapper_blobs) != {wrapper_path}:
                fail(f"upstream wrapper blob is missing for {component}")
            expected_wrapper_blob = git_output(repository, "rev-parse", f"{revision}:{wrapper_path}")
            if wrapper_blobs[wrapper_path] != expected_wrapper_blob:
                fail(f"upstream wrapper blob drifted for {component}")

    print(f"[ok] image provenance verified: images={len(catalog)} platform={receipt['platform']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        fail(str(error))
