#!/usr/bin/env python3
"""控制面及前端双服务窄事务；只恢复两目标及启动链，不恢复数据库。"""
import argparse
import copy
import fcntl
from decimal import Decimal
import hashlib
import inspect
import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path

import vm_development_apply as vm

SERVICES = ("control-plane", "web-console")
PURPOSE = "console-only"
RELEASE_ID = r"dev-[A-Za-z0-9-]+"
SHA256 = r"[0-9a-f]{64}"
FORBIDDEN_OVERRIDES = ("security_input_workers", "security_input_capacity", "judge_queue_capacity",
                       "gateway_security_budget_seconds", "security_engine_client_timeout_seconds",
                       "security_input_budget_seconds", "security_batch_budget_seconds",
                       "semantic_request_parallelism", "semantic_window_parallelism", "semantic_max_windows")
PROVENANCE_ENV = ("JJD_COMMIT", "JJD_VERSION", "JJD_BUILT_AT")
COMPOSE_ENV_FILE_LABEL = "com.docker.compose.project.environment_file"
IMAGE_LABELS = ("org.opencontainers.image.revision", "com.jjdguard.source.tree",
                "com.jjdguard.base.image", "com.jjdguard.release.id")
MEDIA_FILES = ("manifest.json", "images.tar", "vm_development_apply.py", "vm_console_release.py")
ARTIFACTS = ("candidate.json", "rollback.json", "boot-overlay.json", "boot-chain.new", "boot-chain.previous",
             "previous-current.json")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def controlled_environment():
    return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
            "DOCKER_HOST": "unix:///var/run/docker.sock"}


def run(args, **kwargs):
    kwargs.setdefault("env", controlled_environment())
    return vm.run(args, **kwargs)


def portable_image_id(image):
    if not image.get("Descriptor"):
        return image["Id"]
    raw = run(["ctr", "--address", "/run/containerd/containerd.sock", "--namespace", "moby", "content", "get", image["Id"]])
    require("sha256:"+hashlib.sha256(raw.encode()).hexdigest() == image["Id"], "OCI manifest digest differs")
    config = json.loads(raw).get("config", {}).get("digest", "")
    require(re.fullmatch(vm.IMAGE_PATTERN, config), "OCI image config identity missing")
    return config


def protected(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(vm.ROOT) and ".." not in path.parts, "evidence escapes release root")
    for parent in [*reversed(path.parents), path]:
        if parent.is_relative_to(vm.ROOT):
            info = parent.lstat()
            require(not parent.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022, "unprotected release evidence")
    require(path.is_dir() if directory else path.is_file(), "release evidence unavailable")
    return path


def validate_scope(manifest):
    require(manifest.get("console_only") is True and manifest.get("purpose") == PURPOSE and
            manifest.get("preserve_tier1") is True, "unsupported console-only mode")
    require(not any(manifest.get(key) for key in ("security_engine_only", "engineering_only", "portal_only",
                                                "migrations", "migration_preconditions", "enable_file_detection")),
            "console-only cannot change modes, migrations or file settings")
    require(all(manifest.get(key) is None for key in FORBIDDEN_OVERRIDES), "console-only cannot override security capacity")
    require(set(manifest.get("services", {})) == set(SERVICES), "console-only requires exactly two services")
    require(manifest.get("billing_enabled") in ("true", "false"), "explicit billing compile value required")
    require(not any(key in manifest for key in ("tier1_probe_sha256", "migration_runner_sha256", "migration_version_sha256",
                                               "security_engine_script_sha256")), "unexpected migration/model inputs")


def validate_manifest(manifest):
    validate_scope(manifest)
    require(manifest.get("schema") == 1 and re.fullmatch(RELEASE_ID, manifest.get("release_id", "")) and
            re.fullmatch(r"[0-9a-f]{40}", manifest.get("revision", "")) and
            re.fullmatch(r"[0-9a-f]{40}", manifest.get("tree", "")), "invalid release identity")
    require(re.fullmatch(SHA256, manifest.get("source_archive_sha256", "")), "immutable source archive evidence absent")
    require(manifest.get("candidate_validation") == {"console_payload_verified": True, "control_plane_seeds": "preserved"},
            "candidate console validation absent")
    seeds = manifest.get("control_plane_seeds_sha256", {})
    require(seeds and all(valid_path(path, "/etc/uag/seeds/") and re.fullmatch(SHA256, checksum)
                         for path, checksum in seeds.items()), "preserved seed evidence absent")
    directories = manifest.get("control_plane_seed_directories", [])
    require(directories == sorted(set(directories)) and "/etc/uag/seeds" in directories and
            all(path == "/etc/uag/seeds" or valid_path(path, "/etc/uag/seeds/") for path in directories) and
            not set(directories) & set(seeds), "preserved seed directory evidence absent")
    require(all(str(Path(path).parent) in directories for path in (*seeds, *directories) if path != "/etc/uag/seeds"),
            "preserved seed tree parents incomplete")
    for service, record in manifest["services"].items():
        require(all(re.fullmatch(vm.IMAGE_PATTERN, record.get(key, "")) for key in ("image_id", "base_image_id")),
                "unfixed image identity")
        require(isinstance(record.get("tag"), str) and record["tag"] and not any(c.isspace() for c in record["tag"]), "invalid candidate tag")
        hashes = record.get("payload_sha256", {})
        require(hashes and all(valid_path(path, "/app/") and re.fullmatch(SHA256, checksum)
                              for path, checksum in hashes.items()), "invalid runtime payload evidence")
        if service == "control-plane":
            require("/app/control-plane" in hashes and "/app/VERSION" in hashes, "control-plane payload incomplete")
        else:
            require("/app/dist/index.html" in hashes and "/app/server.js" in hashes, "web-console payload incomplete")


def valid_path(path, prefix):
    return isinstance(path, str) and path.startswith(prefix) and ".." not in Path(path).parts and "\n" not in path and "\r" not in path


def check_image_archive(media, manifest):
    require(vm.digest(media/"images.tar") == manifest["images_sha256"], "image transfer differs")
    with tarfile.open(media/"images.tar") as archive:
        members = archive.getmembers()
        require(len([m for m in members if m.name == "manifest.json"]) == 1, "ambiguous image archive index")
        index = json.load(archive.extractfile("manifest.json"))
        expected = {record["tag"]: record["image_id"] for record in manifest["services"].values()}
        require(len(index) == len(SERVICES), "console archive contains other images")
        seen = set()
        for item in index:
            tags = item.get("RepoTags") or []
            require(len(tags) == 1 and tags[0] in expected and tags[0] not in seen, "console archive contains other images")
            seen.add(tags[0])
            name = item["Config"]
            require(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe image archive config")
            configs = [m for m in members if m.name == name]
            require(len(configs) == 1 and configs[0].isfile(), "ambiguous archive image config")
            config = archive.extractfile(configs[0])
            require("sha256:"+hashlib.file_digest(config, "sha256").hexdigest() == expected[tags[0]], "archive image config differs")
        require(seen == set(expected), "console archive is incomplete")


def image_reference(reference):
    require(isinstance(reference, str) and reference and not any(c.isspace() for c in reference), "invalid image reference")
    if re.fullmatch(vm.IMAGE_PATTERN, reference):
        return reference
    repository, separator, digest = reference.partition("@")
    if ":" not in repository.rsplit("/", 1)[-1] and not separator:
        repository += ":latest"
    parts = repository.split("/")
    if len(parts) == 1 or not ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts.insert(0, "docker.io")
    if parts[0] == "index.docker.io":
        parts[0] = "docker.io"
    if parts[0] == "docker.io" and len(parts) == 2:
        parts.insert(1, "library")
    return "/".join(parts)+(separator+digest if separator else "")


def inspect_all():
    ids = run(["docker", "ps", "-aq"]).split()
    require(ids, "VM containers unavailable")
    return json.loads(run(["docker", "inspect", *ids]))


def project_services(rows, project):
    result = {}
    for row in rows:
        labels = row["Config"].get("Labels") or {}
        if labels.get("com.docker.compose.project") == project:
            service = labels.get("com.docker.compose.service")
            require(service and service not in result, "ambiguous project service")
            result[service] = row
    require(set(SERVICES+("postgres",)) <= set(result), "required project services absent")
    return result


def build_runtime_contract(row, allow_provenance=False):
    config = copy.deepcopy(row["Config"])
    config.pop("Hostname", None)
    config.pop("Image", None)
    labels = config.get("Labels") or {}
    # com.docker.compose.depends_on 是 create 时由渲染模型派生的执行元数据：
    # 同一渲染拓扑在不同创建路径下标签值不同（up --no-deps 或单服务重建为空串，
    # 多服务 up 为非空且顺序随文件键序而定；实测 full-release 与 console-only
    # 两条路径对同一拓扑分别产生 '' 与非空标签）。依赖拓扑+condition/required
    # 由 stage 冻结、verify 以渲染模型独立比较守卫（target_depends_on）；
    # 本函数只剔除该标签，其余业务/Compose 标签全部保留比较。
    for key in ("com.docker.compose.config-hash", "com.docker.compose.project.config_files", "com.docker.compose.image",
                "com.docker.compose.depends_on", *IMAGE_LABELS):
        labels.pop(key, None)
    env = config.get("Env") or []
    if allow_provenance:
        # Target labels are independently authenticated by stage and verify.
        # Full fingerprints keep this metadata, including for non-targets.
        labels.pop(COMPOSE_ENV_FILE_LABEL, None)
        # Compose adds this bookkeeping label while recreating a target.
        labels.pop("com.docker.compose.replace", None)
        env = [v for v in env if v.split("=", 1)[0] not in PROVENANCE_ENV]
    config["Env"] = sorted(env)
    host = copy.deepcopy(row.get("HostConfig") or {})
    host.pop("ContainerIDFile", None)
    if allow_provenance:
        # Target creation can reorder binds and encode unset DNS as null.
        if isinstance(host.get("Binds"), list):
            host["Binds"] = sorted(host["Binds"])
        for field in ("Dns", "DnsOptions", "DnsSearch"):
            if host.get(field) is None:
                host[field] = []
    mounts = sorted(row.get("Mounts") or [], key=object_hash)
    networks = {}
    for name, value in row.get("NetworkSettings", {}).get("Networks", {}).items():
        aliases = [v for v in value.get("Aliases") or [] if v not in (row["Id"], row["Id"][:12])]
        networks[name] = {key: value.get(key) for key in ("NetworkID", "IPAMConfig", "Links", "DriverOpts")}
        networks[name]["Aliases"] = sorted(aliases)
    return dict(config=config, host=host, mounts=mounts, networks=networks, path=row.get("Path"), args=row.get("Args"))

def runtime_contract(row, allow_provenance=False):
    return object_hash(build_runtime_contract(row, allow_provenance))

def contract_diff(expected, actual):
    diffs = []
    for top in ("config", "host", "networks", "mounts", "path", "args"):
        if expected.get(top) != actual.get(top):
            if isinstance(expected.get(top), dict) and isinstance(actual.get(top), dict):
                for key in sorted(set(expected[top]) | set(actual[top])):
                    if expected[top].get(key) != actual[top].get(key):
                        diffs.append(top+"."+key+": "+repr(expected[top].get(key))[:100]+" != "+repr(actual[top].get(key))[:100])
            else:
                diffs.append(top+": "+repr(expected.get(top))[:140]+" != "+repr(actual.get(top))[:140])
    return "; ".join(diffs) if diffs else "inputs identical"


JSON_ARRAY_SCALAR = re.compile(r'\["[^"\\$`#]*"(?:,"[^"\\$`#]*")*\]')


def validate_boot_env(path, expected_project=None):
    exceptions = []
    forbidden = {"ROOT", "DC", "ENV", "COMPOSE", "STATE", "LAST_UPGRADE", "BACKUP_ROOT", "command", "BASH_ENV",
                 "PATH", "HOME", "LANG", "IFS", "CDPATH", "SHELLOPTS", "BASHOPTS", "PWD", "OLDPWD", "USER", "LOGNAME", "SHELL", "SHLVL", "_"}
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        require(value == line.lstrip(), "boot env trailing whitespace is not supported")
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", value)
        require(match is not None, "boot env must contain only unexported scalar assignments")
        key, raw = match.groups()
        require(key not in forbidden and not key.startswith(("DOCKER_", "BASH_", "LD_", "PYTHON")) and
                (not key.startswith("COMPOSE_") or key == "COMPOSE_PROFILES" or key == "COMPOSE_PROJECT_NAME"),
                "boot env cannot override startup/Docker implementation")
        if raw.startswith("'"):
            match = re.fullmatch(r"'([^']*)'(?:[ \t]+#.*)?", raw)
            require(match is not None, "unsupported quoted boot env scalar")
            scalar = match[1]
        else:
            if raw.startswith('"'):
                match = re.fullmatch(r'"([^"\n]*)"(?:[ \t]+#.*)?', raw)
            else:
                match = re.fullmatch(r'([^\s\'"\n]*)(?:[ \t]+#.*)?', raw)
                if match is None and JSON_ARRAY_SCALAR.fullmatch(raw):
                    # Narrow exception for the 2.8.0 offline installer's historical
                    # DEFAULT_KEY_SCOPES=JSON-array line: value shape is frozen, no
                    # shell metacharacters. Known semantic difference is recorded,
                    # not silently normalised: bash assignment quote removal strips
                    # the embedded double quotes while compose dotenv keeps them;
                    # the consumer's reading is not verified here.
                    exceptions.append(dict(key=key, exception="json-array-allowed", value=raw,
                                           note="bash assignment quote removal strips embedded double quotes; "
                                                "compose dotenv preserves them; existing live shape kept unchanged, "
                                                "consumer value semantics not verified"))
                    continue
            require(match is not None, "boot env assignment is not a complete shell scalar")
            scalar = match[1]
            require(not scalar.startswith("~") and ":~" not in scalar and not any(char in scalar for char in ("*", "?", "[", "]", "{", "}")),
                    "boot env shell expansion is not supported")
            require(not any(char in scalar for char in ("$", "`", "\\", ";", "&", "|", "(", ")", "<", ">")),
                    "boot env interpolation/code is not supported")
        if key == "COMPOSE_PROJECT_NAME":
            require(expected_project is not None and scalar == expected_project,
                    "boot env COMPOSE_PROJECT_NAME must exactly equal the staged explicit --project-name")
            exceptions.append(dict(key=key, exception="compose-project-name-allowed", value=scalar,
                                   note="value equality with the staged explicit --project-name verified; other COMPOSE_ keys stay rejected"))
    return exceptions


def validate_compose_references(content):
    def mapping(pairs):
        keys = [key for key, value in pairs]
        require(not any(key in ("include", "extends") for key in keys), "unfrozen Compose include/extends input")
        require(len(keys) == len(set(keys)), "unsupported Compose duplicate mapping key")
        return dict(pairs)

    content = content.removeprefix("\ufeff")
    try:
        document = json.loads(content, object_pairs_hook=mapping)
    except json.JSONDecodeError:
        document = None
    else:
        require(isinstance(document, dict), "unsupported Compose document")
        return

    require(not any(char in content for char in ("\x85", "\u2028", "\u2029")) and
            all(ord(char) >= 32 or char in "\t\r\n" for char in content), "unsupported Compose YAML control character")
    lines = []
    for line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        body = line.lstrip(" ")
        require(not body.startswith("\t"), "unsupported Compose YAML indentation")
        if body and not body.startswith("#"):
            lines.append((len(line)-len(body), body))

    def space(text, offset):
        while offset < len(text) and text[offset] in " \t":
            offset += 1
        return offset

    def scalar(text, offset, flow=False, key=False):
        offset = space(text, offset)
        require(offset < len(text), "unsupported Compose YAML scalar")
        quote = text[offset]
        if quote in ("'", '"'):
            value, offset = [], offset+1
            escapes = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v",
                       "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\",
                       "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}
            while offset < len(text):
                char, offset = text[offset], offset+1
                if char == quote:
                    if quote == "'" and offset < len(text) and text[offset] == quote:
                        value.append(quote)
                        offset += 1
                        continue
                    return "".join(value), offset
                if quote == '"' and char == "\\":
                    require(offset < len(text), "unsupported Compose multiline YAML quote")
                    escape, offset = text[offset], offset+1
                    if escape in ("x", "u", "U"):
                        size = {"x": 2, "u": 4, "U": 8}[escape]
                        digits, offset = text[offset:offset+size], offset+size
                        require(len(digits) == size and all(c in "0123456789abcdefABCDEF" for c in digits),
                                "unsupported Compose YAML escape")
                        codepoint = int(digits, 16)
                        require(codepoint <= 0x10ffff and not 0xd800 <= codepoint <= 0xdfff, "unsupported Compose YAML escape")
                        char = chr(codepoint)
                    else:
                        require(escape in escapes, "unsupported Compose YAML escape")
                        char = escapes[escape]
                value.append(char)
            raise RuntimeError("unsupported Compose multiline YAML quote")
        start = offset
        while offset < len(text):
            char = text[offset]
            if (flow and char in "[]{},") or (char == "#" and (offset == start or text[offset-1] in " \t")):
                break
            if char == ":" and (key and flow or offset+1 == len(text) or text[offset+1] in " \t[]{},"):
                break
            offset += 1
        value = text[start:offset].strip()
        require(value and value[0] not in "!&*?%@`|>[{" and
                value not in ("-", ":") and not value.startswith(("- ", "-\t", ": ", ":\t")),
                "unsupported Compose YAML reference syntax")
        require(not key or value != "<<", "unsupported Compose YAML merge key")
        return value, offset

    def inline(text, offset=0, flow=False):
        offset = space(text, offset)
        if offset == len(text) or text[offset] == "#" or flow and text[offset] in ",]}":
            return None, offset
        if text[offset] not in "[{":
            return scalar(text, offset, flow=flow)
        opening, offset = text[offset], offset+1
        closing, values = ("}" if opening == "{" else "]"), []
        offset = space(text, offset)
        while offset < len(text) and text[offset] != closing:
            if opening == "{":
                key, offset = scalar(text, offset, flow=True, key=True)
                offset = space(text, offset)
                require(offset < len(text) and text[offset] == ":", "unsupported Compose YAML mapping")
                value, offset = inline(text, offset+1, flow=True)
                values.append((key, value))
            else:
                value, offset = inline(text, offset, flow=True)
                values.append(value)
            offset = space(text, offset)
            require(offset < len(text) and text[offset] in (",", closing), "unsupported Compose YAML flow collection")
            if text[offset] == ",":
                offset = space(text, offset+1)
            else:
                break
        require(offset < len(text) and text[offset] == closing, "unsupported Compose multiline YAML flow collection")
        return (mapping(values) if opening == "{" else values), offset+1

    def complete(text, offset):
        offset = space(text, offset)
        require(offset == len(text) or text[offset] == "#", "unsupported Compose YAML trailing syntax")

    def block_value(text, index, indent):
        text = text.lstrip(" \t")
        if not text or text.startswith("#"):
            if index < len(lines) and lines[index][0] > indent:
                return block(index, lines[index][0])
            return None, index
        if text[0] in "|>":
            header = text.split("#", 1)[0].rstrip()
            require(len(header) <= 3 and all(char in "+-123456789" for char in header[1:]) and
                    len(set(header[1:])) == len(header[1:]), "unsupported Compose YAML block scalar")
            while index < len(lines) and lines[index][0] > indent:
                index += 1
            return "", index
        value, offset = inline(text)
        complete(text, offset)
        return value, index

    def block_mapping(index, indent, first=None):
        pairs = []
        while first is not None or index < len(lines) and lines[index][0] == indent:
            if first is None:
                text, index = lines[index][1], index+1
            else:
                text, first = first, None
            key, offset = scalar(text, 0, key=True)
            offset = space(text, offset)
            require(offset < len(text) and text[offset] == ":", "unsupported Compose YAML mapping")
            value, index = block_value(text[offset+1:], index, indent)
            pairs.append((key, value))
        return mapping(pairs), index

    def block(index, indent):
        text = lines[index][1]
        if text.startswith(("{", "[")):
            value, offset = inline(text)
            complete(text, offset)
            return value, index+1
        if not (text == "-" or text.startswith(("- ", "-\t"))):
            return block_mapping(index, indent)
        values = []
        while index < len(lines) and lines[index][0] == indent:
            text, index = lines[index][1], index+1
            require(text == "-" or text.startswith(("- ", "-\t")), "unsupported Compose YAML sequence")
            entry = text[1:]
            text = entry.lstrip(" \t")
            spacing = len(entry)-len(text)
            require("\t" not in entry[:spacing], "unsupported Compose YAML indentation")
            item_indent = indent+1+spacing
            if text and text[0] not in "[{|>#":
                key, offset = scalar(text, 0, key=True)
                offset = space(text, offset)
                if offset < len(text) and text[offset] == ":":
                    value, index = block_mapping(index, item_indent, first=text)
                    values.append(value)
                    continue
            value, index = block_value(text, index, indent)
            values.append(value)
        return values, index

    require(lines and lines[0][0] == 0, "unsupported Compose YAML document indentation")
    document, index = block(0, lines[0][0])
    require(index == len(lines) and isinstance(document, dict), "unsupported Compose YAML document")


def duration_ns(value):
    require(isinstance(value, str), "unsupported Compose duration")
    units = {"ns": 1, "us": 1000, "\u00b5s": 1000, "ms": 1000000, "s": 1000000000, "m": 60000000000, "h": 3600000000000}
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|\u00b5s|ms|s|m|h)", value)
    require(parts and "".join(number+unit for number, unit in parts) == value, "invalid Compose duration")
    return sum(int(Decimal(number)*units[unit]) for number, unit in parts)


def validate_runtime_model(service, item, model, row, image, daemon_logging):
    config, defaults = row["Config"], image["Config"]
    supported = {"image", "pull_policy", "environment", "entrypoint", "command", "user", "working_dir", "stop_signal",
                 "tty", "stdin_open", "read_only", "privileged", "security_opt", "cap_add", "cap_drop", "restart",
                 "volumes", "tmpfs", "ports", "networks", "healthcheck", "labels", "expose", "depends_on", "container_name", "logging"}
    require(set(item) <= supported, "unsupported historical target runtime fields")
    environment = dict(v.split("=", 1) for v in defaults.get("Env") or [] if "=" in v)
    for key, value in item.get("environment", {}).items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = str(value)
    actual = dict(v.split("=", 1) for v in config.get("Env") or [] if "=" in v)
    require(actual == environment, "target environment cannot be restored from historical model")
    # compose 对未声明 entrypoint/command 的服务渲染出显式 null 键；按 compose
    # 语义 null = 使用镜像默认值（与 compose up 创建现有容器的方式一致），因此
    # 与键缺失同样回落到镜像默认值。显式非 null 值仍走严格相等，两者皆空仍 fail-closed。
    entrypoint = (item["entrypoint"] if item.get("entrypoint") is not None else defaults.get("Entrypoint")) or []
    command = (item["command"] if item.get("command") is not None else defaults.get("Cmd")) or []
    require(isinstance(entrypoint, list) and isinstance(command, list) and entrypoint+command,
            "unsupported historical target command")
    argv = entrypoint+command
    require(row.get("Path") == argv[0] and row.get("Args", []) == argv[1:], "target command differs from historical model")
    require((config.get("Entrypoint") or []) == entrypoint and (config.get("Cmd") or []) == command,
            "target command configuration differs from historical model")
    for key, field, fallback in (("user", "User", ""), ("working_dir", "WorkingDir", ""), ("stop_signal", "StopSignal", "")):
        require((config.get(field) or fallback) == (item.get(key, defaults.get(field)) or fallback),
                "target runtime scalar differs from historical model: "+key)
    for key, field in (("tty", "Tty"), ("stdin_open", "OpenStdin")):
        require(bool(config.get(field)) == bool(item.get(key, False)), "target interactive runtime differs")
    health = copy.deepcopy(defaults.get("Healthcheck") or {})
    declared_health = item.get("healthcheck") or {}
    durations = (("interval", "Interval"), ("timeout", "Timeout"), ("start_period", "StartPeriod"), ("start_interval", "StartInterval"))
    if declared_health.get("disable"):
        health = {"Test": ["NONE"]}
    else:
        if "test" in declared_health:
            health["Test"] = declared_health["test"]
        for key, field in durations:
            if key in declared_health:
                health[field] = duration_ns(declared_health[key])
        if "retries" in declared_health:
            health["Retries"] = declared_health["retries"]
    actual_health = config.get("Healthcheck") or {}
    normalize_health = lambda value: {key: item for key, item in value.items() if item not in (None, 0, "", [])}
    require(normalize_health(actual_health) == normalize_health(health), "target healthcheck differs from historical model")
    labels = dict(defaults.get("Labels") or {})
    labels.update(item.get("labels") or {})
    actual_labels = {key: value for key, value in (config.get("Labels") or {}).items() if not key.startswith("com.docker.compose.")}
    require(actual_labels == {key: value for key, value in labels.items() if not key.startswith("com.docker.compose.")},
            "target user/image labels differ from historical model")
    if item.get("container_name"):
        require(row["Name"].lstrip("/") == item["container_name"], "target container name differs")
    host = row.get("HostConfig") or {}
    logging = item.get("logging") or {}
    actual_logging = host.get("LogConfig") or {}
    require(set(logging) <= {"driver", "options"} and set(actual_logging) <= {"Type", "Config"}, "unsupported target logging fields")
    driver, options = actual_logging.get("Type", ""), actual_logging.get("Config") or {}
    if driver:
        # 模型未声明 logging 时，compose up 创建的容器落到 daemon 默认 driver
        # （空 options）；仅当容器 driver 等于 daemon 默认且 options 为空才接受，
        # 其余情况仍要求与模型显式冻结值严格相等（fail-closed）。
        require((not logging and not options and driver == daemon_logging) or
                (logging.get("driver") == driver and (logging.get("options") or {}) == options),
                "effective target logging is not explicitly frozen in historical model")
    else:
        require(not logging and not options, "target logging differs from historical model")
    forbidden_host = ("Devices", "DeviceCgroupRules", "DeviceRequests", "VolumesFrom", "Links", "ExtraHosts", "Dns", "DnsSearch", "DnsOptions",
                      "Ulimits", "GroupAdd", "Sysctls", "StorageOpt", "VolumeDriver", "CgroupParent", "CpuShares", "CpuPeriod", "CpuQuota",
                      "CpuRealtimePeriod", "CpuRealtimeRuntime", "NanoCpus", "CpuCount", "CpuPercent", "CpusetCpus", "CpusetMems",
                      "Memory", "MemoryReservation", "MemorySwap", "KernelMemory", "BlkioWeight", "BlkioWeightDevice",
                      "BlkioDeviceReadBps", "BlkioDeviceWriteBps", "BlkioDeviceReadIOps", "BlkioDeviceWriteIOps", "PidsLimit", "OomKillDisable", "OomScoreAdj")
    for field in forbidden_host:
        require(host.get(field) in (None, False, 0, "", [], {}), "unsupported target host runtime: "+field)
    for field, allowed in (("PidMode", (None, "")), ("UTSMode", (None, "")), ("UsernsMode", (None, "")),
                           ("IpcMode", (None, "", "private")), ("CgroupnsMode", (None, "", "private")), ("Runtime", (None, "", "runc"))):
        require(host.get(field) in allowed, "unsupported target host namespace/runtime: "+field)
    require(host.get("MemorySwappiness") in (None, -1), "unsupported target swappiness")
    require(host.get("ShmSize") in (None, 0, 64*1024*1024) and not host.get("AutoRemove") and not host.get("PublishAllPorts"),
            "unsupported target host allocation")
    for key, field in (("read_only", "ReadonlyRootfs"), ("privileged", "Privileged")):
        require(bool(host.get(field)) == bool(item.get(key, False)), "target host security differs")
    for key, field in (("security_opt", "SecurityOpt"), ("cap_add", "CapAdd"), ("cap_drop", "CapDrop")):
        require(sorted(host.get(field) or []) == sorted(item.get(key) or []), "target host security list differs")
    restart = item.get("restart", "no")
    name, _, retries = restart.partition(":")
    policy = host.get("RestartPolicy") or {}
    require(policy.get("Name", "no") == name and policy.get("MaximumRetryCount", 0) == (int(retries) if retries else 0),
            "target restart policy differs")
    declared = {}
    for volume in item.get("volumes") or []:
        require(volume.get("type") in ("bind", "volume"), "unsupported target mount type")
        target = volume["target"]
        require(target not in declared, "ambiguous target mount")
        source = volume.get("source")
        if volume["type"] == "volume":
            require(source and source in model.get("volumes", {}), "anonymous target volume cannot be frozen")
            source = model["volumes"][source]["name"]
        propagation = (volume.get("bind") or {}).get("propagation", "rprivate") if volume["type"] == "bind" else ""
        require(propagation in ("", "private", "rprivate", "shared", "rshared", "slave", "rslave"), "unsupported target mount propagation")
        declared[target] = (volume["type"], source, not volume.get("read_only", False), propagation)
    mounted = {}
    for volume in row.get("Mounts") or []:
        if volume.get("Type") == "tmpfs":
            require(volume["Destination"] in host.get("Tmpfs", {}), "unexpected target tmpfs mount")
            continue
        target = volume["Destination"]
        require(target not in mounted, "ambiguous runtime mount")
        mounted[target] = (volume.get("Type"), volume.get("Name") if volume.get("Type") == "volume" else volume.get("Source"),
                           volume.get("RW"), volume.get("Propagation") or "")
    require(mounted == declared, "target mount differs from historical model")
    tmpfs = dict(value.split(":", 1) if ":" in value else (value, "") for value in item.get("tmpfs") or [])
    require((host.get("Tmpfs") or {}) == tmpfs, "target tmpfs options differ")
    bindings = {}
    for port in item.get("ports") or []:
        require(port.get("published") and port.get("protocol", "tcp") in ("tcp", "udp"), "unfixed target port")
        key = str(port["target"])+"/"+port.get("protocol", "tcp")
        bindings.setdefault(key, []).append(dict(HostIp=port.get("host_ip", ""), HostPort=str(port["published"])))
    exposed = set(defaults.get("ExposedPorts") or {})|set(bindings)
    for value in item.get("expose") or []:
        exposed.add(str(value) if "/" in str(value) else str(value)+"/tcp")
    require(set(config.get("ExposedPorts") or {}) == exposed, "target exposed ports differ")
    normalize = lambda values: {key: sorted(value or [], key=object_hash) for key, value in values.items()}
    require(normalize(host.get("PortBindings") or {}) == normalize(bindings), "target port bindings differ")
    networks = {}
    for name, options in item.get("networks", {}).items():
        require(name in model.get("networks", {}), "target network definition absent")
        network = model["networks"][name].get("name", name)
        networks[network] = options or {}
    actual_networks = row.get("NetworkSettings", {}).get("Networks") or {}
    require(set(actual_networks) == set(networks), "target network membership differs")
    for name, options in networks.items():
        value = actual_networks[name]
        aliases = {v for v in value.get("Aliases") or [] if v not in (row["Id"], row["Id"][:12])}
        expected = {service, row["Name"].lstrip("/"), *(options.get("aliases") or [])}
        require(aliases == expected, "target network aliases differ")
        requested = {key: options[field] for key, field in (("IPv4Address", "ipv4_address"), ("IPv6Address", "ipv6_address")) if options.get(field)}
        # Docker/Compose may materialize empty address fields for dynamic endpoints.
        # Normalize only these two empty strings; static addresses and all other
        # IPAM options must still match the declared model exactly.
        actual_ipam = {key: item for key, item in (value.get("IPAMConfig") or {}).items()
                       if not (key in ("IPv4Address", "IPv6Address") and item == "")}
        require(actual_ipam == requested, "target network IPAM differs")


def fingerprints(rows):
    result = {}
    for row in rows:
        stable = {key: row.get(key) for key in ("Config", "HostConfig", "Mounts", "NetworkSettings", "Name", "Path", "Args")}
        stable["Mounts"] = sorted(row.get("Mounts") or [], key=object_hash)
        result[row["Id"]] = dict(vm.safe_identity({"row": row})["row"], config_sha256=object_hash(stable),
                                 runtime_contract=runtime_contract(row))
    return result


def non_targets(rows, project):
    targets = {row["Id"] for service, row in project_services(rows, project).items() if service in SERVICES}
    return fingerprints([row for row in rows if row["Id"] not in targets])


def scalar_overlay(before, after):
    """绝不把规范化完整模型叠加到基础链，避免列表拼接或资源漂移。"""
    left, right = copy.deepcopy(before), copy.deepcopy(after)
    overlay = {"services": {}}
    require(set(left.get("services", {})) == set(right.get("services", {})), "boot service set differs")
    for service in SERVICES:
        require(service in left["services"], "boot target absent")
        old, new = left["services"][service], right["services"][service]
        delta = {}
        for key in ("image", "pull_policy"):
            if old.get(key) != new.get(key):
                require(key in new and isinstance(new[key], str), "invalid boot scalar")
                delta[key] = new[key]
                old[key] = new[key]
        old_env, new_env = old.get("environment", {}), new.get("environment", {})
        for key in PROVENANCE_ENV:
            if old_env.get(key) != new_env.get(key):
                require(key in new_env and isinstance(new_env[key], str), "invalid boot provenance")
                delta.setdefault("environment", {})[key] = new_env[key]
                old.setdefault("environment", {})[key] = new_env[key]
        if delta:
            overlay["services"][service] = delta
    require(left == right, "boot/live differs outside permitted target scalars (lists/resources/environment preserved)")
    return overlay


def atomic_bytes(path, content):
    vm.atomic_bytes(path, content)
    require(path.stat().st_uid == os.geteuid() and path.stat().st_mode & 0o777 == 0o600, "atomic evidence ownership/mode differs")
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    atomic_bytes(Path(path), (json.dumps(value, indent=2)+"\n").encode())


def seed_hashes(container):
    probe = ('for path do if [ -L "$path" ]; then kind=l; elif [ -d "$path" ]; then kind=d; '
             'elif [ -f "$path" ]; then kind=f; else kind=x; fi; printf "%s %s\\n" "$kind" "$path"; done')
    output = run(["docker", "exec", container, "find", "/etc/uag/seeds", "-exec", "sh", "-c", probe, "sh", "{}", "+"])
    entries = {}
    for line in output.splitlines():
        kind, path = line.split(" ", 1)
        require(kind in ("d", "f") and (path == "/etc/uag/seeds" or valid_path(path, "/etc/uag/seeds/")), "unsupported seed tree entry")
        require(path not in entries, "duplicate seed tree entry")
        entries[path] = kind
    files = sorted(path for path, kind in entries.items() if kind == "f")
    directories = sorted(path for path, kind in entries.items() if kind == "d")
    require(files and entries.get("/etc/uag/seeds") == "d" and
            all(entries.get(str(Path(path).parent)) == "d" for path in entries if path != "/etc/uag/seeds"),
            "preserved seed tree absent or incomplete")
    hashes = {}
    for offset in range(0, len(files), 80):
        output = run(["docker", "exec", container, "sha256sum", "--", *sorted(files)[offset:offset+80]])
        for line in output.splitlines():
            checksum, path = line.split(None, 1)
            require(path not in hashes and re.fullmatch(SHA256, checksum), "invalid seed checksum")
            hashes[path] = checksum
    require(set(hashes) == set(files), "seed checksum tree incomplete")
    return dict(files=hashes, directories=directories)


class ConsoleRelease:
    def __init__(self, media, expected_manifest):
        self.media = protected(media, directory=True)
        require(self.media.parent == vm.ROOT/"development-releases", "unexpected release directory")
        self.manifest_sha = expected_manifest
        require(vm.digest(protected(self.media/"manifest.json")) == expected_manifest, "manifest hash differs")
        self.manifest = json.loads((self.media/"manifest.json").read_text())
        validate_manifest(self.manifest)
        require(self.media.name == self.manifest["release_id"], "media release identity differs")
        for name, field in (("vm_development_apply.py", "apply_script_sha256"), ("vm_console_release.py", "console_script_sha256")):
            require(vm.digest(protected(self.media/name)) == self.manifest[field], "release script differs")
        validate_media_entries(self.media)
        lock_path = self.media.parent/".release.lock"
        self.lock = os.fdopen(os.open(lock_path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "w")
        protected(lock_path)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.state = self.media/"state"
        self.pointer = self.media.parent/"current.json"
        self.log = self.media/"apply.log"

    def event(self, message):
        with self.log.open("a") as stream:
            stream.write(message+"\n")
        print(message, flush=True)

    def image(self, name):
        return json.loads(run(["docker", "image", "inspect", name]))[0]

    def runtime_path(self, path, directory=False):
        path = Path(path)
        require(path.is_absolute() and path.is_relative_to(self.release_root) and ".." not in path.parts, "runtime input escaped")
        for parent in [path, *path.parents]:
            if parent.is_relative_to(self.release_root):
                require(not parent.is_symlink(), "symlinked runtime input")
        require(path.is_dir() if directory else path.is_file(), "runtime input missing")
        return path

    def runtime_evidence(self, path):
        path = self.runtime_path(path)
        info = path.stat()
        require(info.st_uid == os.geteuid() and info.st_mode & 0o777 == 0o600, "boot/live evidence ownership or mode differs")
        return path

    def pointer_bytes(self):
        return protected(self.pointer).read_bytes() if self.pointer.exists() or self.pointer.is_symlink() else None

    def compose_environment(self):
        return controlled_environment()

    def compose_implementation(self):
        docker = shutil.which("docker", path=self.compose_environment()["PATH"])
        require(docker, "Docker executable unavailable")
        docker = Path(docker).resolve(strict=True)
        try:
            version = run(["docker", "compose", "version", "--short"]).strip()
        except vm.CommandFailure:
            executable = self.runtime_path(self.workdir/"bin/docker-compose")
            mode = "bundled"
            version = run([str(executable), "version", "--short"]).strip()
        else:
            plugins = json.loads(run(["docker", "info", "--format", "{{json .ClientInfo.Plugins}}"]))
            compose = [p for p in plugins if p.get("Name") == "compose"]
            require(len(compose) == 1, "ambiguous Compose plugin implementation")
            executable = Path(compose[0]["Path"])
            require(executable.is_absolute(), "relative Compose plugin implementation")
            executable = executable.resolve(strict=True)
            mode = "plugin"
        require(executable.is_file() and os.access(executable, os.X_OK) and version, "Compose implementation unavailable")
        return dict(mode=mode, path=str(executable), sha256=vm.digest(executable), version=version,
                    docker_path=str(docker), docker_sha256=vm.digest(docker))

    def check_implementation(self):
        require(self.compose_implementation() == self.implementation, "Compose implementation changed")

    def compose(self, *args, files):
        self.check_implementation()
        argv = ["sh", str(self.workdir/"compose-wrapper.sh"), "--project-name", self.project,
                "--project-directory", str(self.workdir), "--env-file", str(self.workdir/".env")]
        for path in files:
            argv += ["-f", str(path)]
        return run(argv+list(args), cwd=self.workdir, env=self.compose_environment(), log=None if args[0] == "config" else self.log)

    def render(self, files):
        return json.loads(self.compose("config", "--format", "json", files=files))

    def referenced_inputs(self, files):
        inputs = set()
        for path in files:
            validate_compose_references(self.runtime_path(path).read_text())
        model = json.loads(self.compose("config", "--no-env-resolution", "--format", "json", files=files))
        references = []
        for item in model.get("services", {}).values():
            for entry in item.get("env_file") or []:
                references.append((entry if isinstance(entry, str) else entry["path"], True if isinstance(entry, str) else entry.get("required", True)))
        for kind in ("configs", "secrets"):
            for entry in model.get(kind, {}).values():
                require("environment" not in entry, "unfrozen Compose environment resource")
                if entry.get("file"):
                    references.append((entry["file"], True))
        for path, required in references:
            path = Path(path)
            require(path.is_absolute() and path.is_relative_to(self.release_root) and ".." not in path.parts,
                    "Compose referenced input escaped runtime root")
            if path.exists() or path.is_symlink():
                inputs.add(self.runtime_path(path))
            else:
                require(not required, "required Compose referenced input missing")
                self.absent_inputs.add(str(path))
        return inputs

    def boot_render(self, files):
        self.check_implementation()
        argv = ["sh", str(self.workdir/"compose-wrapper.sh"), *self.boot_arguments]
        for path in files:
            argv += ["-f", str(path)]
        return json.loads(run(argv+["config", "--format", "json"], cwd=self.workdir, env=self.compose_environment()))

    def policy(self, rows):
        row = project_services(rows, self.project)["postgres"]
        env = dict(v.split("=", 1) for v in row["Config"].get("Env", []) if "=" in v)
        user, database = env.get("POSTGRES_USER", "jjdguard"), env.get("POSTGRES_DB", "jjdguard")
        query = ("SELECT coalesce(json_object_agg(key,value),'{}'::json)::text FROM system_settings "
                 "WHERE key IN ('billing_enabled','security_audit_only','file_content_dlp_enabled');")
        return json.loads(run(["docker", "exec", "-i", row["Id"], "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1",
                                  "-U", user, "-d", database], input=query))

    def boot_inputs(self):
        self.chain = self.workdir/".upgrade/compose-files"
        base = self.runtime_path(self.workdir/"docker-compose.offline.yml")
        self.runtime_path(self.workdir/".upgrade", directory=True)
        self.boot_env_exceptions = validate_boot_env(self.runtime_path(self.workdir/".env"), expected_project=getattr(self, "project", None))
        files, inputs = [base], [base, self.release_root/"jjdctl", self.workdir/"compose-wrapper.sh",
                                self.workdir/"bin/docker-compose", self.workdir/".env"]
        self.chain_present = self.chain.exists() or self.chain.is_symlink()
        if self.chain_present:
            chain = self.runtime_evidence(self.chain)
            self.previous_chain = chain.read_bytes()
            entries = self.previous_chain.decode().splitlines()
            require(entries and len(entries) <= 32 and len(entries) == len(set(entries)), "invalid boot chain")
            for entry in entries:
                path = Path(entry)
                require(path.is_absolute() and path.is_relative_to(self.workdir/"active-config") and ".." not in path.parts,
                        "invalid boot overlay path")
                self.runtime_evidence(path)
                files.append(path)
        else:
            self.previous_chain = b""
            fallback = self.workdir/".upgrade/compose.upgrade.yml"
            if fallback.exists() or fallback.is_symlink():
                require(False, "legacy fallback boot chain requires a separate reviewed conversion")
        name_path = self.workdir/".upgrade/project-name"
        directory_path = self.workdir/".upgrade/project-directory"
        self.boot_arguments = []
        if name_path.exists() or name_path.is_symlink():
            name = self.runtime_evidence(name_path).read_text().strip()
            require(name == self.project and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name), "boot project differs")
            directory = self.workdir
            if directory_path.exists() or directory_path.is_symlink():
                directory = Path(self.runtime_evidence(directory_path).read_text().rstrip("\r\n"))
                require(directory == self.workdir, "boot project directory differs")
                inputs.append(directory_path)
            self.boot_arguments = ["--project-name", name, "--project-directory", str(directory),
                                   "--env-file", str(self.workdir/".env")]
            inputs.append(name_path)
        elif directory_path.exists() or directory_path.is_symlink():
            self.runtime_evidence(directory_path)
            inputs.append(directory_path)
        self.boot_absent = [str(path) for path in (name_path, directory_path) if not path.exists()]
        self.boot_files = tuple(files)
        return set(inputs+files)

    def validate_target_environment_file_labels(self, rows):
        environment = self.runtime_path(self.workdir/".env")
        require(environment == environment.resolve(strict=True), "target environment-file path is not canonical")
        services = project_services(rows, self.project)
        for service in SERVICES:
            labels = services[service]["Config"].get("Labels") or {}
            if COMPOSE_ENV_FILE_LABEL in labels:
                require(labels[COMPOSE_ENV_FILE_LABEL] == str(environment),
                        "target Compose environment-file label differs from frozen input")

    def freeze_live(self, rows):
        services = project_services(rows, self.project)
        self.config_hash_exceptions = []
        running = {s: r for s, r in services.items() if r["State"]["Status"] == "running"}
        require(set(SERVICES) <= set(running), "console baseline not running")
        for row in running.values():
            require(row["State"].get("Health", {}).get("Status", "healthy") == "healthy", "project baseline unhealthy")
        self.validate_target_environment_file_labels(rows)
        chains = {s: vm.resolve_compose_chain(running, self.workdir, (s,)) for s in running}
        self.target_chains = {s: tuple(chain) for s, chain in chains.items() if s in SERVICES}
        model = self.boot_render(self.boot_files)
        require(model.get("name") == self.project, "boot Compose project differs")
        daemon_logging = run(["docker", "info", "--format", "{{.LoggingDriver}}"])
        # Authenticate preserved services before a target hash probe can create
        # temporary containers. Their boot model stays authoritative.
        for service, chain in sorted(chains.items(), key=lambda entry: entry[0] in SERVICES):
            historical = self.render(chain)
            require(historical.get("name") == self.project, "historical project differs")
            for kind in ("networks", "volumes", "configs", "secrets"):
                require(model.get(kind) == historical.get(kind), "historical resources differ")
            require(service in model["services"] and service in historical["services"], "historical service absent")
            item = copy.deepcopy(historical["services"][service])
            image = self.image(item["image"])
            require(image["Id"] == running[service]["Image"], "live image differs from declared Compose")
            actual = dict(v.split("=", 1) for v in running[service]["Config"].get("Env", []) if "=" in v)
            require(all(str(v) == actual.get(k) for k, v in item.get("environment", {}).items() if v is not None),
                    "live environment differs from declared Compose")
            if service not in SERVICES:
                boot_item = model["services"][service]
                require(self.image(boot_item["image"])["Id"] == image["Id"],
                        "non-target boot image differs from live image")
                equivalent = copy.deepcopy(item)
                equivalent["image"] = boot_item["image"]
                if boot_item.get("pull_policy") == "never" and "pull_policy" not in item:
                    equivalent["pull_policy"] = "never"
                require(equivalent == boot_item,
                        "non-target boot model differs from historical live configuration")
                continue
            if service in SERVICES:
                value = self.compose("config", "--hash", service, files=chain).split()
                expected = [service, running[service]["Config"].get("Labels", {}).get("com.docker.compose.config-hash")]
                if value != expected:
                    # config --hash 渲染与容器标签不一致时的独立证据路径：同构探针
                    # compose create 的 stamp 等于真实容器标签即认定 match（渲染路径
                    # 差异，如 env_file 服务），渲染与 stamp 均不等才 fail-closed。
                    stamp = self.probe_config_stamp(service, chain, image["Id"])
                    require(stamp == expected[1], "historical service config hash differs")
                    self.config_hash_exceptions.append(dict(
                        service=service, rendered=value[1] if len(value) > 1 else None, stamp=stamp,
                        label=expected[1], probe_project=self.project+"-hashprobe",
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
                validate_runtime_model(service, item, historical, running[service], image, daemon_logging)
            model["services"][service] = item
        return model, {path for chain in chains.values() for path in chain}

    def probe_compose_argv(self, probe_project, files, *args):
        argv = ["sh", str(self.workdir/"compose-wrapper.sh"), "--project-name", probe_project,
                "--project-directory", str(self.workdir), "--env-file", str(self.workdir/".env")]
        for path in files:
            argv += ["-f", str(path)]
        return argv+list(args)

    def live_container_snapshot(self):
        return {row["Id"]: dict(names=row.get("Names") or [row.get("Name", "")], created=row.get("Created"),
                                started=row["State"].get("StartedAt"), status=row["State"].get("Status"),
                                restarts=row["RestartCount"], image=row["Image"])
                for row in inspect_all()
                if (row["Config"].get("Labels") or {}).get("com.docker.compose.project") == self.project}

    def probe_project_resources(self, probe_project):
        containers = run(["docker", "ps", "-a", "--filter", "label=com.docker.compose.project="+probe_project,
                          "--format", "{{.ID}} {{.Names}}"], log=self.log)
        networks = run(["docker", "network", "ls", "--filter", "label=com.docker.compose.project="+probe_project,
                        "--format", "{{.ID}} {{.Name}}"], log=self.log)
        volumes = run(["docker", "volume", "ls", "--filter", "label=com.docker.compose.project="+probe_project,
                       "--format", "{{.Name}}"], log=self.log)
        return [line.split() for line in containers.splitlines() if line.strip()], \
               [line.split() for line in networks.splitlines() if line.strip()], \
               [line for line in volumes.splitlines() if line.strip()]

    def probe_cleanup(self, probe_project, files):
        # 清理前先列出探针项目名下全部资源并核对只含探针自建项；严禁任何作用于
        # 真实项目名的 down/-v 操作——down 的 --project-name 是显式探针名。
        containers, networks, volumes = self.probe_project_resources(probe_project)
        for _, name in containers:
            require(name.startswith(probe_project+"-"), "probe cleanup scope check failed (container)")
        for _, name in networks:
            require(name.startswith(probe_project+"_"), "probe cleanup scope check failed (network)")
        for name in volumes:
            require(name.startswith(probe_project+"_"), "probe cleanup scope check failed (volume)")
        argv = self.probe_compose_argv(probe_project, files, "down", "--volumes", "--remove-orphans")
        require(argv[3] == probe_project, "probe cleanup project name misplaced")
        run(argv, cwd=self.workdir, env=self.compose_environment(), log=self.log)
        containers, networks, volumes = self.probe_project_resources(probe_project)
        require(not containers and not networks and not volumes, "probe resources survived cleanup")

    def probe_config_stamp(self, service, chain, expected_image_id):
        require(service in SERVICES, "probe service out of scope")
        require(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", self.project) and not self.project.endswith("-hashprobe"),
                "unexpected live Compose project name")
        probe_project = self.project+"-hashprobe"
        require(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", probe_project) and probe_project != self.project,
                "probe project name invalid")
        files = tuple(chain)
        snapshot = self.live_container_snapshot()
        stamp = None
        try:
            self.check_implementation()
            run(self.probe_compose_argv(probe_project, files, "create", service),
                cwd=self.workdir, env=self.compose_environment(), log=self.log)
            listing = [line.split() for line in run(["docker", "ps", "-a",
                                                      "--filter", "label=com.docker.compose.project="+probe_project,
                                                      "--filter", "label=com.docker.compose.service="+service,
                                                      "--format", "{{.ID}} {{.Names}}"], log=self.log).splitlines() if line.strip()]
            require(len(listing) == 1, "ambiguous probe container")
            identifier, name = listing[0]
            require(name.startswith(probe_project+"-"), "probe container name unexpected")
            row = json.loads(run(["docker", "container", "inspect", identifier]))[0]
            require(row["State"]["Status"] == "created", "probe container unexpectedly started")
            require(row["Image"] == expected_image_id, "probe container image differs from live")
            stamp = row["Config"].get("Labels", {}).get("com.docker.compose.config-hash")
            require(stamp, "probe config hash missing")
        finally:
            # 探针超时或失败同样先清理再让异常传播（fail-closed），并复核真实项目
            # 容器集合逐字节不变。
            self.probe_cleanup(probe_project, files)
            require(self.live_container_snapshot() == snapshot, "real project containers changed during hash probe")
        return stamp

    def freeze_boot_images(self):
        images = {}
        tags = {image_reference(record["tag"]) for record in self.manifest["services"].values()}
        for service, item in self.boot_render(self.boot_files).get("services", {}).items():
            if service not in SERVICES:
                reference = item.get("image")
                require(reference and image_reference(reference) not in tags, "candidate tag collision with non-target boot image")
                images[reference] = self.image(reference)["Id"]
        return images

    def check_boot_images(self, images):
        require(all(self.image(reference)["Id"] == identity for reference, identity in images.items()),
                "non-target boot image reference changed")

    def stage(self):
        require(not self.state.exists(), "release state exists; inspect before retrying")
        require({p.name for p in self.media.iterdir()} <= set(MEDIA_FILES+("apply.log",)), "unexpected console media files")
        require(shutil.disk_usage(self.media).free >= 4*1024**3, "insufficient free space")
        rows = inspect_all()
        controls = [r for r in rows if (r["Config"].get("Labels") or {}).get("com.docker.compose.service") == "control-plane" and r["State"]["Status"] == "running"]
        require(len(controls) == 1, "ambiguous console deployment")
        labels = controls[0]["Config"]["Labels"]
        self.project = labels["com.docker.compose.project"]
        current = vm.ROOT/"current"
        require(current.is_symlink(), "current runtime root is not a symlink")
        self.root_link = os.readlink(current)
        self.release_root = current.resolve(strict=True)
        require(self.release_root.parent == vm.ROOT/"releases", "unexpected current runtime root")
        self.workdir = Path(labels["com.docker.compose.project.working_dir"])
        require(self.workdir == self.release_root/"deploy/docker-compose", "live working directory differs from current root")
        self.runtime_path(self.workdir/"active-config", directory=True)
        self.implementation = self.compose_implementation()
        self.live = self.workdir/"active-config"/(self.manifest["release_id"]+".json")
        self.overlay = self.workdir/"active-config"/(self.manifest["release_id"]+"-persistent.json")
        require(all(not p.exists() and not p.is_symlink() for p in (self.live, self.overlay)), "active console config already exists")
        files = self.boot_inputs()
        self.absent_inputs = set()
        files.update(self.referenced_inputs(self.boot_files))
        running = {s: r for s, r in project_services(rows, self.project).items() if r["State"]["Status"] == "running"}
        for service in running:
            chain = vm.resolve_compose_chain(running, self.workdir, (service,))
            files.update(chain)
            files.update(self.referenced_inputs(chain))
        hashes = {str(path): vm.digest(self.runtime_path(path)) for path in sorted(files)}
        model, live_inputs = self.freeze_live(rows)
        require(live_inputs <= files, "runtime Compose input appeared during stage")
        boot_images = self.freeze_boot_images()
        original_policy = self.policy(rows)
        # 2.8.0 离线整装线的 system_settings 不再写入 billing_enabled 行，运行
        # 模式由冻结的 compose env（BILLING_ENABLED）决定，与 live 容器 env 一致
        # （freeze_live 已校验 environment 等于历史模型）。库行存在时仍优先以库为准。
        billing_mode = original_policy.get("billing_enabled")
        if billing_mode is None:
            billing_mode = dict(v.split("=", 1) for v in
                                project_services(rows, self.project)["control-plane"]["Config"].get("Env", []) if "=" in v
                                ).get("BILLING_ENABLED")
        require(billing_mode == self.manifest["billing_enabled"], "billing compile value differs from managed mode")
        services = project_services(rows, self.project)
        for service in SERVICES:
            require(portable_image_id(self.image(services[service]["Image"])) == self.manifest["services"][service]["base_image_id"],
                    "candidate base differs from real live image")
            require(not model["services"][service].get("build") and not model["services"][service].get("env_file"),
                    "console runtime cannot retain build/env_file inputs")
        require(seed_hashes(services["control-plane"]["Id"]) == {"files": self.manifest["control_plane_seeds_sha256"],
                                                                 "directories": self.manifest["control_plane_seed_directories"]}, "preserved seeds differ from live tree")
        check_image_archive(self.media, self.manifest)
        self.check_boot_images(boot_images)
        run(["docker", "image", "load", "-i", str(self.media/"images.tar")], timeout=600, log=self.log)
        self.check_boot_images(boot_images)
        for service in SERVICES:
            model["services"][service]["image"] = services[service]["Image"]
            model["services"][service]["pull_policy"] = "never"
        candidate = copy.deepcopy(model)
        old_images, new_images, contracts, contract_inputs, compose_image_labels = {}, {}, {}, {}, {}
        for service in SERVICES:
            record = self.manifest["services"][service]
            image = self.image(record["tag"])
            require(portable_image_id(image) == record["image_id"], "candidate image config differs")
            expected = dict(zip(IMAGE_LABELS, (self.manifest["revision"], self.manifest["tree"], record["base_image_id"], self.manifest["release_id"])))
            require(all(image["Config"].get("Labels", {}).get(k) == v for k, v in expected.items()), "candidate provenance differs")
            require(image["Config"].get("User") not in (None, "", "root", "0", "0:0"), "candidate runtime must remain non-root")
            old_images[service], new_images[service] = services[service]["Image"], image["Id"]
            contracts[service] = runtime_contract(services[service], allow_provenance=True)
            contract_inputs[service] = build_runtime_contract(services[service], allow_provenance=True)
            compose_image_labels[service] = services[service]["Config"].get("Labels", {}).get("com.docker.compose.image")
            require(compose_image_labels[service] in (None, services[service]["Image"]), "baseline Compose image label differs")
            item = candidate["services"][service]
            item["image"] = image["Id"]
            item["pull_policy"] = "never"
            item.setdefault("environment", {}).update(dict(zip(PROVENANCE_ENV, (self.manifest["revision"], self.manifest["version"], self.manifest["created_at"]))))
        # 依赖拓扑以渲染模型为准记录快照：verify 用它独立于容器标签比较
        # （switch 用 candidate.json 单文件重建容器，restore 用原始链重建）。
        target_depends_on = {service: candidate["services"][service].get("depends_on") for service in SERVICES}
        boot = self.boot_render(self.boot_files)
        delta = scalar_overlay(boot, candidate)
        self.state.mkdir(mode=0o700)
        for name, value in (("candidate.json", candidate), ("rollback.json", model), ("boot-overlay.json", delta)):
            write_json(self.state/name, value)
        for name, value in (("candidate.json", candidate), ("rollback.json", model)):
            require(self.render((self.state/name,)) == value, "frozen Compose round-trip differs")
        require(self.boot_render((*self.boot_files, self.state/"boot-overlay.json")) == candidate, "boot chain render differs from candidate")
        prefix = self.previous_chain if self.chain_present else b""
        if prefix and not prefix.endswith(b"\n"):
            prefix += b"\n"
        atomic_bytes(self.state/"boot-chain.new", prefix+str(self.overlay).encode()+b"\n")
        atomic_bytes(self.state/"boot-chain.previous", self.previous_chain)
        previous = self.pointer_bytes()
        write_json(self.state/"previous-current.json", None if previous is None else previous.decode())
        before = dict(project=self.project, workdir=str(self.workdir), release_root=str(self.release_root), root_link=self.root_link,
                      live=str(self.live), overlay=str(self.overlay), chain=str(self.chain), chain_present=self.chain_present,
                      chain_sha256=vm.digest(self.chain) if self.chain_present else None, boot_files=[str(p) for p in self.boot_files],
                      boot_arguments=self.boot_arguments, boot_absent=self.boot_absent, absent_inputs=sorted(self.absent_inputs),
                      implementation=self.implementation, boot_images=boot_images, runtime=fingerprints(rows),
                      non_target=non_targets(rows, self.project), old_images=old_images, new_images=new_images,
                      target_chains={service: [str(path) for path in self.target_chains[service]] for service in SERVICES},
                      target_contracts=contracts, target_contract_inputs=contract_inputs,
                      target_depends_on=target_depends_on,
                      target_compose_image_labels=compose_image_labels, policy=original_policy, files=hashes,
                      boot_env_exceptions=getattr(self, "boot_env_exceptions", []),
                      config_hash_exceptions=getattr(self, "config_hash_exceptions", []),
                      media={name: vm.digest(self.media/name) for name in MEDIA_FILES},
                      artifacts={name: vm.digest(self.state/name) for name in ARTIFACTS})
        require(fingerprints(inspect_all()) == fingerprints(rows), "runtime changed during stage")
        require(all(vm.digest(self.runtime_path(p)) == checksum for p, checksum in hashes.items()), "configuration changed during stage")
        require(self.policy(inspect_all()) == original_policy and self.pointer_bytes() == previous, "managed mode/active pointer changed during stage")
        require(current.is_symlink() and os.readlink(current) == self.root_link and current.resolve(strict=True) == self.release_root, "current root changed during stage")
        require((self.chain_present and self.chain.read_bytes() == self.previous_chain) or
                (not self.chain_present and not self.chain.exists() and not self.chain.is_symlink()), "boot chain changed during stage")
        require(all(not Path(path).exists() and not Path(path).is_symlink() for path in self.boot_absent), "boot arguments changed during stage")
        require(all(not Path(path).exists() and not Path(path).is_symlink() for path in self.absent_inputs), "referenced input appeared during stage")
        self.check_implementation()
        self.check_boot_images(boot_images)
        write_json(self.state/"before.json", before)
        self.event("STAGED console-only: two services and scalar boot overlay; database unchanged")

    def load_state(self):
        before_path = protected(self.state/"before.json")
        self.before_sha = vm.digest(before_path)
        self.before = json.loads(before_path.read_text())
        self.project = self.before["project"]
        self.workdir, self.release_root = Path(self.before["workdir"]), Path(self.before["release_root"])
        self.live, self.overlay, self.chain = (Path(self.before[key]) for key in ("live", "overlay", "chain"))
        require(self.release_root.parent == vm.ROOT/"releases" and self.workdir == self.release_root/"deploy/docker-compose" and
                self.live == self.workdir/"active-config"/(self.manifest["release_id"]+".json") and
                self.overlay == self.workdir/"active-config"/(self.manifest["release_id"]+"-persistent.json") and
                self.chain == self.workdir/".upgrade/compose-files", "saved runtime path differs")
        require(set(self.before["artifacts"]) == set(ARTIFACTS), "saved artifacts incomplete")
        for name, checksum in self.before["artifacts"].items():
            require(vm.digest(protected(self.state/name)) == checksum, "saved rollback/configuration changed")
        self.previous = json.loads((self.state/"previous-current.json").read_text())
        self.previous = None if self.previous is None else self.previous.encode()
        self.boot_files = tuple(Path(p) for p in self.before["boot_files"])
        self.boot_arguments = self.before["boot_arguments"]
        self.implementation = self.before["implementation"]
        self.chain_present = self.before["chain_present"]
        self.previous_chain = (self.state/"boot-chain.previous").read_bytes()

    def check_inputs(self):
        self.check_implementation()
        current = vm.ROOT/"current"
        require(current.is_symlink() and os.readlink(current) == self.before["root_link"] and
                current.resolve(strict=True) == self.release_root, "current root changed")
        for path, checksum in self.before["files"].items():
            require(vm.digest(self.runtime_path(path)) == checksum, "original configuration input changed")
        for path in self.before["boot_absent"]:
            require(not Path(path).exists() and not Path(path).is_symlink(), "boot argument input appeared")
        for path in self.before["absent_inputs"]:
            require(not Path(path).exists() and not Path(path).is_symlink(), "Compose referenced input appeared")
        for name, checksum in self.before["media"].items():
            require(vm.digest(protected(self.media/name)) == checksum, "release media changed")
        self.check_boot_images(self.before["boot_images"])

    def check_preserved(self, rows):
        require(non_targets(rows, self.project) == self.before["non_target"], "non-target container identity/configuration changed")
        require(vm.digest(protected(self.state/"before.json")) == self.before_sha, "saved before evidence changed")
        for name, checksum in self.before["artifacts"].items():
            require(vm.digest(protected(self.state/name)) == checksum, "saved transaction artifact changed")
        self.check_inputs()
        require(self.policy(rows) == self.before["policy"], "managed mode changed")

    def check_boot(self, deployed):
        if deployed:
            require(vm.digest(self.runtime_evidence(self.chain)) == self.before["artifacts"]["boot-chain.new"] and
                    vm.digest(self.runtime_evidence(self.overlay)) == self.before["artifacts"]["boot-overlay.json"], "active boot chain/overlay changed")
            require(self.boot_render((*self.boot_files, self.overlay)) == json.loads((self.state/"candidate.json").read_text()),
                    "active boot render differs")
        elif self.chain_present:
            require(vm.digest(self.runtime_evidence(self.chain)) == self.before["chain_sha256"], "original boot chain changed")
        else:
            require(not self.chain.exists() and not self.chain.is_symlink(), "boot chain appeared")

    def preflight(self):
        self.load_state()
        rows = inspect_all()
        self.validate_target_environment_file_labels(rows)
        self.check_preserved(rows)
        require(fingerprints(rows) == self.before["runtime"], "runtime changed since stage")
        require(self.pointer_bytes() == self.previous, "active release changed since stage")
        self.check_boot(False)
        require(all(not p.exists() and not p.is_symlink() for p in (self.live, self.overlay)), "active config already exists")
        for service in SERVICES:
            require(portable_image_id(self.image(self.before["new_images"][service])) == self.manifest["services"][service]["image_id"],
                    "candidate image changed")
            require(self.image(self.before["old_images"][service])["Id"] == self.before["old_images"][service], "rollback image unavailable")

    def publish_live(self):
        atomic_bytes(self.live, (self.state/"candidate.json").read_bytes())

    def switch(self):
        rows = inspect_all()
        self.validate_target_environment_file_labels(rows)
        self.check_preserved(rows)
        require(fingerprints(rows) == self.before["runtime"], "runtime changed immediately before switch")
        require(self.pointer_bytes() == self.previous, "active release changed immediately before switch")
        self.check_boot(False)
        self.check_live()
        self.check_implementation()
        self.switch_attempted = True
        self.compose("up", "-d", "--no-deps", "--pull", "never", "--force-recreate", *SERVICES, files=(self.live,))

    def check_live(self, rollback=False):
        expected = self.before["artifacts"]["rollback.json" if rollback else "candidate.json"]
        require(vm.digest(self.runtime_evidence(self.live)) == expected, "active live configuration changed")

    def verify(self, rollback=False):
        self.check_live(rollback)
        deadline = time.monotonic()+180
        while True:
            rows = inspect_all()
            self.validate_target_environment_file_labels(rows)
            self.check_preserved(rows)
            services = project_services(rows, self.project)
            if all(services[s]["State"]["Status"] == "running" and services[s]["State"].get("Health", {}).get("Status", "healthy") == "healthy" for s in SERVICES):
                break
            require(time.monotonic() < deadline, "console health deadline exceeded")
            time.sleep(2)
        expected_model = json.loads((self.state/("rollback.json" if rollback else "candidate.json")).read_text())
        # 依赖拓扑独立比较：apply 用 live json（== candidate）重建容器，rollback 用
        # 原始链重建容器；两者都必须与 stage 冻结的渲染拓扑逐键一致（含
        # condition/required）。容器标签里的 depends_on 已从契约剔除，拓扑变更
        # 只能经由渲染模型进入，这里 fail-closed。
        # 依赖拓扑快照是本版本 stage 证据的必备键：旧历史媒体的回滚一律走媒体
        # 自带冻结脚本（manifest 绑定其 digest， remote 引导也执行媒体脚本），
        # 本版本脚本不接受缺键现场——防止新版 stage 漏写该键后被静默跳过比较。
        require("target_depends_on" in self.before, "saved stage evidence missing target dependency topology")
        recorded_deps = self.before["target_depends_on"]
        if rollback:
            rendered = {service: self.render(tuple(Path(p) for p in self.before["target_chains"][service]))["services"][service].get("depends_on")
                        for service in SERVICES}
        else:
            live_render = self.render((self.live,))
            rendered = {service: live_render["services"][service].get("depends_on") for service in SERVICES}
        require(rendered == recorded_deps, "target dependency topology differs from staged render")
        for service in SERVICES:
            row = services[service]
            require(row["Image"] == self.before["old_images" if rollback else "new_images"][service] and row["RestartCount"] == 0,
                    "target image/restarts differ")
            if runtime_contract(row, allow_provenance=True) != self.before["target_contracts"][service]:
                recorded = self.before.get("target_contract_inputs", {}).get(service)
                detail = contract_diff(recorded, build_runtime_contract(row, allow_provenance=True)) if recorded else "inputs not recorded"
                require(False, "target runtime contract changed: "+detail)
            expected_label = row["Image"] if self.before["target_compose_image_labels"][service] is not None else None
            require(row["Config"].get("Labels", {}).get("com.docker.compose.image") == expected_label, "target Compose image label differs")
            actual_env = dict(v.split("=", 1) for v in row["Config"].get("Env", []) if "=" in v)
            expected_env = expected_model["services"][service].get("environment", {})
            require(all(str(v) == actual_env.get(k) for k, v in expected_env.items() if v is not None), "target environment differs")
            if not rollback:
                expected_labels = dict(zip(IMAGE_LABELS, (self.manifest["revision"], self.manifest["tree"],
                                                         self.manifest["services"][service]["base_image_id"], self.manifest["release_id"])))
                require(all(row["Config"].get("Labels", {}).get(k) == v for k, v in expected_labels.items()), "runtime image provenance differs")
                for path, checksum in self.manifest["services"][service]["payload_sha256"].items():
                    actual = run(["docker", "exec", row["Id"], "sha256sum", "--", path]).split()[0]
                    require(actual == checksum, "target runtime payload differs")
        require(seed_hashes(services["control-plane"]["Id"]) == {"files": self.manifest["control_plane_seeds_sha256"],
                                                                 "directories": self.manifest["control_plane_seed_directories"]}, "preserved seeds changed")
        latest = inspect_all()
        self.check_preserved(latest)
        self.check_live(rollback)
        require(fingerprints(latest) == fingerprints(rows), "target runtime changed during verification")
        return fingerprints(rows)

    def persist_boot(self):
        self.check_boot(False)
        atomic_bytes(self.overlay, (self.state/"boot-overlay.json").read_bytes())
        require(self.boot_render((*self.boot_files, self.overlay)) == json.loads((self.state/"candidate.json").read_text()),
                "persistent boot render differs from candidate")
        atomic_bytes(self.chain, (self.state/"boot-chain.new").read_bytes())
        self.check_boot(True)

    def check_publication(self, after, pointer):
        rows = inspect_all()
        self.check_preserved(rows)
        require(fingerprints(rows) == after, "target runtime changed during receipt publication")
        self.check_live()
        self.check_boot(True)
        require(self.pointer_bytes() == pointer, "active release changed during receipt publication")

    def commit(self, after):
        self.check_publication(after, self.previous)
        write_json(self.state/"after.json", after)
        receipt = dict(schema=1, purpose=PURPOSE, status="deployed", release_id=self.manifest["release_id"],
                       revision=self.manifest["revision"], manifest_sha256=self.manifest_sha,
                       before_sha256=vm.digest(self.state/"before.json"), after_sha256=vm.digest(self.state/"after.json"),
                       media=self.before["media"], artifacts=self.before["artifacts"], old_images=self.before["old_images"],
                       images=self.before["new_images"], live_sha256=vm.digest(self.live),
                       boot_chain_sha256=vm.digest(self.chain), boot_overlay_sha256=vm.digest(self.overlay))
        write_json(self.media/"receipt.json", receipt)
        checksum = vm.digest(self.media/"receipt.json")
        self.check_publication(after, self.previous)
        pointer = dict(release=str(self.media), receipt_sha256=checksum)
        write_json(self.pointer, pointer)
        self.check_publication(after, (json.dumps(pointer, indent=2)+"\n").encode())
        self.event("COMMIT console-only receipt_sha256="+checksum)

    def unlink_atomic(self, path):
        path.unlink()
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def restore_pointer(self):
        current = self.pointer_bytes()
        if current == self.previous:
            return
        pointer = json.loads(current) if current is not None else {}
        require(pointer.get("release") == str(self.media) and pointer.get("receipt_sha256") == vm.digest(protected(self.media/"receipt.json")),
                "active receipt changed; pointer not restored")
        if self.previous is None:
            self.unlink_atomic(self.pointer)
        else:
            atomic_bytes(self.pointer, self.previous)

    def restore_boot(self):
        if self.chain.exists():
            checksum = vm.digest(self.runtime_evidence(self.chain))
            require(checksum in (self.before["chain_sha256"], self.before["artifacts"]["boot-chain.new"]), "boot chain changed; refuse overwrite")
        else:
            require(not self.chain_present, "original boot chain disappeared")
        if self.chain_present:
            if self.chain.read_bytes() != self.previous_chain:
                atomic_bytes(self.chain, self.previous_chain)
        elif self.chain.exists():
            self.unlink_atomic(self.chain)
        self.check_boot(False)

    def compensate(self, steps):
        errors = []
        for name, action in steps:
            try:
                action()
            except BaseException as error:
                errors.append(dict(step=name, failure_type=type(error).__name__))
        self.compensation_errors = errors
        require(not errors, "console compensation incomplete")

    def rollback_model(self):
        path = protected(self.state/"rollback.json")
        require(vm.digest(path) == self.before["artifacts"]["rollback.json"], "rollback configuration changed")
        self.check_inputs()
        return path

    def restore_live(self):
        path = self.rollback_model()
        checksum = vm.digest(self.runtime_evidence(self.live))
        require(checksum in (self.before["artifacts"]["candidate.json"], self.before["artifacts"]["rollback.json"]),
                "active live configuration changed; refuse overwrite")
        atomic_bytes(self.live, path.read_bytes())

    def restore_target(self, service):
        path = self.rollback_model()
        image = self.before["old_images"][service]
        require(self.image(image)["Id"] == image, "rollback image unavailable")
        # 用原始链文件重建而非 rollback.json：链渲染 == rollback.json 的目标服务
        # 模型（stage 已冻结），但 config_files 标签会回到 runtime 链而不是媒体
        # 状态目录（避免下一次 stage 的 resolve_compose_chain 拒绝现场）。
        chain = tuple(self.before["target_chains"][service])
        self.compose("up", "-d", "--no-deps", "--pull", "never", "--force-recreate", service,
                     files=chain if chain else (path,))

    def restore(self):
        self.compensate((("live", self.restore_live),
                         *((service, lambda service=service: self.restore_target(service)) for service in SERVICES),
                         ("boot", self.restore_boot), ("pointer", self.restore_pointer)))
        after = self.verify(rollback=True)
        write_json(self.media/"rollback.json", dict(status="rolled_back", purpose=PURPOSE,
                                                      release_id=self.manifest["release_id"], runtime=after,
                                                      old_images=self.before["old_images"], boot_restored=True))
        self.event("ROLLBACK console-only verified; database and all other containers untouched")

    def remove_unswitched_live(self):
        if self.live.exists() or self.live.is_symlink():
            self.check_live()
            self.unlink_atomic(self.live)

    def verify_unswitched(self):
        rows = inspect_all()
        self.check_preserved(rows)
        require(fingerprints(rows) == self.before["runtime"], "runtime changed before switch; no containers recreated")

    def apply(self):
        self.preflight()
        self.switch_attempted = False
        phase = "publish_live"
        try:
            self.publish_live()
            phase = "switch"
            self.switch()
            phase = "verify"
            after = self.verify()
            phase = "persist_boot"
            self.persist_boot()
            phase = "commit"
            self.commit(after)
        except BaseException as failure:
            result = "complete"
            try:
                if self.switch_attempted:
                    self.restore()
                else:
                    self.compensate((("live", self.remove_unswitched_live), ("boot", self.restore_boot),
                                     ("pointer", self.restore_pointer), ("runtime", self.verify_unswitched)))
            except BaseException:
                result = "incomplete"
            write_json(self.media/"failure.json", dict(purpose=PURPOSE, release_id=self.manifest["release_id"], phase=phase,
                                                        failure_type=type(failure).__name__, failure_message=str(failure)[:1500],
                                                        rollback=result,
                                                        compensation_errors=getattr(self, "compensation_errors", [])))
            if result == "incomplete":
                raise RuntimeError("console rollback incomplete; inspect protected failure evidence before retrying") from None
            raise

    def rollback(self, expected_receipt):
        receipt = pinned_receipt(self.media, expected_receipt)
        require(receipt["manifest_sha256"] == self.manifest_sha and
                vm.digest(protected(self.state/"before.json")) == receipt["before_sha256"] and
                vm.digest(protected(self.state/"after.json")) == receipt["after_sha256"], "receipt evidence changed")
        self.load_state()
        require(receipt["media"] == self.before["media"] and receipt["artifacts"] == self.before["artifacts"] and
                receipt["old_images"] == self.before["old_images"] and receipt["images"] == self.before["new_images"], "receipt binding differs")
        rows = inspect_all()
        self.check_preserved(rows)
        require(fingerprints(rows) == json.loads((self.state/"after.json").read_text()), "active containers no longer belong to receipt")
        require(vm.digest(self.runtime_evidence(self.live)) == receipt["live_sha256"] == self.before["artifacts"]["candidate.json"], "receipt live config changed")
        self.check_boot(True)
        require(pinned_receipt(self.media, expected_receipt) == receipt, "active receipt changed immediately before rollback")
        latest = inspect_all()
        self.check_preserved(latest)
        require(fingerprints(latest) == json.loads((self.state/"after.json").read_text()), "active runtime changed immediately before rollback")
        self.restore()


def pinned_receipt(media, expected):
    require(re.fullmatch(SHA256, expected), "full receipt SHA256 required")
    pointer = json.loads(protected(vm.ROOT/"development-releases/current.json").read_text())
    require(pointer == {"release": str(media), "receipt_sha256": expected}, "only the active recorded console release can be rolled back")
    require(vm.digest(protected(media/"receipt.json")) == expected, "receipt hash differs")
    receipt = json.loads((media/"receipt.json").read_text())
    require(receipt.get("schema") == 1 and receipt.get("purpose") == "console-only" and
            receipt.get("status") == "deployed" and receipt.get("release_id") == media.name, "unsupported console rollback receipt")
    require(vm.digest(protected(media/"manifest.json")) == receipt["manifest_sha256"], "recorded manifest changed")
    require(set(receipt.get("media", {})) == {"manifest.json", "images.tar", "vm_development_apply.py", "vm_console_release.py"},
            "receipt media binding incomplete")
    for name, checksum in receipt["media"].items():
        require(vm.digest(protected(media/name)) == checksum, "recorded release media changed")
    return receipt


def validate_media_entries(media):
    require(not (media/"__pycache__").exists() and not list(media.glob("*.pyc")), "unexpected cached release code")
    allowed = set(MEDIA_FILES)|{"state", "apply.log", "receipt.json", "rollback.json", "failure.json"}
    require({path.name for path in media.iterdir()} <= allowed, "unexpected console executable/media input")


def apply_guest_code(release_id, manifest_sha, action):
    from deploy_vm_development import run_installation_helper
    require(re.fullmatch(RELEASE_ID, release_id) and re.fullmatch(SHA256, manifest_sha) and action in ("stage", "apply"),
            "invalid console apply identity")
    validators = "\n\n".join(inspect.getsource(fn) for fn in
                             (require, protected, controlled_environment, validate_media_entries, run_installation_helper))
    return ("import hashlib,json,os,re,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "def digest(p):\n with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()\n"
            "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'),digest=digest)\nMEDIA_FILES="+repr(MEDIA_FILES)+"\n"+validators+"\n"
            "media=vm.ROOT/'development-releases'/"+repr(release_id)+"\n"
            "protected(media,directory=True)\nvalidate_media_entries(media)\n"
            "require(digest(protected(media/'manifest.json'))=="+repr(manifest_sha)+",'console manifest changed before execution')\n"
            "manifest=json.loads((media/'manifest.json').read_text())\n"
            "require(manifest.get('purpose')=='console-only' and manifest.get('console_only') is True,'unsupported console manifest')\n"
            "require(not (media/'__pycache__').exists() and not list(media.glob('*.pyc')),'unexpected cached release code')\n"
            "for name,field in [('vm_console_release.py','console_script_sha256'),('vm_development_apply.py','apply_script_sha256'),('images.tar','images_sha256')]:\n"
            " require(digest(protected(media/name))==manifest[field],'console media changed before execution')\n"
            "run_installation_helper(['/usr/bin/python3','-B',str(media/'vm_development_apply.py'),"+repr(action)+",'--media',str(media),"
            "'--manifest-sha256',"+repr(manifest_sha)+"],vm.ROOT)\n")


def rollback_guest_code(release_id, receipt_sha):
    from deploy_vm_development import run_installation_helper
    require(re.fullmatch(RELEASE_ID, release_id) and re.fullmatch(SHA256, receipt_sha), "invalid rollback identity")
    validators = "\n\n".join(inspect.getsource(fn) for fn in
                             (require, protected, pinned_receipt, controlled_environment, validate_media_entries, run_installation_helper))
    return ("import hashlib,json,os,re,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "def digest(p):\n with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()\n"
            "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'),digest=digest)\nSHA256="+repr(SHA256)+"\nMEDIA_FILES="+repr(MEDIA_FILES)+"\n"+validators+"\n"
            "media=vm.ROOT/'development-releases'/"+repr(release_id)+"\n"
            "protected(media,directory=True)\nvalidate_media_entries(media)\n"
            "receipt=pinned_receipt(media,"+repr(receipt_sha)+")\n"
            "require(not (media/'__pycache__').exists() and not list(media.glob('*.pyc')),'unexpected cached release code')\n"
            "manifest=json.loads((media/'manifest.json').read_text())\n"
            "require(manifest.get('purpose')=='console-only' and manifest.get('console_only') is True,'unsupported console manifest')\n"
            "for name,field in [('vm_console_release.py','console_script_sha256'),('vm_development_apply.py','apply_script_sha256')]:\n"
            " require(digest(protected(media/name))==manifest[field],'recorded release script changed')\n"
            "run_installation_helper(['/usr/bin/python3','-B',str(media/'vm_console_release.py'),'rollback','--release-id',"
            +repr(release_id)+",'--receipt-sha256',"+repr(receipt_sha)+"],vm.ROOT)\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("rollback",))
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--install-owner-uid", type=int)
    parser.add_argument("--install-owner-gid", type=int)
    args = parser.parse_args()
    require(os.geteuid() == 0, "requires VM root")
    vm.configure_installation_owner(args.install_owner_uid, args.install_owner_gid)
    require(re.fullmatch(RELEASE_ID, args.release_id), "invalid release identity")
    os.umask(0o077)
    media = vm.ROOT/"development-releases"/args.release_id
    receipt = pinned_receipt(media, args.receipt_sha256)
    release = ConsoleRelease(media, receipt["manifest_sha256"])
    release.rollback(args.receipt_sha256)


if __name__ == "__main__":
    main()
