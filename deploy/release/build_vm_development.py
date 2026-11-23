#!/usr/bin/env python3
"""Build fixed-source development images on home; never builds a customer installer."""
import argparse, datetime, fcntl, hashlib, json, os, re, shutil, stat, subprocess, tarfile, time
from pathlib import Path
SERVICES = ("control-plane", "gateway-core", "proxy-server", "worker", "web-console", "security-engine", "tier1-classifier")
ENGINEERING_SERVICES = ("gateway-core", "security-engine", "tier1-classifier")
CONSOLE_SERVICES = ("control-plane", "web-console")
IDENTITY_CHAT_SERVICES = ("control-plane", "gateway-core", "web-console", "chat-portal-ui", "chat-portal-proxy")
CONSOLE_FORBIDDEN_OVERRIDES = ("security_input_workers", "security_input_capacity", "judge_queue_capacity", "gateway_security_budget_seconds", "security_engine_client_timeout_seconds", "security_input_budget_seconds", "security_batch_budget_seconds", "semantic_request_parallelism", "semantic_window_parallelism", "semantic_max_windows")
ORIGIN = "git@github.com:yangjiyj/aiguard.git"
CENTRAL = "/srv/git/jjdguard-src.git"
PORTAL_IMAGE_LIMIT = 500*1024*1024
PORTAL_RUNTIME_REQUIRED_ENV = ("NODE_ENV", "npm_config_registry", "PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING")
PORTAL_RUNTIME_ENV = PORTAL_RUNTIME_REQUIRED_ENV + ("PRISMA_SCHEMA_ENGINE_BINARY", "PRISMA_QUERY_ENGINE_LIBRARY")
PORTAL_RUNTIME_REQUIRED = ("app/node_modules/.bin/prisma", "app/node_modules/prisma/package.json",
                          "app/node_modules/@prisma/engines/schema-engine-linux-musl-openssl-3.0.x",
                          "app/node_modules/@prisma/engines/libquery_engine-linux-musl-openssl-3.0.x.so.node",
                          "app/node_modules/.prisma/client/index.js", "usr/local/bin/docker-entrypoint.sh")
PORTAL_FOREIGN_LIBC = ("node_modules/@img/sharp-libvips-linux-x64", "node_modules/@img/sharp-linux-x64")

def positive_integer_argument(value):
    try:
        count = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    if count <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return count

def release_services(args):
    assert not getattr(args,"chat_login_proxy_trust",False) or getattr(args,"identity_chat_only",False), "Chat login proxy trust requires identity-chat-only"
    assert not getattr(args, "include_proxy_server", False) or getattr(args, "identity_chat_only", False), "include-proxy-server requires identity-chat-only"
    if getattr(args, "identity_chat_only", False):
        assert not any(getattr(args, key, False) for key in ("console_only", "chat_theme_only", "security_engine_only", "engineering_only", "portal_only", "preserve_tier1")), "identity-chat-only modes conflict"
        assert not args.enable_file_detection, "identity-chat-only preserves file settings"
        assert all(getattr(args, key, None) is None for key in CONSOLE_FORBIDDEN_OVERRIDES), "identity-chat-only preserves security capacity"
        return IDENTITY_CHAT_SERVICES + (("proxy-server",) if getattr(args, "include_proxy_server", False) else ())
    if getattr(args, "chat_theme_only", False):
        assert not any(getattr(args, key, False) for key in ("console_only", "security_engine_only", "engineering_only", "portal_only", "preserve_tier1")), "chat-theme-only modes conflict"
        assert not args.migration and not args.enable_file_detection, "chat-theme-only preserves migrations and file settings"
        assert all(getattr(args, key, None) is None for key in CONSOLE_FORBIDDEN_OVERRIDES), "chat-theme-only preserves security capacity"
        return ()
    if getattr(args, "console_only", False):
        assert not any(getattr(args, key, False) for key in ("security_engine_only", "engineering_only", "portal_only", "preserve_tier1")), "console-only modes conflict"
        assert not args.migration and not args.enable_file_detection, "console-only preserves migrations and file settings"
        assert all(getattr(args, key, None) is None for key in CONSOLE_FORBIDDEN_OVERRIDES), "console-only preserves security capacity"
        return CONSOLE_SERVICES
    if getattr(args, "security_engine_only", False):
        assert not args.portal_only and not getattr(args, "engineering_only", False), "security-engine-only modes conflict"
        assert not args.migration and not args.enable_file_detection, "security-engine-only preserves migrations and file settings"
        return ("security-engine",)
    if getattr(args, "engineering_only", False):
        assert not args.portal_only and not args.preserve_tier1, "engineering-only modes conflict"
        assert not args.migration and not args.enable_file_detection, "engineering-only preserves migrations and file settings"
        return ENGINEERING_SERVICES
    if args.portal_only:
        assert args.preserve_tier1, "portal-only release must preserve tier1"
        return ("chat-portal-ui",)
    return SERVICES[:-1] if args.preserve_tier1 else SERVICES

def validate_installed_portal_dependencies(installed, expected):
    installed_packages = installed.get("packages", {})
    expected_packages = expected.get("packages", {})
    root = expected_packages.get("", {})
    required = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
    for name in required:
        path = "node_modules/"+name
        actual = installed_packages.get(path)
        locked = expected_packages.get(path)
        assert actual and locked and actual.get("version") == locked.get("version"), "portal root dependency differs: "+name
    for path, actual in installed_packages.items():
        if not path.startswith("node_modules/"):
            continue
        locked = expected_packages.get(path)
        assert locked and actual.get("version") == locked.get("version"), "installed portal dependency differs: "+path

def npm_environment(clean_env, billing_enabled, user_config, global_config):
    # A fixed build-only heap bound prevents one Node build from exhausting the
    # development host; overwrite inherited options rather than accepting loaders.
    return dict(clean_env, VITE_BILLING_ENABLED=billing_enabled, NEXT_PUBLIC_BILLING_ENABLED=billing_enabled,
                NODE_OPTIONS="--max-old-space-size=2048",
                NPM_CONFIG_USERCONFIG=str(user_config), NPM_CONFIG_GLOBALCONFIG=str(global_config))

def portal_runtime_base(dockerfile):
    match = re.search(r"(?m)^FROM (\S+@sha256:[0-9a-f]{64}) AS base$", dockerfile)
    assert match, "portal runtime base image is not pinned by digest"
    return match.group(1)

def portal_prisma_closure(dockerfile):
    match = re.search(r"(?s)<<'NODE'\n(.*?)\nNODE\n", dockerfile)
    assert match and "copyPackage('prisma')" in match.group(1), "portal Prisma closure extraction is unavailable"
    return match.group(1)+"\n"

def portal_runtime_env(base_config):
    env = dict(item.split("=", 1) for item in base_config.get("Env", []) if "=" in item)
    missing = [key for key in PORTAL_RUNTIME_REQUIRED_ENV if key not in env]
    assert not missing, "portal runtime environment is incomplete: "+",".join(missing)
    return [key+"=\""+env[key]+"\"" for key in PORTAL_RUNTIME_ENV if key in env]

def portal_dockerfile(dependency, runtime_base, base_config, user, provenance):
    assert dependency != runtime_base, "portal runtime must not build on the previous portal image"
    entrypoint = base_config.get("Entrypoint")
    assert entrypoint, "portal entrypoint is unavailable"
    ports = sorted(base_config.get("ExposedPorts") or {})
    assert ports, "portal exposed ports are unavailable"
    workdir = base_config.get("WorkingDir") or "/app"
    return ["FROM "+dependency+" AS portal-dependencies",
            "FROM "+runtime_base+" AS portal-prisma-cli",
            "WORKDIR "+workdir,
            "COPY prisma-closure.js /tmp/prisma-closure.js",
            "COPY --from=portal-dependencies "+workdir+"/node_modules /tmp/portal-node_modules",
            "RUN mkdir -p node_modules/.bin"
            " && node /tmp/prisma-closure.js /tmp/portal-node_modules "+workdir+"/node_modules"
            " && cp -a /tmp/portal-node_modules/.prisma node_modules/.prisma"
            " && cp -a /tmp/portal-node_modules/.bin/prisma node_modules/.bin/prisma"
            " && find node_modules/prisma/build \\( -name '*mysql*' -o -name '*sqlite*' -o -name '*sqlserver*' -o -name '*cockroach*' \\) -delete"
            " && rm -rf node_modules/prisma/prisma-client /tmp/portal-node_modules /tmp/prisma-closure.js",
            "FROM "+runtime_base+" AS portal-runtime",
            "WORKDIR "+workdir,
            "ENV "+" ".join(portal_runtime_env(base_config)),
            "RUN addgroup -S "+user+" && adduser -S "+user+" -G "+user,
            "COPY --from=portal-prisma-cli --chown="+user+" "+workdir+"/node_modules ./node_modules",
            "COPY --chown="+user+" runtime/ /",
            "ENV "+" ".join(provenance),
            "EXPOSE "+" ".join(port.split("/")[0] for port in ports),
            "ENTRYPOINT "+json.dumps(entrypoint),
            "USER "+user]


PORTAL_IDENTITY_PROBE = r"""set -eu
printf 'uid=%s\ngid=%s\ngroups=%s\n' "$(id -u)" "$(id -g)" "$(id -G)"
awk -F: '{printf "passwd=%s:%s:%s\n",$1,$3,$4}' /etc/passwd
awk -F: '{printf "group=%s:%s\n",$1,$3}' /etc/group
"""


def portal_user_reference(user):
    assert isinstance(user, str) and re.fullmatch(r"(?:[a-z_][a-z0-9_-]{0,31}|[0-9]+)(?::(?:[a-z_][a-z0-9_-]{0,31}|[0-9]+))?", user), "portal runtime user reference is malformed"
    parts = user.split(":")
    assert parts[0] not in ("root", "0") and (len(parts) == 1 or parts[1] not in ("root", "0")), "portal runtime must retain a non-root numeric identity"
    return parts


def portal_numeric_id(value):
    assert isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value), "portal numeric identity is malformed"
    number = int(value)
    assert number <= 2147483647, "portal numeric identity is outside the supported range"
    return number


def validate_portal_identity(identity, user):
    portal_user_reference(user)
    assert isinstance(identity, dict) and set(identity) == {"configured_user", "uid", "gid", "groups", "user_name", "passwd_gid", "group_names"}, "portal numeric identity proof is incomplete"
    assert identity["configured_user"] == user, "portal numeric identity uses another runtime user"
    for field in ("uid", "gid", "passwd_gid"):
        assert type(identity[field]) is int and 0 < identity[field] <= 2147483647, "portal runtime must retain a non-root numeric identity"
    assert isinstance(identity["user_name"], str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", identity["user_name"]) and identity["user_name"] != "root", "portal account name is unsupported"
    groups = identity["groups"]
    assert isinstance(groups, list) and all(type(value) is int and 0 < value <= 2147483647 for value in groups), "portal runtime groups are malformed"
    assert groups == sorted(set(groups)) and identity["gid"] in groups, "portal runtime group must be non-root"
    entries = identity["group_names"]
    assert isinstance(entries, list) and all(isinstance(item, dict) and set(item) == {"gid", "name"} for item in entries), "portal group proof is malformed"
    assert all(type(item["gid"]) is int and 0 < item["gid"] <= 2147483647 for item in entries), "portal group proof contains invalid numeric IDs"
    assert [item["gid"] for item in entries] == sorted(set(groups) | {identity["passwd_gid"]}), "portal group proof is incomplete or duplicated"
    assert len({item["name"] for item in entries}) == len(entries), "portal group names are ambiguous"
    assert all(isinstance(item["name"], str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", item["name"]) and item["name"] != "root" for item in entries), "portal group name is unsupported"
    reference = portal_user_reference(user)
    assert (identity["uid"] == int(reference[0]) if reference[0].isdigit() else identity["user_name"] == reference[0]), "portal configured user does not match its numeric account"
    if len(reference) == 2:
        name = next(item["name"] for item in entries if item["gid"] == identity["gid"])
        assert (identity["gid"] == int(reference[1]) if reference[1].isdigit() else name == reference[1]), "portal configured group does not match its numeric account"
    else:
        assert identity["gid"] == identity["passwd_gid"], "portal default primary group differs from passwd"
    return identity


def parse_portal_identity(output, user):
    portal_user_reference(user)
    scalars, accounts, groups = {}, [], []
    for line in output.splitlines():
        assert "=" in line, "portal identity probe returned unknown output"
        key, value = line.split("=", 1)
        if key in ("uid", "gid", "groups"):
            assert key not in scalars, "portal identity probe duplicated a scalar"
            scalars[key] = value
        elif key == "passwd":
            fields = value.split(":")
            assert len(fields) == 3, "portal passwd identity is malformed"
            accounts.append((fields[0], portal_numeric_id(fields[1]), portal_numeric_id(fields[2])))
        elif key == "group":
            fields = value.split(":")
            assert len(fields) == 2, "portal group identity is malformed"
            groups.append((fields[0], portal_numeric_id(fields[1])))
        else:
            raise AssertionError("portal identity probe returned unknown output")
    assert set(scalars) == {"uid", "gid", "groups"}, "portal identity probe did not resolve numeric identity"
    uid, gid = portal_numeric_id(scalars["uid"]), portal_numeric_id(scalars["gid"])
    memberships = [portal_numeric_id(value) for value in scalars["groups"].split()]
    assert memberships and len(memberships) == len(set(memberships)), "portal runtime groups are ambiguous"
    owners = [row for row in accounts if row[1] == uid]
    assert len(owners) == 1, "portal numeric UID has no unique passwd account"
    names = []
    for required in sorted(set(memberships) | {owners[0][2]}):
        match = [row for row in groups if row[1] == required]
        assert len(match) == 1, "portal numeric GID has no unique group account"
        names.append({"gid": required, "name": match[0][0]})
    identity = dict(configured_user=user, uid=uid, gid=gid, groups=sorted(memberships),
                    user_name=owners[0][0], passwd_gid=owners[0][2], group_names=names)
    return validate_portal_identity(identity, user)


def probe_portal_identity(image, config, docker_env, log=None):
    user = config.get("User")
    portal_user_reference(user)
    output = run(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                  "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", "sh", image,
                  "-ec", PORTAL_IDENTITY_PROBE], env=docker_env, log=log, capture_stdout=True)
    return parse_portal_identity(output, user)


def freeze_portal_dockerfile_identity(recipe, identity, user):
    # portal_dockerfile renders the existing layer skeleton; this required
    # production gate replaces implicit account allocation with probed IDs.
    validate_portal_identity(identity, user)
    commands = []
    for group in identity["group_names"]:
        name, gid = group["name"], group["gid"]
        lookup = f"""$(awk -F: '$1=="{name}" {{print $3}}' /etc/group)"""
        commands.append(f"""if grep -q '^{name}:' /etc/group; then [ "{lookup}" = {gid} ]; else addgroup -S -g {gid} {name}; fi""")
    name, uid = identity["user_name"], identity["uid"]
    primary = next(item["name"] for item in identity["group_names"] if item["gid"] == identity["passwd_gid"])
    passwd_uid = f"""$(awk -F: '$1=="{name}" {{print $3}}' /etc/passwd)"""
    passwd_gid = f"""$(awk -F: '$1=="{name}" {{print $4}}' /etc/passwd)"""
    commands.append(f"""if grep -q '^{name}:' /etc/passwd; then [ "{passwd_uid}" = {uid} ] && [ "{passwd_gid}" = {identity['passwd_gid']} ]; else adduser -S -u {uid} {name} -G {primary}; fi""")
    for group in identity["group_names"]:
        if group["gid"] in identity["groups"] and group["gid"] != identity["passwd_gid"]:
            commands.append("addgroup "+name+" "+group["name"])
    implicit = "RUN addgroup -S "+user+" && adduser -S "+user+" -G "+user
    assert recipe.count(implicit) == 1, "portal runtime identity layer shape changed"
    fixed = []
    for line in recipe:
        if line == implicit:
            fixed.append("RUN set -eu; "+"; ".join(commands))
        elif line.startswith("COPY "):
            fixed.append(line.replace("--chown="+user+" ", "--chown="+str(uid)+":"+str(identity["gid"])+" "))
        else:
            fixed.append(line)
    assert "USER "+user in fixed, "portal runtime user reference changed"
    return fixed


def verify_portal_numeric_identity(expected, actual):
    assert isinstance(expected, dict) and isinstance(actual, dict), "portal numeric identity proof is unavailable"
    validate_portal_identity(expected, expected.get("configured_user"))
    validate_portal_identity(actual, actual.get("configured_user"))
    assert actual == expected, "portal candidate numeric runtime identity differs from its frozen base"
    return actual

PORTAL_APPLICATION_LAYERS = 2

def verify_portal_layers(candidate, dependency, runtime, *, prisma_closure_verified=False, application_payload_verified=False):
    assert list(candidate[:len(runtime)]) == list(runtime), "portal candidate does not start from the pinned Node runtime"
    shared = 0
    while shared < min(len(candidate), len(dependency)) and candidate[shared] == dependency[shared]: shared += 1
    # Only setup layers before BOTH images' two final COPY layers may share a prefix.
    shared = min(shared, max(0, len(candidate)-PORTAL_APPLICATION_LAYERS),
                 max(0, len(dependency)-PORTAL_APPLICATION_LAYERS))
    trusted_prisma = (prisma_closure_verified is True and application_payload_verified is True and
                     len(candidate) >= len(runtime)+PORTAL_APPLICATION_LAYERS and
                     len(dependency) >= len(runtime)+PORTAL_APPLICATION_LAYERS and
                     candidate[-2] == dependency[-2] and candidate[-2] != dependency[-1])
    reused = [layer for index,layer in enumerate(candidate) if index >= max(len(runtime),shared)
              and layer in set(dependency) and not (trusted_prisma and index == len(candidate)-2)]
    assert not reused, "portal candidate reuses previous portal application layers"
    return {"shared_setup_prefix_layers":shared,
            "prisma_reuse_candidate_index":len(candidate)-2 if trusted_prisma else None,
            "prisma_reuse_diff_id":candidate[-2] if trusted_prisma else None}


def portal_tree_manifest(root):
    root = Path(root)
    assert root.is_dir() and not root.is_symlink(), "portal application root is not a directory"
    root = root.resolve()
    result = {".":{"kind":"directory", "mode":stat.S_IMODE(root.lstat().st_mode)}}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            target = os.readlink(path)
            assert not Path(target).is_absolute(), "portal dependency symlink is absolute: "+relative
            resolved = path.resolve()
            assert resolved.is_relative_to(root) and resolved.exists(), "portal dependency symlink escapes or dangles: "+relative
            result[relative] = {"kind":"symlink", "target":target, "mode":mode}
        elif path.is_dir(): result[relative] = {"kind":"directory", "mode":mode}
        elif path.is_file(): result[relative] = {"kind":"file", "sha256":digest(path), "mode":mode}
        else: raise AssertionError("unsupported portal dependency node: "+relative)
    return result


def portal_tree_digest(manifest):
    return hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def extract_portal_prisma_closure(context, dependency, docker_env, out):
    expected = context/"verified-prisma-closure"
    expected.mkdir(mode=0o700)
    # Runtime artifacts may be owner-readable only. A restricted reader copies
    # their exact bytes/modes/links; only the host proof output ownership changes.
    script = ("set -eu; mkdir -p /out/node_modules; "
              "node /source/prisma-closure.js /app/node_modules /out/node_modules; "
              "cp -a /app/node_modules/.prisma /out/node_modules/.prisma; "
              "mkdir -p /out/node_modules/.bin; cp -a /app/node_modules/.bin/prisma /out/node_modules/.bin/prisma; "
              r"find /out/node_modules/prisma/build \( -name '*mysql*' -o -name '*sqlite*' -o -name '*sqlserver*' -o -name '*cockroach*' \) -delete; "
              "rm -rf /out/node_modules/prisma/prisma-client; "
              "chown -hR "+str(os.getuid())+":"+str(os.getgid())+" /out/node_modules")
    run(["docker","run","--rm","--pull=never","--network=none","--read-only",
         "--tmpfs","/tmp:rw,nosuid,size=64m","--user","0:0",
         "--cap-drop=ALL","--cap-add=DAC_OVERRIDE","--cap-add=CHOWN","--cap-add=FOWNER",
         "--security-opt=no-new-privileges",
         "--mount","type=bind,src="+str(context)+",dst=/source,readonly",
         "--mount","type=bind,src="+str(expected)+",dst=/out",
         "--entrypoint","sh",dependency,"-ec",script],env=docker_env,log=out/"portal-prisma-closure-proof.log")
    closure = portal_tree_manifest(expected)
    assert "node_modules/prisma/package.json" in closure, "independent Prisma CLI closure is empty"
    return closure


def validate_portal_prisma_closure(root, expected_lock, engine_lock):
    root = Path(root)
    locked_packages = expected_lock["packages"]
    visited = {}
    def check(name):
        if name in visited: return
        assert name and not name.startswith("/") and ".." not in name.split("/"), "invalid Prisma package name"
        path = root/"node_modules"/name/"package.json"
        assert path.is_file() and not path.is_symlink(), "Prisma package manifest is unavailable: "+name
        manifest = json.loads(path.read_text())
        locked = locked_packages.get("node_modules/"+name)
        assert locked and manifest.get("version") == locked.get("version"), "Prisma package differs from frozen lock: "+name
        for field in ("dependencies", "optionalDependencies"):
            assert manifest.get(field, {}) == locked.get(field, {}), "Prisma dependency closure differs from frozen lock: "+name
        visited[name] = manifest["version"]
        for dependency in set(manifest.get("dependencies", {})) | set(manifest.get("optionalDependencies", {})):
            check(dependency)
    check("prisma")
    assert engine_lock["platform"] == "linux-musl-openssl-3.0.x", "portal Prisma engine platform differs"
    assert engine_lock["prisma_version"] == visited["prisma"], "portal Prisma engine version differs"
    for entry in engine_lock["manifest"]:
        path = root/"node_modules/@prisma/engines"/entry["path"]
        assert path.is_file() and not path.is_symlink() and path.stat().st_size == entry["size"] and digest(path) == entry["sha256"], "portal Prisma engine differs from frozen lock"
    return visited


def verify_portal_union(application_root, closure, fresh_payload):
    expected = dict(closure)
    expected.update(fresh_payload)
    actual = portal_tree_manifest(application_root)
    assert actual == expected, "portal application tree differs from independent Prisma closure and frozen source payload"
    return portal_tree_digest(actual)

def verify_portal_image_size(size):
    assert size <= PORTAL_IMAGE_LIMIT, "portal candidate image exceeds the 500 MiB contract: "+str(size)

def verify_portal_runtime_contents(present):
    missing = [path for path in PORTAL_RUNTIME_REQUIRED if path not in present]
    assert not missing, "portal runtime is missing required Prisma content: "+",".join(missing)

def proxy_runtime_contract(config, dockerfile):
    runtime = re.search(r"(?m)^ARG NODE_IMAGE=(\S+@sha256:[0-9a-f]{64})$", dockerfile)
    assert runtime and "FROM ${NODE_IMAGE} AS runtime" in dockerfile, "proxy Node runtime is not pinned"
    assert config.get("WorkingDir") == "/app", "proxy workdir differs from the product contract"
    assert config.get("User") in (None, "", "root", "0", "0:0"), "proxy product runtime user differs"
    assert config.get("Entrypoint") == ["docker-entrypoint.sh"], "proxy entrypoint differs"
    command = ["sh", "-c", "./node_modules/.bin/prisma migrate deploy && exec node dist/server.js"]
    assert config.get("Cmd") == command, "proxy startup differs from the product Dockerfile"
    assert re.search(r"(?m)^CMD "+re.escape(json.dumps(command))+"$", dockerfile), "proxy product startup changed"
    environment = dict(value.split("=", 1) for value in config.get("Env", []) if "=" in value)
    assert environment.get("NODE_VERSION", "").startswith("22."), "proxy must retain Node 22"
    assert environment.get("NODE_ENV") == "production", "proxy must retain the production environment"
    assert not any(key.startswith("PRISMA_") for key in environment), "proxy Prisma runtime settings need review"
    return runtime.group(1)


PROXY_PRODUCTION_CLOSURE = r'''
const fs = require('fs'), path = require('path');
const [source, destination, manifestPath] = process.argv.slice(2);
const copied = new Set();
function locate(name, from) {
  for (let cursor = from; ; cursor = path.dirname(cursor)) {
    const candidate = path.join(cursor, 'node_modules', ...name.split('/'));
    if (fs.existsSync(path.join(candidate, 'package.json'))) return fs.realpathSync(candidate);
    if (cursor === path.dirname(cursor)) throw new Error('missing production dependency: ' + name);
  }
}
function copyPackage(name, from, parent) {
  const root = locate(name, from), manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  let target = path.join(destination, ...name.split('/'));
  if (fs.existsSync(path.join(target, 'package.json')) &&
      JSON.parse(fs.readFileSync(path.join(target, 'package.json'), 'utf8')).version !== manifest.version)
    target = path.join(parent, 'node_modules', ...name.split('/'));
  if (copied.has(target)) return;
  copied.add(target);
  fs.cpSync(root, target, {recursive:true, dereference:true,
    filter: item => !path.relative(root, item).split(path.sep).includes('node_modules')});
  for (const dependency of Object.keys(manifest.dependencies || {})) copyPackage(dependency, root, target);
  for (const dependency of Object.keys(manifest.optionalDependencies || {})) {
    let present = true;
    try { locate(dependency, root); } catch (error) { present = false; }
    if (present) copyPackage(dependency, root, target);
  }
}
const application = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
for (const dependency of Object.keys(application.dependencies || {})) copyPackage(dependency, path.dirname(source), destination);
const clientRoot = locate('@prisma/client', path.dirname(source));
const virtualClient = path.join(path.dirname(path.dirname(clientRoot)), '.prisma');
const generated = fs.existsSync(path.join(virtualClient, 'client/index.js')) ? virtualClient : path.join(source, '.prisma');
if (!fs.existsSync(path.join(generated, 'client/index.js'))) throw new Error('missing generated Prisma client');
fs.cpSync(generated, path.join(destination, '.prisma'), {recursive:true, dereference:true});
fs.mkdirSync(path.join(destination, '.bin'), {recursive:true});
fs.writeFileSync(path.join(destination, '.bin/prisma'),
  '#!/bin/sh\nexec node "$(dirname "$0")/../prisma/build/index.js" "$@"\n', {mode:0o755});
'''


def build_proxy_payload(app, context, base, config, source, docker_env, npm_env, out, pnpm_store):
    proxy_runtime_contract(config, (app/"Dockerfile").read_text())
    cache_env = dict(npm_env, COREPACK_ENABLE_NETWORK="0", COREPACK_ENABLE_DOWNLOAD_PROMPT="0", NPM_CONFIG_OFFLINE="true", CI="true")
    assert json.loads((app/"package.json").read_text()).get("packageManager") == "pnpm@10.10.0", "proxy pnpm version is not fixed"
    assert run(["corepack", "pnpm", "--version"], cwd=app, env=cache_env) == "10.10.0", "proxy pnpm tool differs"
    run(["corepack", "pnpm", "install", "--offline", "--frozen-lockfile", "--ignore-scripts", "--store-dir", pnpm_store], cwd=app,
        env=cache_env, log=out/"chat-portal-proxy-dependencies.log")
    container = run(["docker", "create", base], env=docker_env)
    inputs = context/"proxy-inputs"
    inputs.mkdir()
    try:
        for name in ("package.json", "pnpm-lock.yaml"):
            target = context/("base-"+name)
            run(["docker", "cp", container+":/app/"+name, str(target)], env=docker_env)
            assert digest(target) == digest(app/name), "proxy dependencies differ from frozen "+name
            shutil.copy2(app/name, inputs/name)
    finally:
        run(["docker", "rm", container], env=docker_env)
    shutil.copytree(app/"prisma", inputs/"prisma")
    (inputs/"production-closure.cjs").write_text(PROXY_PRODUCTION_CLOSURE)
    output = context/"proxy-runtime-dependencies"
    output.mkdir(mode=0o700)
    script = ("""set -eu; test "$(node -p 'process.versions.node.split(".")[0]')" = 22; """
              "mkdir -p /tmp/proxy; cp -R /app/node_modules /tmp/proxy/node_modules; "
              "cp /source/package.json /source/pnpm-lock.yaml /tmp/proxy/; "
              "cp -a /source/prisma /tmp/proxy/prisma; cd /tmp/proxy; "
              "DATABASE_URL=file:/tmp/proxy-build.db PRISMA_GENERATE_SKIP_AUTOINSTALL=true "
              "PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1 PRISMA_ENGINES_MIRROR=http://127.0.0.1:9 "
              "node /app/node_modules/prisma/build/index.js generate; "
              "node /source/production-closure.cjs /tmp/proxy/node_modules /out/node_modules /tmp/proxy/package.json")
    run(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
         "--tmpfs", "/tmp:rw,nosuid,size=1g", "--user", str(os.getuid())+":"+str(os.getgid()),
         "--mount", "type=bind,src="+str(inputs)+",dst=/source,readonly",
         "--mount", "type=bind,src="+str(output)+",dst=/out", "--entrypoint", "sh", base, "-ec", script],
        env=docker_env, log=out/"chat-portal-proxy-prisma.log")
    locked = json.loads((source/"deploy/docker-compose/release-prisma-engines.lock.json").read_text())
    assert locked["platform"] == "linux-musl-openssl-3.0.x", "proxy Prisma engine platform differs"
    for entry in locked["manifest"]:
        path = output/"node_modules/@prisma/engines"/entry["path"]
        assert path.is_file() and not path.is_symlink() and path.stat().st_size == entry["size"] and digest(path) == entry["sha256"], "proxy Prisma engine differs from frozen lock"
    for name in ("prisma", "@prisma/client"):
        package = json.loads((output/"node_modules"/name/"package.json").read_text())
        assert package["version"] == locked["prisma_version"], "proxy Prisma dependency version differs"
    required = ("node_modules/.bin/prisma", "node_modules/.prisma/client/index.js")
    assert all((output/name).is_file() and not (output/name).is_symlink() for name in required), "proxy Prisma runtime incomplete"
    shutil.copytree(output/"node_modules/.prisma", app/"node_modules/.prisma", dirs_exist_ok=True)
    run(["corepack", "pnpm", "run", "build"], cwd=app, env=cache_env, log=out/"chat-portal-proxy-build.log")
    payload = context/"runtime/app"
    for name in ("dist", "prisma"):
        shutil.copytree(app/name, payload/name)
    for name in ("package.json", "pnpm-lock.yaml"):
        shutil.copy2(app/name, payload/name)
    shutil.copytree(output/"node_modules", payload/"node_modules")


def verify_identity_chat_image_archive(media, manifest):
    assert type(manifest.get("include_proxy_server", False)) is bool, "invalid proxy-server inclusion flag"
    expected_services = IDENTITY_CHAT_SERVICES + (("proxy-server",) if manifest.get("include_proxy_server") else ())
    assert set(manifest["services"]) == set(expected_services), "identity-chat archive scope differs"
    assert digest(media/"images.tar") == manifest["images_sha256"], "identity-chat archive checksum differs"
    expected = {record["tag"]:record["image_id"] for record in manifest["services"].values()}
    with tarfile.open(media/"images.tar") as archive:
        members = archive.getmembers()
        assert len([item for item in members if item.name == "manifest.json"]) == 1, "ambiguous identity-chat archive"
        index = json.load(archive.extractfile("manifest.json"))
        assert len(index) == len(expected), "identity-chat archive contains other images"
        seen = set()
        for item in index:
            tags = item.get("RepoTags") or []
            assert len(tags) == 1 and tags[0] in expected and tags[0] not in seen, "identity-chat archive image scope differs"
            seen.add(tags[0])
            name = item["Config"]
            assert not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe identity-chat image config"
            configs = [member for member in members if member.name == name]
            assert len(configs) == 1 and configs[0].isfile(), "ambiguous identity-chat image config"
            assert "sha256:"+hashlib.file_digest(archive.extractfile(name), "sha256").hexdigest() == expected[tags[0]], "identity-chat archive image identity differs"
        assert seen == set(expected), "identity-chat archive incomplete"


def assemble_identity_chat_media(source, out, manifest, args, docker_env, archive):
    if getattr(args, "include_proxy_server", False):
        manifest["include_proxy_server"] = True
    manifest.update(identity_chat_only=True, preserve_tier1=True, source_archive_sha256=digest(archive),
                    candidate_validation={"identity_chat_payload_verified":True,
                                          "portal_navigation_paths":"explicit_base_path",
                                          "model_services":"preserved_not_touched"},
                    migration_preconditions={})
    media = out/"media"
    media.mkdir()
    migrations = media/"migrations"
    migrations.mkdir()
    assert len(set(args.migration)) == len(args.migration), "duplicate reviewed migration"
    for name in args.migration:
        assert re.fullmatch(r"[0-9]{3,}_[A-Za-z0-9_]+\.sql", name), "invalid reviewed migration filename"
        path = source/"deploy/migrations"/name
        shutil.copy2(path, migrations/name)
        manifest["migrations"][name] = digest(path)
    for migration, prerequisite in (("851_compact_nonfinding_read_metadata.sql", "850_alert_read_metadata.sql"),
                                     ("821_serialize_customer_content_projection.sql", "820_customer_content_projection_triggers.sql")):
        if migration in manifest["migrations"]:
            manifest["migration_preconditions"][prerequisite] = digest(source/"deploy/migrations"/prerequisite)
    copy_migration_runtime(source, media, manifest)
    shutil.copy2(source/"deploy/release/vm_development_apply.py", media/"vm_development_apply.py")
    manifest["apply_script_sha256"] = digest(media/"vm_development_apply.py")
    images = media/"images.tar"
    run(["docker", "image", "save", "-o", str(images), *[record["tag"] for record in manifest["services"].values()]],
        env=docker_env, log=out/"image-export.log")
    manifest["images_sha256"] = digest(images)
    verify_identity_chat_image_archive(media, manifest)
    (media/"manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps({"release_id":manifest["release_id"], "media":str(media),
                      "manifest_sha256":digest(media/"manifest.json")}), flush=True)


def verify_portal_only_release(manifest, media_names, image_tags):
    assert set(manifest["services"]) == {"chat-portal-ui"}, "portal-only release must ship only chat-portal-ui"
    assert manifest.get("portal_only") and manifest.get("preserve_tier1"), "portal-only release must preserve model services"
    assert not manifest["migrations"] and "tier1_probe_sha256" not in manifest, "portal-only release must not carry migrations or a model probe"
    offenders = sorted(name for name in media_names if "tier1" in name or "smoke" in name or "probe" in name)
    assert not offenders, "portal-only media contains model artefacts: "+",".join(offenders)
    assert image_tags == [[manifest["services"]["chat-portal-ui"]["tag"]]], "portal-only images must contain only the portal candidate"

def run(args, cwd=None, env=None, log=None, input=None, capture_stdout=False):
    if log:
        with Path(log).open("ab") as stream:
            if capture_stdout:
                # Small machine-readable probes need their stdout even when
                # diagnostics are logged. Keep stderr out of the parsed value;
                # normal build commands continue streaming without buffering.
                result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                        stderr=stream, input=input, text=True)
                stream.write(result.stdout.encode("utf-8")); stream.flush()
                result.check_returncode()
                return result.stdout.strip()
            subprocess.run(args, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, input=input, text=True)
        return ""
    return subprocess.check_output(args, cwd=cwd, env=env, text=True, input=input).strip()

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def portable_image_id(image, env=None):
    """Classic Docker identifies configs; containerd identifies OCI manifests."""
    descriptor = image.get("Descriptor") or {}
    if not descriptor:
        return image["Id"]
    raw = run(["ctr", "--address", "/run/containerd/containerd.sock", "--namespace", "moby", "content", "get", image["Id"]], env=env)
    if "sha256:"+hashlib.sha256(raw.encode()).hexdigest() != image["Id"]:
        # run strips the final newline; OCI JSON has no required trailing newline.
        raise RuntimeError("OCI manifest digest differs")
    manifest = json.loads(raw)
    config_id = manifest.get("config", {}).get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config_id):
        raise RuntimeError("OCI image config identity missing")
    return config_id


def source_gate(repo, revision):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/home/dev", "LANG": "C.UTF-8"}
    def git(*args): return run(["/usr/bin/git", "-C", str(repo), *args], env=env)
    assert re.fullmatch(r"[0-9a-f]{40}", revision), "full revision required"
    assert git("status", "--porcelain") == "", "source checkout is dirty"
    assert git("rev-parse", "HEAD") == revision
    assert git("remote", "get-url", "origin") == ORIGIN
    assert git("ls-remote", "origin", "refs/heads/main").split()[0] == revision
    assert run(["/usr/bin/git", "--git-dir="+CENTRAL, "rev-parse", "main"], env=env) == revision
    assert not git("replace", "-l"), "replace refs are forbidden"
    return git("rev-parse", "HEAD^{tree}")

def copy_portal_dependencies(source, target, env, log=None):
    source, target = Path(source), Path(target)
    assert source.is_dir() and not source.is_symlink(), "reviewed portal dependency root must be a real directory"
    assert not target.exists() and not target.is_symlink(), "portal dependency destination already exists"
    assert not target.resolve().is_relative_to(source.resolve()), "portal dependency destination overlaps input"
    # cp uses the kernel's copy_file_range path on Linux while preserving the
    # same complete files, modes and symlinks. No hard links to inputs are made.
    run(["/usr/bin/cp", "-a", "--", str(source), str(target)], env=env, log=log)

def copy_migration_runtime(source, media, manifest):
    for filename, field in (("migration-runner.sh", "migration_runner_sha256"), ("migration-version.sh", "migration_version_sha256")):
        shutil.copy2(source/"deploy/lib"/filename, media/filename)
        manifest[field] = digest(media/filename)

def payload_hashes(root):
    result = {}
    for path in sorted(Path(root).rglob("*")):
        assert not path.is_symlink(), "runtime payload symlink is unsupported"
        if path.is_file():
            result["/"+str(path.relative_to(root))] = digest(path)
    return result

def seed_tree(root):
    root = Path(root)
    assert root.is_dir() and not root.is_symlink(), "seed root is unsupported"
    hashes, directories = {}, ["/etc/uag/seeds"]
    for path in sorted(root.rglob("*")):
        name = "/etc/uag/seeds/"+path.relative_to(root).as_posix()
        assert not path.is_symlink() and (path.is_dir() or path.is_file()), "seed tree entry is unsupported"
        if path.is_dir():
            directories.append(name)
        else:
            hashes[name] = digest(path)
    assert hashes, "seed tree is absent"
    return dict(files=hashes, directories=sorted(directories))


def build(args):
    repo = Path(args.repo).resolve()
    tree = source_gate(repo, args.revision)
    build_fixed_source(args, tree)
    source_gate(repo, args.revision)


def is_home_task_path(path):
    # Root AGENTS.md places new worktrees/artifacts on this approved SSD mount.
    # Compare resolved path components, never a textual prefix or an arbitrary symlink.
    path = Path(path).resolve()
    return any(path != root and path.is_relative_to(root)
               for root in (Path("/home/dev"), Path("/fast/home-yj/codex-work")))


def build_fixed_source(args, tree, verified_archive=None):
    """Worker used by the isolated supervisor after its live source gate.

    The supervisor verifies the exact archive digest before and after transport,
    retains the home release lock, and reruns the live source gate before accepting
    the returned media. This worker never updates a runtime service.
    """
    repo = Path(args.repo).resolve()
    assert is_home_task_path(repo), "build inputs must stay in an approved home task root"
    out = Path(args.output).resolve()
    assert is_home_task_path(out) and not out.exists()
    out.mkdir(parents=True, mode=0o700)
    os.umask(0o077)
    lock_path = Path("/home/dev/.cache/jjdguard/home-release.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock = lock_path.open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    source = out/"source"
    source.mkdir()
    archive = out/"source.tar"
    if verified_archive is None:
        with archive.open("wb") as stream:
            subprocess.run(["git", "-C", str(repo), "archive", args.revision], stdout=stream, check=True)
    else:
        path, expected = verified_archive
        assert digest(path) == expected, "isolated source archive differs"
        shutil.copy2(path, archive)
        with tarfile.open(archive) as check:
            assert check.pax_headers.get("comment") == args.revision, "archive revision differs"
    with tarfile.open(archive) as tar:
        tar.extractall(source, filter="data")
    selected_services = release_services(args)
    if getattr(args, "chat_theme_only", False):
        from vm_chat_theme_release import build_theme_media
        created = datetime.datetime.now(datetime.timezone.utc)
        rid = "dev-"+args.revision[:12]+"-theme-"+created.strftime("%Y%m%dT%H%M%SZ")
        manifest = dict(schema=1, purpose="chat-theme-only", chat_theme_only=True, release_id=rid,
                        revision=args.revision, tree=tree, version=(source/"VERSION").read_text().strip(),
                        created_at=created.isoformat(), services={}, migrations={}, source_archive_sha256=digest(archive))
        media = out/"media"
        build_theme_media(source, media, manifest)
        print(json.dumps({"release_id": rid, "media": str(media), "manifest_sha256": digest(media/"manifest.json")}), flush=True)
        return
    bases = json.loads(Path(args.bases).read_text())
    se_only = getattr(args, "security_engine_only", False)
    console_only = getattr(args, "console_only", False)
    identity_chat_only = getattr(args, "identity_chat_only", False)
    preserve_tier1 = args.preserve_tier1 or se_only or console_only or identity_chat_only
    assert set(bases) == (set(selected_services) if args.portal_only or getattr(args, "engineering_only", False) or se_only or console_only or identity_chat_only else set(SERVICES))
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rid = "dev-"+args.revision[:12]+"-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    version = (source/"VERSION").read_text().strip()
    clean_env = {"PATH": "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/home/dev", "LANG": "C.UTF-8"}
    docker_env = dict(clean_env, DOCKER_HOST="unix:///var/run/docker.sock", DOCKER_BUILDKIT="0")
    go_env = dict(clean_env, GOWORK="off", GOENV="off", GOFLAGS="-buildvcs=false", CGO_ENABLED="0", GOMAXPROCS="2", GOPROXY="off")
    (out/"npm-user-config").write_text("")
    (out/"npm-global-config").write_text("")
    npm_env = npm_environment(clean_env, args.billing_enabled, out/"npm-user-config", out/"npm-global-config")
    manifest = {"engineering_only": getattr(args, "engineering_only", False), "schema": 1, "purpose": "development-vm", "release_id": rid, "revision": args.revision, "tree": tree, "version": version, "created_at": created, "services": {}, "migrations": {}, "enable_file_detection": args.enable_file_detection, "preserve_tier1": args.preserve_tier1, "portal_only": args.portal_only, "billing_enabled": args.billing_enabled}
    if getattr(args,"chat_login_proxy_trust",False): manifest["chat_login_proxy_trust"]=True
    for field in ("security_input_workers", "security_input_capacity", "judge_queue_capacity", "security_batch_budget_seconds", "semantic_request_parallelism", "security_input_budget_seconds"):
        value = getattr(args, field, None)
        if value is not None:
            assert not (args.portal_only or getattr(args, "engineering_only", False)), "engine capacity override requires engine release"
            manifest[field] = value
    for field in ("gateway_security_budget_seconds", "security_engine_client_timeout_seconds"):
        value = getattr(args, field, None)
        if value is not None:
            assert "gateway-core" in selected_services, "gateway budget override requires gateway release"
            manifest[field] = value
    semantic_parallelism = getattr(args, "semantic_window_parallelism", None)
    if semantic_parallelism is not None:
        assert not (args.portal_only or getattr(args, "engineering_only", False)), "semantic capacity override requires engine release"
        manifest["semantic_window_parallelism"] = semantic_parallelism
    semantic_max_windows = getattr(args, "semantic_max_windows", None)
    if semantic_max_windows is not None:
        assert not (se_only or args.portal_only or getattr(args, "engineering_only", False)), "semantic capacity override requires full development release"
        manifest["semantic_max_windows"] = semantic_max_windows
    if se_only:
        manifest.update(security_engine_only=True, preserve_tier1=True)
    if console_only:
        manifest.update(purpose="console-only", console_only=True, preserve_tier1=True, source_archive_sha256=digest(archive))
    for service in selected_services:
        print("BUILD "+service, flush=True)
        base = bases[service]
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", base)
        base_ref = ("jjdguard-isolated-base/"+service+":"+base.split(":")[1]) if verified_archive is not None else base
        base_image = json.loads(run(["docker", "image", "inspect", base_ref], env=docker_env))[0]
        assert portable_image_id(base_image, docker_env) == base, "imported base config differs"
        base_config = base_image["Config"]
        context = out/"build"/service
        payload = context/"runtime"
        (payload/"app").mkdir(parents=True)
        app = source/("enterprise-ai-portal" if service == "chat-portal-ui" else "portal-proxy" if service == "chat-portal-proxy" else "apps/"+service)
        dockerfile = ["FROM "+base_ref, "USER root"]
        final_user = base_config.get("User")
        if service == "chat-portal-proxy":
            proxy_runtime_contract(base_config, (app/"Dockerfile").read_text())
            dockerfile = ["FROM "+base_ref]
        else:
            assert final_user and final_user != "root", "candidate must keep non-root runtime"
        if service == "chat-portal-proxy":
            build_proxy_payload(app, context, base_ref, base_config, source, docker_env, npm_env, out, getattr(args, "pnpm_store", "/home/dev/jjdguard-src/.pnpm-store"))
            dockerfile += ["RUN rm -rf /app && mkdir -p /app /data"]
        elif service == "chat-portal-ui":
            portal_identity = probe_portal_identity(base_ref, base_config, docker_env, out/"portal-base-identity.log")
            dependencies = repo/"enterprise-ai-portal/node_modules"
            assert dependencies.is_dir() and not dependencies.is_symlink(), "reviewed portal dependencies are unavailable"
            installed_lock = dependencies/".package-lock.json"
            assert installed_lock.is_file() and not installed_lock.is_symlink(), "installed portal lock is unavailable"
            installed = json.loads(installed_lock.read_text())
            expected = json.loads((app/"package-lock.json").read_text())
            assert installed.get("lockfileVersion") == expected.get("lockfileVersion")
            validate_installed_portal_dependencies(installed, expected)
            copy_portal_dependencies(dependencies, app/"node_modules", clean_env, out/"portal-dependency-copy.log")
            run(["npm", "run", "build"], cwd=app, env=dict(npm_env, NPM_CONFIG_OFFLINE="true"), log=out/"chat-portal-ui-build.log")
            shutil.copytree(app/".next/standalone", payload/"app", dirs_exist_ok=True)
            shutil.copytree(app/".next/static", payload/"app/.next/static")
            shutil.copytree(app/"public", payload/"app/public")
            shutil.copytree(app/"prisma", payload/"app/prisma")
            (payload/"usr/local/bin").mkdir(parents=True)
            shutil.copy2(app/"docker-entrypoint.sh", payload/"usr/local/bin/docker-entrypoint.sh")
            (payload/"usr/local/bin/docker-entrypoint.sh").chmod(0o755)
            for relative in PORTAL_FOREIGN_LIBC:
                shutil.rmtree(payload/"app"/relative, ignore_errors=True)
            for path in (payload/"app/node_modules/@prisma/client/runtime").glob("*"):
                if "wasm" in path.name or path.suffix == ".map": path.unlink()
        elif service in SERVICES[:4]:
            main = "./cmd/worker" if service == "worker" else "./cmd/server"
            binary = payload/"app"/service
            run([getattr(args, "go_binary", "/usr/local/go/bin/go"), "build", "-p=2", "-trimpath", "-buildvcs=false", "-o", str(binary), main], cwd=app, env=go_env, log=out/(service+"-build.log"))
            binary.chmod(0o755)
            if service == "control-plane":
                shutil.copy2(source/"VERSION", payload/"app/VERSION")
                if console_only:
                    expected_seeds = seed_tree(source/"deploy/seeds")
                    check_container = run(["docker", "create", base_ref], env=docker_env)
                    extracted_seeds = context/"base-seeds"
                    try:
                        run(["docker", "cp", check_container+":/etc/uag/seeds", str(extracted_seeds)], env=docker_env)
                        actual_seeds = seed_tree(extracted_seeds)
                        assert actual_seeds == expected_seeds, "console-only cannot update control-plane seeds"
                    finally:
                        run(["docker", "rm", check_container], env=docker_env)
                    manifest["control_plane_seeds_sha256"] = actual_seeds["files"]
                    manifest["control_plane_seed_directories"] = actual_seeds["directories"]
                else:
                    shutil.copytree(source/"deploy/seeds", payload/"etc/uag/seeds")
                    dockerfile += ["RUN rm -rf /etc/uag/seeds"]
        elif service == "web-console":
            run(["npm", "ci", "--offline", "--cache", args.npm_cache, "--no-audit", "--no-fund"], cwd=app, env=npm_env, log=out/"web-npm-ci.log")
            run(["npm", "run", "build"], cwd=app, env=npm_env, log=out/"web-build.log")
            shutil.copytree(app/"dist", payload/"app/dist")
            shutil.copy2(app/"server.js", payload/"app/server.js")
            dockerfile += ["RUN rm -rf /app/dist /app/server.js"]
        else:
            shutil.copytree(app/"app", payload/"app/app", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            dockerfile += ["RUN rm -rf /app/app"]
            if service == "security-engine":
                shutil.copytree(app/"tests/fixtures/file_detection", payload/"app/file-fixtures")
                shutil.copy2(app/"ocr-resources.lock.json", payload/"app/ocr-resources.lock.json")
                dockerfile += ["RUN rm -rf /app/file-fixtures"]
            else:
                (payload/"usr/local/bin").mkdir(parents=True)
                shutil.copy2(app/"entrypoint.sh", payload/"usr/local/bin/entrypoint.sh")
                (payload/"usr/local/bin/entrypoint.sh").chmod(0o755)
        for path in payload.rglob("*"):
            if path.is_dir(): path.chmod(0o755)
            elif path.is_file() and not path.stat().st_mode & 0o111: path.chmod(0o644)
        payload.chmod(0o755)
        provenance = ["JJD_COMMIT="+args.revision, "JJD_VERSION="+version, "JJD_BUILT_AT="+created]
        if service == "chat-portal-ui":
            portal_recipe = (app/"Dockerfile").read_text()
            runtime_base = portal_runtime_base(portal_recipe)
            (context/"prisma-closure.js").write_text(portal_prisma_closure(portal_recipe))
            portal_closure = extract_portal_prisma_closure(context, base_ref, docker_env, out)
            engine_lock_file = source/"deploy/docker-compose/release-prisma-engines.lock.json"
            closure_packages = validate_portal_prisma_closure(context/"verified-prisma-closure", expected,
                                                            json.loads(engine_lock_file.read_text()))
            portal_proof = {"schema":1, "source_revision":args.revision, "source_tree":tree,
                            "source_archive_sha256":digest(archive), "dependency_image_id":base,
                            "runtime_base":runtime_base, "runtime_identity":portal_identity,
                            "recipe_sha256":digest(app/"Dockerfile"),
                            "package_lock_sha256":digest(app/"package-lock.json"),
                            "engine_lock_sha256":digest(engine_lock_file), "closure_packages":closure_packages,
                            "closure_script_sha256":digest(context/"prisma-closure.js"),
                            "closure_tree_sha256":portal_tree_digest(portal_closure),
                            "frozen_payload_tree_sha256":portal_tree_digest(portal_tree_manifest(payload))}
            proof_file = payload/"app/.jjdguard-portal-build-proof.json"
            proof_file.write_text(json.dumps(portal_proof,sort_keys=True,indent=2)+"\n")
            proof_file.chmod(0o644)
            (context/"verified-prisma-closure-manifest.json").write_text(json.dumps(portal_closure,sort_keys=True,indent=2)+"\n")
            json.loads(run(["docker", "image", "inspect", runtime_base], env=docker_env))
            dockerfile = freeze_portal_dockerfile_identity(
                portal_dockerfile(base, runtime_base, base_config, final_user, provenance), portal_identity, final_user)
        else:
            owner = final_user or "0:0"
            dockerfile += ["COPY --chown="+owner+" runtime/ /", "ENV "+" ".join(provenance)]
        if service == "security-engine":
            dockerfile += ["ENV SECURITY_ENGINE_BUILD="+args.revision, "RUN SECURITY_FILE_CONTENT_DLP_ENABLED=true python -m app.file_readiness --require-enabled"]
        if service in ("security-engine", "tier1-classifier"): dockerfile += ["RUN python -m pip check"]
        if final_user:
            dockerfile += ["USER "+final_user]
        (context/"Dockerfile").write_text("\n".join(dockerfile)+"\n")
        if service == "chat-portal-ui":
            portal_proof["candidate_recipe_sha256"] = digest(context/"Dockerfile")
            portal_frozen_tree = portal_tree_manifest(payload)
            portal_payload = portal_tree_manifest(payload/"app")
            portal_proof["expected_union_tree_sha256"] = portal_tree_digest(dict(portal_closure, **portal_payload))
        tag = "jjdguard-dev/"+service+":"+rid
        labels = {"org.opencontainers.image.revision": args.revision, "com.jjdguard.source.tree": tree, "com.jjdguard.base.image": base, "com.jjdguard.release.id": rid}
        command = ["docker", "build", "--pull=false", "--network=none", "-t", tag]
        for key, value in labels.items(): command += ["--label", key+"="+value]
        command += [str(context)]
        run(command, env=docker_env, log=out/(service+"-image.log"))
        image = json.loads(run(["docker", "image", "inspect", tag], env=docker_env))[0]
        if service == "chat-portal-ui":
            assert portal_tree_manifest(payload) == portal_frozen_tree, "frozen portal payload changed during image build"
            assert digest(context/"Dockerfile") == portal_proof["candidate_recipe_sha256"], "portal candidate recipe changed during image build"
            verify_portal_image_size(image["Size"])
            portal_proof["verified_runtime_identity"] = verify_portal_numeric_identity(
                portal_identity, probe_portal_identity(image["Id"], image["Config"], docker_env, out/"portal-candidate-identity.log"))
            dependency_layers = json.loads(run(["docker", "image", "inspect", base], env=docker_env))[0]["RootFS"]["Layers"]
            runtime_layers = json.loads(run(["docker", "image", "inspect", runtime_base], env=docker_env))[0]["RootFS"]["Layers"]
        hashes = payload_hashes(payload)
        container = run(["docker", "create", image["Id"]], env=docker_env)
        extracted = context/"image-check"
        extracted.mkdir()
        try:
            for top in sorted(p.name for p in payload.iterdir()):
                if top == "usr":
                    for item in sorted(p for p in (payload/"usr").rglob("*") if p.is_file()):
                        relative = item.relative_to(payload)
                        (extracted/relative).parent.mkdir(parents=True, exist_ok=True)
                        run(["docker", "cp", container+":/"+relative.as_posix(), str(extracted/relative)], env=docker_env)
                else:
                    run(["docker", "cp", container+":/"+top, str(extracted/top)], env=docker_env)
            for name, expected in hashes.items():
                if service == "chat-portal-ui":
                    actual_path = extracted/name.lstrip("/")
                    payload_path = payload/name.lstrip("/")
                    assert actual_path.is_file() and not actual_path.is_symlink() and stat.S_IMODE(actual_path.lstat().st_mode) == stat.S_IMODE(payload_path.lstat().st_mode), "portal image payload file type or mode differs: "+name
                assert digest(extracted/name.lstrip("/")) == expected, "image payload differs: "+name
            if console_only and service == "control-plane":
                candidate_seeds = context/"candidate-seeds"
                run(["docker", "cp", container+":/etc/uag/seeds", str(candidate_seeds)], env=docker_env)
                assert seed_tree(candidate_seeds) == {"files": manifest["control_plane_seeds_sha256"],
                                                      "directories": manifest["control_plane_seed_directories"]}, "candidate changed preserved seeds"
            if service == "chat-portal-ui":
                probe = context/"image-runtime-check"
                probe.mkdir()
                present = set()
                for required in PORTAL_RUNTIME_REQUIRED:
                    try:
                        run(["docker", "cp", "-L", container+":/"+required, str(probe/required.replace("/", "_"))], env=docker_env)
                        present.add(required)
                    except subprocess.CalledProcessError:
                        pass
                verify_portal_runtime_contents(present)
                union_digest = verify_portal_union(extracted/"app", portal_closure, portal_payload)
                portal_proof["layer_reuse"] = verify_portal_layers(image["RootFS"]["Layers"], dependency_layers, runtime_layers,
                                                                  prisma_closure_verified=True, application_payload_verified=True)
                portal_proof["verified_union_tree_sha256"] = union_digest
        finally:
            run(["docker", "rm", container], env=docker_env)
        manifest["services"][service] = {"image_id": portable_image_id(image, docker_env), "build_image_id": image["Id"], "tag": tag, "base_image_id": base, "payload_sha256": hashes}
        if service == "chat-portal-ui":
            manifest["services"][service]["portal_build_proof"] = portal_proof
        (out/"manifest.partial.json").write_text(json.dumps(manifest, indent=2))
    if console_only:
        manifest["candidate_validation"] = {"console_payload_verified": True, "control_plane_seeds": "preserved"}
        manifest["migration_preconditions"] = {}
        media = out/"media"
        media.mkdir()
        for name, field in (("vm_development_apply.py", "apply_script_sha256"), ("vm_console_release.py", "console_script_sha256")):
            shutil.copy2(source/"deploy/release"/name, media/name)
            manifest[field] = digest(media/name)
        images = media/"images.tar"
        run(["docker", "image", "save", "-o", str(images), *[v["tag"] for v in manifest["services"].values()]], env=docker_env, log=out/"image-export.log")
        manifest["images_sha256"] = digest(images)
        from vm_console_release import check_image_archive, validate_manifest
        validate_manifest(manifest)
        check_image_archive(media, manifest)
        (media/"manifest.json").write_text(json.dumps(manifest, indent=2))
        print(json.dumps({"release_id": rid, "media": str(media), "manifest_sha256": digest(media/"manifest.json")}), flush=True)
        return
    if args.portal_only:
        manifest["candidate_validation"]={"portal_navigation_paths":"explicit_base_path"}
        media = out/"media"
        media.mkdir()
        migrations = media/"migrations"
        migrations.mkdir()
        assert not args.migration, "portal-only release cannot carry database migrations"
        copy_migration_runtime(source, media, manifest)
        manifest["migration_preconditions"] = {}
        shutil.copy2(source/"deploy/release/vm_development_apply.py", media/"vm_development_apply.py")
        manifest["apply_script_sha256"] = digest(media/"vm_development_apply.py")
        images = media/"images.tar"
        run(["docker", "image", "save", "-o", str(images), *[v["tag"] for v in manifest["services"].values()]], env=docker_env, log=out/"image-export.log")
        manifest["images_sha256"] = digest(images)
        with tarfile.open(images) as tar:
            index = json.loads(tar.extractfile("manifest.json").read())
        (media/"manifest.json").write_text(json.dumps(manifest, indent=2))
        verify_portal_only_release(manifest, [str(p.relative_to(media)) for p in media.rglob("*")], [entry.get("RepoTags") for entry in index])
        print(json.dumps({"release_id": rid, "media": str(media), "manifest_sha256": digest(media/"manifest.json")}), flush=True)
        return
    if identity_chat_only:
        assemble_identity_chat_media(source, out, manifest, args, docker_env, archive)
        return
    print("VERIFY real file/OCR candidate", flush=True)
    se_image = manifest["services"]["security-engine"]["build_image_id"]
    run(["docker","run","--rm","--network=none","--cpus=2","--memory=1g","-e","SECURITY_FILE_CONTENT_DLP_ENABLED=true",se_image,"python","-m","app.file_selftest"],env=docker_env,log=out/"file-candidate-smoke.log")
    fixture = run(["docker","run","-d","--network=none","--cpus=2","--memory=1g","--read-only",
                   "--tmpfs","/tmp:rw,noexec,nosuid,size=64m",
                   "--tmpfs","/var/lib/jjdguard/scan-store:rw,noexec,nosuid,size=512m,mode=0700,uid=10001,gid=10001",
                   "-e","SECURITY_FILE_CONTENT_DLP_ENABLED=true","-e","SECURITY_SCAN_STORE_DIR=/var/lib/jjdguard/scan-store",
                   "-e","CONTROL_PLANE_URL=","-e","SECURITY_TIER1_ENABLED=false",
                   "-e","JJD_INTERNAL_API_SECRET=isolated-file-http-fixture",se_image],env=docker_env)
    try:
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            ready=subprocess.run(["docker","exec",fixture,"python","-c","import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2)"],env=docker_env,capture_output=True)
            if ready.returncode==0:break
            time.sleep(1)
        else:raise RuntimeError("candidate security engine did not become healthy")
        run(["docker","exec",fixture,"python","-m","app.file_http_selftest"],env=docker_env,log=out/"file-http-candidate-smoke.log")
    finally:
        run(["docker","rm","-f",fixture],env=docker_env)
    validation={"file_selftest_passed":True,"file_http_selftest_passed":True}
    if preserve_tier1:
        validation["tier1"]="preserved_not_touched"
    else:
        print("VERIFY Tier1 long-token-window candidate", flush=True)
        tier_image = manifest["services"]["tier1-classifier"]["build_image_id"]
        fixture = run(["docker","run","-d","--network=none","--cpus=2","--memory=2g","-e","TIER1_THREADS=2","-e","TIER1_WORKERS=1","-e","JJD_TIER1_INTERNAL_TOKEN=isolated-development-fixture",tier_image],env=docker_env)
        try:
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                ready=subprocess.run(["docker","exec",fixture,"python","-c","import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2)"],env=docker_env,capture_output=True)
                if ready.returncode==0:break
                time.sleep(2)
            else:raise RuntimeError("candidate Tier1 did not become healthy")
            smoke="import os\nos.environ['T1TOK']=os.environ['JJD_TIER1_INTERNAL_TOKEN']\n"+(source/"deploy/lib/tier1-window-smoke.py").read_text()
            run(["docker","exec","-i",fixture,"python","-"],env=docker_env,log=out/"tier1-candidate-smoke.log",input=smoke)
        finally:
            run(["docker","rm","-f",fixture],env=docker_env)
        validation["tier1_real_long_window_passed"]=True
    manifest["candidate_validation"]=validation
    media = out/"media"
    media.mkdir()
    validation_logs=["file-candidate-smoke.log","file-http-candidate-smoke.log"]
    if not preserve_tier1: validation_logs.append("tier1-candidate-smoke.log")
    for name in validation_logs:
        shutil.copy2(out/name,media/name)
    if not preserve_tier1:
        shutil.copy2(source/"deploy/lib/tier1-window-smoke.py",media/"tier1-window-smoke.py")
        manifest["tier1_probe_sha256"]=digest(media/"tier1-window-smoke.py")
    migrations = media/"migrations"
    migrations.mkdir()
    for name in args.migration:
        assert re.fullmatch(r"[0-9]{3,}_[A-Za-z0-9_]+\.sql", name)
        path = source/"deploy/migrations"/name
        shutil.copy2(path, migrations/name)
        manifest["migrations"][name] = digest(path)
    if se_only:
        shutil.copy2(source/"deploy/release/vm_security_engine_release.py", media/"vm_security_engine_release.py")
        manifest["security_engine_script_sha256"] = digest(media/"vm_security_engine_release.py")
    else:
        copy_migration_runtime(source, media, manifest)
    manifest["migration_preconditions"] = {}
    if "851_compact_nonfinding_read_metadata.sql" in manifest["migrations"]:
        manifest["migration_preconditions"]["850_alert_read_metadata.sql"] = digest(source/"deploy/migrations/850_alert_read_metadata.sql")
    if "821_serialize_customer_content_projection.sql" in manifest["migrations"]:
        manifest["migration_preconditions"]["820_customer_content_projection_triggers.sql"] = digest(source/"deploy/migrations/820_customer_content_projection_triggers.sql")
    shutil.copy2(source/"deploy/release/vm_development_apply.py", media/"vm_development_apply.py")
    manifest["apply_script_sha256"] = digest(media/"vm_development_apply.py")
    images = media/"images.tar"
    run(["docker", "image", "save", "-o", str(images), *[v["tag"] for v in manifest["services"].values()]], env=docker_env, log=out/"image-export.log")
    manifest["images_sha256"] = digest(images)
    (media/"manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps({"release_id": rid, "media": str(media), "manifest_sha256": digest(media/"manifest.json")}), flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--bases")
    parser.add_argument("--output", required=True)
    parser.add_argument("--pnpm-store", default="/home/dev/jjdguard-src/.pnpm-store", help="reviewed offline pnpm store root; pnpm chooses its versioned subdirectory")
    parser.add_argument("--npm-cache", default="/home/dev/.npm")
    parser.add_argument("--billing-enabled", choices=("true", "false"))
    parser.add_argument("--migration", action="append", default=[])
    parser.add_argument("--enable-file-detection", action="store_true")
    parser.add_argument("--security-input-workers", type=positive_integer_argument)
    parser.add_argument("--security-input-capacity", type=positive_integer_argument)
    parser.add_argument("--judge-queue-capacity", type=positive_integer_argument)
    parser.add_argument("--gateway-security-budget-seconds", type=positive_integer_argument)
    parser.add_argument("--security-engine-client-timeout-seconds", type=positive_integer_argument)
    parser.add_argument("--security-input-budget-seconds", type=positive_integer_argument)
    parser.add_argument("--security-batch-budget-seconds", type=positive_integer_argument, help="explicit shared batch deadline recorded in the release manifest")
    parser.add_argument("--semantic-request-parallelism", type=positive_integer_argument, help="maximum in-flight windows per request; shared inference capacity is independent")
    parser.add_argument("--semantic-window-parallelism", type=positive_integer_argument, help="per-process window/inference capacity; any positive integer")
    parser.add_argument("--semantic-max-windows", type=positive_integer_argument, help="per-request semantic window budget; any positive integer recorded in the release manifest")
    parser.add_argument("--preserve-tier1", action="store_true", help="leave the existing tier1-classifier image, container and model untouched")
    parser.add_argument("--portal-only", action="store_true", help="build only chat-portal-ui while preserving every model service")
    parser.add_argument("--engineering-only", action="store_true", help="update only gateway-core, security-engine and Tier1 application code")
    parser.add_argument("--security-engine-only", action="store_true", help="replace only security-engine; preserve all other containers and database state")
    parser.add_argument("--console-only", action="store_true", help="仅替换 control-plane 和 web-console，冻结种子、数据库和所有其他服务")
    parser.add_argument("--chat-login-proxy-trust", action="store_true", help="trust only chat-portal-ui/web-console service exit IPs and check portal defaults/internal ports")
    parser.add_argument("--identity-chat-only", action="store_true", help="update only control-plane, gateway-core, web-console, chat-portal-ui and chat-portal-proxy with reviewed migrations")
    parser.add_argument("--include-proxy-server", action="store_true", help="explicitly include proxy-server in an identity-chat-only release; preserve all model services")
    parser.add_argument("--chat-theme-only", action="store_true", help="publish only frozen Keycloak login theme assets; no image or database changes")
    args = parser.parse_args()
    if not args.chat_theme_only and (not args.bases or args.billing_enabled is None):
        parser.error("image releases require --bases and --billing-enabled")
    build(args)
