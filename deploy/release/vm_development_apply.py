#!/usr/bin/env python3
"""Apply a reviewed fixed-image development release inside the existing JJDGuard VM."""
import argparse, base64, contextlib, contextvars, copy, datetime, fcntl, grp, hashlib, hmac, json, os, pwd, re, select, shlex, shutil, stat, subprocess, sys, time, urllib.request
from pathlib import Path
SERVICES = ("control-plane", "gateway-core", "proxy-server", "worker", "web-console", "security-engine", "tier1-classifier")
ENGINEERING_SERVICES = ("gateway-core", "security-engine", "tier1-classifier")
IDENTITY_CHAT_SERVICES = ("control-plane", "gateway-core", "web-console", "chat-portal-ui", "chat-portal-proxy")
IDENTITY_CHAT_FORBIDDEN_OVERRIDES = ("security_input_workers", "security_input_capacity", "judge_queue_capacity", "gateway_security_budget_seconds", "security_engine_client_timeout_seconds", "security_input_budget_seconds", "security_batch_budget_seconds", "semantic_request_parallelism", "semantic_window_parallelism", "semantic_max_windows")
WRITERS = SERVICES + ("chat-portal-ui", "chat-portal-proxy")
ROOT = Path("/opt/jjdguard")
IMAGE_PATTERN = r"sha256:[0-9a-f]{64}"
MAX_GOVERNED_BOOT_FILES = 32  # Includes the offline base and managed addon/release overlays.
ROLLBACK_AUDIT = contextvars.ContextVar("rollback_audit",default=None)
INSTALL_OWNER = contextvars.ContextVar("install_owner",default=None)
PORTAL_ROUTES = ("/billing/page", "/records/page", "/api/me/billing/route", "/api/me/billing/limits/route", "/api/me/billing/redeem/route")

def chat_login_proxy_environment(manifest):
    value=manifest.get("chat_login_proxy_trust",False)
    if type(value) is not bool or (value and manifest.get("identity_chat_only") is not True):
        raise RuntimeError("Chat login proxy trust requires explicit identity-chat-only approval")
    return {"JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS":"chat-portal-ui,web-console"} if value else {}

def login_ip_forward_environment(manifest, running=None):
    if not chat_login_proxy_environment(manifest) or not manifest.get("services"):
        return {}
    names = ("control-plane", "web-console", "chat-portal-ui")
    if not set(names) <= set(manifest["services"]) or running is None or not set(names) <= set(running):
        raise RuntimeError("identity-chat runtime contract signing scope unavailable")
    environments = {name:dict(value.split("=", 1) for value in running[name].get("Config", {}).get("Env", [])
                              if "=" in value) for name in names}
    existing = [environments[name].get("JJD_LOGIN_IP_FORWARD_SECRET", "") for name in names]
    if any(existing):
        if not all(existing) or len(set(existing)) != 1 or len(existing[0].strip()) < 32:
            raise RuntimeError("identity-chat runtime contract signing configuration differs")
        secret = existing[0]
    else:
        master = environments["control-plane"].get("JJD_INTERNAL_API_SECRET", "")
        if len(master.strip()) < 32:
            raise RuntimeError("identity-chat runtime contract signing master unavailable")
        # Domain-separated signing subkey; neither key is placed in public manifest,
        # logs, or image layers. The protected staged/boot Compose stores the value.
        secret = hmac.new(master.encode(), b"jjdguard-login-ip-forward-v1", hashlib.sha256).hexdigest()
    return {name:{"JJD_LOGIN_IP_FORWARD_SECRET":secret} for name in names}

def chat_portal_defaults_preflight(sql):
    missing=json.loads(sql("""SELECT COALESCE(json_agg(t.id ORDER BY t.id),'[]'::json)::text
        FROM tenants t WHERE t.status='active' AND t.id<>'tenant_system'
        AND NOT EXISTS(SELECT 1 FROM teams d WHERE d.tenant_id=t.id AND d.system_key='unassigned');"""))
    if missing:
        raise RuntimeError("Chat portal unassigned department missing; provision tenant defaults before release")
    return {"unassigned_departments":"present"}

def semantic_parallel_environment(manifest):
    values = {}
    count = manifest.get("semantic_window_parallelism")
    if count is not None:
        if type(count) is not int or count <= 0:
            raise RuntimeError("invalid semantic parallelism")
        values.update({key:str(count) for key in ("SECURITY_SEMANTIC_WINDOW_PARALLELISM", "SECURITY_JUDGE_WORKERS", "SECURITY_JUDGE_CAPACITY")})
    for field, key in (("security_input_workers", "SECURITY_INPUT_WORKERS"),
                       ("security_input_capacity", "SECURITY_INPUT_CAPACITY"),
                       ("judge_queue_capacity", "SECURITY_JUDGE_QUEUE_CAPACITY"),
                       ("security_batch_budget_seconds", "SECURITY_BATCH_BUDGET_SECONDS"),
                       ("security_input_budget_seconds", "SECURITY_INPUT_BUDGET_SECONDS"),
                       ("semantic_request_parallelism", "SECURITY_SEMANTIC_REQUEST_PARALLELISM")):
        count = manifest.get(field)
        if count is not None:
            if type(count) is not int or count <= 0:
                raise RuntimeError("invalid engine capacity: "+field)
            values[key] = str(count)
    if values and (manifest.get("portal_only") or manifest.get("engineering_only") or "security-engine" not in manifest.get("services", {})):
        raise RuntimeError("semantic capacity override requires engine release")
    return values

def gateway_budget_environment(manifest):
    fields = ("gateway_security_budget_seconds", "security_engine_client_timeout_seconds")
    if all(manifest.get(field) is None for field in fields):
        return {}
    values = {}
    for field in fields:
        value = manifest.get(field)
        if type(value) is not int or value <= 0:
            raise RuntimeError("invalid gateway budget: "+field)
        values[field] = value
    if manifest.get("security_engine_only") or manifest.get("portal_only") or "gateway-core" not in manifest.get("services", {}):
        raise RuntimeError("gateway budget override requires gateway release")
    outer, client = (values[field] for field in fields)
    if client >= outer:
        raise RuntimeError("gateway client needs headroom inside the request budget")
    inner = manifest.get("security_input_budget_seconds")
    batch = manifest.get("security_batch_budget_seconds")
    for field, value in (("security_input_budget_seconds", inner), ("security_batch_budget_seconds", batch)):
        if value is not None and (type(value) is not int or value <= 0):
            raise RuntimeError("invalid engine budget: "+field)
    if inner is not None and inner >= client:
        raise RuntimeError("engine input needs headroom inside the client budget")
    if batch is not None and inner is not None and batch >= inner:
        raise RuntimeError("batch needs headroom inside the engine input budget")
    return {"GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT": str(outer)+"s", "SECURITY_ENGINE_TIMEOUT": str(client)+"s"}


def release_service_sets(manifest):
    if "include_proxy_server" in manifest and (type(manifest["include_proxy_server"]) is not bool or manifest.get("identity_chat_only") is not True):
        raise RuntimeError("proxy-server inclusion requires an explicit identity-chat-only boolean")
    if "identity_chat_only" in manifest:
        if (manifest.get("identity_chat_only") is not True or manifest.get("preserve_tier1") is not True or
                any(manifest.get(mode, False) is not False for mode in ("console_only", "chat_theme_only", "security_engine_only", "engineering_only", "portal_only", "enable_file_detection")) or
                any(manifest.get(key) is not None for key in IDENTITY_CHAT_FORBIDDEN_OVERRIDES)):
            raise RuntimeError("identity-chat-only cannot change modes, security capacity or file settings")
        services = IDENTITY_CHAT_SERVICES + (("proxy-server",) if manifest.get("include_proxy_server") else ())
        if manifest.get("purpose") != "development-vm" or set(manifest.get("services", {})) != set(services):
            raise RuntimeError("unsupported identity-chat-only services")
        return services, ("tier1-classifier",)
    if "chat_theme_only" in manifest:
        from vm_chat_theme_release import validate_manifest
        validate_manifest(manifest)
        return ("chat-idp",), SERVICES
    if "console_only" in manifest:
        if manifest.get("console_only") is not True:
            raise RuntimeError("invalid console-only mode")
        from vm_console_release import validate_scope, SERVICES as CONSOLE_SERVICES
        validate_scope(manifest)
        return CONSOLE_SERVICES, tuple(s for s in SERVICES if s not in CONSOLE_SERVICES)
    chat_login_proxy_environment(manifest)
    semantic_parallel_environment(manifest)
    gateway_budget_environment(manifest)
    limit = manifest.get("semantic_max_windows")
    if limit is not None:
        if type(limit) is not int or limit <= 0:
            raise RuntimeError("invalid semantic window limit")
        if any(manifest.get(mode) for mode in ("security_engine_only", "portal_only", "engineering_only")):
            raise RuntimeError("semantic capacity override requires full development release")
    se_only = manifest.get("security_engine_only", False)
    if type(se_only) is not bool: raise RuntimeError("invalid security-engine-only mode")
    if se_only:
        if (manifest.get("preserve_tier1") is not True or manifest.get("portal_only") or
                manifest.get("engineering_only") or manifest.get("migrations") or manifest.get("enable_file_detection")):
            raise RuntimeError("security-engine-only cannot change modes, migrations or file settings")
        if set(manifest.get("services", {})) != {"security-engine"}:
            raise RuntimeError("unsupported security-engine-only services")
        return ("security-engine",), ()
    preserve_tier1 = manifest.get("preserve_tier1", False)
    if preserve_tier1 not in (True, False): raise RuntimeError("invalid preserve_tier1 mode")
    portal_only = manifest.get("portal_only", False)
    if portal_only not in (True, False): raise RuntimeError("invalid portal_only mode")
    if portal_only and not preserve_tier1: raise RuntimeError("portal-only release must preserve tier1")
    engineering = manifest.get("engineering_only", False)
    if type(engineering) is not bool: raise RuntimeError("invalid engineering mode")
    if engineering and (portal_only or preserve_tier1 or manifest.get("migrations") or manifest.get("enable_file_detection")):
        raise RuntimeError("engineering-only release cannot change modes, migrations or file settings")
    target = ENGINEERING_SERVICES if engineering else ("chat-portal-ui",) if portal_only else SERVICES[:-1] if preserve_tier1 else SERVICES
    if set(manifest.get("services", {})) != set(target): raise RuntimeError("unsupported release services")
    preserved = ("tier1-classifier",) if preserve_tier1 else ()
    return target, preserved

def portal_surface(env, routes, expected_billing):
    if expected_billing is not None and env.get("NEXT_PUBLIC_BILLING_ENABLED") != expected_billing:
        raise RuntimeError("portal billing flag differs between candidate and runtime")
    missing = [route for route in PORTAL_ROUTES if route not in routes]
    if missing: raise RuntimeError("portal customer-centre routes absent: "+",".join(missing))
    return {"status":"portal_only","billing_enabled":env.get("NEXT_PUBLIC_BILLING_ENABLED"),"routes":sorted(routes)}

def verify_preserved_identities(before, after, services):
    for service in services:
        if before.get(service) != after.get(service):
            raise RuntimeError("preserved service identity changed: "+service)

class CommandFailure(RuntimeError):
    pass


class AuditCollector:
    """本次事务私有的 subprocess 审计收集器。刻意不跨调用共享：contextvar 里存
    的是本事务新建的实例，事务结束即丢弃，因此上一轮 resume 的命令绝不会混进
    本轮证据。记录先按真实顺序攒在内存里，等 attempt 目录安全创建（root 属主、
    0700、唯一名称）之后再 flush，于是 preauth 阶段的命令——包括第一条
    docker ps、决定 interface 的 ip route、以及 iptables-save——同样带真实
    argv 与真实 exit 落在受保护证据里，而不必提前在媒体目录里落任何文件。"""

    def __init__(self):
        self.records=[]
        self.invocation=os.urandom(16).hex()
        self.sequence=0

    def record(self,value):
        self.records.append({**value,"invocation":self.invocation,"sequence":self.sequence})
        self.sequence+=1
        if getattr(self,"path",None): self.flush(self.path)

    def flush(self,path):
        # 追加而非覆盖：同一 attempt 内 flush 两次也不会丢掉先前证据。
        safe_append(path,"".join(json.dumps(value)+"\n" for value in self.records).encode())
        self.records=[]


def run(args, input=None, timeout=180, log=None, cwd=None, env=None):
    audit=ROLLBACK_AUDIT.get()
    def record(value):
        if audit is not None:
            audit.record(value)
    record({"argv":args,"phase":"start","input_sha256":hashlib.sha256(input.encode()).hexdigest() if input is not None else None})
    try:
        result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    except BaseException as error:
        def partial(value):
            return value.decode(errors="replace") if isinstance(value,bytes) else value
        record({"argv":args,"phase":"exception","type":type(error).__name__,
                "stdout":partial(getattr(error,"stdout",None)),"stderr":partial(getattr(error,"stderr",None))})
        raise
    record({"argv":args,"phase":"exit","returncode":result.returncode,"stdout":result.stdout,"stderr":result.stderr})
    if log:
        safe_append(log,(result.stdout+result.stderr).encode())
    if result.returncode:
        raise CommandFailure("command failed: "+str(args[0])+" "+str(args[1] if len(args)>1 else "")+"; details in protected release log")
    return result.stdout.strip()

def digest(path):
    with Path(path).open("rb") as stream: return hashlib.file_digest(stream, "sha256").hexdigest()

def portable_image_id(image):
    if not image.get("Descriptor"):
        return image["Id"]
    raw = run(["ctr", "--address", "/run/containerd/containerd.sock", "--namespace", "moby", "content", "get", image["Id"]])
    if "sha256:"+hashlib.sha256(raw.encode()).hexdigest() != image["Id"]:
        raise RuntimeError("OCI manifest digest differs")
    value = json.loads(raw).get("config", {}).get("digest", "")
    if not re.fullmatch(IMAGE_PATTERN, value): raise RuntimeError("OCI image config identity missing")
    return value


def fd_identity(info):
    return info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink


def written_identity(info):
    return fd_identity(info)+(info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def verify_directory_fd(directory,info):
    private_root=ROOT/"development-releases"/"rollback-attempts"
    if directory==private_root or directory.parent==private_root:
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise RuntimeError("protected recovery directory fd must be owned mode 700")
        return
    owner=INSTALL_OWNER.get() if directory.is_relative_to(ROOT/"releases") else None
    allowed={0,os.geteuid()}|({owner[0]} if owner else set())
    if info.st_uid not in allowed: raise RuntimeError("unauthorised directory owner: "+str(directory))
    if info.st_uid==0 and info.st_mode & stat.S_ISVTX: return
    if info.st_mode & 0o002: raise RuntimeError("unauthorised writable directory: "+str(directory))
    if info.st_mode & 0o020:
        if not owner or info.st_gid!=owner[1]: raise RuntimeError("unauthorised writable directory: "+str(directory))
        members={entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid==owner[1]}
        members.update(pwd.getpwnam(name).pw_uid for name in grp.getgrgid(owner[1]).gr_mem)
        if not members<={0,owner[0]}: raise RuntimeError("unauthorised write-capable installation group")


@contextlib.contextmanager
def safe_parent(path):
    path=Path(os.path.abspath(path))
    descriptors=[os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
    links=[]
    directory=Path("/")
    def verify():
        for parent,name,child,directory in links:
            verify_directory_fd(directory,os.fstat(child))
            if fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=fd_identity(os.fstat(child)):
                raise RuntimeError("safe path directory identity changed")
    try:
        for name in path.parent.parts[1:]:
            directory=directory/name
            parent=descriptors[-1]
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            descriptors.append(child)
            info=os.fstat(child)
            verify_directory_fd(directory,info)
            links.append((parent,name,child,directory))
        verify()
        yield descriptors[-1],path.name,verify
        verify()
    finally:
        for descriptor in reversed(descriptors): os.close(descriptor)


def verify_file_fd(fd,parent,name,private=False):
    info=os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or
            info.st_nlink!=1 or info.st_mode & 0o022 or
            (private and stat.S_IMODE(info.st_mode)!=0o600) or
            fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=fd_identity(info)):
        raise RuntimeError("unsafe managed file fd or changed path identity")
    return info


def safe_read(path,private=False):
    with safe_parent(path) as (parent,name,verify):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            verify_file_fd(fd,parent,name,private); verify()
            with os.fdopen(os.dup(fd),"rb") as stream: value=stream.read()
            verify_file_fd(fd,parent,name,private); verify()
            return value
        finally: os.close(fd)


def safe_append(path,content):
    with safe_parent(path) as (parent,name,verify):
        try: fd=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:
            fd=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            verify_file_fd(fd,parent,name,True); verify()
            with os.fdopen(os.dup(fd),"wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            verify_file_fd(fd,parent,name,True); verify(); os.fsync(parent)
        finally: os.close(fd)


def safe_unlink(path):
    with safe_parent(path) as (parent,name,verify):
        descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            verify_file_fd(descriptor,parent,name); verify()
            os.unlink(name,dir_fd=parent); verify(); os.fsync(parent)
        finally: os.close(descriptor)


def authenticate_write_paths(paths):
    for path in paths:
        with safe_parent(path) as (parent,name,verify):
            try: fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            except FileNotFoundError: continue
            try: verify_file_fd(fd,parent,name); verify()
            finally: os.close(fd)


def safe_mkdir(path,exist_ok=False):
    with safe_parent(path) as (parent,name,verify):
        try: os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:
            if not exist_ok: raise
        descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            info=os.fstat(descriptor)
            if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
                raise RuntimeError("protected directory must belong to executing account and have mode 700")
            if fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=fd_identity(info):
                raise RuntimeError("protected directory identity changed")
            verify(); os.fsync(parent)
        finally: os.close(descriptor)


def persist_audit(audit):
    if not audit.records: return
    if not getattr(audit,"path",None):
        parent=ROOT/"development-releases"/"rollback-attempts"
        safe_mkdir(parent,exist_ok=True)
        directory=parent/("audit-"+audit.invocation)
        safe_mkdir(directory)
        audit.path=directory/"subprocess.jsonl"
        print("ROLLBACK_AUDIT_PATH="+str(audit.path),flush=True)
    audit.flush(audit.path)


def atomic_bytes(path, content, mode=0o600):
    with safe_parent(path) as (parent,name,verify):
        authenticate_write_paths([path])
        if name=="recovery-checkpoint.json":
            try: os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise FileExistsError("immutable recovery checkpoint already exists")
        temporary=name+".development-new"
        try: fd=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
        except FileExistsError as error: raise RuntimeError("stale temporary file: "+str(path)) from error
        published=False; written=None
        try:
            verify_file_fd(fd,parent,temporary); verify()
            with os.fdopen(os.dup(fd),"wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            written=os.fstat(fd)
            verify_file_fd(fd,parent,temporary); verify()
            authenticate_write_paths([path])
            verify()
            if name=="recovery-checkpoint.json":
                os.link(temporary,name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
                os.unlink(temporary,dir_fd=parent)
            else:
                os.replace(temporary,name,src_dir_fd=parent,dst_dir_fd=parent)
            published=True
            verify_file_fd(fd,parent,name); verify(); os.fsync(parent)
        finally:
            if not published and written is not None:
                try:
                    verify_file_fd(fd,parent,temporary); verify()
                    latest=os.fstat(fd)
                    if written_identity(latest)==written_identity(written):
                        with os.fdopen(os.dup(fd),"rb") as stream:
                            stream.seek(0); matches=stream.read()==content
                        if matches and written_identity(os.fstat(fd))==written_identity(latest):
                            verify_file_fd(fd,parent,temporary); verify()
                            os.unlink(temporary,dir_fd=parent)
                except (OSError,RuntimeError): pass
            os.close(fd)

def write_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2)+"\n").encode())

def inspect_runtime():
    ids = run(["docker", "ps", "-q"]).split()
    rows = json.loads(run(["docker", "inspect", *ids]))
    result = {}
    for row in rows:
        labels = row["Config"].get("Labels") or {}
        service = labels.get("com.docker.compose.service")
        if service:
            if service in result: raise RuntimeError("multiple Compose projects use "+service)
            result[service] = row
    return result

OPS_BACKUP_OWNER_UID = 0

def authenticate_ops_rollback(path, workdir, service):
    # Only the reviewed control-plane URL rollback format is an admissible
    # historical input. It remains an input to full image/env/resource checks.
    root = ROOT / "ops-backups"
    if service != "control-plane" or path.name != "rollback-control-plane.json" or path.parent.parent != root:
        raise RuntimeError("Compose file escapes runtime: " + service)
    if not re.fullmatch(r"gateway-public-url-[0-9]{8}T[0-9]{6}Z", path.parent.name):
        raise RuntimeError("unrecognized operational rollback")
    manifest_path = path.parent / "manifest.json"
    for item in (root, path.parent, path, manifest_path):
        metadata = item.lstat()
        if item.is_symlink() or item.resolve(strict=True) != item or metadata.st_uid != OPS_BACKUP_OWNER_UID or metadata.st_mode & 0o022:
            raise RuntimeError("operational rollback input is not root protected")
    if not path.is_file() or not manifest_path.is_file() or path.stat().st_mode & 0o077 or manifest_path.stat().st_mode & 0o077:
        raise RuntimeError("operational rollback files must be private regular files")
    try:
        manifest = json.loads(manifest_path.read_text())
        record = manifest["files"][path.name]
        valid = (manifest.get("complete") is True and manifest.get("working_dir") == str(workdir)
                 and manifest.get("rollback_frozen_config") == str(path)
                 and manifest.get("chain_path") == str(workdir / ".upgrade/compose-files")
                 and record.get("sha256") == digest(path) and record.get("bytes") == path.stat().st_size)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("operational rollback manifest is invalid") from exc
    if not valid:
        raise RuntimeError("operational rollback manifest binding differs")
    return manifest_path

def resolve_compose_chain(rows, workdir, services=SERVICES):
    workdir = Path(workdir).resolve()
    expected = None
    for service in services:
        if service not in rows:
            raise RuntimeError("required VM service absent: "+service)
        labels = rows[service]["Config"].get("Labels") or {}
        raw = labels.get("com.docker.compose.project.config_files","")
        parts = raw.split(",") if raw else []
        if not parts or len(parts) > MAX_GOVERNED_BOOT_FILES or any(not part for part in parts):
            raise RuntimeError("invalid Compose file chain: "+service)
        chain = []
        for part in parts:
            candidate = Path(part)
            if not candidate.is_absolute():
                raise RuntimeError("Compose path must be absolute: "+service)
            if candidate.is_symlink():
                raise RuntimeError("Compose file is a symbolic link: "+service)
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise RuntimeError("Compose file is unavailable: "+service) from exc
            if not resolved.is_relative_to(workdir):
                authenticate_ops_rollback(candidate, workdir, service)
            if not resolved.is_file():
                raise RuntimeError("Compose path is not a file: "+service)
            chain.append(resolved)
        chain = tuple(chain)
        if len(set(chain)) != len(chain):
            raise RuntimeError("Compose file chain contains duplicates: "+service)
        if expected is None:
            expected = chain
        elif chain != expected:
            raise RuntimeError("Compose file chain differs across target services")
    return expected

def resolve_release_compose(rows, workdir, services, engineering, render, image_identity):
    # Full/portal releases can follow partial engineering releases. Verify
    # equivalent historical models for every mode, not just engineering-only.
    chains = {service: resolve_compose_chain(rows, workdir, (service,)) for service in services}
    # Every supported non-portal VM release updates SE. Its complete model also
    # records a later SE-only replacement, while the gateway may still name the
    # preceding full release. Keep the same per-service equivalence checks.
    canonical = chains.get("security-engine", chains.get("gateway-core", next(iter(chains.values()))))
    def verify_model(files):
        model = render(files)
        for service, chain in chains.items():
            other = model if chain == files else render(chain)
            if model.get("name") != other.get("name"):
                raise RuntimeError("Compose projects differ: "+service)
            left = copy.deepcopy(model["services"][service])
            right = copy.deepcopy(other["services"][service])
            for item in (left, right):
                item["image"] = image_identity(item["image"])
                for key in ("build", "env_file", "pull_policy"): item.pop(key, None)
            if left != right or left["image"] != rows[service]["Image"]:
                raise RuntimeError("historical Compose service differs: "+service)
            actual_env = dict(value.split("=",1) for value in rows[service]["Config"].get("Env",[]) if "=" in value)
            if any(str(value) != actual_env.get(key) for key,value in left.get("environment",{}).items() if value is not None):
                raise RuntimeError("live environment differs from declared Compose: "+service)
            # Referenced network/volume definitions are part of the service contract.
            networks = left.get("networks", {})
            volumes = [v["source"] for v in left.get("volumes", []) if isinstance(v, dict) and v.get("type") == "volume"]
            for kind, names in (("networks", networks), ("volumes", volumes)):
                for name in names:
                    if model.get(kind, {}).get(name) != other.get(kind, {}).get(name):
                        raise RuntimeError("historical Compose resource differs: "+service)

    boot_pointer = None
    try:
        verify_model(canonical)
    except RuntimeError:
        # Console-only releases persist CP/Web without recreating SE. Accept the
        # governed boot model only if every historical and live contract matches.
        boot_pointer = Path(workdir)/".upgrade/compose-files"
        if not boot_pointer.exists() and not boot_pointer.is_symlink():
            raise
        canonical = boot_chain_files(workdir)
        if len(canonical) > MAX_GOVERNED_BOOT_FILES or len(set(canonical)) != len(canonical):
            raise RuntimeError("invalid governed boot chain")
        for path in (boot_pointer, *canonical):
            if not path.is_absolute() or ".." in path.parts or path.is_symlink():
                raise RuntimeError("unprotected governed boot chain path")
            resolved = path.resolve(strict=True)
            if resolved != path or not resolved.is_relative_to(Path(workdir).resolve()) or not resolved.is_file():
                raise RuntimeError("unprotected governed boot chain path")
        verify_model(canonical)
    inputs = list(canonical)
    for service, chain in chains.items():
        for path in chain:
            if path not in inputs: inputs.append(path)
            if not path.is_relative_to(Path(workdir).resolve()):
                manifest_path = authenticate_ops_rollback(path, Path(workdir).resolve(), service)
                if manifest_path not in inputs: inputs.append(manifest_path)
    if boot_pointer is not None:
        inputs.append(boot_pointer)
    return canonical, tuple(inputs)


def safe_identity(rows):
    return {s: {"id":r["Id"], "image":r["Image"], "started_at":r["State"]["StartedAt"], "restarts":r["RestartCount"],
                "status":r["State"]["Status"], "health":r["State"].get("Health",{}).get("Status","none")}
            for s,r in rows.items()}

def build_model(model, manifest, running):
    window_limit = manifest.get("semantic_max_windows")
    if window_limit is not None:
        if type(window_limit) is not int or window_limit <= 0:
            raise RuntimeError("invalid semantic window limit")
        if "security-engine" not in manifest["services"]:
            raise RuntimeError("semantic window override requires security-engine release")
    signed_environment = login_ip_forward_environment(manifest, running)
    new = copy.deepcopy(model)
    if not set(SERVICES) <= set(new["services"]): raise RuntimeError("required service absent")
    for service, row in running.items():
        if service not in new["services"]: raise RuntimeError("running service missing from model")
        item = new["services"][service]
        item["image"] = row["Image"]
        item.pop("build", None)
        item.pop("env_file", None)
        item["pull_policy"] = "never"
    for service, record in manifest["services"].items():
        if not re.fullmatch(IMAGE_PATTERN, record["image_id"]): raise RuntimeError("unfixed image")
        item = new["services"][service]
        item["image"] = record["image_id"]
        env = item.setdefault("environment", {})
        env.update(JJD_COMMIT=manifest["revision"], JJD_VERSION=manifest["version"], JJD_BUILT_AT=manifest["created_at"])
        env.update(signed_environment.get(service, {}))
        if service == "control-plane":
            env.update(chat_login_proxy_environment(manifest))
        if service == "gateway-core":
            env.update(gateway_budget_environment(manifest))
        if service == "security-engine":
            env["SECURITY_ENGINE_BUILD"] = manifest["revision"]
            env.update(semantic_parallel_environment(manifest))
            if window_limit is not None:
                env["SECURITY_SEMANTIC_MAX_WINDOWS"] = str(window_limit)
        if service == "proxy-server":
            key = new["services"]["control-plane"].get("environment", {}).get("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY", "")
            if not isinstance(key, str) or len(key) < 16:
                raise RuntimeError("signed proxy inspection scope requires control-plane attestation key")
            existing = env.get("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY")
            if existing and existing != key:
                raise RuntimeError("proxy inspection attestation key differs from control-plane")
            env["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"] = key
        if manifest.get("enable_file_detection") and service in ("control-plane","gateway-core","proxy-server","security-engine"):
            env["SECURITY_FILE_CONTENT_DLP_ENABLED"] = "true"
    if manifest.get("enable_file_detection"):
        item = new["services"]["security-engine"]
        root = item["environment"].setdefault("SECURITY_SCAN_STORE_DIR", "/var/lib/jjdguard/scan-store")
        if root != "/var/lib/jjdguard/scan-store":
            raise RuntimeError("custom scan-store path requires explicit review")
        tmpfs = item.setdefault("tmpfs", [])
        mounted = any(v.split(":", 1)[0] == root for v in tmpfs) or any(v.get("target") == root for v in item.get("volumes", []))
        if not mounted:
            tmpfs.append(root + ":rw,noexec,nosuid,size=512m,mode=0700,uid=10001,gid=10001")
    return new

def perform(adapter):
    """Keep ingress fenced until database/image checks and rollback finish."""
    mutated = False
    adapter.fence()
    try:
        adapter.stop_writers()
        adapter.backup()
        mutated = True
        adapter.migrate()
        adapter.switch()
        adapter.verify()
        adapter.commit()
    except BaseException as error:
        manifest = getattr(adapter, "manifest", None)
        identity_chat = isinstance(manifest, dict) and manifest.get("identity_chat_only") is True
        def evidence(rollback, ingress, restore_error=None):
            if identity_chat:
                record = {"status":"apply_failed", "release_id":adapter.manifest["release_id"],
                          "failure_type":type(error).__name__, "failure_message":str(error)[:1500],
                          "rollback":rollback, "ingress":ingress}
                if restore_error is not None:
                    record["restore_failure_type"] = type(restore_error).__name__
                    record["restore_failure_message"] = str(restore_error)[:1500]
                write_json(adapter.media/"failure.json", record)
        try:
            if mutated: adapter.restore()
            else: adapter.restart_original()
        except BaseException as restore_error:
            evidence("incomplete", "fenced", restore_error)
            raise
        try:
            adapter.unfence()
        except BaseException as restore_error:
            evidence("complete", "unknown", restore_error)
            raise
        evidence("complete", "open")
        raise
    adapter.unfence()

def verify_migration_runtime(media, manifest):
    for filename, field in (("migration-runner.sh", "migration_runner_sha256"), ("migration-version.sh", "migration_version_sha256")):
        path = media/filename
        if not path.is_file() or digest(path) != manifest.get(field):
            raise RuntimeError("migration runtime differs: "+filename)

DATABASE_RESTORE_MINIMUM_TIMEOUT = 3600
DATABASE_RESTORE_LAUNCHER = 'umask 077; set -C; printf "%s\\n" "$$" > "$1" || exit 73; shift; exec "$@"'


def database_restore_process_absent(pg, pid):
    # A failed Docker command is not evidence that the in-container process
    # disappeared. Only this successful explicit /proc absence check is.
    state = run(["docker", "exec", pg, "sh", "-c",
                 'if [ -e "/proc/$1" ]; then printf "present"; else printf "absent"; fi', "--", str(pid)], timeout=30)
    if state not in ("present", "absent"):
        raise RuntimeError("database restore process state is ambiguous; ingress stays fenced")
    return state == "absent"


def database_restore_process_identity(pg, pid, expected, marker):
    if not re.fullmatch(r"[1-9][0-9]*", str(pid)):
        raise RuntimeError("database restore PID is invalid")
    try:
        raw = run(["docker", "exec", pg, "cat", "/proc/"+str(pid)+"/cmdline"], timeout=30)
        info = run(["docker", "exec", pg, "cat", "/proc/"+str(pid)+"/stat"], timeout=30)
    except CommandFailure:
        if database_restore_process_absent(pg, pid):
            return None
        raise
    argv = raw.rstrip("\0").split("\0")
    fields = info[info.rfind(")")+2:].split()
    restoring = bool(argv) and Path(argv[0]).name == "pg_restore" and argv[1:] == expected[1:]
    starting = bool(argv) and Path(argv[0]).name in ("sh", "ash") and argv[1:] == ["-c", DATABASE_RESTORE_LAUNCHER, "--", marker, *expected]
    if not (restoring or starting) or len(fields) < 20:
        raise RuntimeError("database restore process identity differs; no signal sent")
    return dict(pid=int(pid), start_time=fields[19], phase="restore" if restoring else "starting",
                argv_sha256=hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest())


def stop_database_restore_process(pg, identity, expected, marker):
    for sig in ("TERM", "KILL"):
        actual = database_restore_process_identity(pg, identity["pid"], expected, marker)
        if actual is None:
            return
        if any(actual[key] != identity[key] for key in ("pid", "start_time")):
            raise RuntimeError("database restore PID was reused; no signal sent")
        run(["docker", "exec", pg, "kill", "-"+sig, str(identity["pid"])], timeout=30)
        deadline = time.monotonic()+15
        while time.monotonic() < deadline:
            actual = database_restore_process_identity(pg, identity["pid"], expected, marker)
            if actual is None:
                return
            if any(actual[key] != identity[key] for key in ("pid", "start_time")):
                raise RuntimeError("database restore PID was reused; no signal sent")
            time.sleep(.25)
    raise RuntimeError("authenticated database restore did not stop; ingress stays fenced")


def run_database_restore(pg, user, backup_path, state_dir, timeout, event):
    """Restore with a bounded server-side process lifetime and private evidence.

    Killing `docker exec` alone leaves its pg_restore child alive. A random,
    noclobber PID marker binds this exact launch; PID/starttime/argv checks
    authenticate both the starting shell and its exec into pg_restore before
    cleanup may signal anything. The Docker client is stopped last.
    """
    if type(timeout) is not int or timeout < DATABASE_RESTORE_MINIMUM_TIMEOUT:
        raise RuntimeError("database restore deadline is below the supported minimum")
    nonce = os.urandom(16).hex()
    marker = "/tmp/jjdguard-restore-"+nonce+".pid"
    appname = "jjdguard-restore-"+nonce
    expected = ["pg_restore", "--clean", "--if-exists", "--create", "--exit-on-error", "-U", user, "-d", "postgres"]
    argv = ["docker", "exec", "-i", "-e", "PGAPPNAME="+appname, pg, "sh", "-c", DATABASE_RESTORE_LAUNCHER, "--", marker, *expected]
    state_dir, backup_path = Path(state_dir), Path(backup_path)
    stderr_path = state_dir/("pg-restore-"+nonce+".stderr.log")
    attempt_path = state_dir/("restore-attempt-"+nonce+".json")
    authenticate_write_paths([stderr_path, attempt_path])
    result = dict(application_name=appname, stderr_file=stderr_path.name, timeout_seconds=timeout)
    identity = process = None
    with safe_parent(backup_path) as (parent, name, verify):
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=parent)
        try:
            original = verify_file_fd(fd, parent, name, private=True); verify()
            with os.fdopen(os.dup(fd), "rb") as source, os.fdopen(os.open(stderr_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600), "wb") as error_log:
                process = subprocess.Popen(argv, stdin=source, stdout=subprocess.DEVNULL, stderr=error_log)
                started = last_progress = time.monotonic()
                deadline = started+timeout
                event("RESTORE database started; deadline_seconds="+str(timeout))
                try:
                    while process.poll() is None:
                        if identity is None or identity.get("phase") == "starting":
                            try:
                                pid = run(["docker", "exec", pg, "cat", marker], timeout=10).strip()
                                observed = database_restore_process_identity(pg, pid, expected, marker)
                                if observed is not None:
                                    identity = observed
                                    result["process"] = identity
                            except CommandFailure:
                                pass
                        now = time.monotonic()
                        if (identity is None or identity.get("phase") == "starting") and now-started > 30:
                            raise RuntimeError("authenticated database restore did not start within deadline")
                        remaining = deadline-now
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired("authenticated pg_restore", timeout)
                        if now-last_progress >= 30:
                            event("RESTORE database running; elapsed_seconds="+str(int(now-started)))
                            last_progress = now
                        try:
                            process.wait(timeout=min(5, remaining))
                        except subprocess.TimeoutExpired:
                            pass
                    error_log.flush(); os.fsync(error_log.fileno())
                    if process.returncode != 0:
                        raise RuntimeError("database restore failed; inspect protected stderr log")
                    if identity is not None and database_restore_process_identity(pg, identity["pid"], expected, marker) is not None:
                        raise RuntimeError("database restore process remains after client success")
                except BaseException as error:
                    cleanup_error = None
                    try:
                        if identity is None:
                            try:
                                pid = run(["docker", "exec", pg, "cat", marker], timeout=10).strip()
                                identity = database_restore_process_identity(pg, pid, expected, marker)
                            except CommandFailure:
                                if process.poll() is None:
                                    raise RuntimeError("database restore process could not be authenticated for cleanup")
                        if identity is not None:
                            stop_database_restore_process(pg, identity, expected, marker)
                    except BaseException as cleanup:
                        cleanup_error = type(cleanup).__name__
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill(); process.wait(timeout=10)
                    result.update(status="failed", failure_type=type(error).__name__, exit_code=process.returncode,
                                  cleanup_failure_type=cleanup_error)
                    write_json(attempt_path, result)
                    if cleanup_error:
                        raise RuntimeError("database restore cleanup incomplete; ingress stays fenced") from error
                    raise
            after = verify_file_fd(fd, parent, name, private=True); verify()
            if written_identity(original) != written_identity(after):
                raise RuntimeError("database backup changed while restoring; ingress stays fenced")
        finally:
            os.close(fd)
    result.update(status="database_restored", exit_code=0, stderr_sha256=digest(stderr_path))
    write_json(attempt_path, result)
    return result


def selinux_enforce_state():
    try:
        path = Path("/sys/fs/selinux/enforce")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return "unknown"
        value = path.read_text().strip()
        return value if value in ("0", "1") else "unknown"
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unknown"


def read_identity_chat_mount_policy():
    """Observe the daemon and kernel; no request/manifest flag can disable SELinux."""
    policy = {"schema":1, "selinux":"unknown", "daemon_id":None,
              "docker_security_options":None, "kernel_enforce":"unknown"}
    try:
        info = json.loads(run(["docker", "info", "--format",
                               '{"ID":{{json .ID}},"SecurityOptions":{{json .SecurityOptions}}}'], timeout=30))
        options, identifier = info.get("SecurityOptions"), info.get("ID")
        if (not isinstance(options,list) or not all(isinstance(item,str) for item in options) or
                not isinstance(identifier,str) or not identifier):
            return policy
        policy.update(daemon_id=identifier, docker_security_options=sorted(options))
        policy["kernel_enforce"] = selinux_enforce_state()
        daemon_selinux = any(item.split(",",1)[0].lower() in ("selinux", "name=selinux") for item in options)
        if daemon_selinux or policy["kernel_enforce"] in ("0", "1"):
            policy["selinux"] = "enabled"
        elif policy["kernel_enforce"] == "absent":
            policy["selinux"] = "disabled"
    except (CommandFailure, OSError, ValueError, AttributeError):
        pass
    return policy


def disabled_selinux_mount_policy(policy):
    return (isinstance(policy,dict) and policy.get("schema") == 1 and type(policy.get("schema")) is int and
            policy.get("selinux") == "disabled" and policy.get("kernel_enforce") == "absent" and
            isinstance(policy.get("daemon_id"),str) and bool(policy["daemon_id"]) and
            isinstance(policy.get("docker_security_options"),list) and
            all(isinstance(item,str) and item.split(",",1)[0].lower() not in ("selinux", "name=selinux")
                for item in policy["docker_security_options"]))


def named_volume_label_mode(mount, mode):
    # Keep Type/Name/Source/Destination/Driver/RW and the entire HostConfig
    # unchanged in the hash. Only a label-only encoding may be canonicalized.
    if (mount.get("Type") != "volume" or not isinstance(mount.get("Name"),str) or not mount["Name"] or
            not isinstance(mount.get("Source"),str) or not os.path.isabs(mount["Source"]) or
            not isinstance(mount.get("Destination"),str) or not os.path.isabs(mount["Destination"]) or
            not isinstance(mount.get("Driver"),str) or not mount["Driver"] or type(mount.get("RW")) is not bool or
            not isinstance(mode,str)):
        return None
    tokens = mode.split(",") if mode else []
    if not tokens:
        return None
    if (len(tokens) != len(set(tokens)) or any(item not in ("rw","ro","z","Z") for item in tokens) or
            {"z","Z"} <= set(tokens) or {"rw","ro"} <= set(tokens)):
        return None
    if ("ro" in tokens and mount["RW"]) or ("rw" in tokens and not mount["RW"]):
        return None
    return "rw" if mount["RW"] else "ro"


def canonicalize_named_volume_labels(mounts, host, policy):
    if not disabled_selinux_mount_policy(policy):
        return
    named = {}
    for mount in mounts:
        mode = named_volume_label_mode(mount, mount.get("Mode"))
        if mode is None:
            continue
        key = (mount["Name"], mount["Destination"])
        if key in named:
            raise RuntimeError("ambiguous named-volume mount contract")
        named[key] = mount
        mount["Mode"] = mode
    if isinstance(host.get("Binds"),list):
        binds = []
        for binding in host["Binds"]:
            parts = binding.split(":") if isinstance(binding,str) else []
            mount = named.get(tuple(parts[:2])) if len(parts) in (2,3) else None
            mode = named_volume_label_mode(mount,parts[2] if len(parts)==3 else "") if mount is not None else None
            binds.append(parts[0]+":"+parts[1]+":"+mode if mode is not None else binding)
        host["Binds"] = sorted(binds)


def preflight_identity_chat_mount_modes(rows, target_services, policy):
    # A legacy label encoding that cannot be proved inert is rejected during
    # stage, before application fencing, writer stops or database migrations.
    for service in target_services:
        row = rows[service]
        mounts = row.get("Mounts") or []
        for mount in mounts:
            mode = mount.get("Mode")
            tokens = mode.split(",") if isinstance(mode,str) else []
            if set(tokens) & {"z","Z"}:
                if not disabled_selinux_mount_policy(policy) or named_volume_label_mode(mount,mode) is None:
                    raise RuntimeError("unverified SELinux mount-label transition; stage refused before fencing: "+service)
        for binding in (row.get("HostConfig") or {}).get("Binds") or []:
            parts = binding.split(":") if isinstance(binding,str) else []
            if len(parts)==3 and set(parts[2].split(",")) & {"z","Z"}:
                matches = [mount for mount in mounts if mount.get("Type")=="volume" and
                           mount.get("Name")==parts[0] and mount.get("Destination")==parts[1]]
                if (not disabled_selinux_mount_policy(policy) or len(matches)!=1 or
                        named_volume_label_mode(matches[0],parts[2]) is None or
                        named_volume_label_mode(matches[0],matches[0].get("Mode")) is None):
                    raise RuntimeError("unverified SELinux bind/mount option transition; stage refused before fencing: "+service)


def original_input_metadata(paths):
    result = {}
    for path in sorted({str(Path(path)) for path in paths}):
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("original input is not a regular file")
        result[path] = {"uid":info.st_uid, "gid":info.st_gid, "mode":stat.S_IMODE(info.st_mode)}
    return result


def validate_original_input_metadata(before):
    expected = before.get("original_input_metadata")
    if expected is None:
        return  # Do not infer ownership from a legacy installation root.
    paths = set(before.get("compose_sha256") or {}) | {str(staged_env_file(before))}
    if not isinstance(expected,dict) or set(expected)!=paths or original_input_metadata(paths)!=expected:
        raise RuntimeError("original input ownership or mode changed since stage")


def identity_chat_runtime_contract(row, allow_provenance=False, mount_policy=None):
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
                "com.docker.compose.depends_on", *("org.opencontainers.image.revision", "com.jjdguard.source.tree", "com.jjdguard.base.image", "com.jjdguard.release.id")):
        labels.pop(key, None)
    env = config.get("Env") or []
    if allow_provenance:
        # Target labels are independently authenticated by stage and verify.
        # Full fingerprints keep this metadata, including for non-targets.
        labels.pop("com.docker.compose.project.environment_file", None)
        # Creator version and the previous container's ID/name are Compose
        # provenance, not application configuration. Both change when an old
        # 2.24 container is recreated with the authenticated bundled Compose.
        # Keep project/service/working-dir, all user labels, security flags,
        # mounts and network settings bound by the runtime contract.
        labels.pop("com.docker.compose.version", None)
        labels.pop("com.docker.compose.replace", None)
        # 构建来源地址是镜像出处元数据，开发构建不写这个标签，旧镜像有；
        # 出处由 manifest 与 JJD_COMMIT 独立认证，不进运行契约比较。
        labels.pop("org.opencontainers.image.source", None)
        env = [v for v in env if v.split("=", 1)[0] not in ("JJD_COMMIT", "JJD_VERSION", "JJD_BUILT_AT")]
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
    mounts = copy.deepcopy(row.get("Mounts") or [])
    if allow_provenance:
        canonicalize_named_volume_labels(mounts,host,mount_policy)
    mounts = sorted(mounts, key=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")))
    networks = {}
    for name, value in row.get("NetworkSettings", {}).get("Networks", {}).items():
        aliases = [v for v in value.get("Aliases") or [] if v not in (row["Id"], row["Id"][:12])]
        networks[name] = {key: value.get(key) for key in ("NetworkID", "IPAMConfig", "Links", "DriverOpts")}
        networks[name]["Aliases"] = sorted(aliases)
    return dict(config=config, host=host, mounts=mounts, networks=networks, path=row.get("Path"), args=row.get("Args"))

def identity_chat_contract_hash(row, allow_provenance=False, mount_policy=None):
    return hashlib.sha256(json.dumps(identity_chat_runtime_contract(row, allow_provenance, mount_policy), sort_keys=True, separators=(",",":")).encode()).hexdigest()

def identity_chat_snapshot(rows, manifest=None, witness=None, mount_policy=None):
    if mount_policy is None and manifest is not None and manifest.get("identity_chat_only") is True:
        mount_policy = read_identity_chat_mount_policy()
    witness_ids = {row["Id"] for row in rows.values()}
    if witness is not None:
        witness.update(schema=1, containers={})
    def identity(row, target=False, approved_environment=None):
        contract = identity_chat_runtime_contract(row, target, mount_policy)
        if not target:
            contract["config"] = copy.deepcopy(row["Config"])
            contract["config"]["Env"] = sorted(contract["config"].get("Env") or [])
        contract_hash = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",",":")).encode()).hexdigest()
        record = dict(id=row["Id"], image=row["Image"], started_at=row["State"]["StartedAt"],
                      restarts=row["RestartCount"], status=row["State"]["Status"],
                      health=row["State"].get("Health", {}).get("Status", "none"),
                      contract=contract_hash)
        captured = {"contract":copy.deepcopy(contract)}
        if target and approved_environment:
            # Freeze the expected candidate contract using exact manifest-approved values.
            # Keep the original contract for pre-switch checks and rollback; never erase
            # approved keys from the actual runtime hash, so missing/wrong values fail.
            candidate = copy.deepcopy(row)
            env = dict(value.split("=", 1) for value in candidate["Config"].get("Env", []) if "=" in value)
            env.update(approved_environment)
            candidate["Config"]["Env"] = [key+"="+value for key,value in env.items()]
            record["candidate_contract"] = identity_chat_contract_hash(candidate, True, mount_policy)
            captured["candidate_contract"] = identity_chat_runtime_contract(candidate, True, mount_policy)
        if witness is not None and row["Id"] in witness_ids:
            witness["containers"][row["Id"]] = captured
        return record
    targets = set(release_service_sets(manifest)[0] if manifest is not None else IDENTITY_CHAT_SERVICES)
    approved = manifest_approved_environment(manifest, rows) if manifest is not None else {}
    runtime = {name:identity(row, name in targets, approved.get(name)) for name,row in rows.items()}
    ids = run(["docker", "ps", "-a", "-q"]).split()
    objects = json.loads(run(["docker", "inspect", *ids])) if ids else []
    target_ids = {row["Id"] for name,row in rows.items() if name in targets}
    inventory = {row["Id"]:identity(row) for row in objects if row["Id"] not in target_ids}
    if len(objects) != len({row["Id"] for row in objects}): raise RuntimeError("ambiguous container inventory")
    snapshot = dict(runtime=runtime, inventory=inventory)
    if mount_policy is not None:
        snapshot["mount_policy"] = copy.deepcopy(mount_policy)
    return snapshot


def validate_identity_chat_contract_witness(before):
    witness = before.get("identity_chat_contract_witness")
    if witness is None:
        return  # Legacy sealed media has only opaque hashes; never rewrite it.
    snapshot = before.get("identity_chat_runtime") or {}
    runtime = snapshot.get("runtime") or {}
    if (not isinstance(witness,dict) or witness.get("schema") != 1 or type(witness.get("schema")) is not int or
            not isinstance(witness.get("containers"),dict) or
            set(witness["containers"]) != {row["id"] for row in runtime.values()}):
        raise RuntimeError("identity-chat contract witness scope differs")
    for row in runtime.values():
        captured = witness["containers"][row["id"]]
        expected_keys = {"contract", "candidate_contract"} if "candidate_contract" in row else {"contract"}
        if not isinstance(captured,dict) or set(captured) != expected_keys:
            raise RuntimeError("identity-chat contract witness fields differ")
        for key in expected_keys:
            checksum = hashlib.sha256(json.dumps(captured[key],sort_keys=True,separators=(",",":")).encode()).hexdigest()
            if checksum != row[key]:
                raise RuntimeError("identity-chat contract witness differs from frozen hash")


def docker_started_at_ns(value):
    if not isinstance(value, str):
        raise RuntimeError("invalid Docker StartedAt timestamp")
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value)
    if not match or match.group(3) == "-00:00":
        raise RuntimeError("invalid Docker StartedAt timestamp")
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    try:
        instant = datetime.datetime.fromisoformat(match.group(1)+zone)
    except ValueError as error:
        raise RuntimeError("invalid Docker StartedAt timestamp") from error
    delta = instant.astimezone(datetime.timezone.utc)-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000000+int((match.group(2) or "").ljust(9,"0"))


def verify_identity_chat_snapshot(before, after, manifest, replaced=False, resumed=False, rollback=False, resumed_services=None):
    if "mount_policy" in before and before["mount_policy"] != after.get("mount_policy"):
        raise RuntimeError("identity-chat SELinux/daemon mount policy changed")
    if set(before["runtime"]) != set(after["runtime"]): raise RuntimeError("identity-chat runtime service set changed")
    target_services, _ = release_service_sets(manifest)
    stoppable, restartable = release_writer_sets(manifest, before["runtime"], target_services)
    if resumed_services is not None:
        allowed = restartable if replaced else stoppable
        if not set(resumed_services) <= set(allowed):
            raise RuntimeError("identity-chat resumed service scope is not authorised")
        restartable = tuple(resumed_services)
    resumed_ids = {before["runtime"][name]["id"] for name in restartable} if resumed else set()
    def compare(expected, actual, target=False):
        left, right = copy.deepcopy(expected), copy.deepcopy(actual)
        expected_candidate = left.pop("candidate_contract", None)
        right.pop("candidate_contract", None)
        if target and replaced and not rollback and expected_candidate is not None:
            left["contract"] = expected_candidate
        if (resumed and expected["id"] in resumed_ids) or (target and replaced):
            if docker_started_at_ns(actual["started_at"]) < docker_started_at_ns(expected["started_at"]):
                raise RuntimeError("identity-chat Docker StartedAt moved backwards")
        if resumed and expected["id"] in resumed_ids:
            # An explicitly recorded Docker start resets the historical counter.
            # Require the actual counter to be exactly zero; preserve identity and
            # every other contract field, including for the inventory copy.
            if type(actual.get("restarts")) is not int or actual["restarts"] != 0:
                raise RuntimeError("identity-chat authorised writer automatically restarted")
            left["restarts"] = 0
            left.pop("started_at", None); right.pop("started_at", None)
        if target and replaced:
            for value in (left,right):
                value.pop("id",None); value.pop("image",None); value.pop("started_at",None)
                value["restarts"] = 0
        if left != right:
            if left.get("contract") != right.get("contract"): raise RuntimeError("identity-chat runtime contract changed")
            raise RuntimeError("identity-chat non-target identity or runtime changed")
    for name, expected in before["runtime"].items():
        target = name in target_services
        actual = after["runtime"][name]
        if target and replaced:
            image = expected["image"] if rollback else manifest["services"][name]["image_id"]
            if actual["image"] != image or type(actual.get("restarts")) is not int or actual["restarts"] != 0:
                raise RuntimeError("identity-chat target image or restart identity differs: "+name)
        compare(expected, actual, target)
    if set(before["inventory"]) != set(after["inventory"]): raise RuntimeError("identity-chat non-target inventory changed")
    for identifier, expected in before["inventory"].items():
        compare(expected, after["inventory"][identifier])


def release_writer_sets(manifest, rows, target_services):
    if manifest.get("identity_chat_only"):
        scope = tuple(service for service in WRITERS if service != "tier1-classifier")
    elif manifest.get("engineering_only"):
        scope = WRITERS
    else:
        scope = tuple(service for service in WRITERS if service in set(target_services) | {"chat-portal-ui", "chat-portal-proxy"})
    stop = tuple(service for service in scope if service in rows)
    return stop, tuple(service for service in stop if service not in target_services)

def original_project_directory_groups(rows, services, fallback):
    """Keep each authenticated service's Compose creator directory and dependency order."""
    groups=[]
    for service in services:
        labels=rows[service].get("Config",{}).get("Labels") or {}
        directory=Path(labels.get("com.docker.compose.project.working_dir") or str(fallback))
        if (not directory.is_absolute() or directory.resolve()!=directory or
                not directory.is_relative_to(ROOT/"releases")):
            raise RuntimeError("original Compose working directory escapes installed releases")
        if groups and groups[-1][0]==directory:
            groups[-1][1].append(service)
        else:groups.append((directory,[service]))
    return groups


class Release:
    def __init__(self, media, expected_manifest):
        self.media = Path(media).resolve()
        if not self.media.is_relative_to(ROOT/"development-releases"): raise RuntimeError("release must stay in development-releases")
        if digest(self.media/"manifest.json") != expected_manifest: raise RuntimeError("manifest hash differs")
        self.manifest = json.loads((self.media/"manifest.json").read_text())
        m = self.manifest
        if m.get("schema") != 1 or m.get("purpose") != "development-vm": raise RuntimeError("unsupported release")
        self.target_services, self.preserved_services = release_service_sets(m)
        if not re.fullmatch(r"[0-9a-f]{40}", m["revision"]) or not re.fullmatch(r"dev-[A-Za-z0-9-]+",m["release_id"]): raise RuntimeError("invalid release identity")
        if digest(self.media/"vm_development_apply.py") != m["apply_script_sha256"]: raise RuntimeError("apply script differs")
        verify_migration_runtime(self.media, m)
        if self.preserved_services:
            if (self.media/"tier1-window-smoke.py").exists() or "tier1_probe_sha256" in m: raise RuntimeError("preserved Tier1 release contains a model probe")
            expected_validation=(
                {"identity_chat_payload_verified":True,"portal_navigation_paths":"explicit_base_path","model_services":"preserved_not_touched"}
                if m.get("identity_chat_only")
                else {"portal_navigation_paths":"explicit_base_path"}
                if m.get("portal_only")
                else {"file_selftest_passed":True,"file_http_selftest_passed":True,"tier1":"preserved_not_touched"}
            )
        else:
            if digest(self.media/"tier1-window-smoke.py") != m["tier1_probe_sha256"]: raise RuntimeError("Tier1 probe differs")
            expected_validation={"file_selftest_passed":True,"file_http_selftest_passed":True,"tier1_real_long_window_passed":True}
        if m.get("candidate_validation") != expected_validation: raise RuntimeError("candidate capability validation absent")
        for name, checksum in m["migrations"].items():
            if not re.fullmatch(r"[0-9]{3,}_[A-Za-z0-9_]+\.sql",name) or digest(self.media/"migrations"/name) != checksum: raise RuntimeError("migration differs")
        self.state_dir = self.media/"state"
        self.log = self.media/"apply.log"
        self.rows = inspect_runtime()
        if not set(SERVICES+("postgres",)) <= set(self.rows): raise RuntimeError("required VM services absent")
        labels = self.rows["control-plane"]["Config"]["Labels"]
        self.project = labels["com.docker.compose.project"]
        self.workdir = Path(labels["com.docker.compose.project.working_dir"]).resolve()
        if not self.workdir.is_relative_to(ROOT/"releases"): raise RuntimeError("unexpected runtime path")
        def render_chain(files):
            command = [str(self.workdir/"bin/docker-compose"), "--project-directory", str(self.workdir), "-p", self.project]
            for path in files: command += ["-f", str(path)]
            return json.loads(run(command+["config", "--format", "json"]))
        def image_identity(name):
            return json.loads(run(["docker", "image", "inspect", name]))[0]["Id"]
        historical_services = tuple(self.rows) if m.get("identity_chat_only") else self.target_services
        self.live_files, self.input_files = resolve_release_compose(
            self.rows, self.workdir, historical_services, m.get("engineering_only", False),
            render_chain, image_identity)
        active_dir = self.workdir/"active-config"
        if active_dir.is_symlink() or not active_dir.is_dir():
            raise RuntimeError("active-config directory is unavailable")
        self.live = active_dir/(m["release_id"]+".json")
        if not self.live.is_relative_to(self.workdir):
            raise RuntimeError("development Compose target escapes runtime")
        authenticate_write_paths([self.live])
        self.compose_bin = self.workdir/"bin/docker-compose"
        if not self.compose_bin.is_file(): raise RuntimeError("bundled Compose missing")
        self.env_file = staged_env_file({"live":str(self.live)})
        self.pg = self.rows["postgres"]["Id"]
        pg_env = dict(item.split("=",1) for item in self.rows["postgres"]["Config"]["Env"] if "=" in item)
        self.db = pg_env["POSTGRES_DB"]
        self.db_user = pg_env["POSTGRES_USER"]
        if self.db in ("postgres","template0","template1"): raise RuntimeError("application database must be separate from PostgreSQL administrative databases")
        self.chain = "JJDDEV"+hashlib.sha256(m["release_id"].encode()).hexdigest()[:10].upper()
        self.interface = json.loads(run(["ip","-j","route","show","default"]))[0]["dev"]
        self.backup_path = self.state_dir/"database.dump"
        self.lock_file = (ROOT/"development-releases/.release.lock").open("a")
        fcntl.flock(self.lock_file, fcntl.LOCK_EX|fcntl.LOCK_NB)

    def event(self, text):
        print(text, flush=True)
        with self.log.open("a") as stream: stream.write(datetime.datetime.now(datetime.timezone.utc).isoformat()+" "+text+"\n")

    def compose(self, *args, file=None, project_directory=None):
        directory=self.workdir if project_directory is None else Path(project_directory)
        if project_directory is not None:
            approved={item[0] for item in original_project_directory_groups(self.rows,self.target_services,self.workdir)}
            if directory not in approved:
                raise RuntimeError("Compose working directory was not frozen for a target service")
        command=[str(self.compose_bin),"--project-directory",str(directory),"-p",self.project]
        for path in ((Path(file),) if file is not None else self.live_files):
            command += ["-f",str(path)]
        command += list(args)
        return run(command,log=None if args and args[0]=="config" else self.log)

    def recreate_targets(self, file):
        for directory,services in original_project_directory_groups(self.rows,self.target_services,self.workdir):
            args=("up","-d","--no-deps","--pull","never","--force-recreate",*services)
            if directory==self.workdir:self.compose(*args,file=file)
            else:self.compose(*args,file=file,project_directory=directory)

    def sql(self, query):
        return run(["docker","exec","-i",self.pg,"psql","-X","-At","-v","ON_ERROR_STOP=1","-U",self.db_user,"-d",self.db], input=query)

    def ledger(self):
        return json.loads(self.sql("SELECT coalesce(json_object_agg(version,checksum),'{}'::json)::text FROM schema_migrations;"))

    def policy(self):
        keys = "'security_audit_only','file_content_dlp_enabled'"
        if self.manifest.get("identity_chat_only"): keys += ",'billing_enabled'"
        return json.loads(self.sql("SELECT coalesce(json_object_agg(key,value),'{}'::json)::text FROM system_settings WHERE key IN ("+keys+");"))

    def resolve_candidate_images(self):
        for service, record in self.manifest["services"].items():
            image = json.loads(run(["docker", "image", "inspect", record["tag"]]))[0]
            expected = record.get("portable_image_id", record["image_id"])
            if portable_image_id(image) != expected:
                raise RuntimeError("candidate image config differs: "+service)
            record["portable_image_id"] = expected
            record["image_id"] = image["Id"]

    def stage(self):
        if self.state_dir.exists(): raise RuntimeError("release state already exists; inspect it before retrying")
        if self.live.exists() or self.live.is_symlink(): raise RuntimeError("development Compose target already exists")
        if shutil.disk_usage(self.media).free < 4*1024**3: raise RuntimeError("insufficient free space")
        if digest(self.media/"images.tar") != self.manifest["images_sha256"]: raise RuntimeError("image transfer differs")
        if self.manifest.get("identity_chat_only"):
            for service, record in self.manifest["services"].items():
                current = json.loads(run(["docker", "image", "inspect", self.rows[service]["Image"]]))[0]
                if portable_image_id(current) != record.get("base_image_id"):
                    raise RuntimeError("identity-chat base image is not the current live image: "+service)
        self.event("LOAD fixed candidate images")
        run(["docker","image","load","-i",str(self.media/"images.tar")],timeout=600,log=self.log)
        self.resolve_candidate_images()
        for service, record in self.manifest["services"].items():
            image = json.loads(run(["docker","image","inspect",record["image_id"]]))[0]
            labels = image["Config"].get("Labels") or {}
            if labels.get("org.opencontainers.image.revision") != self.manifest["revision"] or labels.get("com.jjdguard.release.id") != self.manifest["release_id"]: raise RuntimeError("candidate provenance differs")
            if self.manifest.get("identity_chat_only"):
                expected = {"org.opencontainers.image.revision":self.manifest["revision"],
                            "com.jjdguard.source.tree":self.manifest["tree"],
                            "com.jjdguard.base.image":record["base_image_id"],
                            "com.jjdguard.release.id":self.manifest["release_id"]}
                if any(labels.get(key) != value for key,value in expected.items()):
                    raise RuntimeError("identity-chat candidate provenance differs: "+service)
        self.state_dir.mkdir(mode=0o700)
        model = json.loads(self.compose("config","--format","json"))
        actual = safe_identity(self.rows)
        for row in actual.values():
            if row["status"]!="running" or row["health"] not in ("healthy","none"): raise RuntimeError("baseline unhealthy")
        for service, row in self.rows.items():
            expected_env = model["services"][service].get("environment",{})
            actual_env = dict(v.split("=",1) for v in row["Config"].get("Env",[]) if "=" in v)
            if any(str(v).replace("$$","$") != actual_env.get(k) for k,v in expected_env.items() if v is not None): raise RuntimeError("live environment differs from Compose: "+service)
        self.before_ledger = self.ledger()
        self.before_policy = self.policy()
        if self.manifest.get("chat_login_proxy_trust"):
            chat_portal_defaults_preflight(self.sql)
            ui_ports=self.rows.get("chat-portal-ui",{}).get("HostConfig",{}).get("PortBindings") or {}
            edge_ports=self.rows.get("chat-edge",{}).get("HostConfig",{}).get("PortBindings") or {}
            if any(ui_ports.values()) or edge_ports.get("3100/tcp"):
                raise RuntimeError("Chat login proxy trust requires internal-only portal/edge UI ports")
        if self.manifest.get("identity_chat_only"):
            billing_mode = self.before_policy.get("billing_enabled")
            if billing_mode is None:
                # Offline 2.8+ uses the frozen live CP environment when the DB row is absent.
                billing_mode = dict(value.split("=", 1) for value in
                                    self.rows["control-plane"]["Config"].get("Env", []) if "=" in value
                                    ).get("BILLING_ENABLED")
            if billing_mode != self.manifest["billing_enabled"]:
                raise RuntimeError("identity-chat billing build differs from the managed setting")
        parent = self.manifest.get("migration_preconditions", {})
        if any(self.before_ledger.get(k) != v for k,v in parent.items()): raise RuntimeError("migration prerequisite differs")
        if self.manifest.get("enable_file_detection") and self.before_policy.get("file_content_dlp_enabled") not in (None,"true"): raise RuntimeError("explicit disabled managed file policy needs review")
        new = build_model(model, self.manifest, self.rows)
        rollback = build_model(model,dict(self.manifest,services={},enable_file_detection=False,semantic_max_windows=None,semantic_window_parallelism=None,security_input_workers=None,security_input_capacity=None,judge_queue_capacity=None,security_batch_budget_seconds=None,semantic_request_parallelism=None,security_input_budget_seconds=None,gateway_security_budget_seconds=None,security_engine_client_timeout_seconds=None),self.rows)
        write_json(self.state_dir/"candidate.json",new)
        write_json(self.state_dir/"rollback.json",rollback)
        rendered = json.loads(self.compose("config","--format","json",file=self.state_dir/"candidate.json"))
        if rendered != new: raise RuntimeError("frozen Compose round-trip differs")
        if self.manifest.get("identity_chat_only"):
            boot_files = boot_chain_files(self.workdir)
            boot_model = render_compose(self.compose_bin, self.workdir, self.project, boot_files)
            scalar_overlay_all(boot_model, new, approved_environment=manifest_approved_environment(self.manifest, self.rows))
            for path in (self.workdir/".upgrade/compose-files", self.compose_bin, *boot_files):
                if path not in self.input_files: self.input_files += (path,)
        original_dir=self.state_dir/"original-compose"
        original_dir.mkdir(mode=0o700)
        compose_hashes={}
        snapshot_index={}
        for index,path in enumerate(self.input_files):
            snapshot=original_dir/(str(index).zfill(2)+"-"+path.name)
            shutil.copy2(path,snapshot)
            os.chmod(snapshot,0o600)
            compose_hashes[str(path)]=digest(path)
            snapshot_index[str(path)]=snapshot.name
        shutil.copy2(self.env_file,self.state_dir/"original-env")
        os.chmod(self.state_dir/"original-env",0o600)
        before_record={"runtime":actual,"ledger":self.before_ledger,"policy":self.before_policy,"compose_files":[str(path) for path in self.live_files],"compose_sha256":compose_hashes,"env_file":str(self.env_file),"env_sha256":digest(self.env_file),"live":str(self.live),"project":self.project}
        if self.manifest.get("identity_chat_only"):
            mount_policy = read_identity_chat_mount_policy()
            preflight_identity_chat_mount_modes(self.rows,self.target_services,mount_policy)
            before_record["original_input_metadata"] = original_input_metadata((*self.input_files,self.env_file))
            witness = {}
            before_record["identity_chat_runtime"] = identity_chat_snapshot(self.rows, self.manifest, witness=witness, mount_policy=mount_policy)
            before_record["identity_chat_contract_witness"] = witness
            validate_identity_chat_contract_witness(before_record)
            verify_identity_chat_snapshot(before_record["identity_chat_runtime"], identity_chat_snapshot(inspect_runtime(), self.manifest), self.manifest)
        write_json(self.state_dir/"before.json", before_record)
        write_json(self.state_dir/"compose-snapshots.json",snapshot_index)
        snapshot_current_pointer(self.state_dir)
        self.migration(dry=True)
        self.event("STAGED: candidate validated; runtime unchanged")

    def migration(self, dry=False):
        if not self.manifest["migrations"]:
            self.event("MIGRATE no pending files")
            return
        wrapper = self.state_dir/"psql-command"
        command = ["docker","exec","-i",self.pg,"psql","-U",self.db_user,"-d",self.db]
        if not wrapper.exists():
            wrapper.write_text("#!/bin/sh\nexec "+" ".join(shlex.quote(v) for v in command)+' "$@"\n')
            wrapper.chmod(0o700)
        env=dict(os.environ,MIGRATION_PSQL=str(wrapper))
        args=["bash",str(self.media/"migration-runner.sh"),"--migrations-dir",str(self.media/"migrations")]
        if dry: args.append("--dry-run")
        with self.log.open("a") as stream:
            subprocess.run(args,env=env,stdout=stream,stderr=stream,check=True,timeout=300)

    def load_state(self):
        self.before = json.loads((self.state_dir/"before.json").read_text())
        validate_identity_chat_contract_witness(self.before)
        validate_original_input_metadata(self.before)
        self.before_ledger = self.before["ledger"]
        self.before_policy = self.before["policy"]

    def fence(self):
        self.resolve_candidate_images()
        self.load_state()
        rows = inspect_runtime()
        if safe_identity(rows) != self.before["runtime"]: raise RuntimeError("runtime changed since stage")
        if self.manifest.get("identity_chat_only"):
            verify_identity_chat_snapshot(self.before["identity_chat_runtime"], identity_chat_snapshot(rows, self.manifest), self.manifest)
        if [str(path) for path in self.live_files] != self.before["compose_files"]: raise RuntimeError("runtime Compose chain changed since stage")
        if any(digest(Path(path)) != checksum for path,checksum in self.before["compose_sha256"].items()) or digest(self.env_file)!=self.before["env_sha256"]: raise RuntimeError("runtime configuration changed since stage")
        if self.ledger()!=self.before_ledger or self.policy()!=self.before_policy: raise RuntimeError("database policy/migration changed since stage")
        authenticate_write_paths([self.live])
        run(["iptables","-N",self.chain])
        try:
            for port in ("3000","443","8080","8082","3128"):
                run(["iptables","-A",self.chain,"-p","tcp","-m","conntrack","--ctdir","ORIGINAL","--ctorigdstport",port,"-j","REJECT"])
            run(["iptables","-I","DOCKER-USER","1","-i",self.interface,"-j",self.chain])
        except BaseException:
            run(["iptables","-F",self.chain]);run(["iptables","-X",self.chain]);raise
        self.event("FENCED application ingress")

    def unfence(self):
        run(["iptables","-D","DOCKER-USER","-i",self.interface,"-j",self.chain])
        run(["iptables","-F",self.chain]);run(["iptables","-X",self.chain])
        self.event("OPEN application ingress")

    def stop_writers(self):
        self.event("STOP application writers")
        stopped, _ = release_writer_sets(self.manifest, self.rows, self.target_services)
        if self.manifest.get("identity_chat_only"):
            self.stopped_services = stopped
        self.compose("stop","--timeout","25",*stopped)
        if self.manifest.get("identity_chat_only") and any(read_drain_evidence(self.rows).values()):
            raise RuntimeError("identity-chat writers did not drain")

    @staticmethod
    def database_timeout(size):
        # 300 秒是下限；按 10 MiB/s 估算再翻倍。恢复要重建索引，调用方按 dump 体积放大。
        return max(300, int(size / (10*1024*1024)) * 2)

    @staticmethod
    def database_restore_timeout(size):
        # Restoring a compressed dump rebuilds table data, indexes and WAL.
        # The 300-second archive/list budget is not a restore deadline.
        return max(DATABASE_RESTORE_MINIMUM_TIMEOUT, Release.database_timeout(size*4))

    def backup(self):
        self.event("BACKUP database after quiescing")
        with self.backup_path.open("wb") as stream:
            subprocess.run(["docker","exec",self.pg,"pg_dump","-Fc","-U",self.db_user,"-d",self.db],stdout=stream,check=True,timeout=1800)
        with self.backup_path.open("rb") as stream:
            subprocess.run(["docker","exec","-i",self.pg,"pg_restore","--list"],stdin=stream,stdout=subprocess.DEVNULL,check=True,timeout=max(60,self.database_timeout(self.backup_path.stat().st_size)//4))
        write_json(self.state_dir/"backup.json",{"sha256":digest(self.backup_path),"size":self.backup_path.stat().st_size})
        self.event("BACKUP validated")

    def migrate(self):
        self.event("MIGRATE reviewed pending files")
        self.migration()
        now=self.ledger()
        if any(now.get(k)!=v for k,v in self.before_ledger.items()): raise RuntimeError("previous migration ledger changed")
        if any(now.get(k)!=v for k,v in self.manifest["migrations"].items()): raise RuntimeError("pending migration not applied")

    def switch(self):
        self.event("SWITCH to fixed candidate image IDs")
        atomic_bytes(self.live,(self.state_dir/"candidate.json").read_bytes())
        self.recreate_targets(self.live)
        _, other = release_writer_sets(self.manifest, self.rows, self.target_services)
        if other:self.compose("start",*other)

    def verify_file_runtime(self, rows):
        if not self.manifest.get("enable_file_detection"):
            write_json(self.state_dir/"file-http-probe.json",{
                "status":"not_requested",
                "reason":"managed_file_detection_disabled",
            })
            return
        file_result=run(["docker","exec",rows["security-engine"]["Id"],"python","-m","app.file_http_selftest"],timeout=180,log=self.log)
        file_probe=json.loads(file_result.splitlines()[-1])
        if not file_probe["passed"]: raise RuntimeError("live HTTP file acceptance failed")
        write_json(self.state_dir/"file-http-probe.json",file_probe)

    def verify(self):
        self.event("VERIFY runtime health, image identities and policies")
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            rows=inspect_runtime()
            if set(rows)==set(self.rows) and all(r["State"]["Status"]=="running" and r["State"].get("Health",{}).get("Status","healthy")=="healthy" for r in rows.values()):break
            time.sleep(2)
        else:raise RuntimeError("candidate health deadline exceeded")
        for service,record in self.manifest["services"].items():
            if rows[service]["Image"]!=record["image_id"]:raise RuntimeError("runtime image differs: "+service)
            if rows[service]["RestartCount"]!=0:raise RuntimeError("candidate restarted")
            paths=list(record["payload_sha256"])
            for offset in range(0,len(paths),80):
                result=run(["docker","exec",rows[service]["Id"],"sha256sum","--",*paths[offset:offset+80]])
                if len(result.splitlines()) != len(paths[offset:offset+80]): raise RuntimeError("runtime checksum count differs")
                for line in result.splitlines():
                    checksum,path=line.split(None,1)
                    if record["payload_sha256"].get(path)!=checksum:raise RuntimeError("runtime payload differs: "+service)
            actual_env=dict(v.split("=",1) for v in rows[service]["Config"]["Env"] if "=" in v)
            if actual_env.get("JJD_COMMIT")!=self.manifest["revision"]:raise RuntimeError("runtime revision differs")
            if self.manifest.get("identity_chat_only"):
                expected_env = {"JJD_COMMIT":self.manifest["revision"], "JJD_VERSION":self.manifest["version"],
                                "JJD_BUILT_AT":self.manifest["created_at"]}
                if any(actual_env.get(key) != value for key,value in expected_env.items()):
                    raise RuntimeError("identity-chat runtime provenance differs: "+service)
        after_identity=safe_identity(rows)
        verify_preserved_identities(self.before["runtime"],after_identity,self.preserved_services)
        if self.policy()!=self.before_policy:raise RuntimeError("managed policy changed")
        if any(digest(Path(path)) != checksum for path,checksum in self.before["compose_sha256"].items()):raise RuntimeError("original Compose file changed")
        if digest(self.env_file)!=self.before["env_sha256"]:raise RuntimeError("original environment file changed")
        if self.manifest.get("identity_chat_only"):
            self.after_identity_chat = identity_chat_snapshot(rows, self.manifest)
            verify_identity_chat_snapshot(self.before["identity_chat_runtime"], self.after_identity_chat,
                                          self.manifest, replaced=True, resumed=True)
        if self.manifest.get("portal_only") or self.manifest.get("identity_chat_only"):
            portal=rows["chat-portal-ui"]
            portal_env=dict(v.split("=",1) for v in portal["Config"]["Env"] if "=" in v)
            routes=json.loads(run(["docker","exec",portal["Id"],"cat","/app/.next/app-path-routes-manifest.json"],timeout=60))
            ready=portal_surface(portal_env,routes,self.manifest.get("billing_enabled"))
        else:
            sec_env=dict(v.split("=",1) for v in rows["security-engine"]["Config"]["Env"] if "=" in v)
            request=urllib.request.Request("http://127.0.0.1:8000/ready",headers={"X-JJDGuard-Internal-Token":sec_env.get("JJD_INTERNAL_API_SECRET","")})
            with urllib.request.urlopen(request,timeout=30) as response: ready=json.loads(response.read())
            if not ready.get("ready"): raise RuntimeError("engine capabilities not ready")
            if self.manifest.get("enable_file_detection") and not ready.get("file_content_dlp",{}).get("enabled"): raise RuntimeError("file detection is not enabled")
            self.verify_file_runtime(rows)
        if self.preserved_services:
            write_json(self.state_dir/"tier1-probe.json",{"status":"preserved_not_touched"})
        else:
            probe="import os\nos.environ[\'T1TOK\']=os.environ[\'JJD_TIER1_INTERNAL_TOKEN\']\n"+(self.media/"tier1-window-smoke.py").read_text()
            tier1_result=run(["docker","exec","-i",rows["tier1-classifier"]["Id"],"python","-"],input=probe,timeout=60,log=self.log)
            write_json(self.state_dir/"tier1-probe.json",json.loads(tier1_result.splitlines()[-1]))
        write_json(self.state_dir/"readiness.json",ready)
        write_json(self.state_dir/"after.json",safe_identity(rows))

    def commit(self):
        # receipt 反向绑定全部前置材料：调用方随后只能凭 receipt 的整体摘要进入
        # persist/rollback，因此这里写入的每一个摘要都是「外部固定值」——
        # 事后单独改 before/candidate/snapshot/persist 任一文件都会在下一道校验
        # 被发现。candidate 与 snapshot 索引同样在绑定范围内：只绑 live 文件
        # 不足以证明回滚目标就是本次发布的候选配置。
        bindings=stage_binding_digests(self.state_dir)
        receipt={"status":"deployed","release_id":self.manifest["release_id"],
                 "revision":self.manifest["revision"],"version":self.manifest["version"],
                 "services":{s:v["image_id"] for s,v in self.manifest["services"].items()},
                 "preserved_services":list(self.preserved_services),
                 "migrations":self.manifest["migrations"],"policy":self.before_policy,
                 "backup":str(self.backup_path),"compose_sha256":digest(self.live),
                 "manifest_sha256":digest(self.media/"manifest.json"),
                 "stage_binding":bindings,"persist_boot":None}
        if self.manifest.get("identity_chat_only"):
            current = identity_chat_snapshot(inspect_runtime(), self.manifest)
            if current != self.after_identity_chat: raise RuntimeError("identity-chat runtime changed before receipt commit")
            receipt["identity_chat_runtime"] = current
        write_json(self.media/"receipt.json",receipt)
        write_json(ROOT/"development-releases/current.json",{"release":str(self.media),"receipt_sha256":digest(self.media/"receipt.json")})
        self.event("COMMIT development release receipt")

    def restart_original(self):
        stopped, _ = release_writer_sets(self.manifest, self.rows, self.target_services)
        if self.manifest.get("identity_chat_only"):
            stopped = getattr(self, "stopped_services", ())
        if stopped:
            self.compose("start",*stopped)
        if self.manifest.get("identity_chat_only"):
            deadline = time.monotonic()+180
            while True:
                rows = inspect_runtime()
                if all(name in rows and rows[name]["State"]["Status"] == "running" and
                       rows[name]["State"].get("Health", {}).get("Status", "none") in ("healthy", "none")
                       for name in stopped):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("original writer health deadline exceeded; ingress stays fenced")
                time.sleep(2)
            for name in stopped:
                if rows[name]["Config"] != self.rows[name]["Config"]:
                    raise RuntimeError("original writer runtime contract changed: "+name)
            verify_identity_chat_snapshot(self.before["identity_chat_runtime"], identity_chat_snapshot(rows, self.manifest),
                                          self.manifest, resumed=True, resumed_services=stopped)
        self.event("RESTORE original stopped containers")

    def restore(self):
        self.event("ROLLBACK while ingress remains fenced")
        stopped, _ = release_writer_sets(self.manifest, self.rows, self.target_services)
        self.compose("stop","--timeout","25",*stopped)
        backup=json.loads((self.state_dir/"backup.json").read_text())
        if digest(self.backup_path)!=backup["sha256"]:raise RuntimeError("backup changed; ingress stays fenced")
        escaped_db=self.db.replace("\'","\'\'")
        run(["docker","exec",self.pg,"psql","-X","-At","-U",self.db_user,"-d","postgres","-c","SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=\'"+escaped_db+"\' AND pid<>pg_backend_pid();"])
        run_database_restore(self.pg, self.db_user, self.backup_path, self.state_dir,
                             self.database_restore_timeout(self.backup_path.stat().st_size), self.event)
        atomic_bytes(self.live,(self.state_dir/"rollback.json").read_bytes())
        self.recreate_targets(self.live)
        _, other = release_writer_sets(self.manifest, self.rows, self.target_services)
        if other:self.compose("start",*other)
        if self.ledger()!=self.before_ledger or self.policy()!=self.before_policy:raise RuntimeError("restored database differs; ingress stays fenced")
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            restored=inspect_runtime()
            if set(restored)==set(self.rows) and all(r["Image"]==self.before["runtime"][service]["image"] and r["State"].get("Health",{}).get("Status","healthy")=="healthy" for service,r in restored.items()): break
            time.sleep(2)
        else: raise RuntimeError("rollback image/health verification failed; ingress stays fenced")
        verify_preserved_identities(self.before["runtime"],safe_identity(restored),self.preserved_services)
        if self.manifest.get("identity_chat_only"):
            verify_identity_chat_snapshot(self.before["identity_chat_runtime"], identity_chat_snapshot(restored, self.manifest),
                                          self.manifest, replaced=True, resumed=True, rollback=True)
            previous = json.loads((self.state_dir/"previous-current.json").read_text())
            pointer = ROOT/"development-releases/current.json"
            if previous is None:
                if pointer.exists() or pointer.is_symlink(): safe_unlink(pointer)
            elif isinstance(previous, str):
                atomic_bytes(pointer, previous.encode())
            else:
                raise RuntimeError("invalid staged previous pointer; ingress stays fenced")
        write_json(self.media/"rollback.json",{"status":"rolled_back","release_id":self.manifest["release_id"]})
        self.event("ROLLBACK completed")

def snapshot_current_pointer(state_dir):
    """stage 时冻结 current.json 前值：rollback 依据它恢复指针（缺省记 null）。"""
    pointer_path=ROOT/"development-releases/current.json"
    previous=None
    if pointer_path.exists() or pointer_path.is_symlink():
        previous=pointer_path.read_bytes().decode()
    write_json(Path(state_dir)/"previous-current.json", previous)
    return previous

def render_compose(compose_bin, workdir, project, files):
    command=[str(compose_bin),"--project-directory",str(workdir),"-p",project]
    for path in files: command+=["-f",str(path)]
    return json.loads(run(command+["config","--format","json"]))

def boot_chain_files(workdir):
    """jjdctl 启动读取的真实文件链：隐式 offline 基础永远在最前，其后是
    .upgrade/compose-files 的受管条目（jjdctl 要求每个条目位于 active-config/
    下且为普通文件；offline.yml 本身不得出现在清单里，否则会被渲染两遍且
    使清单条目脱离 active-config 治理）。persist 的差量基准与最终验收都
    必须用这条链渲染，不能用 stage 输入文件或裸链条目替代。"""
    workdir=Path(workdir)
    base=workdir/"docker-compose.offline.yml"
    if base.is_symlink() or not base.is_file(): raise RuntimeError("governed offline base missing: "+str(base))
    chain_path=workdir/".upgrade/compose-files"
    if chain_path.is_symlink() or not chain_path.is_file():
        raise RuntimeError("governed boot chain absent; persist-boot requires an existing compose-files chain")
    active=workdir/"active-config"
    entries=[]
    for entry in chain_path.read_text().splitlines():
        if not entry: continue
        path=Path(entry)
        if path.is_symlink() or not path.is_file() or not path.is_relative_to(active):
            raise RuntimeError("governed boot chain entry must be a regular active-config file: "+entry)
        entries.append(path)
    return (base,*entries)

def manifest_approved_environment(manifest, running=None):
    """build_model 环境差量的精确批准值表（与 build_model 逐键同源派生）：
    provenance 三键取 manifest 字段、SECURITY_ENGINE_BUILD=revision、容量/预算键
    取对应 manifest 字段的字符串化值、文件检测键取固定批准值。persist 用它对
    overlay 环境差量做逐键值级验证——键对但值不是 manifest 批准值同样拒绝。"""
    expected={}
    signed_environment = login_ip_forward_environment(manifest, running)
    for service in manifest["services"]:
        expected.setdefault(service,{}).update(JJD_COMMIT=manifest["revision"],JJD_VERSION=manifest["version"],
                                               JJD_BUILT_AT=manifest["created_at"])
    for service, environment in signed_environment.items():
        expected[service].update(environment)
    if "control-plane" in manifest["services"]:
        expected["control-plane"].update(chat_login_proxy_environment(manifest))
    if "gateway-core" in manifest["services"]:
        for key,value in gateway_budget_environment(manifest).items():
            expected["gateway-core"][key]=value
    if "security-engine" in manifest["services"]:
        expected["security-engine"]["SECURITY_ENGINE_BUILD"]=manifest["revision"]
        for key,value in semantic_parallel_environment(manifest).items():
            expected["security-engine"][key]=value
        if manifest.get("semantic_max_windows") is not None:
            expected["security-engine"]["SECURITY_SEMANTIC_MAX_WINDOWS"]=str(manifest["semantic_max_windows"])
    if manifest.get("enable_file_detection"):
        for service in ("control-plane","gateway-core","proxy-server","security-engine"):
            if service in manifest["services"]:
                expected.setdefault(service,{})["SECURITY_FILE_CONTENT_DLP_ENABLED"]="true"
        if "security-engine" in manifest["services"]:
            expected["security-engine"]["SECURITY_SCAN_STORE_DIR"]="/var/lib/jjdguard/scan-store"
    return expected

def scalar_overlay_all(before_model, after_model, approved_environment=None):
    """全服务标量差量：仅允许 image/pull_policy/环境标量变化；列表与资源差异
    fail-closed。approved_environment 给定时，环境差量必须逐键等于 manifest
    批准值（键集合外或值不符一律拒绝）。"""
    if before_model.get("name")!=after_model.get("name"): raise RuntimeError("boot Compose project differs")
    if set(before_model.get("services",{}))!=set(after_model.get("services",{})): raise RuntimeError("boot service set differs")
    overlay={"services":{}}
    left=copy.deepcopy(before_model)
    for name, item in before_model["services"].items():
        old, new = left["services"][name], copy.deepcopy(after_model["services"][name])
        delta={}
        for key in ("image","pull_policy"):
            if old.get(key)!=new.get(key):
                if key not in new or not isinstance(new[key],str): raise RuntimeError("invalid boot scalar: "+name+"."+key)
                delta[key]=new[key]
                old[key]=new[key]
        old_env,new_env=old.get("environment",{}) or {},new.get("environment",{}) or {}
        for key in sorted(set(old_env)|set(new_env)):
            before_value,after_value=old_env.get(key),new_env.get(key)
            if before_value==after_value: continue
            if after_value is None: raise RuntimeError("environment key removal is not expressible in a scalar boot overlay: "+name+"."+key)
            if not isinstance(after_value,(str,int)): raise RuntimeError("invalid boot environment scalar: "+name+"."+key)
            if approved_environment is not None and str(after_value)!=approved_environment.get(name,{}).get(key):
                raise RuntimeError("environment delta not manifest-approved: "+name+"."+key)
            delta.setdefault("environment",{})[key]=str(after_value)
            old_env[key]=str(after_value)
        if old_env and "environment" not in old: old["environment"]=old_env
        if old!=new: raise RuntimeError("boot/live differs outside permitted target scalars (lists/resources preserved): "+name)
        if delta: overlay["services"][name]=delta
    return overlay

STAGE_BINDING_FILES=("before.json","candidate.json","rollback.json","previous-current.json",
                     "compose-snapshots.json","original-env","backup.json")

def stage_binding_digests(state_dir):
    """stage 产物的逐文件摘要。写入 receipt 后即为外部固定值：receipt 的整体摘要
    由调用方在锁外固定，persist/rollback 都必须逐项复核，任何事后单独改动都会被发现。"""
    state_dir=Path(state_dir)
    bindings={}
    for name in STAGE_BINDING_FILES:
        path=state_dir/name
        if not path.is_file(): raise RuntimeError("stage evidence missing for receipt binding: "+name)
        bindings[name]=digest(path)
    snapshots=json.loads((state_dir/"compose-snapshots.json").read_text())
    original=state_dir/"original-compose"
    for live,snapshot in snapshots.items():
        snapshot_path=original/snapshot
        if not snapshot_path.is_file(): raise RuntimeError("compose snapshot missing for receipt binding: "+live)
        bindings["snapshot:"+live]=digest(snapshot_path)
    return bindings

def verify_stage_binding(receipt, state_dir):
    """逐项复核 receipt 反向绑定的 stage 证据。record 内自存的摘要不构成认证：
    这里比的是 receipt 里的固定值与磁盘现值，攻击者同时改两侧也会被发现，因为
    receipt 的整体摘要必须由调用方在锁外提供。"""
    expected=receipt.get("stage_binding")
    if not isinstance(expected,dict) or not expected: raise RuntimeError("receipt lacks stage binding; refusing unauthenticated release")
    actual=stage_binding_digests(state_dir)
    if set(expected)!=set(actual): raise RuntimeError("receipt stage binding does not cover the staged evidence set")
    for name in sorted(expected):
        if expected[name]!=actual[name]: raise RuntimeError("staged evidence changed after commit: "+name)


def staged_env_file(before):
    """stage 冻结摘要所对应的原始环境文件（安装树 workdir/.env）。"""
    live=Path(before["live"])
    if not live.is_absolute() or live.parent.name!="active-config":
        raise RuntimeError("staged live path does not identify an installed environment file")
    env_file=live.parent.parent/".env"
    if before.get("env_file",str(env_file))!=str(env_file):
        raise RuntimeError("staged environment file path differs from installed environment file")
    if env_file.is_symlink() or not env_file.is_file():
        raise RuntimeError("installed environment file must be a regular non-symlink file")
    return env_file


def pinned_dev_receipt(media, expected_receipt):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_receipt): raise RuntimeError("full receipt SHA256 required")
    pointer_path=ROOT/"development-releases/current.json"
    if pointer_path.is_symlink() or not pointer_path.is_file():
        raise RuntimeError("no active recorded development release to roll back")
    try:
        pointer=json.loads(pointer_path.read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError("active development release pointer is unreadable") from exc
    if pointer!={"release":str(media),"receipt_sha256":expected_receipt}:
        raise RuntimeError("only the active recorded development release can be rolled back")
    if digest(media/"receipt.json")!=expected_receipt: raise RuntimeError("receipt hash differs")
    receipt=json.loads((media/"receipt.json").read_text())
    if receipt.get("status")!="deployed" or receipt.get("release_id")!=media.name:
        raise RuntimeError("unsupported development rollback receipt")
    return receipt

@contextlib.contextmanager
def release_lock():
    """与 stage/apply（Release 构造器）共用同一把 .release.lock：persist-boot 与
    rollback 的 pinned receipt、全部前置校验、变更与发布后断言都在锁内完成。"""
    directory=ROOT/"development-releases"
    with safe_parent(directory/".release.lock") as (parent,name,verify):
        try: descriptor=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:
            descriptor=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        stream=os.fdopen(descriptor,"r+")
        try:
            verify_file_fd(descriptor,parent,name); verify()
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException as exc:
            stream.close()
            if isinstance(exc,OSError):
                raise RuntimeError("another release transaction holds the release lock; retry after it finishes") from exc
            raise
        try:
            print("RELEASE_LOCK_HELD="+json.dumps({"pid":os.getpid(),"start_ticks":Path("/proc/self/stat").read_text().rsplit(")",1)[1].split()[19],
                  "dev":os.fstat(descriptor).st_dev,"inode":os.fstat(descriptor).st_ino,
                  "fdinfo":Path("/proc/self/fdinfo/"+str(descriptor)).read_text()}),flush=True)
            yield
        finally:
            fcntl.flock(stream,fcntl.LOCK_UN)
            try: verify_file_fd(descriptor,parent,name); verify()
            finally: stream.close()

def authenticate_media(media):
    """路径与属主守卫：media 必须位于受管的 development-releases 根下，关键成员
    不得为符号链接、必须属于执行账户且不对 group/other 可写。"""
    if Path(media).parent!=ROOT/"development-releases" or Path(media)==ROOT/"development-releases":
        raise RuntimeError("release media must live directly under "+str(ROOT/"development-releases"))
    for name in ("manifest.json","receipt.json","state"):
        path=media/name
        if path.is_symlink() or not path.exists(): raise RuntimeError("release media member missing or symbolic: "+name)
        info=path.stat()
        if info.st_uid!=os.geteuid(): raise RuntimeError("release media member not owned by the executing account: "+name)
        if info.st_mode & 0o022: raise RuntimeError("release media member is group or world writable: "+name)

def writer_drain_sets(rows, target_services, manifest=None):
    """writer 排空范围：所有能产生业务写入的应用服务（control-plane/gateway-core/
    proxy-server/worker/web-console/security-engine/tier1-classifier/chat-portal-*）
    在 fence 后全部 stop；postgres 不在排空范围（零数据库回滚不触碰它）。
    返回 (停止清单, 回滚后需重启的非目标 writer 清单)。"""
    if manifest and manifest.get("identity_chat_only"):
        stopped, restartable = release_writer_sets(manifest, rows, target_services)
        return list(stopped), list(restartable)
    present=[service for service in WRITERS if service in rows]
    return present,[service for service in present if service not in target_services]

def read_migration_ledger(rows):
    postgres=rows.get("postgres")
    if postgres is None: raise RuntimeError("required VM services absent: postgres")
    env=dict(item.split("=",1) for item in postgres["Config"]["Env"] if "=" in item)
    query="SELECT coalesce(json_object_agg(version,checksum),'{}'::json)::text FROM schema_migrations;"
    return json.loads(run(["docker","exec","-i",postgres["Id"],"psql","-X","-At","-v","ON_ERROR_STOP=1",
                           "-U",env["POSTGRES_USER"],"-d",env["POSTGRES_DB"]],input=query))


def read_transaction_evidence(rows):
    postgres=rows["postgres"]
    env=dict(item.split("=",1) for item in postgres["Config"]["Env"] if "=" in item)
    argv=["docker","exec","-i",postgres["Id"],"psql","-X","-At","-v","ON_ERROR_STOP=1","-U",env["POSTGRES_USER"],"-d",env["POSTGRES_DB"]]
    names=("wallet_ledger","releaseit_post_apply_tx","releaseit_marker","schema_migrations")
    query="SELECT json_object_agg(name,to_regclass('public.' || name) IS NOT NULL)::text FROM (VALUES ('wallet_ledger'),('releaseit_post_apply_tx'),('releaseit_marker'),('schema_migrations')) AS expected(name);"
    present=json.loads(run(argv,input=query))
    if not isinstance(present,dict) or set(present)!=set(names) or any(type(value) is not bool for value in present.values()):
        raise RuntimeError("transaction preservation catalog evidence is malformed")
    if not present["schema_migrations"]: raise RuntimeError("migration preservation table is missing")
    result={}
    for name in names:
        if not present[name]: result[name]=None; continue
        data=json.loads(run(argv,input="SELECT coalesce(json_agg(to_jsonb(t)::text ORDER BY to_jsonb(t)::text),'[]'::json)::text FROM public."+name+" t;"))
        if not isinstance(data,list) or any(not isinstance(row,str) for row in data):
            raise RuntimeError("transaction preservation rows are malformed")
        result[name]={"rows":len(data),"sha256":hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
    return result


def read_preserved_inventory(rows,target_services):
    ids=run(["docker","ps","-a","-q"]).split()
    objects=json.loads(run(["docker","inspect",*ids])) if ids else []
    scope={(service,(rows[service]["Config"].get("Labels") or {}).get("com.docker.compose.project")) for service in target_services}
    result={}
    for row in objects:
        labels=row["Config"].get("Labels") or {}
        if (labels.get("com.docker.compose.service"),labels.get("com.docker.compose.project")) in scope: continue
        identity=protected_identity(row)
        identity["mount_source_identity"]=[]
        for mount in identity["mounts"]:
            source=mount.get("Source")
            if not source: identity["mount_source_identity"].append(None); continue
            descriptor=os.open(source,os.O_PATH|os.O_NOFOLLOW)
            try:
                info=os.fstat(descriptor)
                if stat.S_ISLNK(info.st_mode): raise RuntimeError("preserved mount source is symbolic")
                identity["mount_source_identity"].append({"dev":info.st_dev,"inode":info.st_ino,"uid":info.st_uid,"gid":info.st_gid,"type":stat.S_IFMT(info.st_mode)})
            finally: os.close(descriptor)
        result[row["Id"]]=identity
    return result

def read_drain_evidence(rows):
    """只读排空确认材料：pg_stat_activity 中除本查询自身外仍处于活动/未决事务
    状态的客户端后端，以及 pg_prepared_xacts 全量。两项任一非空即无法确认
    writer 排空；本查询自身后端经 pg_backend_pid() 排除。"""
    postgres=rows.get("postgres")
    if postgres is None: raise RuntimeError("required VM services absent: postgres")
    env=dict(item.split("=",1) for item in postgres["Config"]["Env"] if "=" in item)
    query=("SELECT json_build_object('active',(SELECT coalesce(json_object_agg(pid,json_build_object("
           "'usename',usename,'state',state,'query',left(query,120))),'{}'::json)::text FROM pg_stat_activity "
           "WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state IN "
           "('active','idle in transaction','idle in transaction (aborted)')),"
           "'prepared',(SELECT coalesce(json_object_agg(gid,prepared),'{}'::json)::text FROM pg_prepared_xacts))::text;")
    view=json.loads(run(["docker","exec","-i",postgres["Id"],"psql","-X","-At","-v","ON_ERROR_STOP=1",
                         "-U",env["POSTGRES_USER"],"-d",env["POSTGRES_DB"]],input=query))
    return {"active":json.loads(view["active"]),"prepared":json.loads(view["prepared"])}

def perform_persist_boot(media, manifest_sha, receipt_sha):
    """受控登记的开机链固化：把 candidate 与真实启动链渲染的标量差量写成链尾
    overlay，备份原链并记录 digest 证据；rollback 只信任本动作写下的证据。
    调用者必须传入最终 receipt 摘要（外部固定 pin），与 current.json 指针、
    receipt.json 双向校验后绑定进 persist 记录。全程持有 release 锁。"""
    with release_lock():
        return _persist_boot_locked(media, manifest_sha, receipt_sha)

def _persist_boot_locked(media, manifest_sha, receipt_sha):
    authenticate_media(media)
    if digest(media/"manifest.json")!=manifest_sha: raise RuntimeError("manifest hash differs")
    manifest=json.loads((media/"manifest.json").read_text())
    if manifest.get("console_only"): raise RuntimeError("console releases persist inside their own transaction")
    receipt=pinned_dev_receipt(media,receipt_sha)
    if manifest.get("identity_chat_only"):
        release_service_sets(manifest)
        if identity_chat_snapshot(inspect_runtime(), manifest) != receipt.get("identity_chat_runtime"):
            raise RuntimeError("identity-chat runtime changed before boot persistence")
    if "persist_boot" not in receipt or receipt["persist_boot"] is not None:
        raise RuntimeError("persist-boot requires an unpersisted authenticated apply receipt")
    state=media/"state"
    # 固化也要复核 receipt 的反向绑定：candidate 变了就意味着要固化的内容
    # 不是本次发布真正提交的那份，不能写进开机链
    verify_stage_binding(receipt,state)
    before_path=state/"before.json"
    candidate_path=state/"candidate.json"
    previous_pointer_path=state/"previous-current.json"
    if not previous_pointer_path.is_file():
        raise RuntimeError("staged previous pointer evidence missing; persist-boot refused")
    before=json.loads(before_path.read_text())
    if any(digest(path)!=checksum for path,checksum in before["compose_sha256"].items()):
        raise RuntimeError("release input drifted since stage; persist will not overwrite it")
    if digest(staged_env_file(before))!=before["env_sha256"]:
        raise RuntimeError("release environment file drifted since stage; persist refused")
    live=Path(before["live"])
    if digest(live)!=receipt["compose_sha256"]: raise RuntimeError("active live configuration changed")
    workdir=live.parent.parent
    compose_bin=workdir/"bin/docker-compose"
    # 差量基准与最终验收都用真实启动链渲染（隐式 offline 基础 + 受管条目），
    # 而非 stage 输入文件或裸链条目的等价替身。
    boot_model=render_compose(compose_bin,workdir,before["project"],boot_chain_files(workdir))
    candidate=json.loads(candidate_path.read_text())
    overlay=scalar_overlay_all(boot_model,candidate,approved_environment=manifest_approved_environment(manifest, inspect_runtime()))
    chain_path=workdir/".upgrade/compose-files"
    previous_chain=chain_path.read_bytes()
    overlay_path=workdir/"active-config"/(manifest["release_id"]+"-persistent.json")
    if overlay_path.exists() or overlay_path.is_symlink(): raise RuntimeError("active persistent overlay already exists")
    entries=[entry for entry in previous_chain.decode().splitlines() if entry]
    if str(overlay_path) in entries: raise RuntimeError("persistent overlay already chained")
    # persist 的每一次写入都登记补偿：链前值、overlay、链本身、认证记录。
    # 任一步失败都复原，绝不留下「链已引用但无认证证据」的现场——那会让后续
    # rollback 无法证明持久化归属，只能靠人工介入。
    previous_chain_path=state/"boot-chain.previous"
    record_path=state/"persist-boot.json"
    if previous_chain_path.exists() or previous_chain_path.is_symlink() or record_path.exists() or record_path.is_symlink():
        raise RuntimeError("persist evidence already exists; inspect the previous transaction before retrying")
    receipt_path=media/"receipt.json"
    pointer_path=ROOT/"development-releases/current.json"
    undo={}
    try:
        undo[previous_chain_path]=previous_chain_path.read_bytes() if previous_chain_path.exists() else None
        atomic_bytes(previous_chain_path,previous_chain)
        undo[overlay_path]=None
        atomic_bytes(overlay_path,(json.dumps(overlay,indent=2)+"\n").encode())
        undo[chain_path]=chain_path.read_bytes()
        atomic_bytes(chain_path,("\n".join(entries+[str(overlay_path)])+"\n").encode())
        chained=boot_chain_files(workdir)
        rendered=render_compose(compose_bin,workdir,before["project"],chained)
        if rendered!=candidate: raise RuntimeError("persistent boot render differs from candidate")
        record={"manifest_sha256":manifest_sha,"receipt_sha256":receipt_sha,
                "before_sha256":digest(before_path),"candidate_sha256":digest(candidate_path),
                "previous_current_sha256":digest(previous_pointer_path),
                "overlay":str(overlay_path),"overlay_sha256":digest(overlay_path),
                "chain_sha256":digest(chain_path),
                "previous_chain_sha256":digest(previous_chain_path),
                "created_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
        undo[record_path]=record_path.read_bytes() if record_path.exists() else None
        write_json(record_path,record)
        final_receipt=copy.deepcopy(receipt)
        final_receipt["persist_boot"]={"apply_receipt_sha256":receipt_sha,
                                      "record_sha256":digest(record_path),
                                      "previous_chain_sha256":digest(previous_chain_path),
                                      "overlay":str(overlay_path),"overlay_sha256":digest(overlay_path),
                                      "chain_sha256":digest(chain_path)}
        undo[receipt_path]=receipt_path.read_bytes()
        write_json(receipt_path,final_receipt)
        final_pin=digest(receipt_path)
        undo[pointer_path]=pointer_path.read_bytes()
        write_json(pointer_path,{"release":str(media),"receipt_sha256":final_pin})
    except BaseException:
        for path,original in reversed(list(undo.items())):
            try:
                if original is None:
                    if path.exists(): path.unlink()
                else:
                    atomic_bytes(path,original)
            except BaseException: pass
        raise
    print("PERSIST-BOOT chain overlay registered: "+str(overlay_path),flush=True)
    with (media/"apply.log").open("a") as stream:
        stream.write(datetime.datetime.now(datetime.timezone.utc).isoformat()+" PERSIST-BOOT "+str(overlay_path)+" FINAL_RECEIPT_SHA256="+final_pin+"\n")
    print("FINAL_RECEIPT_SHA256="+final_pin,flush=True)
    return final_pin

def authenticated_fence(snapshot, chain, interface):
    table=None
    declarations=[]
    rules=[]
    references=[]
    filter_rules=[]
    for line in snapshot.splitlines():
        if not line or line.startswith("#"): continue
        if line.startswith("*"): table=line[1:]; continue
        if line=="COMMIT": table=None; continue
        if line.startswith(":"+chain+" "):
            declarations.append((table,line.split()[1]))
        if not line.startswith("-A "): continue
        tokens=shlex.split(line)
        if table=="filter": filter_rules.append(tokens)
        if tokens[1]==chain: rules.append((table,tokens))
        if any(tokens[i] in ("-j","--jump","-g","--goto") and tokens[i+1]==chain for i in range(len(tokens)-1)):
            references.append((table,tokens))
    if declarations!=[("filter","-")]:
        raise RuntimeError("resume requires exactly one existing filter fence")
    expected_link=["-A","DOCKER-USER","-i",interface,"-j",chain]
    if references!=[("filter",expected_link)]:
        raise RuntimeError("fence has foreign or duplicate references")
    user_rules=[r for r in filter_rules if r[1]=="DOCKER-USER"]
    if not user_rules or user_rules[0]!=expected_link:
        raise RuntimeError("fence link must be first in DOCKER-USER")
    if len(rules)!=5: raise RuntimeError("fence rules differ")
    for (rule_table,tokens),port in zip(rules,("3000","443","8080","8082","3128")):
        if rule_table!="filter" or len(tokens)!=14:
            raise RuntimeError("fence rules differ")
        pairs=list(zip(tokens[2::2],tokens[3::2]))
        expected={"-p":"tcp","-m":"conntrack","--ctdir":"ORIGINAL","--ctorigdstport":port,
                  "-j":"REJECT","--reject-with":"icmp-port-unreachable"}
        if len(pairs)!=len(expected) or dict(pairs)!=expected:
            raise RuntimeError("fence rule scope or order differs")
    return snapshot


# 解封收尾的合法残留状态。readback 失败不等于「入口仍隔离」，也不等于「入口
# 已开放」——那种情况下什么都不可知，必须落到 unknown 并 fail-closed。
FENCE_LINKED="fence_linked"                      # 链在、原五规则完整、link 在：ingress 仍隔离
FENCE_UNLINKED_RULES="fence_unlinked_rules"      # -D 成功 -F 失败：ingress 已开放，链与原规则残留
FENCE_UNLINKED_EMPTY="fence_unlinked_empty"      # -F 成功 -X 失败：ingress 已开放，空链残留
FENCE_CLEARED="fence_cleared"                    # 无链无引用：解封已完成
FENCE_UNKNOWN="fence_unknown"                    # 读回失败或有 foreign 规则/引用：不可推断


def probe_fence_residual(snapshot, chain, interface):
    """按权威 iptables-save 判定残留状态，严格解析全表。

    只做只读判定，绝不改任何规则，因此拿不准时返回 unknown 让调用方
    fail-closed —— 零盲清。「无链无 link」是第四种合法状态：解封已做完但收尾
    记录写入失败，必须能重入。

    严格性要点（任何一条不满足即 unknown，绝不猜）：
      · 链声明必须在 filter 表恰好一条、policy 为 '-'；
      · 链内规则必须是原五规则、顺序与内容与建链时逐字一致；
      · 对本链的引用（-j/--jump/-g/--goto）必须零条；出现任何 foreign 引用
        （例如 OUTPUT 或 nat 表也跳进来）即 unknown，因为盲目清链会误删他人规则；
      · DOCKER-USER 中对本链的引用恰好一条且必须是首条，interface 必须相符；
      · DOCKER-USER 里其余规则只做身份记录（无关规则身份进 checkpoint），
        不做内容判断 —— 它们属于 Docker，不归本次事务管。
    """
    if snapshot is None:
        return FENCE_UNKNOWN
    if snapshot.count("*filter\n")!=1 or "COMMIT" not in snapshot.splitlines():
        return FENCE_UNKNOWN
    table=None
    declarations=[]
    rules=[]
    references=[]
    user_rules=[]
    for line in snapshot.splitlines():
        if not line or line.startswith("#"): continue
        if line.startswith("*"): table=line[1:]; continue
        if line=="COMMIT": table=None; continue
        if line.startswith(":"):
            parts=line.split()
            if len(parts)>=2 and parts[0][1:]==chain:
                declarations.append((table,parts[1]))
            continue
        if not line.startswith("-A "): continue
        try:
            tokens=shlex.split(line)
        except ValueError:
            return FENCE_UNKNOWN
        if len(tokens)<2: return FENCE_UNKNOWN
        if tokens[1]==chain:
            rules.append((table,tokens))
        if table=="filter" and tokens[1]=="DOCKER-USER":
            user_rules.append(tokens)
        if any(tokens[i] in ("-j","--jump","-g","--goto") and tokens[i+1]==chain
               for i in range(len(tokens)-1)):
            references.append((table,tokens))
    # 无声明且无任何引用 ⇒ 链已被 -X 删除，解封彻底完成。这是第四种合法状态，
    # 必须能重入收尾，所以先于「声明必须恰好一条」判定。
    if not declarations:
        return FENCE_UNKNOWN if references or rules else FENCE_CLEARED
    # 声明必须恰好一条且在 filter 表。
    if len(declarations)!=1 or declarations[0]!=("filter","-"):
        return FENCE_UNKNOWN
    expected_link=["-A","DOCKER-USER","-i",interface,"-j",chain]
    links=[tokens for tokens in user_rules if any(tokens[i] in ("-j","--jump","-g","--goto")
           and tokens[i+1]==chain for i in range(len(tokens)-1))]
    linked=bool(links)
    if linked and (len(links)!=1 or links[0]!=expected_link):
        return FENCE_UNKNOWN
    if linked and (not user_rules or user_rules[0]!=expected_link):
        return FENCE_UNKNOWN
    # 对本链的引用必须恰好是那一条合法 DOCKER-USER link。出现任何额外引用
    # （OUTPUT 跳进来、nat 表跳进来、重复 link）都意味着这条链还被别人用着，
    # 盲目 -F/-X 会误删他人规则 —— 一律 unknown，零盲清。
    if len(references)>1 or (references and not linked):
        return FENCE_UNKNOWN
    if linked and references!=[("filter",expected_link)]:
        return FENCE_UNKNOWN
    if not rules:
        # 链已声明但链内无规则：-F 已执行、-X 未成功。
        return FENCE_UNLINKED_EMPTY if not linked else FENCE_UNKNOWN
    # 链内必须恰好是原五规则，顺序与内容逐字一致。
    if len(rules)!=5: return FENCE_UNKNOWN
    for (rule_table,tokens),port in zip(rules,("3000","443","8080","8082","3128")):
        if rule_table!="filter" or len(tokens)!=14: return FENCE_UNKNOWN
        pairs=dict(zip(tokens[2::2],tokens[3::2]))
        expected={"-p":"tcp","-m":"conntrack","--ctdir":"ORIGINAL","--ctorigdstport":port,
                  "-j":"REJECT","--reject-with":"icmp-port-unreachable"}
        if pairs!=expected: return FENCE_UNKNOWN
    return FENCE_LINKED if linked else FENCE_UNLINKED_RULES



def ingress_state_of(residual):
    """把残留状态映射成运维可据以行动的三值 ingress。

    刻意与残留状态名区分开：readback 失败得到的是 unknown，意思是「不可推断」，
    既不是「入口仍隔离」也不是「入口已开放」。把 unknown 写成 fence_unknown
    会让人误以为已经确认仍隔离。
    """
    if residual==FENCE_UNKNOWN: return "unknown"
    if residual==FENCE_CLEARED: return "open"
    if residual==FENCE_UNLINKED_RULES or residual==FENCE_UNLINKED_EMPTY: return "open"
    return "fenced"


def read_fence_residual(chain, interface):
    """读回真实残留状态。iptables-save 自身失败时返回 unknown —— 读回失败不是
    「仍隔离」的证据，也不是「已开放」的证据。"""
    try:
        return probe_fence_residual(run(["iptables-save"]),chain,interface)
    except BaseException:
        return FENCE_UNKNOWN


def unrelated_fence_identity(snapshot,chain,interface):
    if probe_fence_residual(snapshot,chain,interface)==FENCE_UNKNOWN:
        raise RuntimeError("unknown fence rules or foreign references")
    table=None; identity=[]; user=[]
    link=["-A","DOCKER-USER","-i",interface,"-j",chain]
    for line in snapshot.splitlines():
        if not line or line.startswith("#"): continue
        if line.startswith("*"): table=line[1:]; identity.append([table]); continue
        if line=="COMMIT": identity.append([table,"COMMIT"]); table=None; continue
        tokens=shlex.split(line)
        if line.startswith(":"):
            if tokens[0]==":"+chain: continue
            identity.append([table,*tokens[:2]])
        elif tokens[:1]==["-A"]:
            if table=="filter" and (tokens[1]==chain or tokens==link): continue
            identity.append([table,*tokens])
            if table=="filter" and tokens[1]=="DOCKER-USER": user.append(tokens)
        else: raise RuntimeError("unrecognised firewall snapshot syntax")
    return identity,user


def verify_fence_identity(record,attempt,snapshot):
    baseline=safe_read(Path(attempt)/"fence-before.txt")
    if hashlib.sha256(baseline).hexdigest()!=record["fence_before_sha256"]:
        raise RuntimeError("checkpoint fence source differs from authenticated snapshot")
    expected,user=unrelated_fence_identity(baseline.decode(),record["iptables_chain"],record["interface"])
    actual,_=unrelated_fence_identity(snapshot,record["iptables_chain"],record["interface"])
    if record.get("schema") in (2,3):
        user_bytes=json.dumps(user,separators=(",",":")).encode()
        foreign_bytes=json.dumps(expected,separators=(",",":")).encode()
    else:
        link=["-A","DOCKER-USER","-i",record["interface"],"-j",record["iptables_chain"]]
        lines=[line for line in baseline.decode().splitlines() if line.startswith("-A DOCKER-USER ") and shlex.split(line)!=link]
        user_bytes="\n".join(lines).encode(); foreign_bytes=b""
    if (hashlib.sha256(user_bytes).hexdigest()!=record["unrelated_user_rules_sha256"] or
            hashlib.sha256(foreign_bytes).hexdigest()!=record["foreign_rules_sha256"] or actual!=expected):
        raise RuntimeError("unrelated firewall rules changed since checkpoint")
    return probe_fence_residual(snapshot,record["iptables_chain"],record["interface"])


def recovery_terminal_records(record,pin,media,live,archive,rows):
    recovery={key:record[key] for key in ("original_apply_sha256","execution_sha256","manifest_sha256","receipt_sha256","attempt")}
    recovery["checkpoint_sha256"]=pin
    rollback={"status":"rolled_back","release_id":media.name,"runtime":safe_identity(rows),
              "ledger":record["ledger_after"],"pointer_restored":record["current_present"],
              "boot_chain_restored":record["overlay_sha256"] is not None,"writers_drained":[s for s in WRITERS if s in rows],
              "live_evidence":{"path":str(live),"archived":str(archive),"archived_sha256":record["live_evidence_sha256"]},
              "recovery":recovery}
    completed={"status":"rolled_back","recovery":recovery,"checkpoint_sha256":pin}
    if record.get("schema") in (2,3):
        rollback.update({"schema":record["schema"],"checkpoint_sha256":pin})
        completed.update({"schema":record["schema"],"release_id":media.name,"rollback":rollback})
    return rollback,completed


def authenticate_terminal(path,expected,alternatives=()):
    try: raw=safe_read(path)
    except FileNotFoundError: return False
    existing=json.loads(raw)
    if existing!=expected and existing not in alternatives:
        raise RuntimeError("conflicting rollback/completed record payload; refusing to overwrite")
    return True


def verify_recovery_checkpoint(attempt, checkpoint_sha, media, manifest_sha, receipt_sha,
                              original_apply_sha, target_services, preserved_services,
                              workdir, chain_path, live, archive_path):
    """认证 finish-only 的唯一事实来源。

    checkpoint 由调用方在锁外固定完整 SHA256 —— 自存摘要不能当认证，否则改完
    checkpoint 再把新摘要写回同一处就绕过了。这里比的是外部传入的 pin 与磁盘
    现值，两侧同时改也会被发现。

    checkpoint 记录「本次恢复动态核实过的事实」。其中三类事实 receipt 的
    stage_binding 原理上推导不出来，必须由 checkpoint 认证、且与现场实测同时成立：
      1. 非目标容器的 Id 快照：重试时 VM 上这些容器（例如 postgres）早已不是
         stage 时刻的 Id，拿 stage 覆盖会把正常状态误判成环境漂移。
      2. 本次运行前的完整迁移账本：允许保留 stage 之后新增的迁移（如 302），
         只要求本次恢复期间账本未被改动。
      3. 目标服务重建后的真实 Id 与本次执行代码的 SHA：它们是「这次恢复确实
         发生过并已核实」的证据。
    """
    if not checkpoint_sha or not re.fullmatch(r"[0-9a-f]{64}",checkpoint_sha):
        raise RuntimeError("finish requires external recovery checkpoint SHA256")
    attempt=Path(attempt)
    parent=ROOT/"development-releases"/"rollback-attempts"
    if attempt.parent!=parent or \
       not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}",attempt.name):
        raise RuntimeError("finish requires the protected rollback attempt path")
    # 路径链上每一环都必须是真实目录、无符号链接。只有 attempt 及其直接父目录
    # rollback-attempts 要求 root 属主 0700（受保护的证据根）；更上层的
    # development-releases 与 /opt/jjdguard 是共享安装根，本就不该是 0700，
    # 对它们要求 0700 会把合法收尾全部误拒。
    for directory in (ROOT,ROOT/"development-releases",parent,attempt):
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("recovery attempt path component is not a real directory: "+str(directory))
    for directory in (parent,attempt):
        info=directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or
                stat.S_IMODE(info.st_mode)!=0o700):
            raise RuntimeError("recovery attempt directory must be root-owned mode 700: "+str(directory))
    path=attempt/"recovery-checkpoint.json"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("recovery checkpoint missing or unsafe")
    info=path.lstat()
    # nlink 必须为 1：硬链接的 checkpoint 意味着别处还有一份同一 inode 的副本，
    # 外部 pin 就无法唯一确定被认证的字节。
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
            stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
        raise RuntimeError("recovery checkpoint must be root-owned regular mode 600 with a single link")
    raw=safe_read(path,private=True)
    if hashlib.sha256(raw).hexdigest()!=checkpoint_sha:
        raise RuntimeError("recovery checkpoint differs from the external pin")
    record=json.loads(raw)
    required={"status","release_id","manifest_sha256","receipt_sha256","original_apply_sha256",
              "execution_sha256","target_services","preserved_services","preserved_ids",
              "ledger_before","ledger_after","runtime_after","boot_chain_sha256",
              "live_evidence_sha256","attempt","ingress_state","recorded_at",
              "current_present","current_bytes_b64","rollback_record_sha256",
              "previous_chain_sha256","overlay_sha256","env_path","env_sha256",
              "compose_identity","interface","iptables_chain","fence_before_sha256",
              "foreign_rules_sha256","unrelated_user_rules_sha256"}
    if not isinstance(record,dict) or (set(record)!=required and
            not (record.get("schema")==2 and set(record)==required|{"schema","runtime_identity","preserved_identity"}) and
            not (record.get("schema")==3 and set(record)==required|{"schema","runtime_identity","preserved_identity","transaction_evidence","preserved_inventory"})):
        raise RuntimeError("recovery checkpoint does not cover the authenticated recovery set")
    if record["status"]!="runtime_restored_cleanup_pending":
        raise RuntimeError("recovery checkpoint is not an immutable pending recovery record")
    if record["ingress_state"]!=FENCE_LINKED or record["rollback_record_sha256"] is not None:
        raise RuntimeError("checkpoint contradicts detach boundary or rollback absence")
    if (record["release_id"]!=media.name or record["manifest_sha256"]!=manifest_sha or
            record["receipt_sha256"]!=receipt_sha or record["original_apply_sha256"]!=original_apply_sha or
            record["attempt"]!=str(attempt)):
        raise RuntimeError("recovery checkpoint does not belong to this rollback")
    # 本次执行的代码身份：finish 必须由与 checkpoint 相同的执行体收尾，否则
    # 「已核实的运行态」与「正在收尾的代码」就脱钩了。
    if record["execution_sha256"]!=digest(Path(__file__)):
        raise RuntimeError("recovery checkpoint was produced by a different execution image")
    if record["target_services"]!=list(target_services) or record["preserved_services"]!=list(preserved_services):
        raise RuntimeError("recovery checkpoint covers a different service scope")
    if not isinstance(record["compose_identity"],dict) or not record["compose_identity"]:
        raise RuntimeError("recovery checkpoint lacks the original compose identity")
    if not isinstance(record["preserved_ids"],dict) or not record["preserved_ids"]:
        raise RuntimeError("recovery checkpoint preserved identity evidence is malformed")
    if not isinstance(record["runtime_after"],dict) or not record["runtime_after"]:
        raise RuntimeError("recovery checkpoint runtime evidence is malformed")
    # 账本允许在 stage 之后新增迁移，但本次恢复期间不得改动：以 checkpoint 记录的
    # before/after 相对关系为准，而不是拿 stage 的旧条数覆盖现场。
    if not isinstance(record["ledger_before"],dict) or not isinstance(record["ledger_after"],dict):
        raise RuntimeError("recovery checkpoint ledger evidence is malformed")
    if record["ledger_after"]!=record["ledger_before"]:
        raise RuntimeError("recovery checkpoint contradicts itself about the migration ledger")
    return record


def verify_recovered_runtime(record, rows_now, target_services, preserved_services, before):
    """现场实测必须与 checkpoint 同时成立：非目标容器 Id 用 checkpoint 认证过的
    快照（不是 stage），目标服务镜像/重启数用 stage 冻结值，账本与 policy 用本次
    动态证据。任何一项对不上都说明环境在恢复之后又动过，拒绝收尾。

    健康状态也必须认证：Id 与 Image 都没变、但 Health.Status 变成 unhealthy 的
    目标容器仍然是坏容器 —— 只比身份会让这种状态通过收尾。仅凭 Id/Image 无法
    察觉，所以 running/healthy 是独立的必要条件。
    """
    preserved=record["preserved_ids"]
    if not isinstance(preserved,dict):
        raise RuntimeError("recovery checkpoint preserved identity evidence is malformed")
    # 目标集合必须精确：checkpoint 覆盖的目标集合与本次 scope 逐项相同，多一个
    # 少一个都说明 checkpoint 与当前授权的恢复范围脱节。
    if set(record["runtime_after"])!=set(target_services):
        raise RuntimeError("recovery checkpoint target set differs from the authenticated scope")
    if set(record["target_services"])!=set(target_services):
        raise RuntimeError("recovery checkpoint target scope differs from the authenticated scope")
    # 非目标集合也必须完整：checkpoint 记录的非目标集合 + 本次 scope 的非目标
    # 集合必须一致，否则「未记录的服务」会被静默跳过核验。
    expected_preserved=(set(before["runtime"])|set(rows_now)|set(preserved_services))-set(target_services)
    if set(preserved)!=expected_preserved:
        raise RuntimeError("recovery checkpoint preserved scope is inconsistent")
    for service in preserved:
        if service not in rows_now:
            raise RuntimeError("preserved container absent while finishing rollback: "+service)
        if rows_now[service]["Id"]!=preserved[service]:
            raise RuntimeError("preserved container identity changed since the verified recovery: "+service)
        if record.get("schema") in (2,3) and protected_identity(rows_now[service])!=record["preserved_identity"].get(service):
            raise RuntimeError("preserved container image or volume identity changed: "+service)
    for service in record["preserved_ids"]:
        if service in target_services:
            raise RuntimeError("recovery checkpoint scope overlaps target and preserved services")
    after=record["runtime_after"]
    if not isinstance(after,dict):
        raise RuntimeError("recovery checkpoint runtime evidence is malformed")
    for service,snapshot in after.items():
        if service not in rows_now:
            raise RuntimeError("recovered target container absent while finishing rollback: "+service)
        row=rows_now[service]
        if row["Id"]!=snapshot["id"] or row["Image"]!=snapshot["image"]:
            raise RuntimeError("recovered target identity differs from the verified recovery: "+service)
        # 镜像必须同时绑 stage 冻结值：checkpoint 是本次恢复写的，但 stage 才是
        # 原始授权。只比 checkpoint 自己的记录等于没比。
        if service in before["runtime"] and row["Image"]!=before["runtime"][service]["image"]:
            raise RuntimeError("recovered target image differs from the staged identity: "+service)
        if row["RestartCount"]!=0:
            raise RuntimeError("recovered target restarted since the verified recovery: "+service)
        state=row.get("State") or {}
        if state.get("Status")!="running":
            raise RuntimeError("recovered target is not running while finishing rollback: "+service)
        health=(state.get("Health") or {}).get("Status","none")
        if health!="healthy":
            raise RuntimeError("recovered target is not healthy while finishing rollback: "+service)
    ledger_now=read_migration_ledger(rows_now)
    if ledger_now!=record["ledger_after"]:
        raise RuntimeError("migration ledger changed since the verified recovery; refusing to finish")
    return ledger_now


def protected_identity(row):
    # Docker inspect does not guarantee mount-array order; retain every field and duplicate.
    mounts=sorted(row.get("Mounts",[]),key=lambda mount:json.dumps(mount,sort_keys=True,separators=(",",":")))
    return {"id":row["Id"],"image":row["Image"],"mounts":mounts}


def resume_failure(media):
    path=media/"failure.json"
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
        raise RuntimeError("resume failure evidence must be root-owned regular mode 600")
    failure=json.loads(path.read_text())
    if (set(failure)!={"status","release_id","failure_type","failure_message","ingress"} or
            failure["status"]!="rollback_incomplete" or failure["release_id"]!=media.name or
            failure["ingress"]!="fenced" or not isinstance(failure["failure_type"],str) or
            not failure["failure_type"] or not isinstance(failure["failure_message"],str)):
        raise RuntimeError("resume failure evidence does not belong to this rollback")
    return path.read_bytes()


def perform_rollback(media, manifest_sha, receipt_sha, resume_fenced=False, attempt=None, original_apply_sha=None, checkpoint_ack=False, finish_pending=False):
    """受控提交后回滚：零数据库操作（不 pg_restore/不回迁移），全程持有 release
    锁；pinned receipt 与全部前置校验（只读）通过后才 fence，fence 后才恢复原链
    与原 Compose 输入、排空全部业务 writer，再按 stage 冻结的原始镜像身份重建目标
    服务；live 证据归档保留不删除；任一步失败保持 ingress fenced 并回退已执行的
    文件变更、尽力重启被排空的 writer。"""
    with release_lock():
        audit=AuditCollector()
        token=ROLLBACK_AUDIT.set(audit)
        try:
            try:
                return _rollback_locked(media, manifest_sha, receipt_sha, resume_fenced, attempt, original_apply_sha, checkpoint_ack)
            except BaseException:
                if not finish_pending or not getattr(audit,"checkpoint_pin",None): raise
                persist_audit(audit)
                print("ROLLBACK_PENDING_EXTERNAL_PIN_REQUIRED",flush=True)
                if not select.select([sys.stdin],[],[],60)[0]: raise RuntimeError("finish requires the saved external pin")
                external=sys.stdin.readline().strip()
                if not re.fullmatch(r"FINISH_CHECKPOINT=[0-9a-f]{64}",external):
                    raise RuntimeError("finish requires the saved external pin")
                finish_audit=AuditCollector(); finish_token=ROLLBACK_AUDIT.set(finish_audit)
                try:
                    result=_finish_locked(media,manifest_sha,receipt_sha,audit.path.parent,
                                          audit.original_apply_sha,external.split("=",1)[1])
                    print("ROLLBACK-FINISH "+result+"; same writer and release lock",flush=True)
                    return result
                finally:
                    try: persist_audit(finish_audit)
                    finally: ROLLBACK_AUDIT.reset(finish_token)
        finally:
            try:
                persist_audit(audit)
            finally: ROLLBACK_AUDIT.reset(token)

def _rollback_locked(media, manifest_sha, receipt_sha, resume_fenced=False, attempt=None, original_apply_sha=None, checkpoint_ack=False):
    authenticate_media(media)
    if digest(media/"manifest.json")!=manifest_sha: raise RuntimeError("manifest hash differs")
    manifest=json.loads((media/"manifest.json").read_text())
    if manifest.get("console_only"): raise RuntimeError("console releases roll back via vm_console_release.py")
    target_services,preserved_services=release_service_sets(manifest)
    if (media/"rollback.json").exists() or (media/"rollback.json").is_symlink():
        raise RuntimeError("release already rolled back; duplicate rollback refused")
    receipt=pinned_dev_receipt(media,receipt_sha)
    if manifest.get("identity_chat_only"):
        if identity_chat_snapshot(inspect_runtime(), manifest) != receipt.get("identity_chat_runtime"):
            raise RuntimeError("identity-chat runtime changed before recorded rollback")
    state=media/"state"
    verify_stage_binding(receipt, state)
    if not (state/"previous-current.json").exists():
        raise RuntimeError("legacy development release without a recorded previous pointer; roll forward via a rebuilt release instead")
    before_path=state/"before.json"
    before=json.loads(before_path.read_text())
    if receipt.get("revision")!=manifest.get("revision"): raise RuntimeError("receipt revision differs")
    live=Path(before["live"])
    if digest(live)!=receipt["compose_sha256"]: raise RuntimeError("active live configuration changed")
    previous_record=json.loads((state/"previous-current.json").read_text())
    if previous_record is not None and not isinstance(previous_record,str):
        raise RuntimeError("previous-current must wrap null or the original string")
    previous_bytes=None if previous_record is None else previous_record.encode()
    workdir=live.parent.parent
    chain_path=workdir/".upgrade/compose-files"
    chain_before=safe_read(chain_path)
    rows=inspect_runtime()
    current_ledger=read_migration_ledger(rows)
    transaction_before=read_transaction_evidence(rows)
    preserved_inventory=read_preserved_inventory(rows,target_services)
    if any(current_ledger.get(k)!=v for k,v in before["ledger"].items()):
        raise RuntimeError("previous migration ledger changed; rollback refused")
    # fence 前的只读预检：存在未决 prepared 事务就无法确认排空，拒绝且不产生任何变更。
    if read_drain_evidence(rows)["prepared"]:
        raise RuntimeError("prepared transactions present; writer drain cannot be confirmed; rollback refused")
    for service in target_services:
        image=before["runtime"][service]["image"]
        if json.loads(run(["docker","image","inspect",image]))[0]["Id"]!=image:
            raise RuntimeError("rollback image unavailable: "+service)
    # 以下全部为只读前置校验；任何变更都推迟到 fence 之后执行。
    chain_entries=chain_path.read_text().splitlines() if (chain_path.exists() or chain_path.is_symlink()) else []
    release_refs=[entry for entry in chain_entries if entry.startswith(str(workdir/"active-config")+"/"+media.name)]
    if "persist_boot" not in receipt:
        raise RuntimeError("receipt lacks authenticated persist state; rollback refused")
    persist_binding=receipt["persist_boot"]
    persist_record=state/"persist-boot.json"
    previous_chain=state/"boot-chain.previous"
    if persist_binding is None:
        if release_refs or persist_record.exists() or previous_chain.exists():
            raise RuntimeError("authenticated persist evidence conflicts with unpersisted receipt; rollback refused")
    else:
        required={"apply_receipt_sha256","record_sha256","previous_chain_sha256","overlay","overlay_sha256","chain_sha256"}
        if not isinstance(persist_binding,dict) or set(persist_binding)!=required:
            raise RuntimeError("receipt lacks complete authenticated persist evidence; rollback refused")
        if not persist_record.is_file() or persist_record.is_symlink() or not previous_chain.is_file() or previous_chain.is_symlink():
            raise RuntimeError("authenticated persist evidence missing; rollback refused")
        if digest(persist_record)!=persist_binding["record_sha256"]:
            raise RuntimeError("authenticated persist evidence changed: record; rollback refused")
        record=json.loads(persist_record.read_text())
        if record.get("manifest_sha256")!=manifest_sha or record.get("receipt_sha256")!=persist_binding["apply_receipt_sha256"]:
            raise RuntimeError("persist evidence is not bound to this release manifest and apply receipt; rollback refused")
        for field,path in (("before_sha256",before_path),("candidate_sha256",state/"candidate.json"),
                           ("previous_current_sha256",state/"previous-current.json")):
            if record.get(field)!=digest(path):
                raise RuntimeError("persist evidence is not bound to the staged before evidence: "+field)
        if (chain_path.is_symlink() or not chain_path.is_file() or
                digest(previous_chain)!=persist_binding["previous_chain_sha256"] or
                digest(chain_path)!=persist_binding["chain_sha256"] or
                record.get("previous_chain_sha256")!=persist_binding["previous_chain_sha256"] or
                record.get("chain_sha256")!=persist_binding["chain_sha256"]):
            raise RuntimeError("authenticated persist evidence changed: chain; rollback refused")
        overlay_path=Path(persist_binding["overlay"])
        if (overlay_path!=workdir/"active-config"/(media.name+"-persistent.json") or
                record.get("overlay")!=str(overlay_path) or record.get("overlay_sha256")!=persist_binding["overlay_sha256"] or
                overlay_path.is_symlink() or not overlay_path.is_file() or
                digest(overlay_path)!=persist_binding["overlay_sha256"]):
            raise RuntimeError("persisted overlay evidence changed; rollback refused")
        if release_refs!=[str(overlay_path)]:
            raise RuntimeError("authenticated persist chain reference missing or duplicated; rollback refused")
    # 快照是「stage 时它是什么」的证据，不是覆盖他人改动的授权：任何输入文件
    # 偏离 stage 冻结值都说明有人在发布期间动过它（他人漂移或环境被改），
    # 一律 fail-closed 拒绝，绝不拿快照把别人的改动覆盖掉。env 文件同理。
    snapshots=state/"compose-snapshots.json"
    if not snapshots.exists(): raise RuntimeError("compose snapshot index missing; rollback refused")
    snapshot_index=json.loads(snapshots.read_text())
    for path,checksum in before["compose_sha256"].items():
        current=digest(path)
        if current==checksum: continue
        if (manifest.get("identity_chat_only") and persist_binding is not None and
                Path(path) == chain_path and checksum == persist_binding["previous_chain_sha256"] and
                current == persist_binding["chain_sha256"]):
            # The chain's sole authorised change is this receipt-bound persist.
            # Its previous bytes and both hashes were authenticated above.
            continue
        snapshot=state/"original-compose"/snapshot_index.get(path,"")
        detail=("matches a staged snapshot but overwriting someone else's change is not authorised"
                if snapshot.is_file() and digest(snapshot)==checksum
                else "no matching staged snapshot")
        raise RuntimeError("release input drifted since stage and rollback will not overwrite it ("
                           +path+"): "+detail)
    if digest(staged_env_file(before))!=before["env_sha256"]:
        raise RuntimeError("release environment file drifted since stage; rollback will not overwrite it")
    # live 证据归档冲突是只读可判定的：归档里已有同一 release 的副本，说明本次
    # live 证据已被别的 rollback 归档过。不能覆盖它，更不能因此走到 fence 之后
    # 才失败 —— 那会消耗 rollback pointer 并把 ingress 留在 fenced。
    archive_dir=ROOT/"development-releases"/"archived-live"
    archive_path=archive_dir/(media.name+"-live.json")
    if archive_path.exists() or archive_path.is_symlink():
        raise RuntimeError("live evidence archive already exists; refusing to overwrite it or consume the rollback pointer")
    routes=json.loads(run(["ip","-j","route","show","default"]))
    if len(routes)!=1: raise RuntimeError("rollback requires a unique default interface")
    interface=routes[0]["dev"]
    iptables_chain="JJDDEV"+hashlib.sha256(media.name.encode()).hexdigest()[:10].upper()
    fence_snapshot=run(["iptables-save"])
    if not resume_fenced and any(line.startswith(":"+iptables_chain+" ") for line in fence_snapshot.splitlines()):
        raise RuntimeError("existing rollback fence requires explicit resume")
    old_failure=None
    if resume_fenced:
        if not original_apply_sha or not re.fullmatch(r"[0-9a-f]{64}",original_apply_sha):
            raise RuntimeError("resume requires external original apply SHA256")
        source=media/"vm_development_apply.py"
        info=source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or
                digest(source)!=original_apply_sha):
            raise RuntimeError("original media apply source differs from external pin or is unsafe")
        if manifest.get("apply_script_sha256")!=original_apply_sha:
            raise RuntimeError("original source pin differs from authenticated manifest")
        old_failure=resume_failure(media)
        fence_snapshot=authenticated_fence(fence_snapshot,iptables_chain,interface)
        if attempt is None: raise RuntimeError("resume requires a unique protected attempt path")
    else:
        original_apply_sha=original_apply_sha or manifest.get("apply_script_sha256")
        if (not isinstance(original_apply_sha,str) or not re.fullmatch(r"[0-9a-f]{64}",original_apply_sha) or
                manifest.get("apply_script_sha256")!=original_apply_sha or
                hashlib.sha256(safe_read(media/"vm_development_apply.py")).hexdigest()!=original_apply_sha):
            raise RuntimeError("original media apply source differs from the pinned manifest")
    parent=ROOT/"development-releases"/"rollback-attempts"
    attempt=Path(attempt) if attempt else parent/("rollback-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+os.urandom(8).hex())
    if attempt.parent!=parent or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}",attempt.name):
        raise RuntimeError("rollback requires a unique protected attempt path")
    if attempt.exists() or attempt.is_symlink(): raise RuntimeError("rollback attempt already exists")
    safe_mkdir(parent,exist_ok=True); safe_mkdir(attempt)
    authenticate_write_paths([attempt/name for name in ("subprocess.jsonl","apply.log","completed.json","recovery-checkpoint.json")])
    authenticate_write_paths([media/"rollback.json",chain_path,ROOT/"development-releases/current.json"])
    if old_failure is not None: atomic_bytes(attempt/"original-failure.json",old_failure)
    atomic_bytes(attempt/"fence-input.txt",fence_snapshot.encode())
    atomic_bytes(attempt/"boot-chain-input.txt",chain_before)
    recovery={"original_apply_sha256":original_apply_sha,"execution_sha256":digest(Path(__file__)),
              "manifest_sha256":manifest_sha,"receipt_sha256":receipt_sha,"attempt":str(attempt)}
    write_json(attempt/"authentication.json",recovery)
    command_log=attempt/"apply.log"; failure_path=attempt/"failure.json"
    audit=ROLLBACK_AUDIT.get()
    if isinstance(audit,AuditCollector):
        audit.path=attempt/"subprocess.jsonl"; audit.flush(audit.path)
    drained,restartable=writer_drain_sets(rows,target_services,manifest)
    undo={}
    restored_chain=False
    committed=False
    try:
        if not resume_fenced:
            run(["iptables","-N",iptables_chain])
            for port in ("3000","443","8080","8082","3128"):
                run(["iptables","-A",iptables_chain,"-p","tcp","-m","conntrack","--ctdir","ORIGINAL","--ctorigdstport",port,"-j","REJECT"])
            run(["iptables","-I","DOCKER-USER","1","-i",interface,"-j",iptables_chain])
        authenticated_fence(run(["iptables-save"]),iptables_chain,interface)
        print("FENCED application ingress for rollback",flush=True)
        if release_refs:
            undo[str(chain_path)]=chain_path.read_bytes()
            atomic_bytes(chain_path,(state/"boot-chain.previous").read_bytes())
            if any(entry.startswith(str(workdir/"active-config")+"/"+media.name)
                   for entry in chain_path.read_text().splitlines()):
                raise RuntimeError("restored boot chain still references this release")
            restored_chain=True
        # 零数据库操作：本函数不执行 pg_dump/pg_restore/任何写 SQL；postgres 不停。
        # fence 后排空全部业务 writer（含目标与非目标），避免回滚窗口内出现新旧
        # 镜像混写的业务提交；非目标 writer 在目标服务重建并验证后原样启动回来。
        if drained:
            run([str(workdir/"bin/docker-compose"),"--project-directory",str(workdir),"-p",before["project"],
                 "-f",str(live),"stop","--timeout","25",*drained],log=command_log)
        # 排空确认：stop 后经 pg_stat_activity/pg_prepared_xacts 独立确认没有
        # 仍在进行的事务；无法确认则拒绝（ingress 保持 fenced，由失败路径恢复）。
        drained_view=read_drain_evidence(rows)
        if drained_view["active"] or drained_view["prepared"]:
            raise RuntimeError("writer drain could not be confirmed after stop (active sessions: "
                               +str(len(drained_view["active"]))+", prepared transactions: "
                               +str(len(drained_view["prepared"]))+"); rollback refused")
        files=[Path(p) for p in before["compose_files"]]
        flat=[]
        for path in files: flat+=["-f",str(path)]
        for service in target_services:
            command=[str(workdir/"bin/docker-compose"),"--project-directory",str(workdir),"-p",before["project"],
                     *flat,"up","-d","--no-deps","--pull","never","--force-recreate",service]
            run(command,log=command_log)
        deadline=time.monotonic()+180
        while True:
            now=inspect_runtime()
            if set(target_services)<=set(now) and all(now[s]["State"]["Status"]=="running" and now[s]["State"].get("Health",{}).get("Status","none")=="healthy" for s in target_services):
                break
            if time.monotonic()>=deadline: raise RuntimeError("rollback health deadline exceeded")
            time.sleep(2)
        if restartable:
            run([str(workdir/"bin/docker-compose"),"--project-directory",str(workdir),"-p",before["project"],
                 "-f",str(live),"start",*restartable],log=command_log)
            deadline=time.monotonic()+180
            while True:
                restarted=inspect_runtime()
                if all(service in restarted and restarted[service]["State"]["Status"]=="running" and
                       restarted[service]["State"].get("Health",{}).get("Status","none") in ("healthy","none") for service in restartable): break
                if time.monotonic()>=deadline: raise RuntimeError("non-target writer restart health deadline exceeded")
                time.sleep(2)
        now=inspect_runtime()
        for service in target_services:
            if now[service]["Image"]!=before["runtime"][service]["image"]: raise RuntimeError("rollback image differs: "+service)
            if now[service]["RestartCount"]!=0: raise RuntimeError("rollback target restarted: "+service)
        verify_preserved_identities(before["runtime"],safe_identity(now),preserved_services)
        for service in rows:
            if service in target_services: continue
            if service not in now or protected_identity(now[service])!=protected_identity(rows[service]):
                raise RuntimeError("non-target container was recreated during rollback: "+service)
        if manifest.get("identity_chat_only"):
            verify_identity_chat_snapshot(before["identity_chat_runtime"], identity_chat_snapshot(now, manifest), manifest,
                                          replaced=True, resumed=True, rollback=True)
        current_policy=read_policy(now, include_billing="billing_enabled" in before["policy"])
        if current_policy!=before["policy"]: raise RuntimeError("managed policy changed during rollback")
        if read_migration_ledger(now)!=current_ledger: raise RuntimeError("migration ledger changed during rollback")
        if read_transaction_evidence(now)!=transaction_before:
            raise RuntimeError("existing transaction preservation evidence changed during rollback")
        if read_preserved_inventory(now,target_services)!=preserved_inventory:
            raise RuntimeError("complete non-target container or volume inventory changed during rollback")
        restored_fence=authenticated_fence(run(["iptables-save"]),iptables_chain,interface)
        if unrelated_fence_identity(restored_fence,iptables_chain,interface)[1]!=unrelated_fence_identity(fence_snapshot,iptables_chain,interface)[1]:
            raise RuntimeError("unrelated DOCKER-USER rules changed during runtime restoration")
        fence_snapshot=restored_fence
        atomic_bytes(attempt/"fence-before.txt",fence_snapshot.encode())
        pointer_path=ROOT/"development-releases/current.json"
        undo[str(pointer_path)]=pointer_path.read_bytes() if (pointer_path.exists() or pointer_path.is_symlink()) else None
        if previous_bytes is None:
            if pointer_path.exists() or pointer_path.is_symlink(): safe_unlink(pointer_path)
        else:
            atomic_bytes(pointer_path,previous_bytes)
        # live 证据归档保留：受保护的 archived-live 副本 + 原文件都不删除
        safe_mkdir(archive_dir,exist_ok=True)
        undo[str(archive_path)]=None
        atomic_bytes(archive_path,live.read_bytes())
        if digest(archive_path)!=receipt["compose_sha256"]:
            raise RuntimeError("archived live evidence differs from the pinned receipt")
        # ── 提交点 ────────────────────────────────────────────────────────────
        # 到这里为止运行态（目标按 stage 冻结镜像重建并核验、非目标容器 Id 恒等、
        # 账本与 policy 未变）、指针、归档都已核实。解封从这一刻起不再回退它们：
        # 一旦 ingress 已开放，再把指针回退到新 dev release 会造出「指针指向
        # dev-release-X 但容器是旧镜像」的不一致，比堵死更糟。
        # 但 committed 只能在 checkpoint 成功落盘之后才翻转 —— checkpoint 是
        # finish-only 唯一的认证锚，它没写成就不该进入不可回退的解封阶段。
        if recovery is not None:
            # 无关规则与 foreign 规则的身份：必须排除本 chain 自身的合法差量
            # （链声明、五条 REJECT 规则、那条 DOCKER-USER link），剩下的才是
            # 「别人的规则」。只记录不判断 —— 判断在 finish 侧做。
            foreign,unrelated=unrelated_fence_identity(fence_snapshot,iptables_chain,interface)
            checkpoint={"status":"runtime_restored_cleanup_pending","release_id":media.name,
                        "schema":3,"runtime_identity":safe_identity(now),"transaction_evidence":transaction_before,
                        "preserved_inventory":preserved_inventory,
                        "preserved_identity":{s:protected_identity(rows[s]) for s in rows if s not in target_services},
                        "manifest_sha256":manifest_sha,"receipt_sha256":receipt_sha,
                        "original_apply_sha256":original_apply_sha,
                        "execution_sha256":digest(Path(__file__)),
                        "target_services":list(target_services),
                        "preserved_services":list(preserved_services),
                        # 动态事实：重试时这些容器早已不是 stage 时刻的 Id（例如
                        # postgres 长期运行），必须用本次恢复核实过的真实 Id，
                        # 不能用 stage receipt 推导。
                        "preserved_ids":{service:rows[service]["Id"] for service in rows
                                         if service not in target_services},
                        "runtime_after":{service:{"id":now[service]["Id"],"image":now[service]["Image"]}
                                         for service in target_services},
                        "ledger_before":current_ledger,
                        # 恢复期间账本必须严格不变：before 与 after 是同一份实测
                        # 值，不一致本身就说明恢复期动过账本。
                        "ledger_after":current_ledger,
                        "boot_chain_sha256":digest(chain_path),
                        "previous_chain_sha256":digest(state/"boot-chain.previous") if persist_binding is not None else hashlib.sha256(chain_before).hexdigest(),
                        "overlay_sha256":digest(overlay_path) if persist_binding is not None else None,
                        "env_path":str(staged_env_file(before)),
                        "env_sha256":digest(staged_env_file(before)),
                        "compose_identity":{path:checksum for path,checksum in before["compose_sha256"].items()},
                        "live_evidence_sha256":digest(archive_path),
                        # detach 前 media/rollback.json 必须不存在：若存在，任何
                        # is_file() 式的「已完成」判断都会把外来伪记录当成本次
                        # 恢复的产物。None 表示「已核实不存在」。
                        "rollback_record_sha256":None,
                        # current 字节必须与 stage 冻结的 previous-current 原字符串
                        # 逐字节相等（不是解析后的对象相等）。
                        "current_present":previous_bytes is not None,
                        "current_bytes_b64":base64.b64encode(previous_bytes or b"").decode(),
                        "interface":interface,
                        "iptables_chain":iptables_chain,
                        "fence_before_sha256":hashlib.sha256(fence_snapshot.encode()).hexdigest(),
                        "foreign_rules_sha256":hashlib.sha256(
                            json.dumps(foreign,separators=(",",":")).encode()).hexdigest(),
                        "unrelated_user_rules_sha256":hashlib.sha256(
                            json.dumps(unrelated,separators=(",",":")).encode()).hexdigest(),
                        "attempt":str(attempt),"ingress_state":FENCE_LINKED,
                        "recorded_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
            # immutable：只在不存在时创建，已存在即拒绝覆盖。
            checkpoint_path=attempt/"recovery-checkpoint.json"
            if checkpoint_path.exists() or checkpoint_path.is_symlink():
                raise RuntimeError("recovery checkpoint already exists; refusing to overwrite")
            atomic_bytes(checkpoint_path,(json.dumps(checkpoint,indent=2)+"\n").encode())
            checkpoint_pin=digest(checkpoint_path)
            recovery["checkpoint_sha256"]=checkpoint_pin
            audit=ROLLBACK_AUDIT.get()
            if isinstance(audit,AuditCollector):
                audit.checkpoint_pin=checkpoint_pin; audit.original_apply_sha=original_apply_sha
            print("FINAL_ROLLBACK_CHECKPOINT_SHA256="+checkpoint_pin,flush=True)
        committed=True
        if checkpoint_ack:
            if not select.select([sys.stdin],[],[],60)[0] or sys.stdin.readline().strip()!="ACK_CHECKPOINT="+checkpoint_pin:
                pending=RuntimeError("checkpoint sealed; external acknowledgement missing; ingress remains fenced")
                pending.unfence_pending=True
                raise pending
        # 解封纳入受保护范围：任一步失败都按实测残留状态取证，而不是硬编码
        # 「仍 fenced」—— -D 成功而 -F/-X 失败时 ingress 其实已经开放。
        try:
            authenticated_fence(run(["iptables-save"]),iptables_chain,interface)
            verify_fence_identity(checkpoint,attempt,run(["iptables-save"]))
            run(["iptables","-D","DOCKER-USER","-i",interface,"-j",iptables_chain])
            residual=verify_fence_identity(checkpoint,attempt,run(["iptables-save"])) if recovery is not None else read_fence_residual(iptables_chain,interface)
            if residual in (FENCE_UNLINKED_RULES,FENCE_UNLINKED_EMPTY):
                run(["iptables","-F",iptables_chain])
                residual=verify_fence_identity(checkpoint,attempt,run(["iptables-save"])) if recovery is not None else read_fence_residual(iptables_chain,interface)
                if residual==FENCE_UNLINKED_EMPTY:
                    run(["iptables","-X",iptables_chain])
                    residual=verify_fence_identity(checkpoint,attempt,run(["iptables-save"])) if recovery is not None else read_fence_residual(iptables_chain,interface)
            if residual!=FENCE_CLEARED:
                raise RuntimeError("unfence did not reach a cleared state; residual: "+residual)
        except BaseException as unfence_error:
            actual=read_fence_residual(iptables_chain,interface)
            if recovery is not None:
                try:
                    write_json(attempt/"unfence-failure.json",
                               {"status":"cleanup_pending","release_id":media.name,
                                "failure_type":type(unfence_error).__name__,
                                "failure_message":str(unfence_error)[:1500],
                                "ingress":ingress_state_of(actual),
                                "fence_residual":actual,
                                "checkpoint_sha256":recovery.get("checkpoint_sha256"),
                                "note":"ingress 依 iptables-save 实测；open 表示 -D 已成功、入口已开放"})
                except BaseException: pass
            # 审计必须在 raise 之前落盘：否则解封失败这一最需要证据的时刻
            # 反而没有命令记录。
            if isinstance(ROLLBACK_AUDIT.get(),AuditCollector):
                try: ROLLBACK_AUDIT.get().flush(attempt/"subprocess.jsonl")
                except BaseException: pass
            pending=RuntimeError("development rollback unfence incomplete; ingress residue: "+actual
                                 +"; finish with finish-rollback and the external checkpoint SHA256")
            pending.unfence_pending=True
            raise pending from None
        # 解封已完成才写终态记录。managed 记录写成 rolled_back；immutable pending
        # checkpoint 保持原样，completed 终态单独绑定它的 SHA。
        terminal,done=recovery_terminal_records(checkpoint,checkpoint_pin,media,live,archive_path,now) if recovery is not None else (None,None)
        write_json(media/"rollback.json",terminal if terminal is not None else {"status":"rolled_back","release_id":media.name,
                                          "runtime":safe_identity(now),"ledger":current_ledger,
                                          "pointer_restored":previous_bytes is not None,
                                          "boot_chain_restored":restored_chain,
                                          "writers_drained":drained,
                                          "live_evidence":{"path":str(live),"archived":str(archive_path),
                                                           "archived_sha256":digest(archive_path)},
                                          **({"recovery":recovery} if recovery is not None else {})})
        # 成功日志与 completed 记录写入失败同样必须可 finish：解封已完成、无链无
        # link 属第四种合法残留状态，finish 认这个状态并补写记录。
        try:
            safe_append(command_log,(datetime.datetime.now(datetime.timezone.utc).isoformat()+" ROLLBACK "+media.name+"\n").encode())
            if recovery is not None:
                write_json(attempt/"completed.json",
                           done)
        except BaseException as record_error:
            if recovery is not None:
                try:
                    write_json(attempt/"record-failure.json",
                               {"status":"records_incomplete","release_id":media.name,
                                "failure_type":type(record_error).__name__,
                                "failure_message":str(record_error)[:1500],
                                "ingress":FENCE_CLEARED,
                                "checkpoint_sha256":recovery.get("checkpoint_sha256"),
                                "note":"解封已完成（无链无 link）；缺的是成功日志或 completed 记录，可用 finish-rollback 补写"})
                except BaseException: pass
            if isinstance(ROLLBACK_AUDIT.get(),AuditCollector):
                try: ROLLBACK_AUDIT.get().flush(attempt/"subprocess.jsonl")
                except BaseException: pass
            records_pending=RuntimeError("development rollback finished unfencing but final records are incomplete;"
                                         " finish with finish-rollback and the external checkpoint SHA256")
            records_pending.unfence_pending=True
            raise records_pending from None
        if isinstance(ROLLBACK_AUDIT.get(),AuditCollector) and recovery is not None:
            ROLLBACK_AUDIT.get().flush(attempt/"subprocess.jsonl")
        # 成功只在全部记录落盘之后输出。
        print("ROLLBACK completed; database, new transactions and live evidence preserved",flush=True)
    except BaseException as error:
        # 解封分支已自行按实测残留取证并抛出明确错误；那种情况不能再被改写成
        # 「inspect protected failure evidence」，否则运维看不到该走 finish。
        if committed and getattr(error,"unfence_pending",False):
            raise
        if not committed:
            for path,original in reversed(list(undo.items())):
                try:
                    if original is None:
                        candidate=Path(path)
                        if candidate.exists() or candidate.is_symlink(): safe_unlink(candidate)
                    else:
                        atomic_bytes(Path(path),original)
                except BaseException: pass
            try:
                if restartable:
                    run([str(workdir/"bin/docker-compose"),"--project-directory",str(workdir),"-p",before["project"],
                         "-f",str(live),"start",*restartable])
            except BaseException:
                pass
        # 提交点之前的失败：解封从未开始，ingress 必然仍隔离。提交点之后的失败
        # 由上面的解封分支自己取证（那里才知道真实的 ingress 状态），这里的
        # 硬编码只在 committed 为假时成立。
        try:
            write_json(failure_path,{"status":"rollback_incomplete","release_id":media.name,
                                             "failure_type":type(error).__name__,"failure_message":str(error)[:1500],
                                             "ingress":FENCE_LINKED if not committed else FENCE_UNKNOWN})
            legacy_failure=media/"failure.json"
            if not resume_fenced and not legacy_failure.exists() and not legacy_failure.is_symlink():
                atomic_bytes(legacy_failure,safe_read(failure_path))
        except BaseException:
            pass
        raise RuntimeError("development rollback incomplete; inspect protected failure evidence") from None


def perform_rollback_finish(media, manifest_sha, receipt_sha, attempt, original_apply_sha, checkpoint_sha):
    """从受保护 checkpoint 收尾：只认证、只补齐解封残留与终态记录。不重建容器、
    不改指针、不碰数据库 —— 这些在 checkpoint 认证的那次运行里已经做完并核实过，
    重做一遍反而会破坏「非目标容器 Id 恒等」这条证据。

    认证分两层，缺一即拒：
      · 原凭证：manifest/receipt 的外部 pin、stage_binding 逐项复核、旧 source
        的外部 pin —— 与本次恢复的原始授权绑定。
      · 已恢复状态：pointer 已回退、开机链等于 boot-chain.previous、live 证据
        归档在位且等于 receipt 的 compose digest。注意这里不能原样重跑
        pinned_dev_receipt：它强制 current 指向本 media，而收尾时 current 已经
        恢复成 previous-current，两者本就不相等。
    """
    with release_lock():
        audit=AuditCollector()
        token=ROLLBACK_AUDIT.set(audit)
        try:
            result=_finish_locked(media,manifest_sha,receipt_sha,attempt,original_apply_sha,checkpoint_sha)
            print("ROLLBACK-FINISH "+result+"; authenticated recovery and audit persisted",flush=True)
            return result
        finally:
            try:
                persist_audit(audit)
            finally: ROLLBACK_AUDIT.reset(token)


def _finish_locked(media, manifest_sha, receipt_sha, attempt, original_apply_sha, checkpoint_sha):
    authenticate_write_paths([Path(attempt)/name for name in ("subprocess.jsonl","apply.log","completed.json","finish-failure.json")]+[media/"rollback.json"])
    if isinstance(ROLLBACK_AUDIT.get(),AuditCollector):
        ROLLBACK_AUDIT.get().path=Path(attempt)/"subprocess.jsonl"
    authenticate_media(media)
    if digest(media/"manifest.json")!=manifest_sha: raise RuntimeError("manifest hash differs")
    manifest=json.loads((media/"manifest.json").read_text())
    if manifest.get("console_only"): raise RuntimeError("console releases roll back via vm_console_release.py")
    target_services,preserved_services=release_service_sets(manifest)
    if not original_apply_sha or not re.fullmatch(r"[0-9a-f]{64}",original_apply_sha):
        raise RuntimeError("finish requires external original apply SHA256")
    # 原凭证仍要独立认证：manifest pin、旧 source pin、receipt 本体与 stage 证据。
    source=media/"vm_development_apply.py"
    info=source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or
            digest(source)!=original_apply_sha):
        raise RuntimeError("original media apply source differs from external pin or is unsafe")
    if manifest.get("apply_script_sha256")!=original_apply_sha:
        raise RuntimeError("original source pin differs from authenticated manifest")
    if digest(media/"receipt.json")!=receipt_sha: raise RuntimeError("receipt hash differs")
    receipt=json.loads((media/"receipt.json").read_text())
    if receipt.get("status")!="deployed" or receipt.get("release_id")!=media.name:
        raise RuntimeError("unsupported development rollback receipt")
    if receipt.get("revision")!=manifest.get("revision"): raise RuntimeError("receipt revision differs")
    state=media/"state"
    verify_stage_binding(receipt,state)
    before=json.loads((state/"before.json").read_text())
    live=Path(before["live"]); workdir=live.parent.parent
    chain_path=workdir/".upgrade/compose-files"
    archive_path=ROOT/"development-releases"/"archived-live"/(media.name+"-live.json")
    record_checkpoint_pin=checkpoint_sha
    record=verify_recovery_checkpoint(attempt,checkpoint_sha,media,manifest_sha,receipt_sha,
                                      original_apply_sha,target_services,preserved_services,
                                      workdir,chain_path,live,archive_path)
    # 已恢复状态认证：current 指针必须与 checkpoint 记录的「存在性 + 原字节」
    # 逐字相符。注意这里不能原样重跑 pinned_dev_receipt：它强制 current 指向本
    # media，而收尾时 current 已恢复成 previous-current，两者本就不相等。
    # 比对用原始字节而不是解析后的 json 对象：json 往返会规范化格式与键序，
    # 拿对象比会放过「内容对但字节不同」的篡改。
    pointer_path=ROOT/"development-releases/current.json"
    if record["current_present"]:
        if pointer_path.is_symlink() or not pointer_path.is_file():
            raise RuntimeError("release pointer is missing or unsafe; refusing to finish")
        if pointer_path.read_bytes()!=base64.b64decode(record["current_bytes_b64"]):
            raise RuntimeError("release pointer bytes differ from the verified recovery; refusing to finish")
    else:
        if pointer_path.exists() or pointer_path.is_symlink():
            raise RuntimeError("release pointer exists but the verified recovery recorded none; refusing to finish")
    # 存在性必须与 stage 冻结的 previous-current 一致。注意括号：`!=` 与
    # `is not` 混写会被解析成 `!= (is not)`，恒为真，必须显式加括号。
    staged_previous=json.loads((state/"previous-current.json").read_text())
    if staged_previous is not None and not isinstance(staged_previous,str):
        raise RuntimeError("previous-current must wrap null or the original string")
    staged_bytes=None if staged_previous is None else staged_previous.encode()
    if (record["current_present"]!=(staged_previous is not None) or
            base64.b64decode(record["current_bytes_b64"],validate=True)!=(staged_bytes or b"")):
        raise RuntimeError("recovered pointer presence contradicts the staged previous pointer")
    if chain_path.is_symlink() or not chain_path.is_file():
        raise RuntimeError("boot chain missing or unsafe; refusing to finish")
    if digest(chain_path)!=record["boot_chain_sha256"]:
        raise RuntimeError("boot chain differs from the verified recovery; refusing to finish")
    previous_chain=state/"boot-chain.previous" if receipt.get("persist_boot") is not None else Path(attempt)/"boot-chain-input.txt"
    if digest(chain_path)!=digest(previous_chain):
        raise RuntimeError("boot chain is not the restored previous chain; refusing to finish")
    if any(entry.startswith(str(workdir/"active-config")+"/"+media.name)
           for entry in chain_path.read_text().splitlines()):
        raise RuntimeError("restored boot chain still references this release; refusing to finish")
    if archive_path.is_symlink() or not archive_path.is_file():
        raise RuntimeError("live evidence archive missing or unsafe; refusing to finish")
    if digest(archive_path)!=receipt["compose_sha256"] or digest(archive_path)!=record["live_evidence_sha256"]:
        raise RuntimeError("archived live evidence differs from the pinned receipt or the verified recovery")
    # 原 Compose 输入与安装 env 身份：env 路径必须由 staged_env_file 唯一推导
    # （安装树 workdir/.env），并与 checkpoint 与 stage 三方一致。
    env_path=staged_env_file(before)
    if str(env_path)!=record["env_path"]:
        raise RuntimeError("checkpoint environment path is not the staged installed environment")
    if env_path.is_symlink() or not env_path.is_file():
        raise RuntimeError("installed environment file is missing or unsafe; refusing to finish")
    if digest(env_path)!=record["env_sha256"] or digest(env_path)!=before["env_sha256"]:
        raise RuntimeError("installed environment identity changed since the verified recovery")
    # compose 集合与逐项 hash 必须等于 stage 冻结的 before，不是 checkpoint 自述。
    if set(record["compose_identity"])!=set(before["compose_sha256"]):
        raise RuntimeError("checkpoint compose set differs from the staged compose set")
    for path,checksum in record["compose_identity"].items():
        if before["compose_sha256"][path]!=checksum:
            raise RuntimeError("checkpoint compose identity differs from the staged evidence: "+path)
        candidate=Path(path)
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError("release compose input is missing or unsafe: "+path)
        if digest(candidate)!=checksum:
            raise RuntimeError("release compose identity changed since the verified recovery: "+path)
    # persist 认证：复用原 rollback 的只读语义（record/previous-chain/overlay
    # 三者摘要 + record 内 manifest/apply receipt/stage 绑定），但 current 与
    # chain 采用「已恢复」状态去核 —— 不调用要求 current 仍指向本 media 的
    # pinned_dev_receipt。persist-boot.json 只追加一个 LF 就必须被发现。
    persist_binding=receipt.get("persist_boot")
    persist_record=state/"persist-boot.json"
    if persist_binding is None:
        if ("persist_boot" not in receipt or record["overlay_sha256"] is not None or
                persist_record.exists() or persist_record.is_symlink() or
                (state/"boot-chain.previous").exists() or (state/"boot-chain.previous").is_symlink()):
            raise RuntimeError("unpersisted receipt contradicts persist evidence")
        if hashlib.sha256(safe_read(previous_chain,private=True)).hexdigest()!=record["previous_chain_sha256"]:
            raise RuntimeError("authenticated unpersisted boot chain input changed")
    else:
        verify_finish_persist(persist_binding,record,state,before,workdir,manifest_sha,media)
    # Existing terminal evidence is authenticated before any cleanup operation.
    rollback_record=media/"rollback.json"
    if rollback_record.is_symlink() or (rollback_record.exists() and not rollback_record.is_file()):
        raise RuntimeError("media rollback record is unsafe; refusing to finish")
    if digest(previous_chain)!=record["previous_chain_sha256"]:
        raise RuntimeError("authenticated previous boot chain changed; refusing to finish")
    rows_now=inspect_runtime()
    verify_recovered_runtime(record,rows_now,target_services,preserved_services,before)
    if record.get("schema") in (2,3) and safe_identity(rows_now)!=record["runtime_identity"]:
        raise RuntimeError("complete runtime identity differs from checkpoint")
    if record.get("schema")==3 and read_transaction_evidence(rows_now)!=record["transaction_evidence"]:
        raise RuntimeError("existing transactions changed since the verified recovery")
    if record.get("schema")==3 and read_preserved_inventory(rows_now,target_services)!=record["preserved_inventory"]:
        raise RuntimeError("complete non-target container or volume inventory changed since checkpoint")
    terminal,done=recovery_terminal_records(record,checkpoint_sha,media,live,archive_path,rows_now)
    legacy_rollback={key:value for key,value in terminal.items() if key not in ("recovery","writers_drained")}
    legacy_rollback.update({"finished_by":"finish-only","checkpoint_sha256":checkpoint_sha})
    legacy_dual={**terminal,"checkpoint_sha256":checkpoint_sha}
    rollback_exists=authenticate_terminal(rollback_record,terminal,(legacy_rollback,legacy_dual) if "schema" not in record else ())
    completed=Path(attempt)/"completed.json"
    legacy_done={"status":"rolled_back","checkpoint_sha256":checkpoint_sha,"original_apply_sha256":original_apply_sha,"finished_by":"finish-only"}
    completed_exists=authenticate_terminal(completed,done,(legacy_done,) if "schema" not in record else ())
    return finish_cleanup(media,attempt,checkpoint_sha,original_apply_sha,record,before,rows_now,
                          terminal,done,rollback_record,completed,rollback_exists,completed_exists)


def verify_finish_persist(persist_binding,record,state,before,workdir,manifest_sha,media):
    if not isinstance(persist_binding,dict) or record["overlay_sha256"] is None:
        raise RuntimeError("finish requires authenticated persist evidence")
    persist_record=state/"persist-boot.json"
    previous_chain=state/"boot-chain.previous"
    required={"apply_receipt_sha256","record_sha256","previous_chain_sha256","overlay","overlay_sha256","chain_sha256"}
    if set(persist_binding)!=required:
        raise RuntimeError("receipt lacks complete authenticated persist evidence; refusing to finish")
    if persist_record.is_symlink() or not persist_record.is_file():
        raise RuntimeError("authenticated persist evidence missing; refusing to finish")
    if previous_chain.is_symlink() or not previous_chain.is_file():
        raise RuntimeError("authenticated previous boot chain missing; refusing to finish")
    if digest(persist_record)!=persist_binding["record_sha256"]:
        raise RuntimeError("authenticated persist evidence changed: record; refusing to finish")
    if digest(previous_chain)!=persist_binding["previous_chain_sha256"]:
        raise RuntimeError("authenticated persist evidence changed: previous chain; refusing to finish")
    persist=json.loads(persist_record.read_text())
    if (persist.get("manifest_sha256")!=manifest_sha or
            persist.get("receipt_sha256")!=persist_binding["apply_receipt_sha256"]):
        raise RuntimeError("persist evidence is not bound to this release manifest and apply receipt")
    for field,target in (("before_sha256",state/"before.json"),
                         ("candidate_sha256",state/"candidate.json"),
                         ("previous_current_sha256",state/"previous-current.json")):
        if persist.get(field)!=digest(target):
            raise RuntimeError("persist evidence is not bound to the staged before evidence: "+field)
    if (persist.get("previous_chain_sha256")!=persist_binding["previous_chain_sha256"] or
            persist.get("overlay")!=persist_binding["overlay"] or
            persist.get("overlay_sha256")!=persist_binding["overlay_sha256"]):
        raise RuntimeError("persist record contradicts the pinned persist evidence")
    overlay_path=Path(persist_binding["overlay"])
    if (overlay_path!=workdir/"active-config"/(media.name+"-persistent.json") or
            overlay_path.is_symlink() or not overlay_path.is_file()):
        raise RuntimeError("persisted overlay evidence missing or unsafe; refusing to finish")
    if (digest(overlay_path)!=persist_binding["overlay_sha256"] or
            digest(overlay_path)!=record["overlay_sha256"]):
        raise RuntimeError("persisted overlay evidence changed; refusing to finish")


def finish_cleanup(media,attempt,checkpoint_sha,original_apply_sha,record,before,rows_now,
                   terminal,done,rollback_record,completed,rollback_exists,completed_exists):
    if read_policy(rows_now, include_billing="billing_enabled" in before["policy"])!=before["policy"]: raise RuntimeError("managed policy changed since the verified recovery")
    routes=json.loads(run(["ip","-j","route","show","default"]))
    if len(routes)!=1: raise RuntimeError("finish requires a unique default interface")
    interface=routes[0]["dev"]
    if interface!=record["interface"]:
        raise RuntimeError("default interface differs from the verified recovery; refusing to finish")
    iptables_chain="JJDDEV"+hashlib.sha256(media.name.encode()).hexdigest()[:10].upper()
    if iptables_chain!=record["iptables_chain"]:
        raise RuntimeError("fence chain identity differs from the verified recovery; refusing to finish")
    command_log=Path(attempt)/"apply.log"
    audit=ROLLBACK_AUDIT.get()
    audit_path=Path(attempt)/"subprocess.jsonl"
    # 统一出口：无论 cleanup 成功、失败、readback 失败、记录写失败还是幂等早返，
    # 审计都按本次 collector 的真实顺序落盘。缺了它，最需要证据的失败时刻
    # 反而没有 argv/exit —— 那正是 r6 之前的真实缺陷。
    try:
        if isinstance(audit,AuditCollector):
            audit.flush(audit_path)
        residual=verify_fence_identity(record,attempt,run(["iptables-save"]))
        completed=Path(attempt)/"completed.json"
        # 完成记录必须安全无 symlink，否则「已完成」判断可被重定向伪造。
        if completed.is_symlink():
            raise RuntimeError("completion record is a symbolic link; refusing to finish")
        # 二次幂等：completed 已存在且绑定同一个 checkpoint pin，说明收尾已完成。
        # 幂等绝不依赖改 immutable checkpoint —— 只读它、只重验现场。
        if completed_exists:
            if residual!=FENCE_CLEARED:
                raise RuntimeError("completion record conflicts with fence residue")
            if not rollback_exists:
                write_json(rollback_record,terminal)
                return "completed"
            return "already-completed"
        try:
            if residual==FENCE_LINKED:
                # 提交点已过（运行态已核实并已封存 checkpoint），这里只补齐解封，
                # 不 recreate、不改 pointer、不执行任何 SQL。
                run(["iptables","-D","DOCKER-USER","-i",interface,"-j",iptables_chain])
                residual=verify_fence_identity(record,attempt,run(["iptables-save"]))
            if residual in (FENCE_UNLINKED_RULES,FENCE_UNLINKED_EMPTY):
                # -D 已成功、ingress 已开放：只剩清链，绝不重跑 -D。
                if residual==FENCE_UNLINKED_RULES:
                    run(["iptables","-F",iptables_chain])
                    residual=verify_fence_identity(record,attempt,run(["iptables-save"]))
                if residual==FENCE_UNLINKED_EMPTY:
                    run(["iptables","-X",iptables_chain])
                    residual=verify_fence_identity(record,attempt,run(["iptables-save"]))
            elif residual==FENCE_UNKNOWN:
                # 读回失败或有 foreign 规则/引用：既不能推断仍隔离，也不能推断已开放。
                # 零盲清 —— 拒绝改任何规则，把判断交回人工。
                raise RuntimeError("fence residue could not be read back (unknown); refusing to finish")
        except BaseException as error:
            # -D/-F/-X 或 readback 的任何异常都记录实际 ingress 状态与真实 argv/exit；
            # readback 失败本身也是 unknown，不写成「仍隔离」。
            actual=read_fence_residual(iptables_chain,interface)
            try:
                write_json(Path(attempt)/"finish-failure.json",
                           {"status":"cleanup_pending","release_id":media.name,
                            "failure_type":type(error).__name__,"failure_message":str(error)[:1500],
                            "ingress":ingress_state_of(actual),
                            "fence_residual":actual,
                            "checkpoint_sha256":checkpoint_sha,
                            "note":"ingress 依 iptables-save 实测；open 表示 -D 已成功、入口已开放"})
            except BaseException: pass
            raise RuntimeError("development rollback cleanup pending; ingress residue: "+actual
                               +"; inspect protected finish evidence") from None
        if residual!=FENCE_CLEARED:
            try:
                write_json(Path(attempt)/"finish-failure.json",
                           {"status":"cleanup_pending","release_id":media.name,
                            "failure_type":"RuntimeError",
                            "failure_message":"finish did not reach a cleared state",
                            "ingress":ingress_state_of(residual),
                            "fence_residual":residual,"checkpoint_sha256":checkpoint_sha})
            except BaseException: pass
            raise RuntimeError("finish did not reach a cleared fence state; residue: "+residual)
        if not rollback_exists: write_json(rollback_record,terminal)
        safe_append(command_log,(datetime.datetime.now(datetime.timezone.utc).isoformat()+" ROLLBACK-FINISH "+media.name+chr(10)).encode())
        if not completed_exists: write_json(completed,done)
    finally:
        # 审计落盘失败绝不能被当成成功：让它向上抛，成功输出就不会被执行。
        if isinstance(audit,AuditCollector):
            audit.flush(audit_path)
    return "completed"


def read_policy(rows, include_billing=False):
    postgres=rows["postgres"]
    env=dict(item.split("=",1) for item in postgres["Config"]["Env"] if "=" in item)
    keys = "'security_audit_only','file_content_dlp_enabled'"
    if include_billing: keys += ",'billing_enabled'"
    query="SELECT coalesce(json_object_agg(key,value),'{}'::json)::text FROM system_settings WHERE key IN ("+keys+");"
    return json.loads(run(["docker","exec","-i",postgres["Id"],"psql","-X","-At","-v","ON_ERROR_STOP=1",
                           "-U",env["POSTGRES_USER"],"-d",env["POSTGRES_DB"]],input=query))

def configure_installation_owner(uid, gid):
    if uid is not None or gid is not None:
        if (uid is None or gid is None or
                str(uid)!=os.environ.get("SUDO_UID") or str(gid)!=os.environ.get("SUDO_GID") or
                pwd.getpwuid(uid).pw_name!=os.environ.get("SUDO_USER") or
                pwd.getpwuid(uid).pw_gid!=gid):
            raise RuntimeError("installation owner must be the authenticated sudo caller")
        INSTALL_OWNER.set((uid,gid))


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("stage","apply","persist-boot","rollback","finish-rollback"))
    parser.add_argument("--media",required=True)
    parser.add_argument("--manifest-sha256",required=True)
    parser.add_argument("--receipt-sha256",required=False)
    parser.add_argument("--resume-fenced-rollback",action="store_true")
    parser.add_argument("--rollback-attempt")
    parser.add_argument("--original-apply-sha256")
    parser.add_argument("--checkpoint-sha256")
    parser.add_argument("--checkpoint-ack",action="store_true")
    parser.add_argument("--finish-pending",action="store_true")
    parser.add_argument("--install-owner-uid",type=int)
    parser.add_argument("--install-owner-gid",type=int)
    args=parser.parse_args()
    if (args.checkpoint_ack or args.finish_pending) and args.action!="rollback": raise RuntimeError("checkpoint acknowledgement and finish-pending require rollback")
    if args.action not in ("rollback","finish-rollback") and (args.resume_fenced_rollback or args.rollback_attempt or args.original_apply_sha256 or args.checkpoint_sha256):
        raise RuntimeError("recovery arguments require rollback")
    if os.geteuid()!=0:raise RuntimeError("requires VM root")
    configure_installation_owner(args.install_owner_uid,args.install_owner_gid)
    media = Path(args.media).resolve()
    if args.action=="persist-boot":
        if not args.receipt_sha256: raise RuntimeError("persist-boot requires --receipt-sha256")
        perform_persist_boot(media,args.manifest_sha256,args.receipt_sha256); return
    if args.action=="finish-rollback":
        if not args.receipt_sha256: raise RuntimeError("finish-rollback requires --receipt-sha256")
        if args.resume_fenced_rollback: raise RuntimeError("finish-rollback does not re-enter the recovery path")
        if not args.rollback_attempt: raise RuntimeError("finish-rollback requires --rollback-attempt")
        if not args.original_apply_sha256: raise RuntimeError("finish-rollback requires --original-apply-sha256")
        if not args.checkpoint_sha256: raise RuntimeError("finish-rollback requires --checkpoint-sha256")
        perform_rollback_finish(media,args.manifest_sha256,args.receipt_sha256,args.rollback_attempt,
                                args.original_apply_sha256,args.checkpoint_sha256); return
    if args.action=="rollback":
        if not args.receipt_sha256: raise RuntimeError("rollback requires --receipt-sha256")
        if args.checkpoint_sha256: raise RuntimeError("checkpoint pin belongs to finish-rollback only")
        perform_rollback(media,args.manifest_sha256,args.receipt_sha256,args.resume_fenced_rollback,
                         args.rollback_attempt,args.original_apply_sha256,args.checkpoint_ack,args.finish_pending); return
    if digest(media/"manifest.json") != args.manifest_sha256: raise RuntimeError("manifest hash differs")
    manifest = json.loads((media/"manifest.json").read_text())
    if manifest.get("console_only"):
        if (media/"__pycache__").exists() or list(media.glob("*.pyc")):
            raise RuntimeError("unexpected cached release code")
        if digest(media/"vm_console_release.py") != manifest["console_script_sha256"]:
            raise RuntimeError("console release script differs")
        # Console helpers must share this entry's authenticated owner context.
        entry_module = sys.modules.get(__name__)
        if entry_module is None or entry_module.__dict__ is not globals():
            raise RuntimeError("console entry module identity differs")
        existing_module = sys.modules.get("vm_development_apply")
        if existing_module is not None and existing_module is not entry_module:
            raise RuntimeError("console entry module alias differs")
        existing_console = sys.modules.get("vm_console_release")
        if existing_console is not None and getattr(existing_console, "vm", None) is not entry_module:
            raise RuntimeError("console imported module identity differs")
        sys.modules["vm_development_apply"] = entry_module
        from vm_console_release import ConsoleRelease
        if sys.modules["vm_console_release"].vm is not entry_module:
            raise RuntimeError("console imported module identity differs")
        release = ConsoleRelease(media, args.manifest_sha256)
        if args.action == "stage": release.stage()
        else: release.apply()
        return
    if manifest.get("security_engine_only"):
        if (media/"__pycache__").exists() or list(media.glob("*.pyc")):
            raise RuntimeError("unexpected cached release code")
        if digest(media/"vm_security_engine_release.py") != manifest["security_engine_script_sha256"]:
            raise RuntimeError("security-engine release script differs")
        from vm_security_engine_release import SecurityEngineRelease
        release = SecurityEngineRelease(media, args.manifest_sha256)
        if args.action == "stage": release.stage()
        else: release.apply()
        return
    release=Release(args.media,args.manifest_sha256)
    if args.action=="stage":release.stage()
    else:perform(release)
if __name__=="__main__":main()
