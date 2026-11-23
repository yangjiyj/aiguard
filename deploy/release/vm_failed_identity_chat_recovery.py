#!/usr/bin/env python3
"""Recover an authenticated failed identity/chat apply while preserving its ingress fence."""
import argparse, ast, contextlib, copy, datetime, hashlib, importlib.util, json, os, re, shlex, stat, subprocess, sys, time, pwd
from pathlib import Path
from decimal import Decimal

vm=None
RECOVERY_OPERATOR=None
INSTALLED_INPUT_ARTIFACTS={}
ERROR="identity-chat non-target identity or runtime changed"
RESTORE_TIMEOUT=3600
RESTORE_FAILURE="identity-chat runtime contract changed"
RESTORE_LAUNCHER='umask 077; set -C; printf "%s\\n" "$$" > "$1" || exit 73; shift; exec "$@"'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pinned(path, expected=None):
    data=vm.safe_read(path,private=True)
    if expected is not None and (not re.fullmatch(r"[0-9a-f]{64}",expected) or sha(data)!=expected):
        raise RuntimeError("failed-apply recovery evidence pin differs")
    return data

def stage_bindings(media):
    state=media/"state"
    result={name:sha(pinned(state/name)) for name in vm.STAGE_BINDING_FILES}
    index=json.loads(pinned(state/"compose-snapshots.json"))
    if not isinstance(index,dict) or not index:
        raise RuntimeError("failed-apply compose snapshot index missing")
    for live,name in index.items():
        if not isinstance(name,str) or Path(name).name!=name or name in (".",".."):
            raise RuntimeError("failed-apply compose snapshot escapes state")
        result["snapshot:"+live]=sha(pinned(state/"original-compose"/name))
    result["apply.log"]=sha(pinned(media/"apply.log"))
    return result

def stage_digest(media):
    return sha(json.dumps(stage_bindings(Path(media)),sort_keys=True,separators=(",",":")).encode())

@contextlib.contextmanager
def installed_artifact_parent(path,before=None,checksum=None,parent_bound=False,expected_parent=None):
    """Allow only the authenticated Compose artifact's exact private bin parent."""
    path=Path(os.path.abspath(path))
    workdir=Path(os.path.abspath(before["live"])).parent.parent if before is not None else None
    permitted=(RECOVERY_OPERATOR is not None and workdir is not None and
               workdir.is_relative_to(vm.ROOT/"releases") and path==workdir/"bin/docker-compose" and
               isinstance(checksum,str) and re.fullmatch(r"[0-9a-f]{64}",checksum) and
               before.get("compose_sha256",{}).get(str(path))==checksum)
    if not permitted:
        with vm.safe_parent(path) as value:yield value
        return
    owner=vm.INSTALL_OWNER.get();allowed={0,os.geteuid()}|({owner[0]} if owner else set())
    descriptors=[os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)];links=[];directory=Path("/")
    def check(directory,info,initial=None):
        if directory!=workdir/"bin" or info.st_uid in allowed:
            vm.verify_directory_fd(directory,info)
        elif (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid<=0 or info.st_gid<=0):
            raise RuntimeError("original artifact bin directory protection differs")
        if directory==workdir/"bin":
            metadata=installed_artifact_metadata(info)
            if initial is not None and metadata!=initial:raise RuntimeError("original artifact bin directory changed while authenticating")
            if parent_bound and expected_parent is not None and metadata!=expected_parent:
                raise RuntimeError("original artifact bin directory differs from authenticated metadata")
            if parent_bound and expected_parent is None and info.st_uid not in allowed:
                raise RuntimeError("unexpected creator-owned artifact bin directory")
    def verify():
        for parent,name,child,directory,initial in links:
            check(directory,os.fstat(child),initial)
            if vm.fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=vm.fd_identity(os.fstat(child)):
                raise RuntimeError("artifact parent path identity changed")
    try:
        for name in path.parent.parts[1:]:
            directory=directory/name;parent=descriptors[-1]
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);descriptors.append(child)
            info=os.fstat(child);check(directory,info)
            links.append((parent,name,child,directory,installed_artifact_metadata(info) if directory==workdir/"bin" else None))
        verify();yield descriptors[-1],path.name,verify;verify()
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)


def installed_read(path,private=False,input_binding=None):
    path=Path(os.path.abspath(path))
    if not path.is_relative_to(vm.ROOT/"releases"):
        raise RuntimeError("failed-apply installed file escapes installation")
    owner=vm.INSTALL_OWNER.get()
    allowed={os.geteuid()}|({owner[0]} if owner else set())
    artifact=INSTALLED_INPUT_ARTIFACTS.get(str(path)) if input_binding is not None else None
    if artifact is not None and input_binding.get("compose_sha256",{}).get(str(path))!=artifact["sha256"]:
        raise RuntimeError("installed artifact does not match the authenticated stage scope")
    with installed_artifact_parent(path,input_binding,artifact["sha256"] if artifact else None,parent_bound=True,expected_parent=artifact.get("parent") if artifact else None) as (parent,name,verify):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            before=os.fstat(fd);verify()
            authenticated_legacy=(artifact is not None and installed_artifact_metadata(before)==artifact["metadata"])
            if (not stat.S_ISREG(before.st_mode) or (before.st_uid not in allowed and not authenticated_legacy) or before.st_nlink!=1 or
                    before.st_mode & 0o022 or (private and stat.S_IMODE(before.st_mode)!=0o600) or
                    vm.fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=vm.fd_identity(before)):
                raise RuntimeError("failed-apply installed file protection differs")
            with os.fdopen(os.dup(fd),"rb") as stream:data=stream.read()
            after=os.fstat(fd);verify()
            if (vm.written_identity(before)!=vm.written_identity(after) or
                    vm.fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=vm.fd_identity(after)):
                raise RuntimeError("failed-apply installed file changed while authenticating")
            if authenticated_legacy and sha(data)!=artifact["sha256"]:
                raise RuntimeError("authenticated installed input differs from pinned stage bytes")
            return data
        finally:
            os.close(fd)

def configure_recovery_operator(uid,gid):
    global RECOVERY_OPERATOR
    if uid is None and gid is None:return
    if (uid is None or gid is None or uid<=0 or gid<=0 or str(uid)!=os.environ.get("SUDO_UID") or
            str(gid)!=os.environ.get("SUDO_GID")):
        raise RuntimeError("recovery operator requires an authenticated sudo caller")
    account=pwd.getpwuid(uid)
    if account.pw_name!=os.environ.get("SUDO_USER") or account.pw_gid!=gid:
        raise RuntimeError("recovery operator account differs from authenticated sudo caller")
    RECOVERY_OPERATOR=(uid,gid,account.pw_name)

def installed_artifact_metadata(info):
    return {"uid":info.st_uid,"gid":info.st_gid,"mode":stat.S_IMODE(info.st_mode),"dev":info.st_dev,
            "inode":info.st_ino,"links":info.st_nlink,"size":info.st_size,"mtime_ns":info.st_mtime_ns,"ctime_ns":info.st_ctime_ns}


def bind_installed_artifacts(media,home,before):
    global INSTALLED_INPUT_ARTIFACTS
    INSTALLED_INPUT_ARTIFACTS={}
    workdir=Path(os.path.abspath(before["live"])).parent.parent
    if workdir==vm.ROOT/"releases" or not workdir.is_relative_to(vm.ROOT/"releases"):
        raise RuntimeError("installed artifact release scope differs")
    index=json.loads(pinned(media/"state/compose-snapshots.json"));artifacts={}
    for path,mode in ((workdir/"docker-compose.offline.yml",0o600),(workdir/"bin/docker-compose",0o700)):
        checksum=before.get("compose_sha256",{}).get(str(path))
        if checksum is None:continue
        snapshot=index.get(str(path))
        if not isinstance(snapshot,str) or Path(snapshot).name!=snapshot or snapshot in (".",".."):
            raise RuntimeError("installed artifact original snapshot scope differs")
        original=media/"state/original-compose"/snapshot
        source=pinned(original)
        if sha(source)!=checksum:raise RuntimeError("installed artifact root snapshot differs from original stage")
        with installed_artifact_parent(path,before,checksum) as (parent,name,verify):
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                info=os.fstat(descriptor);verify()
                if info.st_uid==os.geteuid():continue
                owner=vm.INSTALL_OWNER.get()
                if owner and info.st_uid==owner[0]:continue
                if RECOVERY_OPERATOR is None:raise RuntimeError("non-root artifact input requires authenticated recovery operator")
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=mode or info.st_nlink!=1 or
                        vm.fd_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=vm.fd_identity(info)):
                    raise RuntimeError("original installed artifact protection differs")
                with os.fdopen(os.dup(descriptor),"rb") as stream:data=stream.read()
                after=os.fstat(descriptor);verify()
                if installed_artifact_metadata(info)!=installed_artifact_metadata(after) or data!=source:
                    raise RuntimeError("original installed artifact changed or differs from root snapshot")
                parent_info=os.fstat(parent);base_allowed={0,os.geteuid()}|({owner[0]} if owner else set())
                creator_parent=None
                if parent_info.st_uid not in base_allowed:
                    if (path!=workdir/"bin/docker-compose" or parent_info.st_uid!=info.st_uid or parent_info.st_gid!=info.st_gid or
                            stat.S_IMODE(parent_info.st_mode)!=0o700):
                        raise RuntimeError("artifact parent identity is not bound to its authenticated creator")
                    creator_parent=installed_artifact_metadata(parent_info)
                artifacts[str(path)]={"sha256":checksum,"metadata":installed_artifact_metadata(info),"snapshot":str(original),"parent":creator_parent}
            finally:os.close(descriptor)
    if artifacts:
        record={"schema":1,"operator":{"uid":RECOVERY_OPERATOR[0],"gid":RECOVERY_OPERATOR[1],"name":RECOVERY_OPERATOR[2]},"artifacts":artifacts}
        saved=home/"authenticated-installed-artifacts.json"
        if saved.exists() or saved.is_symlink():
            if json.loads(pinned(saved))!=record:raise RuntimeError("installed artifact identity changed after authentication")
        else:vm.write_json(saved,record)
    INSTALLED_INPUT_ARTIFACTS=artifacts


def root_owned_compose(home,binary,before):
    artifact=INSTALLED_INPUT_ARTIFACTS.get(str(binary))
    if artifact is None:return binary
    source=pinned(Path(artifact["snapshot"]))
    if sha(source)!=before["compose_sha256"][str(binary)]:raise RuntimeError("original Compose snapshot changed")
    executable=home/"original-compose-executable"
    with vm.safe_parent(executable) as (parent,name,verify):
        try:descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:
            descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700,dir_fd=parent)
            with os.fdopen(descriptor,"wb") as stream:stream.write(source);stream.flush();os.fsync(stream.fileno())
            os.fsync(parent)
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            info=vm.verify_file_fd(descriptor,parent,name,private=False);verify()
            if stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError("recovery Compose executable mode differs")
            with os.fdopen(os.dup(descriptor),"rb") as stream:data=stream.read()
            if data!=source:raise RuntimeError("recovery Compose executable differs from root snapshot")
            vm.verify_file_fd(descriptor,parent,name,private=False);verify()
        finally:os.close(descriptor)
    return executable


def private_digest(path):
    with vm.safe_parent(path) as (parent,name,verify):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            before=vm.verify_file_fd(fd,parent,name,private=True);verify()
            with os.fdopen(os.dup(fd),"rb") as stream:
                value=hashlib.file_digest(stream,"sha256").hexdigest()
            after=vm.verify_file_fd(fd,parent,name,private=True);verify()
            if vm.written_identity(before)!=vm.written_identity(after):
                raise RuntimeError("failed-apply backup changed while authenticating")
            return value,before.st_size
        finally:
            os.close(fd)

def authenticate(media,manifest_pin,failure_pin,stage_pin,original_pin,revision,helper_pin,validator_pin):
    media=Path(os.path.abspath(media))
    if media.parent!=vm.ROOT/"development-releases" or not re.fullmatch(r"dev-[A-Za-z0-9-]+",media.name):
        raise RuntimeError("failed-apply recovery media escapes its scope")
    if not re.fullmatch(r"[0-9a-f]{40}",revision):
        raise RuntimeError("failed-apply recovery source revision invalid")
    home=media.parent/"failed-apply-recoveries"/(media.name+"-"+revision[:12])
    if Path(__file__)!=home/"vm_failed_identity_chat_recovery.py":
        raise RuntimeError("recovery must use a separately installed authenticated helper")
    pinned(Path(__file__),helper_pin)
    pinned(home/"vm_development_apply.py",validator_pin)
    m=json.loads(pinned(media/"manifest.json",manifest_pin))
    if (m.get("schema")!=1 or type(m.get("schema")) is not int or m.get("identity_chat_only") is not True or m.get("purpose")!="development-vm" or
            m.get("release_id")!=media.name or type(m.get("include_proxy_server",False)) is not bool or
            vm.release_service_sets(m)[0]!=(vm.IDENTITY_CHAT_SERVICES+(("proxy-server",) if m.get("include_proxy_server") else ()))):
        raise RuntimeError("failed-apply recovery requires a governed identity service scope")
    if m.get("apply_script_sha256")!=original_pin:
        raise RuntimeError("original failed-apply helper pin differs")
    pinned(media/"vm_development_apply.py",original_pin)
    if (media/"receipt.json").exists() or (media/"receipt.json").is_symlink() or (media/"rollback.json").exists() or (media/"rollback.json").is_symlink():
        raise RuntimeError("failed-apply recovery cannot replace a deployment or rollback receipt")
    failure=json.loads(pinned(media/"failure.json",failure_pin))
    if (failure.get("status")!="apply_failed" or failure.get("release_id")!=media.name or
            failure.get("rollback")!="incomplete" or failure.get("ingress")!="fenced" or failure.get("failure_type")!="RuntimeError"):
        raise RuntimeError("failed-apply recovery failure scope differs")
    directory_failure=workdir_contract_failure(failure)
    if m.get("include_proxy_server") and not directory_failure:
        raise RuntimeError("six-service recovery only permits authenticated working-directory repair")
    if not timeout_failure(failure) and not directory_failure and not (failure.get("restore_failure_type")=="RuntimeError" and
            failure.get("failure_message")==ERROR and failure.get("restore_failure_message")==ERROR):
        raise RuntimeError("failed-apply recovery failure scope differs")
    actual_stage=stage_digest(media)
    if stage_pin is not None and (not re.fullmatch(r"[0-9a-f]{64}",stage_pin) or actual_stage!=stage_pin):
        raise RuntimeError("failed-apply stage evidence changed")
    before=json.loads(pinned(media/"state/before.json"))
    if "identity_chat_runtime" not in before:
        raise RuntimeError("failed-apply original identity evidence missing")
    events=pinned(media/"apply.log").decode().splitlines()
    markers=("FENCED application ingress","STOP application writers","BACKUP validated",
             "MIGRATE reviewed pending files","SWITCH to fixed candidate image IDs",
             "VERIFY runtime health, image identities and policies","ROLLBACK while ingress remains fenced")
    position=-1
    for marker in markers:
        matches=[i for i,line in enumerate(events) if i>position and line.endswith(marker)]
        if not matches:
            raise RuntimeError("failed-apply authorised writer transition evidence missing")
        position=matches[0]
    return media,home,m,before,actual_stage

# Closed historical model validator copied from the governed console release.
def historical_require(condition, message):
    if not condition:
        raise RuntimeError(message)

def historical_object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def historical_duration_ns(value):
    historical_require(isinstance(value, str), "unsupported Compose duration")
    units = {"ns": 1, "us": 1000, "\u00b5s": 1000, "ms": 1000000, "s": 1000000000, "m": 60000000000, "h": 3600000000000}
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|\u00b5s|ms|s|m|h)", value)
    historical_require(parts and "".join(number+unit for number, unit in parts) == value, "invalid Compose duration")
    return sum(int(Decimal(number)*units[unit]) for number, unit in parts)

def validate_historical_target(service, item, model, row, image, daemon_logging):
    config, defaults = row["Config"], image["Config"]
    supported = {"image", "pull_policy", "environment", "entrypoint", "command", "user", "working_dir", "stop_signal",
                 "tty", "stdin_open", "read_only", "privileged", "security_opt", "cap_add", "cap_drop", "restart",
                 "volumes", "tmpfs", "ports", "networks", "healthcheck", "labels", "expose", "depends_on", "container_name", "logging", "profiles", "extra_hosts"}
    historical_require(set(item) <= supported, "unsupported historical target runtime fields")
    environment = dict(v.split("=", 1) for v in defaults.get("Env") or [] if "=" in v)
    for key, value in item.get("environment", {}).items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = str(value)
    actual = dict(v.split("=", 1) for v in config.get("Env") or [] if "=" in v)
    historical_require(actual == environment, "target environment cannot be restored from historical model")
    # compose 对未声明 entrypoint/command 的服务渲染出显式 null 键；按 compose
    # 语义 null = 使用镜像默认值（与 compose up 创建现有容器的方式一致），因此
    # 与键缺失同样回落到镜像默认值。显式非 null 值仍走严格相等，两者皆空仍 fail-closed。
    entrypoint = (item["entrypoint"] if item.get("entrypoint") is not None else defaults.get("Entrypoint")) or []
    command = (item["command"] if item.get("command") is not None else defaults.get("Cmd")) or []
    historical_require(isinstance(entrypoint, list) and isinstance(command, list) and entrypoint+command,
            "unsupported historical target command")
    argv = entrypoint+command
    historical_require(row.get("Path") == argv[0] and row.get("Args", []) == argv[1:], "target command differs from historical model")
    historical_require((config.get("Entrypoint") or []) == entrypoint and (config.get("Cmd") or []) == command,
            "target command configuration differs from historical model")
    for key, field, fallback in (("user", "User", ""), ("working_dir", "WorkingDir", ""), ("stop_signal", "StopSignal", "")):
        historical_require((config.get(field) or fallback) == (item.get(key, defaults.get(field)) or fallback),
                "target runtime scalar differs from historical model: "+key)
    for key, field in (("tty", "Tty"), ("stdin_open", "OpenStdin")):
        historical_require(bool(config.get(field)) == bool(item.get(key, False)), "target interactive runtime differs")
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
                health[field] = historical_duration_ns(declared_health[key])
        if "retries" in declared_health:
            health["Retries"] = declared_health["retries"]
    actual_health = config.get("Healthcheck") or {}
    normalize_health = lambda value: {key: item for key, item in value.items() if item not in (None, 0, "", [])}
    historical_require(normalize_health(actual_health) == normalize_health(health), "target healthcheck differs from historical model")
    labels = dict(defaults.get("Labels") or {})
    labels.update(item.get("labels") or {})
    actual_labels = {key: value for key, value in (config.get("Labels") or {}).items() if not key.startswith("com.docker.compose.")}
    historical_require(actual_labels == {key: value for key, value in labels.items() if not key.startswith("com.docker.compose.")},
            "target user/image labels differ from historical model")
    if item.get("container_name"):
        historical_require(row["Name"].lstrip("/") == item["container_name"], "target container name differs")
    host = row.get("HostConfig") or {}
    logging = item.get("logging") or {}
    actual_logging = host.get("LogConfig") or {}
    historical_require(set(logging) <= {"driver", "options"} and set(actual_logging) <= {"Type", "Config"}, "unsupported target logging fields")
    driver, options = actual_logging.get("Type", ""), actual_logging.get("Config") or {}
    if driver:
        # 模型未声明 logging 时，compose up 创建的容器落到 daemon 默认 driver
        # （空 options）；仅当容器 driver 等于 daemon 默认且 options 为空才接受，
        # 其余情况仍要求与模型显式冻结值严格相等（fail-closed）。
        historical_require((not logging and not options and driver == daemon_logging) or
                (logging.get("driver") == driver and (logging.get("options") or {}) == options),
                "effective target logging is not explicitly frozen in historical model")
    else:
        historical_require(not logging and not options, "target logging differs from historical model")
    historical_require(sorted_historical_hosts(host.get("ExtraHosts") or []) == sorted_historical_hosts(item.get("extra_hosts") or []), "target extra_hosts differs from frozen model")
    historical_require(isinstance(item.get("profiles", []), list) and all(isinstance(value, str) and value for value in item.get("profiles", [])), "invalid frozen target profiles")
    forbidden_host = ("Devices", "DeviceCgroupRules", "DeviceRequests", "VolumesFrom", "Links", "Dns", "DnsSearch", "DnsOptions",
                      "Ulimits", "GroupAdd", "Sysctls", "StorageOpt", "VolumeDriver", "CgroupParent", "CpuShares", "CpuPeriod", "CpuQuota",
                      "CpuRealtimePeriod", "CpuRealtimeRuntime", "NanoCpus", "CpuCount", "CpuPercent", "CpusetCpus", "CpusetMems",
                      "Memory", "MemoryReservation", "MemorySwap", "KernelMemory", "BlkioWeight", "BlkioWeightDevice",
                      "BlkioDeviceReadBps", "BlkioDeviceWriteBps", "BlkioDeviceReadIOps", "BlkioDeviceWriteIOps", "PidsLimit", "OomKillDisable", "OomScoreAdj")
    for field in forbidden_host:
        historical_require(host.get(field) in (None, False, 0, "", [], {}), "unsupported target host runtime: "+field)
    for field, allowed in (("PidMode", (None, "")), ("UTSMode", (None, "")), ("UsernsMode", (None, "")),
                           ("IpcMode", (None, "", "private")), ("CgroupnsMode", (None, "", "private")), ("Runtime", (None, "", "runc"))):
        historical_require(host.get(field) in allowed, "unsupported target host namespace/runtime: "+field)
    historical_require(host.get("MemorySwappiness") in (None, -1), "unsupported target swappiness")
    historical_require(host.get("ShmSize") in (None, 0, 64*1024*1024) and not host.get("AutoRemove") and not host.get("PublishAllPorts"),
            "unsupported target host allocation")
    for key, field in (("read_only", "ReadonlyRootfs"), ("privileged", "Privileged")):
        historical_require(bool(host.get(field)) == bool(item.get(key, False)), "target host security differs")
    for key, field in (("security_opt", "SecurityOpt"), ("cap_add", "CapAdd"), ("cap_drop", "CapDrop")):
        historical_require(sorted(host.get(field) or []) == sorted(item.get(key) or []), "target host security list differs")
    restart = item.get("restart", "no")
    name, _, retries = restart.partition(":")
    policy = host.get("RestartPolicy") or {}
    historical_require(policy.get("Name", "no") == name and policy.get("MaximumRetryCount", 0) == (int(retries) if retries else 0),
            "target restart policy differs")
    declared = {}
    for volume in item.get("volumes") or []:
        historical_require(volume.get("type") in ("bind", "volume"), "unsupported target mount type")
        target = volume["target"]
        historical_require(target not in declared, "ambiguous target mount")
        source = volume.get("source")
        if volume["type"] == "volume":
            historical_require(source and source in model.get("volumes", {}), "anonymous target volume cannot be frozen")
            source = model["volumes"][source]["name"]
        propagation = (volume.get("bind") or {}).get("propagation", "rprivate") if volume["type"] == "bind" else ""
        historical_require(propagation in ("", "private", "rprivate", "shared", "rshared", "slave", "rslave"), "unsupported target mount propagation")
        declared[target] = (volume["type"], source, not volume.get("read_only", False), propagation)
    mounted = {}
    for volume in row.get("Mounts") or []:
        if volume.get("Type") == "tmpfs":
            historical_require(volume["Destination"] in host.get("Tmpfs", {}), "unexpected target tmpfs mount")
            continue
        target = volume["Destination"]
        historical_require(target not in mounted, "ambiguous runtime mount")
        mounted[target] = (volume.get("Type"), volume.get("Name") if volume.get("Type") == "volume" else volume.get("Source"),
                           volume.get("RW"), volume.get("Propagation") or "")
    historical_require(mounted == declared, "target mount differs from historical model")
    tmpfs = dict(value.split(":", 1) if ":" in value else (value, "") for value in item.get("tmpfs") or [])
    historical_require((host.get("Tmpfs") or {}) == tmpfs, "target tmpfs options differ")
    bindings = {}
    for port in item.get("ports") or []:
        historical_require(port.get("published") and port.get("protocol", "tcp") in ("tcp", "udp"), "unfixed target port")
        key = str(port["target"])+"/"+port.get("protocol", "tcp")
        bindings.setdefault(key, []).append(dict(HostIp=port.get("host_ip", ""), HostPort=str(port["published"])))
    exposed = set(defaults.get("ExposedPorts") or {})|set(bindings)
    for value in item.get("expose") or []:
        exposed.add(str(value) if "/" in str(value) else str(value)+"/tcp")
    historical_require(set(config.get("ExposedPorts") or {}) == exposed, "target exposed ports differ")
    normalize = lambda values: {key: sorted(value or [], key=historical_object_hash) for key, value in values.items()}
    historical_require(normalize(host.get("PortBindings") or {}) == normalize(bindings), "target port bindings differ")
    networks = {}
    for name, options in item.get("networks", {}).items():
        historical_require(name in model.get("networks", {}), "target network definition absent")
        network = model["networks"][name].get("name", name)
        networks[network] = options or {}
    actual_networks = row.get("NetworkSettings", {}).get("Networks") or {}
    historical_require(set(actual_networks) == set(networks), "target network membership differs")
    for name, options in networks.items():
        value = actual_networks[name]
        aliases = {v for v in value.get("Aliases") or [] if v not in (row["Id"], row["Id"][:12])}
        expected = {service, row["Name"].lstrip("/"), *(options.get("aliases") or [])}
        historical_require(aliases == expected, "target network aliases differ")
        requested = {key: options[field] for key, field in (("IPv4Address", "ipv4_address"), ("IPv6Address", "ipv6_address")) if options.get(field)}
        # Docker/Compose may materialize empty address fields for dynamic endpoints.
        # Normalize only these two empty strings; static addresses and all other
        # IPAM options must still match the declared model exactly.
        actual_ipam = {key: item for key, item in (value.get("IPAMConfig") or {}).items()
                       if not (key in ("IPv4Address", "IPv6Address") and item == "")}
        historical_require(actual_ipam == requested, "target network IPAM differs")

def sorted_historical_hosts(value):
    pairs=list(value.items()) if isinstance(value,dict) else []
    if not isinstance(value,(list,dict)):raise RuntimeError("invalid frozen extra_hosts")
    if isinstance(value,list):
        for item in value:
            if not isinstance(item,str):raise RuntimeError("invalid frozen extra_hosts entry")
            match=re.fullmatch(r"([^:=\s]+)[:=](.+)",item)
            if not match:raise RuntimeError("invalid frozen extra_hosts entry")
            pairs.append((match[1],match[2]))
    if any(not isinstance(key,str) or not isinstance(item,str) or not key or not item for key,item in pairs) or len({key for key,_ in pairs})!=len(pairs):
        raise RuntimeError("ambiguous frozen extra_hosts")
    return sorted(pairs)


def verify_legacy_target_contracts(media,rows,before):
    model=json.loads(pinned(media/"state/rollback.json"))
    daemon_logging=vm.run(["docker","info","--format","{{.LoggingDriver}}"],timeout=30).strip()
    proof={}
    for service in vm.IDENTITY_CHAT_SERVICES:
        row=rows[service]
        if row["Image"]!=before["runtime"][service]["image"]:raise RuntimeError("legacy target image differs")
        image=json.loads(vm.run(["docker","image","inspect",row["Image"]]))
        manifest=json.loads(pinned(media/"manifest.json"))
        if len(image)!=1 or vm.portable_image_id(image[0])!=manifest["services"][service]["base_image_id"]:raise RuntimeError("legacy target image configuration differs")
        labels=row["Config"].get("Labels") or {}
        if labels.get("com.docker.compose.project")!=before["project"] or labels.get("com.docker.compose.service")!=service:
            raise RuntimeError("legacy target Compose ownership differs")
        if labels.get("com.docker.compose.project.working_dir")!=str(Path(before["live"]).parent.parent):
            raise RuntimeError("legacy target Compose working directory differs")
        validate_historical_target(service,model["services"][service],model,row,image[0],daemon_logging)
        proof[service]={"model_sha256":historical_object_hash(model["services"][service]),
                        "image_config_sha256":historical_object_hash(image[0].get("Config")),
                        "runtime_contract_sha256":vm.identity_chat_contract_hash(row,True)}
    return proof


def workdir_contract_failure(failure):
    return (failure.get("failure_type")=="RuntimeError" and failure.get("restore_failure_type")=="RuntimeError"
            and failure.get("failure_message")==RESTORE_FAILURE and failure.get("restore_failure_message")==RESTORE_FAILURE)


def plan_restored_workdir_repairs(rows,m,before):
    vm.validate_identity_chat_contract_witness(before)
    services,_=vm.release_service_sets(m)
    workdir=Path(before["live"]).parent.parent
    witness=before["identity_chat_contract_witness"]["containers"]
    policy=before["identity_chat_runtime"].get("mount_policy")
    plan=[]
    for service in services:
        row=rows[service];original=before["identity_chat_runtime"]["runtime"][service]
        if row["Image"]!=original["image"] or row["RestartCount"]!=0:
            raise RuntimeError("working-directory repair requires the original image and zero restarts")
        expected=witness[original["id"]]["contract"]
        actual=vm.identity_chat_runtime_contract(row,True,policy)
        if actual==expected:continue
        key="com.docker.compose.project.working_dir"
        old=expected.get("config",{}).get("Labels",{}).get(key)
        current=actual.get("config",{}).get("Labels",{}).get(key)
        # This repair only reverses the known parent-vs-active-config creator bug.
        if old!=str(workdir/"active-config") or current!=str(workdir):
            raise RuntimeError("working-directory repair is outside the frozen parent/active-config transition")
        projected=copy.deepcopy(actual);projected["config"]["Labels"][key]=old
        if projected!=expected:
            raise RuntimeError("working-directory repair found another runtime contract change")
        plan.append({"service":service,"directory":old,"before_contract":original["contract"]})
    return plan


def repair_restored_workdirs(media,home,m,before):
    # No database replay: authenticate the completed restore from the frozen apply.
    failure=json.loads(pinned(media/"failure.json"))
    if not workdir_contract_failure(failure):return
    no_restore_processes()
    rows=vm.inspect_runtime()
    if set(rows)!=set(before["runtime"]) or any(row["State"]["Status"]!="running" or
            row["State"].get("Health",{}).get("Status","none") not in ("healthy","none") for row in rows.values()):
        raise RuntimeError("working-directory repair requires a healthy restored runtime")
    attempts=[json.loads(pinned(path)) for path in (media/"state").glob("restore-attempt-*.json")]
    completed=[item for item in attempts if item.get("status")=="database_restored" and item.get("exit_code")==0]
    if len(attempts)!=1 or len(completed)!=1:
        raise RuntimeError("working-directory repair requires one completed authenticated database restore")
    attempt=completed[0]
    if not re.fullmatch(r"jjdguard-restore-[0-9a-f]{32}",attempt.get("application_name","")):
        raise RuntimeError("working-directory restore application identity invalid")
    nonce=attempt["application_name"].removeprefix("jjdguard-restore-")
    env=dict(value.split("=",1) for value in rows["postgres"]["Config"].get("Env",[]) if "=" in value)
    expected=["pg_restore","--clean","--if-exists","--create","--exit-on-error","-U",env["POSTGRES_USER"],"-d","postgres"]
    process=attempt.get("process",{})
    if (attempt.get("stderr_file")!="pg-restore-"+nonce+".stderr.log" or process.get("phase")!="restore" or
            process.get("argv_sha256")!=sha(json.dumps(expected,separators=(",",":")).encode())):
        raise RuntimeError("completed restore command or private evidence identity differs")
    stderr=media/"state"/attempt["stderr_file"]
    if stderr.parent!=media/"state" or sha(pinned(stderr))!=attempt.get("stderr_sha256"):
        raise RuntimeError("working-directory completed restore stderr differs")
    backup=json.loads(pinned(media/"state/backup.json"));checksum,size=private_digest(media/"state/database.dump")
    if backup!={"sha256":checksum,"size":size}:raise RuntimeError("completed restore backup differs")
    if vm.read_migration_ledger(rows)!=before["ledger"] or vm.read_policy(rows,include_billing=True)!=before["policy"]:
        raise RuntimeError("working-directory restored database policy or ledger differs")
    if installed_read(Path(before["live"]))!=pinned(media/"state/rollback.json"):
        raise RuntimeError("working-directory original live model differs")
    plan=plan_restored_workdir_repairs(rows,m,before)
    projected=copy.deepcopy(rows)
    for item in plan:projected[item["service"]]["Config"]["Labels"]["com.docker.compose.project.working_dir"]=item["directory"]
    vm.verify_identity_chat_snapshot(before["identity_chat_runtime"],vm.identity_chat_snapshot(projected,m),m,replaced=True,resumed=True,rollback=True)
    vm.write_json(home/"working-directory-repair-plan.json",{"repairs":plan,"restore_attempt":attempt})
    for item in plan:
        compose_original(home,before,"up","-d","--no-deps","--pull","never","--force-recreate",item["service"],project_directory=Path(item["directory"]))
    deadline=time.monotonic()+180
    while True:
        current=vm.inspect_runtime()
        if set(current)==set(rows) and all(row["State"].get("Status")=="running" and row["State"].get("Health",{}).get("Status","none") in ("healthy","none") for row in current.values()):break
        if time.monotonic()>=deadline:raise RuntimeError("working-directory repaired runtime did not become healthy")
        time.sleep(2)
    verify_restored(media,m,before)
    vm.write_json(home/"working-directory-repair-complete.json",{"repairs":plan,"database_replayed":False})


def verify_restored_identity(media,rows,m,before,snapshot):
    expected=before["identity_chat_runtime"]
    if timeout_failure(json.loads(pinned(media/"failure.json"))):
        verify_legacy_target_contracts(media,rows,before)
        # The old opaque hashes are never rewritten. Only these five targets
        # use the independent frozen-model/image validator above; every preserved
        # runtime and inventory entry still uses its original opaque identity.
        expected=copy.deepcopy(expected)
        for service in vm.IDENTITY_CHAT_SERVICES:
            expected["runtime"][service]["contract"]=snapshot["runtime"][service]["contract"]
    vm.verify_identity_chat_snapshot(expected,snapshot,m,replaced=True,resumed=True,rollback=True)

def verify_restored(media,m,before):
    rows=vm.inspect_runtime()
    if set(rows)!=set(before["runtime"]):
        raise RuntimeError("failed-apply restored service set differs")
    if any(row["State"].get("Status")!="running" or
           row["State"].get("Health",{}).get("Status","none") not in ("healthy","none")
           for row in rows.values()):
        raise RuntimeError("failed-apply restored runtime is unhealthy")
    snapshot=vm.identity_chat_snapshot(rows,m)
    verify_restored_identity(media,rows,m,before,snapshot)
    if vm.read_migration_ledger(rows)!=before["ledger"] or vm.read_policy(rows,include_billing=True)!=before["policy"]:
        raise RuntimeError("failed-apply restored migration ledger or policy differs")
    env=vm.staged_env_file(before)
    if sha(installed_read(env,private=True))!=before["env_sha256"]:
        raise RuntimeError("failed-apply original environment changed")
    index=json.loads(pinned(media/"state/compose-snapshots.json"))
    if set(index)!=set(before["compose_sha256"]):
        raise RuntimeError("failed-apply original compose scope differs")
    for path,checksum in before["compose_sha256"].items():
        installed=Path(path)
        if not installed.is_relative_to(vm.ROOT/"releases"):
            raise RuntimeError("failed-apply original compose escapes installation")
        if sha(installed_read(installed,input_binding=before))!=checksum or sha(pinned(media/"state/original-compose"/index[path]))!=checksum:
            raise RuntimeError("failed-apply original compose changed")
    live=Path(before["live"])
    if live.parent.name!="active-config" or not live.is_relative_to(vm.ROOT/"releases"):
        raise RuntimeError("failed-apply live configuration escapes installation")
    if installed_read(live)!=pinned(media/"state/rollback.json"):
        raise RuntimeError("failed-apply original live configuration differs")
    previous=json.loads(pinned(media/"state/previous-current.json"))
    pointer=media.parent/"current.json"
    if previous is None:
        if pointer.exists() or pointer.is_symlink():
            raise RuntimeError("failed-apply original release pointer differs")
    elif not isinstance(previous,str) or pinned(pointer)!=previous.encode():
        raise RuntimeError("failed-apply original release pointer differs")
    backup=json.loads(pinned(media/"state/backup.json"))
    checksum,size=private_digest(media/"state/database.dump")
    if backup!={"sha256":checksum,"size":size}:
        raise RuntimeError("failed-apply protected database backup differs")
    return rows,snapshot

def timeout_failure(failure):
    if failure.get("restore_failure_type")!="TimeoutExpired" or failure.get("failure_message")!=RESTORE_FAILURE:
        return False
    match=re.fullmatch(r"Command '(.+)' timed out after ([0-9]+(?:\.[0-9]+)?) seconds",failure.get("restore_failure_message",""))
    if not match or not 299<=float(match[2])<=301:return False
    try:command=ast.literal_eval(match[1])
    except (ValueError,SyntaxError):return False
    return (isinstance(command,list) and len(command)==13 and command[:3]==["docker","exec","-i"] and
            re.fullmatch(r"[0-9a-f]{64}",command[3]) is not None and
            command[4:11]==["pg_restore","--clean","--if-exists","--create","--exit-on-error","-U",command[10]] and
            isinstance(command[10],str) and bool(command[10]) and command[11:]==["-d","postgres"])


def is_restore_executable(argv):
    if not argv:return False
    name=Path(argv[0]).name
    if name=="pg_restore":return True
    if name.startswith("python"):
        for value in argv[1:]:
            if value in ("-c","-m"):return False
            if not value.startswith("-"):return Path(value).name=="vm_development_apply.py"
    if name=="docker" and "exec" in argv:
        items=argv[argv.index("exec")+1:];index=0
        while index<len(items) and items[index].startswith("-"):
            index+=2 if items[index] in ("-e","--env","-u","--user","-w","--workdir") else 1
        return index+1<len(items) and is_restore_executable(items[index+1:])
    if name in ("sh","bash","ash") and len(argv)>2 and argv[1]=="-c":
        try:items=shlex.split(argv[2])
        except ValueError:return True
        if items and items[0]=="exec":items=items[1:]
        return is_restore_executable(items)
    return False


def no_restore_processes():
    for folder in Path("/proc").iterdir():
        if not folder.name.isdigit() or int(folder.name)==os.getpid():continue
        try:argv=[value.decode(errors="replace") for value in (folder/"cmdline").read_bytes().split(b"\0") if value]
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
        if is_restore_executable(argv):
            raise RuntimeError("another apply or pg_restore process exists; ingress stays fenced")


def database_quiescent(rows):
    pg=rows["postgres"]
    env=dict(item.split("=",1) for item in pg["Config"].get("Env",[]) if "=" in item)
    database=env["POSTGRES_DB"];user=env["POSTGRES_USER"]
    if database in ("postgres","template0","template1"):raise RuntimeError("invalid restore application database")
    escaped=database.replace("'","''")
    query=("SELECT json_build_object('clients',(SELECT count(*) FROM pg_stat_activity WHERE datname='"+escaped+
           "' AND backend_type='client backend' AND pid<>pg_backend_pid()),'prepared',(SELECT count(*) FROM pg_prepared_xacts))::text;")
    view=json.loads(vm.run(["docker","exec","-i",pg["Id"],"psql","-X","-At","-v","ON_ERROR_STOP=1","-U",user,"-d","postgres"],input=query,timeout=60))
    if view!={"clients":0,"prepared":0}:raise RuntimeError("database clients or prepared transactions remain; ingress stays fenced")
    return pg["Id"],user,database


def restore_inputs(media,m,before):
    env=vm.staged_env_file(before)
    if sha(installed_read(env,private=True))!=before["env_sha256"]:raise RuntimeError("failed-apply original environment changed")
    index=json.loads(pinned(media/"state/compose-snapshots.json"))
    if set(index)!=set(before["compose_sha256"]):raise RuntimeError("failed-apply original compose scope differs")
    for path,checksum in before["compose_sha256"].items():
        if sha(installed_read(Path(path),input_binding=before))!=checksum or sha(pinned(media/"state/original-compose"/index[path]))!=checksum:
            raise RuntimeError("failed-apply original compose changed")
    previous=json.loads(pinned(media/"state/previous-current.json"));pointer=media.parent/"current.json"
    if previous is None:
        if pointer.exists() or pointer.is_symlink():raise RuntimeError("failed-apply original release pointer differs")
    elif not isinstance(previous,str) or pinned(pointer)!=previous.encode():raise RuntimeError("failed-apply original release pointer differs")
    backup=json.loads(pinned(media/"state/backup.json"));checksum,size=private_digest(media/"state/database.dump")
    if backup!={"sha256":checksum,"size":size}:raise RuntimeError("failed-apply protected database backup differs")
    live=Path(before["live"])
    if live.parent.name!="active-config" or not live.is_relative_to(vm.ROOT/"releases"):
        raise RuntimeError("failed-apply live configuration escapes installation")
    live_bytes=installed_read(live)
    if live_bytes not in (pinned(media/"state/candidate.json"),pinned(media/"state/rollback.json")):
        raise RuntimeError("failed-apply installed live configuration differs from frozen state")
    rollback=json.loads(pinned(media/"state/rollback.json"))
    if not isinstance(rollback.get("services"),dict) or not set(before["runtime"])<=set(rollback["services"]):
        raise RuntimeError("failed-apply rollback compose service scope differs")
    for name,row in before["runtime"].items():
        if rollback["services"][name].get("image")!=row["image"]:raise RuntimeError("failed-apply rollback image is not the pinned original")
    for name in vm.IDENTITY_CHAT_SERVICES:
        image=json.loads(vm.run(["docker","image","inspect",before["runtime"][name]["image"]]))
        if len(image)!=1 or vm.portable_image_id(image[0])!=m["services"][name]["base_image_id"]:
            raise RuntimeError("failed-apply original image config pin differs")
    return backup


def inspect_stopped_runtime(before):
    identifiers=vm.run(["docker","ps","-a","-q"]).split()
    objects=json.loads(vm.run(["docker","inspect",*identifiers])) if identifiers else []
    rows={}
    for row in objects:
        labels=row.get("Config",{}).get("Labels") or {}
        name=labels.get("com.docker.compose.service")
        if labels.get("com.docker.compose.project")!=before["project"]:continue
        if name not in before["runtime"]:raise RuntimeError("failed-apply project service inventory changed")
        if name in rows:raise RuntimeError("failed-apply duplicate project service containers")
        rows[name]=row
    if set(rows)!=set(before["runtime"]):raise RuntimeError("failed-apply stopped service inventory incomplete")
    return rows


def stopped_restore_scope(rows,m,before):
    if set(rows)!=set(before["runtime"]):raise RuntimeError("failed-apply restore service set differs")
    writers,restarted=vm.release_writer_sets(m,rows,vm.IDENTITY_CHAT_SERVICES)
    if any(rows[name]["State"].get("Status")!="exited" or rows[name]["State"].get("Running") is True for name in writers):
        raise RuntimeError("failed-apply restore requires all authenticated writers stopped")
    current=vm.identity_chat_snapshot(rows,m)
    expected=before["identity_chat_runtime"]
    # Candidate containers are stopped and never executed by recovery. Only the
    # five manifest-scoped containers may be replaced from the pinned old model.
    for name in vm.IDENTITY_CHAT_SERVICES:
        row=rows[name];labels=row["Config"].get("Labels") or {}
        candidate_expected=m["services"][name].get("portable_image_id",m["services"][name]["image_id"])
        image=json.loads(vm.run(["docker","image","inspect",row["Image"]]))
        allowed=(row["Image"]==before["runtime"][name]["image"] or
                 len(image)==1 and vm.portable_image_id(image[0])==candidate_expected)
        if not allowed or row["RestartCount"]!=0 or labels.get("com.docker.compose.project")!=before["project"] or labels.get("com.docker.compose.service")!=name:
            raise RuntimeError("failed-apply stopped target identity differs")
    def paused(value,name,reference=False):
        result=copy.deepcopy(value)
        if name in writers:
            result["status"]=expected["runtime"][name]["status"]
            result["health"]=expected["runtime"][name]["health"]
        if name in restarted:
            # Authenticated SWITCH/VERIFY/ROLLBACK markers prove the original
            # switch explicitly resumed these same preserved writers.
            if vm.docker_started_at_ns(value["started_at"])<vm.docker_started_at_ns(expected["runtime"][name]["started_at"]):
                raise RuntimeError("preserved writer StartedAt moved backwards")
            if not reference and value.get("restarts")!=0:
                raise RuntimeError("preserved writer automatically restarted")
            result.pop("started_at",None);result["restarts"]=0
        result.pop("candidate_contract",None)
        return result
    for name,value in expected["runtime"].items():
        if name not in vm.IDENTITY_CHAT_SERVICES and paused(current["runtime"][name],name)!=paused(value,name,True):
            raise RuntimeError("failed-apply preserved runtime changed before restore")
    if set(current["inventory"])!=set(expected["inventory"]):raise RuntimeError("failed-apply preserved inventory changed before restore")
    by_id={value["id"]:name for name,value in expected["runtime"].items()}
    for identifier,value in expected["inventory"].items():
        name=by_id.get(identifier)
        if paused(current["inventory"][identifier],name)!=paused(value,name,True):raise RuntimeError("failed-apply preserved inventory contract changed")
    return writers


def compose_original(home,before,*args,project_directory=None):
    live=Path(before["live"]);workdir=live.parent.parent;binary=workdir/"bin/docker-compose"
    if str(binary) not in before["compose_sha256"]:raise RuntimeError("failed-apply original Compose executable is not pinned")
    if sha(installed_read(binary,input_binding=before))!=before["compose_sha256"][str(binary)]:
        raise RuntimeError("failed-apply original Compose executable changed before execution")
    binary=root_owned_compose(home,binary,before)
    directory=workdir if project_directory is None else Path(project_directory)
    if directory not in (workdir,live.parent) or directory.resolve()!=directory:
        raise RuntimeError("failed-apply Compose directory escapes authenticated original directories")
    return vm.run([str(binary),"--project-directory",str(directory),"-p",before["project"],"-f",str(live),*args],timeout=300,log=home/"restore.log")


def process_identity(pg,pid,expected,marker=None):
    if not re.fullmatch(r"[1-9][0-9]*",str(pid)):raise RuntimeError("restore process PID is invalid")
    raw=vm.run(["docker","exec",pg,"cat","/proc/"+str(pid)+"/cmdline"],timeout=30)
    argv=raw.rstrip("\0").split("\0")
    info=vm.run(["docker","exec",pg,"cat","/proc/"+str(pid)+"/stat"],timeout=30)
    fields=info[info.rfind(")")+2:].split()
    restoring=bool(argv) and Path(argv[0]).name=="pg_restore" and argv[1:]==expected[1:]
    starting=bool(argv) and marker is not None and Path(argv[0]).name in ("sh","ash") and argv[1:]==["-c",RESTORE_LAUNCHER,"--",marker,*expected]
    if not (restoring or starting) or len(fields)<20:
        raise RuntimeError("restore process identity differs; no signal sent")
    return {"pid":int(pid),"start_time":fields[19],"phase":"restore" if restoring else "starting","argv_sha256":sha(json.dumps(argv,separators=(",",":")).encode())}


def stop_restore_process(pg,identity,expected,marker=None):
    for sig in ("TERM","KILL"):
        try:actual=process_identity(pg,str(identity["pid"]),expected,marker)
        except vm.CommandFailure:return
        if any(actual[key]!=identity[key] for key in ("pid","start_time")):raise RuntimeError("restore process PID was reused; no signal sent")
        vm.run(["docker","exec",pg,"kill","-"+sig,str(identity["pid"])],timeout=30)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            try:actual=process_identity(pg,str(identity["pid"]),expected,marker)
            except vm.CommandFailure:return
            if any(actual[key]!=identity[key] for key in ("pid","start_time")):raise RuntimeError("restore process PID was reused; no signal sent")
            time.sleep(.25)
    raise RuntimeError("authenticated restore process did not exit; ingress stays fenced")


def run_full_restore(media,home,rows,backup,binding):
    pg,user,_=database_quiescent(rows)
    nonce=os.urandom(16).hex();marker="/tmp/jjdguard-recovery-"+nonce+".pid"
    appname="jjdguard-recovery-"+nonce
    expected=["pg_restore","--clean","--if-exists","--create","--exit-on-error","-U",user,"-d","postgres"]
    argv=["docker","exec","-i","-e","PGAPPNAME="+appname,pg,"sh","-c",
          RESTORE_LAUNCHER,"--",marker,*expected]
    log=home/("pg-restore-"+nonce+".stderr.log")
    vm.authenticate_write_paths([log,home/("restore-attempt-"+nonce+".json")])
    identity=None;process=None;result={"binding":binding,"backup":backup,"application_name":appname,"stderr_file":log.name,"timeout_seconds":RESTORE_TIMEOUT}
    with vm.safe_parent(media/"state/database.dump") as (parent,name,verify):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            original=vm.verify_file_fd(fd,parent,name,private=True);verify()
            with os.fdopen(os.dup(fd),"rb") as source,os.fdopen(os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),"wb") as error_log:
                process=subprocess.Popen(argv,stdin=source,stdout=subprocess.DEVNULL,stderr=error_log)
                started=time.monotonic();deadline=started+RESTORE_TIMEOUT;last_progress=started
                print("FULL_RESTORE_STARTED timeout_seconds="+str(RESTORE_TIMEOUT)+" stderr="+str(log),flush=True)
                try:
                    while process.poll() is None:
                        if identity is None or identity.get("phase")=="starting":
                            try:
                                pid=vm.run(["docker","exec",pg,"cat",marker],timeout=10).strip()
                                identity=process_identity(pg,pid,expected,marker)
                                result["process"]=identity
                            except vm.CommandFailure:pass
                        now=time.monotonic();remaining=deadline-now
                        if (identity is None or identity.get("phase")=="starting") and now-started>30:
                            raise RuntimeError("authenticated pg_restore did not start within deadline")
                        if now-last_progress>=30:
                            print("FULL_RESTORE_RUNNING elapsed_seconds="+str(int(now-started)),flush=True);last_progress=now
                        if remaining<=0:raise subprocess.TimeoutExpired("authenticated pg_restore",RESTORE_TIMEOUT)
                        try:process.wait(timeout=min(5,remaining))
                        except subprocess.TimeoutExpired:pass
                    error_log.flush();os.fsync(error_log.fileno())
                    if process.returncode!=0:raise RuntimeError("full pg_restore failed; inspect protected stderr log")
                    result["exit_code"]=0
                except BaseException as error:
                    cleanup_error=None
                    try:
                        if identity is None and process.poll() is None:
                            try:identity=process_identity(pg,vm.run(["docker","exec",pg,"cat",marker],timeout=10).strip(),expected,marker)
                            except vm.CommandFailure:pass
                        if identity is not None:stop_restore_process(pg,identity,expected,marker)
                    except BaseException as cleanup:cleanup_error=type(cleanup).__name__
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:process.wait(timeout=10)
                            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
                    result.update(status="failed",failure_type=type(error).__name__,exit_code=process.returncode,cleanup_failure_type=cleanup_error)
                    vm.write_json(home/("restore-attempt-"+nonce+".json"),result)
                    raise
            after=vm.verify_file_fd(fd,parent,name,private=True);verify()
            if vm.written_identity(original)!=vm.written_identity(after):raise RuntimeError("backup changed while restoring")
        finally:os.close(fd)
    if private_digest(media/"state/database.dump")!=(backup["sha256"],backup["size"]):raise RuntimeError("backup changed while restoring")
    no_restore_processes();database_quiescent(rows)
    result.update(status="database_restored",stderr_sha256=sha(pinned(log)))
    vm.write_json(home/("restore-attempt-"+nonce+".json"),result)
    return result


DATABASE_RESUME_FIELDS={"revision","helper_sha256","validator_sha256","database_sha256","attempt_sha256","firewall_sha256","audit_sha256"}
RUNTIME_RESUME_FIELDS={"revision","helper_sha256","validator_sha256","database_sha256","firewall_sha256","audit_sha256","resume_proof_sha256"}

def validate_database_resume_proof(proof):
    if (not isinstance(proof,dict) or set(proof) not in (DATABASE_RESUME_FIELDS,DATABASE_RESUME_FIELDS|{"runtime"}) or
            not isinstance(proof.get("revision"),str) or not re.fullmatch(r"[0-9a-f]{40}",proof["revision"]) or
            any(not isinstance(proof.get(key),str) or not re.fullmatch(r"[0-9a-f]{64}",proof[key]) for key in DATABASE_RESUME_FIELDS-{"revision"})):
        raise RuntimeError("database resume requires complete external evidence pins")
    if "runtime" in proof:
        runtime=proof["runtime"]
        if (not isinstance(runtime,dict) or set(runtime)!=RUNTIME_RESUME_FIELDS or
                not isinstance(runtime.get("revision"),str) or not re.fullmatch(r"[0-9a-f]{40}",runtime["revision"]) or
                any(not isinstance(runtime.get(key),str) or not re.fullmatch(r"[0-9a-f]{64}",runtime[key]) for key in RUNTIME_RESUME_FIELDS-{"revision"})):
            raise RuntimeError("runtime resume requires complete external evidence pins")
    return proof


def authenticated_running_audit(raw,before,prior,writers):
    records=[json.loads(line) for line in raw.decode().splitlines()]
    if not records or not isinstance(records[-1],dict):raise RuntimeError("prior recovery audit missing")
    invocation=records[-1].get("invocation")
    if not isinstance(invocation,str) or not re.fullmatch(r"[0-9a-f]{32}",invocation):raise RuntimeError("prior recovery audit invocation invalid")
    active=[record for record in records if isinstance(record,dict) and record.get("invocation")==invocation]
    if [record.get("sequence") for record in active]!=list(range(len(active))):raise RuntimeError("prior recovery audit sequence differs")
    successful=lambda record,argv:record.get("phase")=="exit" and type(record.get("returncode")) is int and record["returncode"]==0 and record.get("argv")==argv and isinstance(record.get("stdout"),str)
    saves=[(index,record) for index,record in enumerate(active) if successful(record,["iptables-save"])]
    if not saves:raise RuntimeError("prior running firewall audit missing")
    position,record=saves[-1];firewall=record["stdout"].strip()
    workdir=Path(before["live"]).parent.parent
    stop=[str(prior/"original-compose-executable"),"--project-directory",str(workdir),"-p",before["project"],"-f",before["live"],"stop","--timeout","25",*writers]
    tail=active[position+1:]
    if len(tail)!=2 or tail[0].get("phase")!="start" or tail[0].get("argv")!=stop or not successful(tail[1],stop):
        raise RuntimeError("prior failed firewall verification did not stop the exact original writers")
    inspections=[record for record in active[:position] if isinstance(record.get("argv"),list) and record["argv"][:2]==["docker","inspect"] and successful(record,record["argv"])]
    if not inspections:raise RuntimeError("prior running container audit missing")
    objects=json.loads(inspections[-1]["stdout"]);rows={}
    if not isinstance(objects,list):raise RuntimeError("prior running container audit differs")
    for row in objects:
        labels=row.get("Config",{}).get("Labels") or {};name=labels.get("com.docker.compose.service")
        if labels.get("com.docker.compose.project")!=before["project"]:continue
        if name not in before["runtime"] or name in rows:raise RuntimeError("prior running project inventory differs")
        if row.get("State",{}).get("Status")!="running" or row.get("State",{}).get("Health",{}).get("Status","none") not in ("healthy","none"):
            raise RuntimeError("prior restored runtime was not healthy")
        rows[name]=row
    if set(rows)!=set(before["runtime"]):raise RuntimeError("prior running project inventory incomplete")
    return firewall,rows


def resume_writer_order(firewall,rows,writers):
    table=None;rules=[]
    for line in firewall.splitlines():
        if line.startswith("*"):table=line[1:]
        elif line=="COMMIT":table=None
        elif table=="raw" and line.startswith("-A "):rules.append(shlex.split(line))
    order=[]
    for name in writers:
        networks=rows[name].get("NetworkSettings",{}).get("Networks") or {}
        if not isinstance(networks,dict) or not networks:raise RuntimeError("prior writer bridge membership is missing")
        positions=[]
        for endpoint in networks.values():
            if not isinstance(endpoint,dict):raise RuntimeError("prior writer endpoint identity missing")
            address=endpoint.get("IPAddress");network=endpoint.get("NetworkID")
            if (not isinstance(address,str) or not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}",address) or
                    not isinstance(network,str) or not re.fullmatch(r"[0-9a-f]{64}",network)):
                raise RuntimeError("prior writer endpoint identity missing")
            expected=["-A","PREROUTING","-d",address+"/32","!","-i","br-"+network[:12],"-j","DROP"]
            positions.extend(index for index,rule in enumerate(rules) if rule==expected)
        if len(positions)!=1:raise RuntimeError("prior writer endpoint rule is absent or ambiguous")
        order.append((positions[0],name))
    if len({position for position,name in order})!=len(order):raise RuntimeError("prior writer endpoints overlap")
    return [name for position,name in sorted(order)]


def authenticate_database_resume(media,home,m,before,binding,rows,backup,proof,firewall,chain,interface,writers):
    proof=validate_database_resume_proof(proof)
    prior=media.parent/"failed-apply-recoveries"/(media.name+"-"+proof["revision"][:12])
    if prior==home:raise RuntimeError("database resume requires a distinct immutable prior recovery")
    info=prior.stat()
    if prior.is_symlink() or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise RuntimeError("prior recovery directory must be owned mode 700")
    pinned(prior/"vm_failed_identity_chat_recovery.py",proof["helper_sha256"])
    pinned(prior/"vm_development_apply.py",proof["validator_sha256"])
    database_bytes=pinned(prior/"database-restore-complete.json",proof["database_sha256"])
    database=json.loads(database_bytes)
    expected_binding={**binding,"recovery_revision":proof["revision"],"recovery_helper_sha256":proof["helper_sha256"],"validator_sha256":proof["validator_sha256"]}
    if (not isinstance(database,dict) or database.get("binding")!=expected_binding or database.get("backup")!=backup or
            database.get("status")!="database_restored" or type(database.get("exit_code")) is not int or database["exit_code"]!=0 or
            database.get("timeout_seconds")!=RESTORE_TIMEOUT):
        raise RuntimeError("prior database completion is not bound to this restore")
    match=re.fullmatch(r"jjdguard-recovery-([0-9a-f]{32})",database.get("application_name", ""))
    if not match or database.get("stderr_file")!="pg-restore-"+match[1]+".stderr.log":raise RuntimeError("prior restore attempt identity differs")
    attempt=json.loads(pinned(prior/("restore-attempt-"+match[1]+".json"),proof["attempt_sha256"]))
    if attempt!=database:raise RuntimeError("prior restore attempt does not prove completion")
    if not isinstance(database.get("stderr_sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",database["stderr_sha256"]):
        raise RuntimeError("prior restore stderr pin missing")
    pinned(prior/database["stderr_file"],database["stderr_sha256"])
    old_firewall=pinned(prior/"restore-fence-before.txt",proof["firewall_sha256"]).decode()
    vm.authenticated_fence(old_firewall,chain,interface)
    if vm.unrelated_fence_identity(old_firewall,chain,interface)!=vm.unrelated_fence_identity(firewall,chain,interface):
        raise RuntimeError("stopped recovery firewall changed since completed restore")
    expected_firewall,old_rows=authenticated_running_audit(pinned(prior/"subprocess.jsonl",proof["audit_sha256"]),before,prior,writers)
    vm.authenticated_fence(expected_firewall,chain,interface)
    if "runtime" in proof:
        runtime=proof["runtime"]
        recent=media.parent/"failed-apply-recoveries"/(media.name+"-"+runtime["revision"][:12])
        if recent in (home,prior):raise RuntimeError("runtime resume requires a distinct immutable recovery")
        info=recent.stat()
        if recent.is_symlink() or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise RuntimeError("recent runtime recovery directory must be owned mode 700")
        pinned(recent/"vm_failed_identity_chat_recovery.py",runtime["helper_sha256"])
        pinned(recent/"vm_development_apply.py",runtime["validator_sha256"])
        if pinned(recent/"database-restore-complete.json",runtime["database_sha256"])!=database_bytes:
            raise RuntimeError("recent runtime database completion differs from original successful restore")
        saved_proof=validate_database_resume_proof(json.loads(pinned(recent/"database-resume-proof.json",runtime["resume_proof_sha256"])))
        if {key:saved_proof[key] for key in DATABASE_RESUME_FIELDS}!={key:proof[key] for key in DATABASE_RESUME_FIELDS}:
            raise RuntimeError("recent runtime recovery used a different database completion proof")
        recent_firewall=pinned(recent/"restore-fence-before.txt",runtime["firewall_sha256"]).decode()
        vm.authenticated_fence(recent_firewall,chain,interface)
        if vm.unrelated_fence_identity(recent_firewall,chain,interface)!=vm.unrelated_fence_identity(firewall,chain,interface):
            raise RuntimeError("stopped firewall changed since recent runtime recovery")
        expected_firewall,old_rows=authenticated_running_audit(pinned(recent/"subprocess.jsonl",runtime["audit_sha256"]),before,recent,writers)
        vm.authenticated_fence(expected_firewall,chain,interface)
    for name,row in rows.items():
        old=old_rows[name]
        if (row["Id"]!=old["Id"] or row["Image"]!=old["Image"] or row["RestartCount"]!=old["RestartCount"] or
                vm.identity_chat_contract_hash(row)!=vm.identity_chat_contract_hash(old) or row["State"]["StartedAt"]!=old["State"]["StartedAt"]):
            raise RuntimeError("prior restored container changed before database resume")
    verify_legacy_target_contracts(media,rows,before)
    if vm.read_migration_ledger(rows)!=before["ledger"] or vm.read_policy(rows,include_billing=True)!=before["policy"]:
        raise RuntimeError("completed restore ledger or policy changed before resume")
    return database,expected_firewall,resume_writer_order(expected_firewall,old_rows,writers)


def start_authenticated_writer(home,rows,name):
    row=rows[name];identifier=row["Id"]
    if not isinstance(identifier,str) or not re.fullmatch(r"[0-9a-f]{64}",identifier):raise RuntimeError("authenticated writer container ID invalid")
    if vm.run(["docker","start",identifier],timeout=90,log=home/"restore.log").strip()!=identifier:
        raise RuntimeError("Docker did not acknowledge the exact authenticated writer")
    deadline=time.monotonic()+120
    while True:
        objects=json.loads(vm.run(["docker","inspect",identifier],timeout=30))
        if (not isinstance(objects,list) or len(objects)!=1 or objects[0]["Id"]!=identifier or objects[0]["Image"]!=row["Image"] or
                objects[0]["RestartCount"]!=0 or vm.identity_chat_contract_hash(objects[0])!=vm.identity_chat_contract_hash(row)):
            raise RuntimeError("authenticated writer changed while starting")
        state=objects[0].get("State",{})
        if state.get("Status")=="running" and state.get("Health",{}).get("Status","none") in ("healthy","none"):return
        if state.get("Status")!="running" or time.monotonic()>=deadline:
            raise RuntimeError("authenticated writer did not become healthy without restarting")
        time.sleep(2)


def restore_timed_out_database(media,home,m,before,binding,database_resume=None):
    rows=inspect_stopped_runtime(before)
    writers=stopped_restore_scope(rows,m,before)
    backup=restore_inputs(media,m,before)
    no_restore_processes();database_quiescent(rows)
    failure=json.loads(pinned(media/"failure.json"))
    command=ast.literal_eval(re.fullmatch(r"Command '(.+)' timed out after ([0-9]+(?:\.[0-9]+)?) seconds",failure["restore_failure_message"])[1])
    env=dict(value.split("=",1) for value in rows["postgres"]["Config"].get("Env",[]) if "=" in value)
    if command[3]!=rows["postgres"]["Id"] or command[10]!=env["POSTGRES_USER"]:raise RuntimeError("timed-out restore database identity differs")
    chain="JJDDEV"+sha(media.name.encode())[:10].upper()
    interface=json.loads(vm.run(["ip","-j","route","show","default"]))[0]["dev"]
    firewall=vm.run(["iptables-save"]);vm.authenticated_fence(firewall,chain,interface)
    foreign,user_rules=vm.unrelated_fence_identity(firewall,chain,interface)
    vm.atomic_bytes(home/"restore-fence-before.txt",firewall.encode())
    if database_resume is not None:
        database,expected_firewall,start_order=authenticate_database_resume(media,home,m,before,binding,rows,backup,database_resume,firewall,chain,interface,writers)
        foreign,user_rules=vm.unrelated_fence_identity(expected_firewall,chain,interface)
        vm.write_json(home/"database-resume-proof.json",database_resume)
        vm.atomic_bytes(home/"expected-running-firewall.txt",expected_firewall.encode())
    else:
        try:database=run_full_restore(media,home,rows,backup,binding)
        except BaseException:
            compose_original(home,before,"stop","--timeout","25",*writers)
            raise
    vm.write_json(home/"database-restore-complete.json",database)
    # The frozen apply log, failure evidence and media helper are never changed.
    try:
        if vm.read_migration_ledger(rows)!=before["ledger"] or vm.read_policy(rows,include_billing=True)!=before["policy"]:
            raise RuntimeError("restored database ledger or policy differs")
        vm.atomic_bytes(Path(before["live"]),pinned(media/"state/rollback.json"))
        if database_resume is not None:
            for name in start_order:start_authenticated_writer(home,rows,name)
        else:
            compose_original(home,before,"up","-d","--no-deps","--pull","never","--force-recreate",*vm.IDENTITY_CHAT_SERVICES)
            _,other=vm.release_writer_sets(m,rows,vm.IDENTITY_CHAT_SERVICES)
            if other:compose_original(home,before,"start",*other)
        deadline=time.monotonic()+180
        while True:
            current=vm.inspect_runtime()
            if set(current)==set(before["runtime"]) and all(row["State"].get("Status")=="running" and row["State"].get("Health",{}).get("Status","none") in ("healthy","none") for row in current.values()):break
            if time.monotonic()>=deadline:raise RuntimeError("restored original runtime health deadline exceeded")
            time.sleep(2)
        verify_restored(media,m,before)
        now=vm.run(["iptables-save"]);vm.authenticated_fence(now,chain,interface)
        if vm.unrelated_fence_identity(now,chain,interface)!=(foreign,user_rules):raise RuntimeError("unrelated firewall rules changed during restore")
        vm.write_json(home/"restored-runtime-complete.json",{"binding":binding,"runtime":vm.identity_chat_snapshot(current,m),"database":database,
                    "legacy_target_contracts":verify_legacy_target_contracts(media,current,before)})
    except BaseException:
        compose_original(home,before,"stop","--timeout","25",*writers)
        raise

def perform(media,manifest_pin,failure_pin,stage_pin,original_pin,revision,helper_pin,validator_pin,checkpoint_pin=None,database_resume=None):
    audit=vm.AuditCollector()
    token=vm.ROLLBACK_AUDIT.set(audit)
    try:
        with vm.release_lock():
            media,home,m,before,actual_stage=authenticate(media,manifest_pin,failure_pin,stage_pin,original_pin,
                                                         revision,helper_pin,validator_pin)
            info=home.stat()
            if home.is_symlink() or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
                raise RuntimeError("failed-apply recovery directory must be owned mode 700")
            audit.path=home/"subprocess.jsonl"
            audit.flush(audit.path)
            bind_installed_artifacts(media,home,before)
            binding={"manifest_sha256":manifest_pin,"failure_sha256":failure_pin,"stage_sha256":actual_stage,
                     "original_apply_sha256":original_pin,"recovery_revision":revision,
                     "recovery_helper_sha256":helper_pin,"validator_sha256":validator_pin}
            if timeout_failure(json.loads(pinned(media/"failure.json"))) and not (home/"recovery-checkpoint.json").exists():
                completed=home/"restored-runtime-complete.json"
                if completed.exists() or completed.is_symlink():
                    prior=json.loads(pinned(completed))
                    if prior.get("binding")!=binding or prior.get("runtime")!=verify_restored(media,m,before)[1]:
                        raise RuntimeError("completed failed-restore runtime evidence differs")
                else:restore_timed_out_database(media,home,m,before,binding,database_resume)
            if workdir_contract_failure(json.loads(pinned(media/"failure.json"))):
                repair_restored_workdirs(media,home,m,before)
            rows,snapshot=verify_restored(media,m,before)
            chain="JJDDEV"+sha(media.name.encode())[:10].upper()
            interface=json.loads(vm.run(["ip","-j","route","show","default"]))[0]["dev"]
            checkpoint_path=home/"recovery-checkpoint.json"
            receipt_path=home/"recovery-receipt.json"
            binding={"manifest_sha256":manifest_pin,"failure_sha256":failure_pin,"stage_sha256":actual_stage,
                     "original_apply_sha256":original_pin,"recovery_revision":revision,
                     "recovery_helper_sha256":helper_pin,"validator_sha256":validator_pin}
            firewall=vm.run(["iptables-save"])
            if checkpoint_path.exists() or checkpoint_path.is_symlink():
                if checkpoint_pin is None:
                    raise RuntimeError("existing failed-apply checkpoint requires its external pin")
                checkpoint=json.loads(pinned(checkpoint_path,checkpoint_pin))
                if (checkpoint.get("binding")!=binding or checkpoint.get("release_id")!=media.name or
                        checkpoint.get("runtime")!=snapshot or checkpoint.get("interface")!=interface or
                        checkpoint.get("iptables_chain")!=chain):
                    raise RuntimeError("failed-apply recovery checkpoint identity changed")
                residual=vm.verify_fence_identity(checkpoint,home,firewall)
            else:
                if checkpoint_pin is not None:
                    raise RuntimeError("failed-apply checkpoint pin has no checkpoint")
                vm.authenticated_fence(firewall,chain,interface)
                foreign,user=vm.unrelated_fence_identity(firewall,chain,interface)
                checkpoint={"schema":3,"binding":binding,"release_id":media.name,"runtime":snapshot,
                            "interface":interface,"iptables_chain":chain,"fence_before_sha256":sha(firewall.encode()),
                            "foreign_rules_sha256":sha(json.dumps(foreign,separators=(",",":")).encode()),
                            "unrelated_user_rules_sha256":sha(json.dumps(user,separators=(",",":")).encode())}
                vm.atomic_bytes(home/"fence-before.txt",firewall.encode())
                vm.write_json(checkpoint_path,checkpoint)
                checkpoint_pin=sha(pinned(checkpoint_path))
                residual=vm.FENCE_LINKED
                print("FAILED_APPLY_RECOVERY_CHECKPOINT_SHA256="+checkpoint_pin,flush=True)
            if receipt_path.exists() or receipt_path.is_symlink():
                result=json.loads(pinned(receipt_path))
                if (residual!=vm.FENCE_CLEARED or result.get("binding")!=binding or
                        result.get("checkpoint_sha256")!=checkpoint_pin or result.get("runtime")!=snapshot or
                        result.get("status")!="restored_failed_apply"):
                    raise RuntimeError("failed-apply completed recovery receipt differs")
                return result
            # Recheck all protected pins and measured state at the detach boundary.
            authenticate(media,manifest_pin,failure_pin,stage_pin,original_pin,revision,helper_pin,validator_pin)
            if verify_restored(media,m,before)[1]!=snapshot:
                raise RuntimeError("failed-apply runtime changed before unfence")
            try:
                residual=vm.verify_fence_identity(checkpoint,home,vm.run(["iptables-save"]))
                if residual==vm.FENCE_LINKED:
                    vm.run(["iptables","-D","DOCKER-USER","-i",interface,"-j",chain])
                    residual=vm.verify_fence_identity(checkpoint,home,vm.run(["iptables-save"]))
                if residual==vm.FENCE_UNLINKED_RULES:
                    vm.run(["iptables","-F",chain])
                    residual=vm.verify_fence_identity(checkpoint,home,vm.run(["iptables-save"]))
                if residual==vm.FENCE_UNLINKED_EMPTY:
                    vm.run(["iptables","-X",chain])
                    residual=vm.verify_fence_identity(checkpoint,home,vm.run(["iptables-save"]))
                if residual!=vm.FENCE_CLEARED:
                    raise RuntimeError("failed-apply unfence residue is unrecognised")
                if verify_restored(media,m,before)[1]!=snapshot:
                    raise RuntimeError("failed-apply runtime changed during cleanup")
                authenticate(media,manifest_pin,failure_pin,stage_pin,original_pin,revision,helper_pin,validator_pin)
                result={"status":"restored_failed_apply","release_id":media.name,"binding":binding,
                        "checkpoint_sha256":checkpoint_pin,"runtime":snapshot,"migrations":before["ledger"],
                        "policy":before["policy"],"ingress":vm.FENCE_CLEARED,
                        "recorded_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
                vm.write_json(receipt_path,result)
                return result
            except BaseException:
                actual=vm.read_fence_residual(chain,interface)
                vm.write_json(home/"recovery-failure.json",{"status":"cleanup_pending","release_id":media.name,
                    "checkpoint_sha256":checkpoint_pin,"ingress":vm.ingress_state_of(actual),"fence_residual":actual})
                raise RuntimeError("failed-apply recovery cleanup incomplete; resume with pinned checkpoint") from None
    finally:
        try:
            if getattr(audit,"path",None):audit.flush(audit.path)
        finally:
            vm.ROLLBACK_AUDIT.reset(token)

def main():
    global vm
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    for flag in ("media","manifest-sha256","failure-sha256","original-apply-sha256","recovery-revision",
                 "recovery-helper-sha256","validator-sha256"):
        parser.add_argument("--"+flag,required=True)
    parser.add_argument("--stage-sha256")
    parser.add_argument("--checkpoint-sha256")
    parser.add_argument("--database-resume-proof",type=json.loads)
    parser.add_argument("--prepare",action="store_true")
    parser.add_argument("--install-owner-uid",type=int)
    parser.add_argument("--install-owner-gid",type=int)
    parser.add_argument("--recovery-operator-uid",type=int)
    parser.add_argument("--recovery-operator-gid",type=int)
    args=parser.parse_args()
    if args.database_resume_proof is not None:validate_database_resume_proof(args.database_resume_proof)
    if os.geteuid()!=0:raise RuntimeError("failed-apply recovery requires VM root")
    # The host separately installs this immutable two-file closure from gated main.
    folder=Path(__file__).parent
    for filename,pin in (("vm_failed_identity_chat_recovery.py",args.recovery_helper_sha256),
                         ("vm_development_apply.py",args.validator_sha256)):
        path=folder/filename
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise RuntimeError("recovery executable must be root-owned private regular file")
            with os.fdopen(os.dup(fd),"rb") as stream:data=stream.read()
            if sha(data)!=pin:raise RuntimeError("recovery executable source pin differs")
            if filename=="vm_development_apply.py":validator=data
        finally:os.close(fd)
    spec=importlib.util.spec_from_file_location("_jjdguard_failed_apply_validator",folder/"vm_development_apply.py")
    vm=importlib.util.module_from_spec(spec)
    exec(compile(validator,str(folder/"vm_development_apply.py"),"exec"),vm.__dict__)
    vm.configure_installation_owner(args.install_owner_uid,args.install_owner_gid)
    configure_recovery_operator(args.recovery_operator_uid,args.recovery_operator_gid)
    if args.prepare:
        media,home,manifest,before,pin=authenticate(Path(args.media),args.manifest_sha256,args.failure_sha256,None,
            args.original_apply_sha256,args.recovery_revision,args.recovery_helper_sha256,args.validator_sha256)
        bind_installed_artifacts(media,home,before)
        print("FAILED_APPLY_STAGE_SHA256="+pin,flush=True)
        return
    if not args.stage_sha256:raise RuntimeError("failed-apply recovery requires externally pinned stage")
    perform(Path(args.media),args.manifest_sha256,args.failure_sha256,args.stage_sha256,args.original_apply_sha256,
            args.recovery_revision,args.recovery_helper_sha256,args.validator_sha256,args.checkpoint_sha256,args.database_resume_proof)
    print("FAILED_APPLY_RECOVERY_RECEIPT_SHA256="+sha((folder/"recovery-receipt.json").read_bytes()),flush=True)

if __name__=="__main__":main()
