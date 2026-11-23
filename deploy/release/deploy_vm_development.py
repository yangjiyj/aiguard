#!/usr/bin/env python3
"""Transfer and apply a prevalidated development release to the fixed test VM."""
import argparse, base64, contextlib, fcntl, hashlib, http.server, inspect, json, re, secrets, subprocess, threading, time, zlib
from pathlib import Path
from build_vm_development import source_gate, digest, SERVICES, IDENTITY_CHAT_SERVICES, CONSOLE_FORBIDDEN_OVERRIDES

def qga(domain, request):
    return json.loads(subprocess.check_output(["virsh","qemu-agent-command",domain,json.dumps(request)],text=True))["return"]

def guest(domain, code, seconds=900):
    raw=code.encode("utf-8")
    if len(raw)>2*1024*1024:
        raise RuntimeError("guest bootstrap exceeds the reviewed 2 MiB limit")
    request=lambda value:{"execute":"guest-exec","arguments":{"path":"/usr/bin/python3","arg":["-u","-c",value],"capture-output":True}}
    if len(json.dumps(request(code)).encode("utf-8"))>=120*1024:
        packed=base64.b64encode(zlib.compress(raw,9)).decode("ascii")
        # Bound decompression, authenticate the exact original UTF-8 program,
        # and keep the complete QGA JSON below Linux MAX_ARG_STRLEN.
        code=("import base64,hashlib,zlib\n"
              "d=zlib.decompressobj()\n"
              "payload=d.decompress(base64.b64decode("+repr(packed)+"),"+str(len(raw)+1)+")\n"
              "if not d.eof or d.unconsumed_tail or d.unused_data or len(payload)!="+str(len(raw))+": raise RuntimeError('QGA bootstrap length differs')\n"
              "if hashlib.sha256(payload).hexdigest()!="+repr(hashlib.sha256(raw).hexdigest())+": raise RuntimeError('QGA bootstrap digest differs')\n"
              "exec(compile(payload,'<authenticated-qga-bootstrap>','exec'))\n")
    if len(json.dumps(request(code)).encode("utf-8"))>=120*1024:
        raise RuntimeError("compressed guest bootstrap exceeds the safe QGA argument limit")
    pid=qga(domain,request(code))["pid"]
    print("guest_pid="+str(pid),flush=True)
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=qga(domain,{"execute":"guest-exec-status","arguments":{"pid":pid}})
        if result.get("exited"):
            output=base64.b64decode(result.get("out-data","")).decode()
            error=base64.b64decode(result.get("err-data","")).decode()
            if output:print(output,flush=True)
            if result.get("exitcode")!=0:
                if error:print(error,flush=True)
                raise RuntimeError("guest operation failed; inspect protected release state")
            return output
        time.sleep(1)
    raise RuntimeError("guest still running pid="+str(pid)+"; inspect before retrying")

@contextlib.contextmanager
def release_lock():
    path = Path('/home/dev/.cache/jjdguard/home-release.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def rollback_recorded(args):
    repo = Path(args.repo).resolve()
    revision = subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD'],
                                      env={'PATH':'/usr/bin:/bin','HOME':'/home/dev','LANG':'C.UTF-8'}, text=True).strip()
    source_gate(repo, revision)
    if getattr(args, "rollback_identity_chat_release_id", None):
        guest(args.vm, identity_chat_rollback_guest_code(args.rollback_identity_chat_release_id, args.receipt_sha256), seconds=900)
        return
    if getattr(args, 'rollback_chat_theme_release_id', None):
        from vm_chat_theme_release import apply_guest_code
        release_id = args.rollback_chat_theme_release_id
        if not re.fullmatch(r'dev-[A-Za-z0-9-]+', release_id):
            raise RuntimeError('invalid theme rollback identity')
        pin = guest(args.vm, "import hashlib\nfrom pathlib import Path\np=Path('/opt/jjdguard/development-releases')/"+repr(release_id)+"/'manifest.json'\nprint('THEME_MANIFEST_SHA256='+hashlib.sha256(p.read_bytes()).hexdigest())\n")
        code = apply_guest_code(release_id, receipt_output_pin(pin, 'THEME_MANIFEST_SHA256='), 'rollback', args.receipt_sha256)
        guest(args.vm, code, seconds=900)
        return
    if getattr(args, 'rollback_console_release_id', None):
        from vm_console_release import rollback_guest_code
        release_id = args.rollback_console_release_id
    else:
        from vm_security_engine_release import rollback_guest_code
        release_id = args.rollback_release_id
    code = rollback_guest_code(release_id, args.receipt_sha256)
    guest(args.vm, code, seconds=900)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",required=True)
    parser.add_argument("--media")
    parser.add_argument("--rollback-release-id", help="rollback only the active recorded SE-only release")
    parser.add_argument("--rollback-console-release-id", help="只回滚活动且已固定回执的控制面/前端双服务发布")
    parser.add_argument("--rollback-identity-chat-release-id", help="rollback the active recorded identity/chat release (including explicitly selected proxy-server) without restoring the database")
    parser.add_argument("--rollback-chat-theme-release-id", help="rollback only the active theme asset release using its pinned receipt")
    parser.add_argument("--recover-failed-identity-chat-release-id", help="recover authenticated pre-receipt identity/chat failure, including full replay of a timed-out database restore")
    parser.add_argument("--checkpoint-sha256", help="external failed-apply recovery checkpoint pin for cleanup continuation")
    parser.add_argument("--database-resume-proof",type=json.loads,help="externally pinned prior complete restore evidence")
    parser.add_argument("--receipt-sha256", help="pinned SHA256 of that deployment receipt")
    parser.add_argument("--persist-boot", action="store_true", help="persist full/preserve-tier1 images in the governed jjdctl boot chain")
    parser.add_argument("--persist-only", action="store_true", help="persist an applied full release using its original media and pinned receipt")
    parser.add_argument("--vm",choices=("jjdguard-gateway",),default="jjdguard-gateway")
    args=parser.parse_args()
    if args.recover_failed_identity_chat_release_id:
        if (args.media or args.receipt_sha256 or args.persist_boot or args.persist_only or
                any((args.rollback_release_id,args.rollback_console_release_id,args.rollback_chat_theme_release_id,args.rollback_identity_chat_release_id))):
            parser.error("failed-apply recovery conflicts with deployment, persistence and recorded rollback")
        with release_lock(): recover_failed_identity_chat(args)
        return
    if args.checkpoint_sha256: parser.error("checkpoint pin requires failed identity/chat recovery")
    if args.database_resume_proof is not None:parser.error("database resume proof requires failed identity/chat recovery")
    if sum(bool(value) for value in (args.rollback_release_id, args.rollback_console_release_id, args.rollback_chat_theme_release_id, args.rollback_identity_chat_release_id)) > 1: parser.error('rollback modes conflict')
    if args.rollback_release_id or args.rollback_console_release_id or args.rollback_chat_theme_release_id or args.rollback_identity_chat_release_id:
        if args.media or not args.receipt_sha256 or args.persist_boot or args.persist_only:
            parser.error('rollback requires --receipt-sha256 and forbids media/persistence options')
        with release_lock(): rollback_recorded(args)
        return
    if args.persist_only:
        if not args.media or not args.receipt_sha256 or args.persist_boot:
            parser.error('persist-only requires --media and --receipt-sha256; it forbids --persist-boot')
        with release_lock(): persist_recorded(args)
        return
    if not args.media or args.receipt_sha256: parser.error('deployment requires --media; receipt hash is only for rollback')
    media=Path(args.media).resolve()
    manifest=json.loads((media/"manifest.json").read_text())
    with release_lock() if args.persist_boot or manifest.get('security_engine_only') or manifest.get('console_only') or manifest.get('chat_theme_only') or manifest.get('identity_chat_only') else contextlib.nullcontext():
        deploy(args, media, manifest)


def failed_identity_chat_metadata_guest_code(release_id):
    if not re.fullmatch(r"dev-[A-Za-z0-9-]+",release_id):
        raise RuntimeError("invalid failed identity/chat recovery identity")
    from vm_console_release import require, protected
    validators="\n\n".join(inspect.getsource(fn) for fn in (require,protected))
    return ("import hashlib,json,os,stat\nfrom pathlib import Path\nfrom types import SimpleNamespace\nvm=SimpleNamespace(ROOT=Path('/opt/jjdguard'))\n"+validators+"\n"
            "media=Path('/opt/jjdguard/development-releases')/"+repr(release_id)+"\nprotected(media,directory=True)\n"
            "m=protected(media/'manifest.json');f=protected(media/'failure.json');s=protected(media/'vm_development_apply.py')\n"
            "value=json.loads(m.read_text())\n"
            "require(value.get('identity_chat_only') is True and value.get('release_id')=="+repr(release_id)+",'failed recovery scope differs')\n"
            "print('FAILED_IDENTITY_CHAT_METADATA='+json.dumps({'revision':value['revision'],"
            "'manifest_sha256':hashlib.sha256(m.read_bytes()).hexdigest(),"
            "'failure_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),"
            "'original_apply_sha256':hashlib.sha256(s.read_bytes()).hexdigest()}))\n")

def failed_identity_chat_recovery_guest_code(release_id,revision,metadata,files,stage_pin=None,checkpoint=None,installed_input_password_fd=None,recovery_operator_uid=None,database_resume=None):
    full=lambda pattern,value:isinstance(value,str) and re.fullmatch(pattern,value)
    required={"manifest_sha256","failure_sha256","original_apply_sha256"}
    if (not full(r"dev-[A-Za-z0-9-]+",release_id) or not full(r"[0-9a-f]{40}",revision) or
            not isinstance(metadata,dict) or not required<=set(metadata) or set(metadata)-required-{"revision"} or
            any(not full(r"[0-9a-f]{64}",metadata[key]) for key in required) or
            (stage_pin is not None and not full(r"[0-9a-f]{64}",stage_pin)) or
            (checkpoint is not None and not full(r"[0-9a-f]{64}",checkpoint)) or
            (installed_input_password_fd is not None and (type(installed_input_password_fd) is not int or installed_input_password_fd!=0)) or
            (recovery_operator_uid is not None and (type(recovery_operator_uid) is not int or recovery_operator_uid<=0)) or
            set(files)!={"vm_development_apply.py","vm_failed_identity_chat_recovery.py"} or
            any(not isinstance(value,bytes) for value in files.values())):
        raise RuntimeError("failed-apply recovery source identity or pins invalid")
    if database_resume is not None:
        from vm_failed_identity_chat_recovery import validate_database_resume_proof
        validate_database_resume_proof(database_resume)
    from vm_console_release import require, protected, controlled_environment
    validators="\n\n".join(inspect.getsource(fn) for fn in (require,protected,controlled_environment,run_installation_helper,run_failed_recovery_helper))
    folder="/opt/jjdguard/development-releases/failed-apply-recoveries/"+release_id+"-"+revision[:12]
    pins={name:hashlib.sha256(content).hexdigest() for name,content in files.items()}
    body={"folder":folder,"files":{name:{"packed":base64.b64encode(zlib.compress(content,9)).decode(),"size":len(content)} for name,content in files.items()},"pins":pins}
    code=("import base64,hashlib,json,os,stat,subprocess,zlib\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
          "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'))\n"+validators+"\n"
          "payload="+repr(body)+"\nfolder=Path(payload['folder'])\n"
          "for directory in (folder.parent,folder):\n"
          " if not directory.exists() and not directory.is_symlink(): directory.mkdir(mode=0o700)\n"
          " protected(directory,directory=True)\n"
          " require(stat.S_IMODE(directory.stat().st_mode)==0o700,'recovery directory must be private')\n"
          "require(set(payload['files'])=={'vm_development_apply.py','vm_failed_identity_chat_recovery.py'},'recovery closure differs')\n"
          "for name,material in payload['files'].items():\n"
          " require(type(material['size']) is int and 0<material['size']<=2*1024*1024,'recovery source decoded limit differs')\n"
          " packed=base64.b64decode(material['packed'],validate=True);decoder=zlib.decompressobj()\n"
          " content=decoder.decompress(packed,material['size']+1)\n"
          " require(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data and len(content)==material['size'],'recovery source compressed length differs')\n"
          " path=folder/name\n"
          " require(hashlib.sha256(content).hexdigest()==payload['pins'][name],'recovery source transfer differs')\n"
          " if not path.exists() and not path.is_symlink():\n"
          "  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n"
          "  with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())\n"
          " protected(path)\n"
          " require(stat.S_IMODE(path.stat().st_mode)==0o600 and path.stat().st_nlink==1 and path.read_bytes()==content,'recovery executable differs')\n")
    argv=["/usr/bin/python3","-I","-B",folder+"/vm_failed_identity_chat_recovery.py",
          "--media","/opt/jjdguard/development-releases/"+release_id,
          "--manifest-sha256",metadata["manifest_sha256"],"--failure-sha256",metadata["failure_sha256"],
          "--original-apply-sha256",metadata["original_apply_sha256"],"--recovery-revision",revision,
          "--recovery-helper-sha256",pins["vm_failed_identity_chat_recovery.py"],
          "--validator-sha256",pins["vm_development_apply.py"]]
    if database_resume is not None:argv+=["--database-resume-proof",json.dumps(database_resume,sort_keys=True,separators=(",",":"))]
    if stage_pin is None:argv+=["--prepare"]
    else:
        argv+=["--stage-sha256",stage_pin]
        if checkpoint is not None:argv+=["--checkpoint-sha256",checkpoint]
    return code+"run_failed_recovery_helper("+repr(argv)+",vm.ROOT,installed_input_password_fd="+repr(installed_input_password_fd)+",recovery_operator_uid="+repr(recovery_operator_uid)+")\n"

def recover_failed_identity_chat(args):
    repo=Path(args.repo).resolve()
    env={"PATH":"/usr/bin:/bin","HOME":"/home/dev","LANG":"C.UTF-8"}
    revision=subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],env=env,text=True).strip()
    source_gate(repo,revision)
    release_id=args.recover_failed_identity_chat_release_id
    checkpoint=getattr(args,"checkpoint_sha256",None)
    database_resume=getattr(args,"database_resume_proof",None)
    if checkpoint is not None and not re.fullmatch(r"[0-9a-f]{64}",checkpoint):
        raise RuntimeError("full failed-apply checkpoint SHA256 required")
    output=guest(args.vm,failed_identity_chat_metadata_guest_code(release_id))
    values=[line.split("=",1)[1] for line in output.splitlines() if line.startswith("FAILED_IDENTITY_CHAT_METADATA=")]
    if len(values)!=1:raise RuntimeError("failed-apply recovery metadata output is ambiguous")
    metadata=json.loads(values[0])
    if (set(metadata)!={"revision","manifest_sha256","failure_sha256","original_apply_sha256"} or
            not re.fullmatch(r"[0-9a-f]{40}",metadata["revision"]) or
            any(not re.fullmatch(r"[0-9a-f]{64}",metadata[key]) for key in metadata if key!="revision")):
        raise RuntimeError("failed-apply recovery metadata malformed")
    subprocess.run(["git","-C",str(repo),"merge-base","--is-ancestor",metadata["revision"],revision],env=env,check=True)
    old=subprocess.check_output(["git","-C",str(repo),"show",metadata["revision"]+":deploy/release/vm_development_apply.py"],env=env)
    if hashlib.sha256(old).hexdigest()!=metadata["original_apply_sha256"]:
        raise RuntimeError("failed-apply frozen helper differs from its original source")
    files={name:subprocess.check_output(["git","-C",str(repo),"show",revision+":deploy/release/"+name],env=env)
           for name in ("vm_development_apply.py","vm_failed_identity_chat_recovery.py")}
    prepared=guest(args.vm,failed_identity_chat_recovery_guest_code(release_id,revision,metadata,files,database_resume=database_resume))
    stage_pin=receipt_output_pin(prepared,"FAILED_APPLY_STAGE_SHA256=")
    result=guest(args.vm,failed_identity_chat_recovery_guest_code(release_id,revision,metadata,files,stage_pin,checkpoint,database_resume=database_resume),seconds=4800)
    receipt_output_pin(result,"FAILED_APPLY_RECOVERY_RECEIPT_SHA256=")

def validate_persist_scope(manifest):
    if "include_proxy_server" in manifest and (type(manifest["include_proxy_server"]) is not bool or manifest.get("identity_chat_only") is not True):
        raise RuntimeError("proxy-server inclusion requires an explicit identity-chat-only boolean")
    if "identity_chat_only" in manifest:
        if (manifest.get("identity_chat_only") is not True or manifest.get("purpose") != "development-vm" or
                manifest.get("preserve_tier1") is not True or
                any(manifest.get(mode, False) is not False for mode in ("console_only", "chat_theme_only", "security_engine_only", "engineering_only", "portal_only", "enable_file_detection")) or
                any(manifest.get(key) is not None for key in CONSOLE_FORBIDDEN_OVERRIDES) or
                set(manifest.get("services", {})) != set(IDENTITY_CHAT_SERVICES + (("proxy-server",) if manifest.get("include_proxy_server") else ()))):
            raise RuntimeError("boot persistence requires the exact identity-chat-only service scope")
        return
    if (manifest.get("purpose") != "development-vm" or
            any(manifest.get(mode) for mode in ("console_only", "security_engine_only", "engineering_only", "portal_only")) or
            type(manifest.get("preserve_tier1", False)) is not bool):
        raise RuntimeError("boot persistence requires a full development release or preserve-tier1")
    expected = SERVICES[:-1] if manifest.get("preserve_tier1") else SERVICES
    if set(manifest.get("services", {})) != set(expected):
        raise RuntimeError("boot persistence requires the exact full development release service set")


def validate_persist_source_media(repo, media, manifest):
    validate_persist_scope(manifest)
    env = {"PATH":"/usr/bin:/bin", "HOME":"/home/dev", "LANG":"C.UTF-8"}
    source = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "show",
                                      manifest["revision"]+":deploy/release/vm_development_apply.py"], env=env)
    script = media/"vm_development_apply.py"
    if (script.is_symlink() or not script.is_file() or
            hashlib.sha256(source).hexdigest() != manifest.get("apply_script_sha256") or
            digest(script) != manifest["apply_script_sha256"]):
        raise RuntimeError("persist helper is not the authenticated frozen source")


def receipt_output_pin(output, prefix):
    values = [line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
        raise RuntimeError("guest receipt output lacks one full authenticated SHA256")
    return values[0]


def run_installation_helper(command, root, stdin=None):
    import pwd
    root = Path(root)
    current = root/"current"
    require(root.is_absolute() and root.resolve(strict=True) == root and current.is_symlink(),
            "managed installation pointer unavailable")
    installed = current.resolve(strict=True)
    require(installed.parent == root/"releases" and installed.is_dir() and
            installed.parent.resolve(strict=True) == installed.parent,
            "managed installation pointer escapes releases")
    info = installed.stat()
    require(current.lstat().st_uid in {0, info.st_uid} and not info.st_mode & 0o002,
            "managed installation ownership differs")
    if info.st_uid == 0:
        subprocess.run(command, env=controlled_environment(), cwd='/root', check=True, stdin=stdin)
        return
    try:
        account = pwd.getpwuid(info.st_uid)
    except KeyError as error:
        raise RuntimeError("installation owner account unavailable") from error
    require(account.pw_uid == info.st_uid and account.pw_gid == info.st_gid and account.pw_name,
            "installation owner account differs")
    sudo = Path('/usr/bin/sudo')
    require(sudo.is_file() and os.access(sudo, os.X_OK), "non-interactive sudo unavailable")
    authenticated = [str(sudo), '-u', account.pw_name, '-n', '--', str(sudo), '-n', '--',
                     *command, '--install-owner-uid', str(account.pw_uid),
                     '--install-owner-gid', str(account.pw_gid)]
    subprocess.run(authenticated, env=controlled_environment(), cwd='/', check=True, stdin=stdin)


def run_failed_recovery_helper(command,root,installed_input_password_fd=None,recovery_operator_uid=None):
    """Authenticate legacy staged inputs through a real sudo owner round trip.

    Root-owned installations may retain two stage-pinned artifacts under a build
    UID. That artifact creator is never used as the operator identity. The caller
    supplies the actual recovery operator UID; real sudo establishes its identity
    without a general installation-owner exception or rewritten SUDO_* values.
    """
    import pwd
    if installed_input_password_fd is not None:
        require(type(installed_input_password_fd) is int and installed_input_password_fd==0 and
                stat.S_ISFIFO(os.fstat(installed_input_password_fd).st_mode),
                "installed input password requires anonymous pipe stdin")
    root=Path(root);installed=(root/"current").resolve(strict=True)
    if installed.stat().st_uid!=0:
        return run_installation_helper(command,root)
    require("--media" in command,"failed recovery media identity missing")
    media=Path(command[command.index("--media")+1])
    require(media.parent==root/"development-releases","failed recovery media scope differs")
    before_file=protected(media/"state/before.json")
    before=json.loads(before_file.read_text())
    workdir=Path(before["live"]).parent.parent
    require(workdir in (installed,installed/"deploy/docker-compose") and
            workdir.resolve(strict=True)==workdir and workdir.is_dir(),
            "failed recovery original installation differs")
    owners=set()
    for path,mode in ((workdir/"docker-compose.offline.yml",0o600),(workdir/"bin/docker-compose",0o700)):
        if str(path) not in before.get("compose_sha256",{}):continue
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not info.st_mode&0o022,
                "failed recovery original input protection differs")
        require(hashlib.sha256(path.read_bytes()).hexdigest()==before["compose_sha256"][str(path)],
                "failed recovery original input digest differs")
        if info.st_uid!=0:
            require(stat.S_IMODE(info.st_mode)==mode,"failed recovery legacy input mode differs")
            owners.add((info.st_uid,info.st_gid))
    require(len(owners)<=1,"failed recovery original input owners are ambiguous")
    if not owners:return run_installation_helper(command,root)
    require(type(recovery_operator_uid) is int and recovery_operator_uid>0,
            "mixed-owner artifacts require the explicit authenticated recovery operator UID")
    account=pwd.getpwuid(recovery_operator_uid);uid,gid=account.pw_uid,account.pw_gid
    require(uid==recovery_operator_uid and gid>0 and account.pw_name,
            "failed recovery operator account differs")
    inner=['/usr/bin/sudo',*(['-n'] if installed_input_password_fd is None else ['-S','-p','']),'--']
    authenticated=['/usr/bin/sudo','-u',account.pw_name,'-n','--',*inner,
                   *command,'--recovery-operator-uid',str(uid),'--recovery-operator-gid',str(gid)]
    return run_installation_helper(authenticated,root,stdin=installed_input_password_fd)


def forward_guest_code(release_id, manifest_sha, apply_sha, action):
    if (not re.fullmatch(r"dev-[A-Za-z0-9-]+", release_id) or action not in ('stage', 'apply') or
            not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (manifest_sha, apply_sha))):
        raise RuntimeError("invalid forward release identity")
    from vm_console_release import require, protected, controlled_environment
    validators = "\n\n".join(inspect.getsource(fn) for fn in
                             (require, protected, controlled_environment, run_installation_helper))
    return ("import hashlib,json,os,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "def digest(path):\n with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()\n"
            "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'))\n"+validators+"\n"
            "media=vm.ROOT/'development-releases'/"+repr(release_id)+"\nprotected(media,directory=True)\n"
            "require(digest(protected(media/'manifest.json'))=="+repr(manifest_sha)+",'forward manifest changed')\n"
            "manifest=json.loads((media/'manifest.json').read_text())\n"
            "require(manifest.get('release_id')=="+repr(release_id)+" and manifest.get('purpose')=='development-vm',"
            "'forward release identity changed')\n"
            "require(digest(protected(media/'vm_development_apply.py'))==manifest.get('apply_script_sha256')=="
            +repr(apply_sha)+",'forward script changed before execution')\n"
            "run_installation_helper(['/usr/bin/python3','-E','-s','-B',str(media/'vm_development_apply.py'),"
            +repr(action)+",'--media',str(media),'--manifest-sha256',"+repr(manifest_sha)+"],vm.ROOT)\n")


def require_persistence_service_ids(manifest, receipt):
    """Authenticate OCI descriptor IDs without confusing them with config IDs."""
    expected = {name: record['image_id'] for name, record in manifest['services'].items()}
    actual = receipt.get('services')
    require(isinstance(actual, dict) and set(actual) == set(expected), 'persistence receipt service scope differs')
    for name, config_id in expected.items():
        image_id = actual[name]
        if image_id == config_id:
            continue
        require(isinstance(image_id, str) and len(image_id) == 71 and image_id.startswith('sha256:') and
                all(char in '0123456789abcdef' for char in image_id[7:]), 'persistence image ID malformed')
        result = subprocess.run(['/usr/bin/docker', 'image', 'inspect', image_id],
                                env=controlled_environment(), cwd='/root', check=True, capture_output=True, text=True, timeout=30)
        inspected = json.loads(result.stdout)
        require(isinstance(inspected, list) and len(inspected) == 1 and inspected[0].get('Id') == image_id and
                inspected[0].get('Descriptor'), 'persistence image descriptor differs')
        result = subprocess.run(['/usr/bin/ctr', '--address', '/run/containerd/containerd.sock', '--namespace', 'moby', 'content', 'get', image_id],
                                env=controlled_environment(), cwd='/root', check=True, capture_output=True, timeout=30)
        raw = result.stdout
        require('sha256:' + hashlib.sha256(raw).hexdigest() == image_id, 'persistence OCI manifest digest differs')
        require(json.loads(raw).get('config', {}).get('digest') == config_id, 'persistence OCI config digest differs')


def persist_guest_code(release_id, manifest_sha, apply_sha, receipt_sha=None):
    if (not re.fullmatch(r"dev-[A-Za-z0-9-]+", release_id) or
            not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (manifest_sha, apply_sha)) or
            (receipt_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", receipt_sha))):
        raise RuntimeError("invalid persistence identity")
    from vm_console_release import require, protected, controlled_environment
    validators = "\n\n".join(inspect.getsource(fn) for fn in
                             (require, protected, controlled_environment, validate_persist_scope, run_installation_helper, require_persistence_service_ids))
    code = ("import hashlib,json,os,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "def digest(path):\n with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()\n"
            "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'))\nSERVICES="+repr(SERVICES)+"\nIDENTITY_CHAT_SERVICES="+repr(IDENTITY_CHAT_SERVICES)+"\nCONSOLE_FORBIDDEN_OVERRIDES="+repr(CONSOLE_FORBIDDEN_OVERRIDES)+"\n"+validators+"\n"
            "media=vm.ROOT/'development-releases'/"+repr(release_id)+"\nprotected(media,directory=True)\n"
            "require(digest(protected(media/'manifest.json'))=="+repr(manifest_sha)+",'persistence manifest changed')\n"
            "manifest=json.loads((media/'manifest.json').read_text())\nvalidate_persist_scope(manifest)\n"
            "require(manifest.get('release_id')=="+repr(release_id)+",'persistence release identity changed')\n"
            "require(digest(protected(media/'vm_development_apply.py'))==manifest.get('apply_script_sha256')=="
            +repr(apply_sha)+",'persistence script changed before execution')\n"
            "receipt_path=protected(media/'receipt.json')\npin=digest(receipt_path)\n"
            "pointer=json.loads(protected(media.parent/'current.json').read_text())\n"
            "require(pointer=={'release':str(media),'receipt_sha256':pin},'persistence requires the active recorded release receipt')\n"
            "receipt=json.loads(receipt_path.read_text())\n"
            "require(receipt.get('status')=='deployed' and receipt.get('release_id')==manifest['release_id'] and "
            "receipt.get('manifest_sha256')=="+repr(manifest_sha)+" and receipt.get('revision')==manifest['revision'], 'persistence receipt identity differs')\n"
            "require_persistence_service_ids(manifest, receipt)\n"
            "require('persist_boot' in receipt and receipt['persist_boot'] is None,'persistence receipt is already persisted or unsupported')\n")
    if receipt_sha is None:
        return code+"print('APPLY_RECEIPT_SHA256='+pin)\n"
    return (code+"require(pin=="+repr(receipt_sha)+",'persistence receipt changed before execution')\n"
            "run_installation_helper(['/usr/bin/python3','-I','-B',str(media/'vm_development_apply.py'),'persist-boot',"
            "'--media',str(media),'--manifest-sha256',"+repr(manifest_sha)+",'--receipt-sha256',"+repr(receipt_sha)+"],"
            "vm.ROOT)\n")


def identity_chat_rollback_guest_code(release_id, receipt_sha):
    if (not re.fullmatch(r"dev-[A-Za-z0-9-]+", release_id) or
            not re.fullmatch(r"[0-9a-f]{64}", receipt_sha)):
        raise RuntimeError("invalid identity-chat rollback identity")
    from vm_console_release import require, protected, controlled_environment
    validators = "\n\n".join(inspect.getsource(fn) for fn in
                             (require, protected, controlled_environment, validate_persist_scope, run_installation_helper))
    return ("import hashlib,json,os,subprocess\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
            "def digest(path):\n with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()\n"
            "vm=SimpleNamespace(ROOT=Path('/opt/jjdguard'))\nSERVICES="+repr(SERVICES)+"\n"
            "IDENTITY_CHAT_SERVICES="+repr(IDENTITY_CHAT_SERVICES)+"\n"
            "CONSOLE_FORBIDDEN_OVERRIDES="+repr(CONSOLE_FORBIDDEN_OVERRIDES)+"\n"+validators+"\n"
            "media=vm.ROOT/'development-releases'/"+repr(release_id)+"\nprotected(media,directory=True)\n"
            "require(not (media/'__pycache__').exists() and not list(media.glob('*.pyc')),'unexpected cached release code')\n"
            "receipt_path=protected(media/'receipt.json')\n"
            "require(digest(receipt_path)=="+repr(receipt_sha)+",'identity-chat receipt changed')\n"
            "pointer=json.loads(protected(media.parent/'current.json').read_text())\n"
            "require(pointer=={'release':str(media),'receipt_sha256':"+repr(receipt_sha)+"},'rollback requires the active recorded receipt')\n"
            "receipt=json.loads(receipt_path.read_text())\n"
            "manifest_path=protected(media/'manifest.json')\nmanifest_sha=digest(manifest_path)\n"
            "require(receipt.get('manifest_sha256')==manifest_sha,'rollback manifest is not bound to receipt')\n"
            "manifest=json.loads(manifest_path.read_text())\nvalidate_persist_scope(manifest)\n"
            "require(manifest.get('identity_chat_only') is True and manifest.get('release_id')=="+repr(release_id)+","
            "'rollback requires identity-chat-only media')\n"
            "require(receipt.get('status')=='deployed' and receipt.get('release_id')==manifest['release_id'] and "
            "receipt.get('revision')==manifest['revision'],'rollback receipt identity differs')\n"
            "script=protected(media/'vm_development_apply.py')\n"
            "require(digest(script)==manifest.get('apply_script_sha256'),'rollback script changed before execution')\n"
            "run_installation_helper(['/usr/bin/python3','-I','-B',str(script),'rollback','--media',str(media),"
            "'--manifest-sha256',manifest_sha,'--receipt-sha256',"+repr(receipt_sha)+"],vm.ROOT)\n")


def validate_identity_chat_source_media(repo, media, manifest):
    from build_vm_development import verify_identity_chat_image_archive
    validate_persist_scope(manifest)
    if manifest.get("identity_chat_only") is not True:
        raise RuntimeError("identity-chat source validation requires the exact identity/chat service mode")
    names = {"manifest.json", "images.tar", "vm_development_apply.py",
             "migration-runner.sh", "migration-version.sh"} | {"migrations/"+name for name in manifest["migrations"]}
    if ({str(path.relative_to(media)) for path in media.rglob("*") if path.is_file()} != names or
            any(path.is_symlink() for path in media.rglob("*"))):
        raise RuntimeError("unexpected identity-chat media")
    env = {"PATH":"/usr/bin:/bin", "HOME":"/home/dev", "LANG":"C.UTF-8"}
    for relative, field in (("deploy/release/vm_development_apply.py", "apply_script_sha256"),
                            ("deploy/lib/migration-runner.sh", "migration_runner_sha256"),
                            ("deploy/lib/migration-version.sh", "migration_version_sha256")):
        frozen = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "show", manifest["revision"]+":"+relative], env=env)
        if hashlib.sha256(frozen).hexdigest() != manifest.get(field) or digest(media/Path(relative).name) != manifest[field]:
            raise RuntimeError("identity-chat helper is not authenticated frozen source")
    for name, checksum in manifest["migrations"].items():
        if not re.fullmatch(r"[0-9]{3,}_[A-Za-z0-9_]+\.sql", name):
            raise RuntimeError("invalid identity-chat migration filename")
        frozen = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "show", manifest["revision"]+":deploy/migrations/"+name], env=env)
        if hashlib.sha256(frozen).hexdigest() != checksum or digest(media/"migrations"/name) != checksum:
            raise RuntimeError("identity-chat migration is not frozen source")
    archive = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "archive", manifest["revision"]], env=env)
    if hashlib.sha256(archive).hexdigest() != manifest.get("source_archive_sha256"):
        raise RuntimeError("identity-chat immutable source archive differs")
    verify_identity_chat_image_archive(media, manifest)


def persist_recorded(args):
    media = Path(args.media).resolve()
    manifest = json.loads((media/"manifest.json").read_text())
    validate_persist_scope(manifest)
    repo = Path(args.repo).resolve()
    if source_gate(repo, manifest["revision"]) != manifest["tree"]:
        raise RuntimeError("persist source tree differs from live main")
    validate_persist_source_media(repo, media, manifest)
    output = guest(args.vm, persist_guest_code(manifest["release_id"], digest(media/"manifest.json"),
                                              manifest["apply_script_sha256"], args.receipt_sha256))
    pin = receipt_output_pin(output, "FINAL_RECEIPT_SHA256=")
    print(json.dumps({"release_id":manifest["release_id"], "revision":manifest["revision"],
                      "boot_persisted":True, "receipt_sha256":pin}), flush=True)


def validate_console_source_media(repo, media, manifest):
    from vm_console_release import validate_manifest, check_image_archive, MEDIA_FILES
    validate_manifest(manifest)
    assert {str(p.relative_to(media)) for p in media.rglob('*') if p.is_file()} == set(MEDIA_FILES), 'unexpected console media'
    assert not any(p.is_symlink() for p in media.rglob('*')), 'symlinked console media'
    env = {'PATH':'/usr/bin:/bin','HOME':'/home/dev','LANG':'C.UTF-8'}
    for name, field in (('vm_development_apply.py','apply_script_sha256'),('vm_console_release.py','console_script_sha256')):
        content = subprocess.check_output(['/usr/bin/git','-C',str(repo),'show',manifest['revision']+':deploy/release/'+name], env=env)
        assert hashlib.sha256(content).hexdigest() == manifest[field] == digest(media/name), 'console script is not frozen source'
    archive = subprocess.check_output(['/usr/bin/git','-C',str(repo),'archive',manifest['revision']], env=env)
    assert hashlib.sha256(archive).hexdigest() == manifest['source_archive_sha256'], 'immutable console source archive differs'
    check_image_archive(media, manifest)


def validate_chat_theme_source_media(repo, media, manifest):
    from vm_chat_theme_release import validate_manifest, read_theme_archive, THEME_FILES, THEME_PATH, MEDIA_FILES
    validate_manifest(manifest)
    assert {str(p.relative_to(media)) for p in media.rglob('*') if p.is_file()} == set(MEDIA_FILES), 'unexpected theme media'
    assert not any(p.is_symlink() for p in media.rglob('*')), 'symlinked theme media'
    env = {'PATH':'/usr/bin:/bin','HOME':'/home/dev','LANG':'C.UTF-8'}
    for name, field in (('vm_development_apply.py','apply_script_sha256'),('vm_chat_theme_release.py','theme_script_sha256')):
        content = subprocess.check_output(['/usr/bin/git','-C',str(repo),'show',manifest['revision']+':deploy/release/'+name], env=env)
        assert hashlib.sha256(content).hexdigest() == manifest[field] == digest(media/name), 'theme script is not frozen source'
    archive = subprocess.check_output(['/usr/bin/git','-C',str(repo),'archive',manifest['revision']], env=env)
    assert hashlib.sha256(archive).hexdigest() == manifest['source_archive_sha256'], 'immutable theme source archive differs'
    assert digest(media/'theme.tar') == manifest['theme_archive_sha256'], 'theme archive differs'
    assets = read_theme_archive((media/'theme.tar').read_bytes(), manifest['theme_files'])
    for name in THEME_FILES:
        content = subprocess.check_output(['/usr/bin/git','-C',str(repo),'show',manifest['revision']+':'+THEME_PATH+'/'+name], env=env)
        assert assets[name] == content, 'theme asset is not frozen source'


def deploy(args, media, manifest):
    persist_boot = getattr(args, "persist_boot", False)
    if manifest.get("identity_chat_only") and not persist_boot:
        raise RuntimeError("identity-chat deployment requires --persist-boot")
    if persist_boot:
        validate_persist_scope(manifest)
    tree = source_gate(Path(args.repo).resolve(),manifest["revision"])
    expected=digest(media/"manifest.json")
    if persist_boot:
        if manifest["tree"] != tree: raise RuntimeError("persist source tree differs from live main")
        validate_persist_source_media(Path(args.repo).resolve(), media, manifest)
    if manifest.get("identity_chat_only"):
        if manifest["tree"] != tree: raise RuntimeError("identity-chat source tree differs from live main")
        validate_identity_chat_source_media(Path(args.repo).resolve(), media, manifest)
    elif manifest.get('chat_theme_only'):
        assert manifest["tree"] == tree, "theme source tree differs from live main"
        validate_chat_theme_source_media(Path(args.repo).resolve(), media, manifest)
    elif manifest.get('console_only'):
        assert manifest["tree"] == tree, "console source tree differs from live main"
        validate_console_source_media(Path(args.repo).resolve(), media, manifest)
    else:
        assert manifest["purpose"]=="development-vm"
    destination="/opt/jjdguard/development-releases/"+manifest["release_id"]
    route=json.loads(subprocess.check_output(["ip","-j","route","get","192.168.56.10"],text=True))[0]
    address=route["prefsrc"]
    assert address.startswith("192.168.56."), "transfer must use the VM private subnet"
    token=secrets.token_hex(24)
    files={str(p.relative_to(media)):p for p in media.rglob("*") if p.is_file() and "state" not in p.relative_to(media).parts}
    checksums={name:digest(p) for name,p in files.items()}
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            prefix="/"+token+"/"
            if not self.path.startswith(prefix) or self.path[len(prefix):] not in files:self.send_error(404);return
            path=files[self.path[len(prefix):]]
            self.send_response(200);self.send_header("Content-Length",str(path.stat().st_size));self.end_headers()
            with path.open("rb") as stream:
                import shutil
                shutil.copyfileobj(stream,self.wfile)
    server=http.server.ThreadingHTTPServer((address,0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    config={"destination":destination,"url":"http://"+address+":"+str(server.server_port)+"/"+token+"/","files":checksums}
    code="""import urllib.request,os,hashlib
from pathlib import Path
os.umask(0o077)
cfg=CONFIG
root=Path(cfg['destination'])
root.mkdir(parents=True,exist_ok=True,mode=0o700)
if root.is_symlink():raise RuntimeError('release destination is a symlink')
for name,checksum in cfg['files'].items():
 path=root/name
 if not path.resolve().is_relative_to(root.resolve()):raise RuntimeError('transfer path escaped release')
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 if path.exists():
  with path.open('rb') as existing:
   if hashlib.file_digest(existing,'sha256').hexdigest()==checksum:continue
 temporary=path.with_name(path.name+'.part')
 with urllib.request.urlopen(cfg['url']+name,timeout=180) as response,temporary.open('wb') as stream:
  import shutil
  shutil.copyfileobj(response,stream)
 with temporary.open('rb') as stream:
  if hashlib.file_digest(stream,'sha256').hexdigest()!=checksum:raise RuntimeError('transfer checksum differs')
 os.replace(temporary,path)
print('TRANSFER verified files='+str(len(cfg['files'])))
""".replace("CONFIG",repr(config))
    if manifest.get("console_only") or manifest.get("chat_theme_only") or manifest.get("identity_chat_only"):
        from vm_console_release import protected, require
        import inspect
        preflight = "\n\n".join(inspect.getsource(fn) for fn in (require, protected))
        insertion = ("from types import SimpleNamespace\nvm=SimpleNamespace(ROOT=Path('/opt/jjdguard'))\n"+preflight+"\n"
                     "protected(root.parent,directory=True)\n"
                     "if root.exists() or root.is_symlink():\n protected(root,directory=True)\n"
                     " for name in cfg['files']:\n"
                     "  for path in (root/name,root/(name+'.part')):\n"
                     "   if path.exists() or path.is_symlink():protected(path)\n"
                     "else:\n require(not root.is_symlink(),'release destination is a symlink')\n")
        code = code.replace("root.mkdir(parents=True,exist_ok=True,mode=0o700)", insertion+"root.mkdir(exist_ok=True,mode=0o700)\nprotected(root,directory=True)")
    try:
        print("TRANSFER fixed artifacts on VM private subnet",flush=True)
        guest(args.vm,code)
    finally:
        server.shutdown();server.server_close();thread.join()
    source_gate(Path(args.repo).resolve(),manifest["revision"])
    for action in ("stage","apply"):
        print(action.upper()+" "+manifest["release_id"],flush=True)
        if manifest.get("chat_theme_only"):
            from vm_chat_theme_release import apply_guest_code
            code = apply_guest_code(manifest["release_id"], expected, action)
        elif manifest.get("console_only"):
            from vm_console_release import apply_guest_code
            code = apply_guest_code(manifest["release_id"], expected, action)
        else:
            code = forward_guest_code(manifest["release_id"], expected, manifest["apply_script_sha256"], action)
        # Apply includes the quiesced database backup and a possible complete
        # restore. Keep the host lock and observe the guest through slow I/O;
        # the guest retains its own bounded operation timeouts and rollback.
        output = guest(args.vm,code,seconds=7200 if action == "apply" else 900)
    result = {"release_id":manifest["release_id"],"revision":manifest["revision"],"guest_receipt":destination+"/receipt.json"}
    if manifest.get('chat_theme_only'):
        result['receipt_sha256'] = receipt_output_pin(output, 'CHAT_THEME_RECEIPT_SHA256=')
    if persist_boot:
        source_gate(Path(args.repo).resolve(), manifest["revision"])
        snapshot = guest(args.vm, persist_guest_code(manifest["release_id"], expected, manifest["apply_script_sha256"]))
        receipt_sha = receipt_output_pin(snapshot, "APPLY_RECEIPT_SHA256=")
        print("PERSIST-BOOT "+manifest["release_id"], flush=True)
        output = guest(args.vm, persist_guest_code(manifest["release_id"], expected,
                                                  manifest["apply_script_sha256"], receipt_sha))
        result.update(boot_persisted=True, receipt_sha256=receipt_output_pin(output, "FINAL_RECEIPT_SHA256="))
    print(json.dumps(result),flush=True)

if __name__=="__main__":main()
