"""双服务窄事务只使用临时 Docker/Compose/guest 夹具，不连接真实 VM。"""
import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"release"))
import build_vm_development as build
import deploy_vm_development as deploy
import vm_development_apply as vm
import vm_console_release as console
REAL_PROTECTED = console.protected
REAL_VM_RUN = vm.run


class ConsoleEntryOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["docker", "image", "inspect", "python:3.12-alpine", "--format", "{{.Id}}"],
                                capture_output=True, text=True, check=True)
        cls.python_image = result.stdout.strip()
        if not __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", cls.python_image):
            raise RuntimeError("isolated Python fixture image is not pinned")

    def invoke(self, mode="main", rejection=None):
        source = r'''
import hashlib, importlib.util, json, os, pwd, runpy, shutil, sys, tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
mode, rejection = CASE
with tempfile.TemporaryDirectory(prefix='console-owner-entry-') as directory:
    root = Path(directory)/'jjdguard'
    root.mkdir(mode=0o700)
    account = next(entry for entry in pwd.getpwall() if entry.pw_uid != 0 and entry.pw_uid == entry.pw_gid)
    owner = (account.pw_uid, account.pw_gid)
    # These are isolated sudo-caller fixtures. The real entry still checks EUID,
    # both arguments, pwd user identity, and the account's primary group.
    os.environ.update(SUDO_UID=str(owner[0]), SUDO_GID=str(owner[1]), SUDO_USER=account.pw_name)
    installed = root/'releases/installed'
    installed.mkdir(parents=True, mode=0o755)
    installed.chmod(0o755)
    active = installed/'active-config'
    active.mkdir(mode=0o755)
    os.chown(installed, *owner)
    os.chown(active, *owner)
    media = root/'development-releases/dev-owner-test'
    media.mkdir(parents=True, mode=0o700)
    for name in ['vm_development_apply.py', 'vm_console_release.py']:
        shutil.copyfile('/release/'+name, media/name)
        (media/name).chmod(0o600)
    (media/'images.tar').write_bytes(b'isolated-fixed-image-fixture')
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = dict(schema=1, purpose='console-only', console_only=True, release_id=media.name,
                    revision='a'*40, tree='b'*40, source_archive_sha256='c'*64, version='2.8.0', created_at='fixture',
                    preserve_tier1=True, migrations={}, migration_preconditions={}, enable_file_detection=False,
                    billing_enabled='false', candidate_validation={'console_payload_verified':True,'control_plane_seeds':'preserved'},
                    control_plane_seeds_sha256={'/etc/uag/seeds/policy.json':'d'*64},control_plane_seed_directories=['/etc/uag/seeds'],
                    apply_script_sha256=digest(media/'vm_development_apply.py'),console_script_sha256=digest(media/'vm_console_release.py'),
                    images_sha256=digest(media/'images.tar'),services={})
    for name in ['control-plane','web-console']:
        payload = ['/app/control-plane','/app/VERSION'] if name == 'control-plane' else ['/app/dist/index.html','/app/server.js']
        manifest['services'][name] = dict(image_id='sha256:'+'e'*64,base_image_id='sha256:'+'f'*64,tag='fixture/'+name+':fixed',payload_sha256={path:'1'*64 for path in payload})
    (media/'manifest.json').write_text(json.dumps(manifest))
    state = media/'state'
    state.mkdir(mode=0o700)
    payload = b'{"isolated":"console-publish"}\n'
    (state/'candidate.json').write_bytes(payload)
    target = active/'candidate.json'
    captured = {}
    if mode == 'rollback':
        receipt = dict(schema=1, purpose='console-only', status='deployed', release_id=media.name,
                       manifest_sha256=digest(media/'manifest.json'),
                       media={name:digest(media/name) for name in ['manifest.json','images.tar','vm_development_apply.py','vm_console_release.py']})
        (media/'receipt.json').write_text(json.dumps(receipt))
        (media.parent/'current.json').write_text(json.dumps(dict(release=str(media),receipt_sha256=digest(media/'receipt.json'))))
    sys.path.insert(0, str(media))
    def publish_fixture(self):
        self.live = target
        self.state = state
        self.publish_live()
    def trace(frame, event, arg):
        if frame.f_code.co_filename == str(media/'vm_development_apply.py'):
            if (event == 'call' and frame.f_code.co_name == 'main') or (event == 'return' and frame.f_code.co_name == '<module>'):
                # Only the filesystem root is redirected into the disposable
                # fixture; no authentication or fd-safety function is replaced.
                frame.f_globals['ROOT'] = root
                captured['entry'] = sys.modules[frame.f_globals['__name__']]
            if event == 'call' and frame.f_code.co_name == 'main':
                captured['entry'] = sys.modules[frame.f_globals['__name__']]
        if event == 'return' and frame.f_code.co_name == '__init__' and frame.f_code.co_filename == str(media/'vm_console_release.py'):
            frame.f_locals['self'].__class__.apply = publish_fixture
            frame.f_locals['self'].__class__.rollback = lambda release, receipt: publish_fixture(release)
            captured['console_module'] = SimpleNamespace(vm=frame.f_globals['vm'])
    foreign = None
    if rejection == 'foreign_vm':
        foreign = ModuleType('vm_development_apply')
        sys.modules['vm_development_apply'] = foreign
    elif rejection == 'foreign_console':
        foreign = ModuleType('vm_console_release')
        foreign.vm = ModuleType('foreign_vm')
        class UnsafeForeignRelease:
            def __init__(self, *args): target.write_bytes(b'foreign writer invoked')
            def apply(self): pass
        foreign.ConsoleRelease = UnsafeForeignRelease
        sys.modules['vm_console_release'] = foreign
    requested_uid = owner[0]+1 if rejection == 'caller' else owner[0]
    sys.argv = [str(media/'vm_development_apply.py'),'apply','--media',str(media),'--manifest-sha256',digest(media/'manifest.json'),
                '--install-owner-uid',str(requested_uid),'--install-owner-gid',str(owner[1])]
    if mode == 'rollback':
        sys.argv = [str(media/'vm_console_release.py'),'rollback','--release-id',media.name,'--receipt-sha256',digest(media/'receipt.json'),
                    '--install-owner-uid',str(requested_uid),'--install-owner-gid',str(owner[1])]
    sys.setprofile(trace)
    failure = None
    try:
        if mode == 'main':
            runpy.run_path(str(media/'vm_development_apply.py'), run_name='__main__')
        elif mode == 'rollback':
            runpy.run_path(str(media/'vm_console_release.py'), run_name='__main__')
        else:
            spec = importlib.util.spec_from_file_location('vm_development_apply',media/'vm_development_apply.py')
            entry = importlib.util.module_from_spec(spec)
            sys.modules['vm_development_apply'] = entry
            spec.loader.exec_module(entry)
            entry.main()
    except BaseException as error:
        failure = {'type':type(error).__name__,'message':str(error)}
    finally:
        sys.setprofile(None)
    entry = captured.get('entry')
    imported = captured.get('console_module')
    print(json.dumps({'failure':failure,'published':target.exists(),
                      'bytes_match':target.read_bytes()==payload if target.exists() else False,
                      'canonical_is_entry':sys.modules.get('vm_development_apply') is entry,
                      'context_shared':imported.vm.INSTALL_OWNER is entry.INSTALL_OWNER if imported else False,
                      'owner_authenticated':entry.INSTALL_OWNER.get()==owner if entry else False,
                      'foreign_unchanged':(sys.modules.get('vm_development_apply') is foreign if rejection=='foreign_vm' else sys.modules.get('vm_console_release') is foreign) if foreign else None,
                      'installed_uid':installed.stat().st_uid,'writer_euid':os.geteuid(),'fixture_only':True}))
'''
        directory = str(Path(console.__file__).resolve().parent)
        argv = ["docker", "run", "-i", "--rm", "--pull=never", "--network=none", "--read-only", "--user=0:0",
                "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--security-opt=no-new-privileges:true",
                "--cpus=1", "--memory=256m", "--pids-limit=64", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                "--mount", "type=bind,src="+directory+",dst=/release,readonly", "--entrypoint", "/usr/local/bin/python3",
                self.python_image, "-I", "-B", "-"]
        result = subprocess.run(argv, input="CASE="+repr((mode, rejection))+"\n"+source,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        if rejection is None:
            self.assertIsNone(value['failure'], value)
            self.assertTrue(value['published'] and value['bytes_match'] and value['canonical_is_entry'] and value['context_shared'] and value['owner_authenticated'], value)
            self.assertNotEqual(value['installed_uid'], value['writer_euid'], value)
        else:
            self.assertFalse(value['published'], value)
            self.assertEqual(value['failure']['type'], 'RuntimeError', value)
            expected = 'authenticated sudo caller' if rejection == 'caller' else 'console entry module' if rejection == 'foreign_vm' else 'console imported module'
            self.assertIn(expected, value['failure']['message'], value)
            if rejection.startswith('foreign_'):
                self.assertTrue(value['foreign_unchanged'], value)

    def test_main_console_entry_shares_authenticated_owner_through_real_atomic_publish(self):
        self.invoke()

    def test_imported_console_entry_keeps_same_authenticated_owner_context(self):
        self.invoke(mode="import")

    def test_main_console_entry_rejects_invalid_caller_before_publish(self):
        self.invoke(rejection="caller")

    def test_main_console_entry_rejects_foreign_vm_alias_without_overwrite_or_publish(self):
        self.invoke(rejection="foreign_vm")

    def test_main_console_entry_rejects_foreign_console_module_before_publish(self):
        self.invoke(rejection="foreign_console")

    def test_rollback_console_entry_authenticates_owner_through_real_atomic_publish(self):
        self.invoke(mode="rollback")

    def test_rollback_console_entry_rejects_invalid_caller_before_publish(self):
        self.invoke(mode="rollback", rejection="caller")


class ScopeTests(unittest.TestCase):
    def args(self, **changes):
        value = dict(console_only=True, security_engine_only=False, engineering_only=False,
                     portal_only=False, preserve_tier1=False, migration=[], enable_file_detection=False)
        return SimpleNamespace(**dict(value, **changes))

    def manifest(self, **changes):
        value = dict(console_only=True, purpose="console-only", preserve_tier1=True,
                     migrations={}, enable_file_detection=False, billing_enabled="false",
                     services={s: {} for s in console.SERVICES})
        return dict(value, **changes)

    def test_builder_and_apply_only_allow_two_services(self):
        self.assertEqual(build.release_services(self.args()), console.SERVICES)
        self.assertEqual(vm.release_service_sets(self.manifest())[0], console.SERVICES)
        for change in (dict(security_engine_only=True), dict(engineering_only=True), dict(portal_only=True),
                       dict(preserve_tier1=True), dict(migration=["001.sql"]), dict(enable_file_detection=True)):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                build.release_services(self.args(**change))
        for change in (dict(console_only=1), dict(preserve_tier1=False), dict(security_engine_only=True),
                       dict(engineering_only=True), dict(portal_only=True), dict(migrations={"001.sql": "x"}),
                       dict(enable_file_detection=True), dict(services={**self.manifest()["services"], "security-engine": {}})):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                vm.release_service_sets(self.manifest(**change))

    def test_all_capacity_overrides_are_rejected(self):
        for field in console.FORBIDDEN_OVERRIDES:
            with self.subTest(field=field), self.assertRaises(AssertionError):
                build.release_services(self.args(**{field: 8}))
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                vm.release_service_sets(self.manifest(**{field: 8}))

    def test_source_gate_runs_on_both_sides_of_frozen_build(self):
        calls = []
        args = SimpleNamespace(repo="/home/dev/reviewed", revision="a"*40, console_only=True)
        with patch.object(build, "source_gate", side_effect=lambda *a: calls.append("gate") or "tree"), \
                patch.object(build, "build_fixed_source", side_effect=lambda *a: calls.append("build")):
            build.build(args)
        self.assertEqual(calls, ["gate", "build", "gate"])

    def test_rollback_source_failure_never_contacts_guest(self):
        args = SimpleNamespace(repo="/home/dev/reviewed", rollback_console_release_id="dev-test",
                               rollback_release_id=None, receipt_sha256="a"*64, vm="jjdguard-gateway")
        with patch.object(deploy.subprocess, "check_output", return_value="b"*40), \
                patch.object(deploy, "source_gate", side_effect=RuntimeError("source rejected")), \
                patch.object(deploy, "guest") as guest:
            with self.assertRaisesRegex(RuntimeError, "source rejected"):
                deploy.rollback_recorded(args)
            guest.assert_not_called()

    def test_rollback_id_and_receipt_cannot_inject_a_shell_or_path(self):
        for release, receipt in (("../dev-test", "a"*64), ("dev-test", "latest"), ("dev-test;touch /tmp/x", "a"*64)):
            with self.assertRaises(RuntimeError):
                console.rollback_guest_code(release, receipt)

    def test_full_remote_main_gate_cannot_be_bypassed_for_console(self):
        values = {
            ("status", "--porcelain"): "",
            ("rev-parse", "HEAD"): "a"*40,
            ("remote", "get-url", "origin"): build.ORIGIN,
            ("ls-remote", "origin", "refs/heads/main"): "a"*40+" refs/heads/main",
            ("replace", "-l"): "",
            ("rev-parse", "HEAD^{tree}"): "b"*40,
        }
        def run(argv, **kwargs):
            if argv[1].startswith("--git-dir="):
                return "a"*40
            return values[tuple(argv[3:])]
        with patch.object(build, "run", run):
            self.assertEqual(build.source_gate(Path("/home/dev/reviewed"), "a"*40), "b"*40)
        for key, value in ((("status", "--porcelain"), " M file"),
                           (("ls-remote", "origin", "refs/heads/main"), "c"*40+" refs/heads/main"),
                           (("replace", "-l"), "replace-ref")):
            before = values[key]
            values[key] = value
            with patch.object(build, "run", run), self.assertRaises(AssertionError):
                build.source_gate(Path("/home/dev/reviewed"), "a"*40)
            values[key] = before
        with patch.object(build, "run", side_effect=lambda argv, **kw: "c"*40 if argv[1].startswith("--git-dir=") else run(argv, **kw)), \
                self.assertRaises(AssertionError):
            build.source_gate(Path("/home/dev/reviewed"), "a"*40)

    def test_new_evidence_rejects_non_root_or_writable_paths(self):
        for owner, mode in ((1000, 0o100600), (0, 0o100666)):
            with patch.object(vm, "ROOT", Path("/opt/jjdguard")), \
                    patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=owner, st_mode=mode)), \
                    patch.object(Path, "is_symlink", return_value=False), self.assertRaisesRegex(RuntimeError, "unprotected"):
                REAL_PROTECTED(Path("/opt/jjdguard/development-releases/dev-test/receipt.json"))

    def test_host_checks_immutable_source_scripts_and_archive_before_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            media = Path(directory)
            archive = b"fixed-source-archive"
            scripts = {name: ("frozen "+name).encode() for name in ("vm_development_apply.py", "vm_console_release.py")}
            for name, content in scripts.items():
                (media/name).write_bytes(content)
            (media/"manifest.json").write_text("{}")
            (media/"images.tar").write_bytes(b"images")
            manifest = dict(console_only=True, revision="a"*40, source_archive_sha256=hashlib.sha256(archive).hexdigest(),
                            apply_script_sha256=vm.digest(media/"vm_development_apply.py"),
                            console_script_sha256=vm.digest(media/"vm_console_release.py"))
            def git(argv, **kwargs):
                return archive if argv[-2] == "archive" else scripts[argv[-1].split("/")[-1]]
            with patch.object(console, "validate_manifest"), patch.object(console, "check_image_archive"), \
                    patch.object(deploy.subprocess, "check_output", git):
                deploy.validate_console_source_media(Path("/home/dev/reviewed"), media, manifest)
                (media/"vm_console_release.py").write_text("tampered")
                with self.assertRaisesRegex(AssertionError, "frozen source"):
                    deploy.validate_console_source_media(Path("/home/dev/reviewed"), media, manifest)
                (media/"vm_console_release.py").write_bytes(scripts["vm_console_release.py"])
                with self.assertRaisesRegex(AssertionError, "archive differs"):
                    deploy.validate_console_source_media(Path("/home/dev/reviewed"), media, dict(manifest, source_archive_sha256="b"*64))

    def test_console_manifest_tree_must_match_the_live_source_gate(self):
        args = SimpleNamespace(repo="/home/dev/reviewed", vm="jjdguard-gateway")
        manifest = dict(console_only=True, revision="a"*40, tree="c"*40)
        with patch.object(deploy, "source_gate", return_value="b"*40), \
                patch.object(deploy, "digest", return_value="a"*64), \
                patch.object(deploy, "validate_console_source_media") as media, \
                patch.object(deploy, "guest") as guest, self.assertRaisesRegex(AssertionError, "tree"):
            deploy.deploy(args, Path("/home/dev/reviewed-media"), manifest)
        media.assert_not_called()
        guest.assert_not_called()

    def test_npm_keeps_explicit_billing_compile_value(self):
        for value in ("true", "false"):
            env = build.npm_environment({}, value, "/tmp/u", "/tmp/g")
            self.assertEqual(env["VITE_BILLING_ENABLED"], value)

    def test_boot_overlay_rejects_lists_resources_non_targets_and_other_environment(self):
        model = dict(name="project", services={s: dict(image="old", environment={"JJD_COMMIT": "old", "MODE": "keep"},
                                                                  security_opt=["no-new-privileges:true"])
                                              for s in console.SERVICES+("postgres",)}, networks={"n": {}})
        desired = copy.deepcopy(model)
        desired["services"]["control-plane"]["image"] = "new"
        desired["services"]["control-plane"]["environment"]["JJD_COMMIT"] = "new"
        overlay = console.scalar_overlay(model, desired)
        self.assertEqual(overlay, {"services": {"control-plane": {"image": "new", "environment": {"JJD_COMMIT": "new"}}}})
        for mutate in (lambda v: v["services"]["control-plane"]["security_opt"].append("seccomp:unconfined"),
                       lambda v: v["services"]["control-plane"]["environment"].update(MODE="changed"),
                       lambda v: v["services"]["postgres"].update(image="new-db"),
                       lambda v: v["networks"]["n"].update(internal=True),
                       lambda v: v["services"]["web-console"].update(volumes=[{"type": "bind", "source": "/x", "target": "/x"}])):
            value = copy.deepcopy(desired)
            mutate(value)
            with self.assertRaises(RuntimeError):
                console.scalar_overlay(model, value)


@unittest.skipUnless(Path("/home/dev").is_dir() and os.access("/home/dev", os.W_OK), "固定构建路径夹具仅在 home 执行")
class BuildMediaTests(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.temp = tempfile.TemporaryDirectory(prefix="console-build-fixture-", dir="/home/dev")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/"fixture-source"
        self.source.mkdir()
        files = {"VERSION": b"2.8.0\n", "deploy/seeds/policy.json": b"{\"frozen\":true}\n",
                 "apps/control-plane/cmd/server/main.go": b"package main\n",
                 "apps/web-console/package-lock.json": b"{}\n",
                 "apps/web-console/server.js": b"frozen server\n"}
        for name, content in files.items():
            path = self.source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        for name in ("vm_development_apply.py", "vm_console_release.py"):
            path = self.source/"deploy/release"/name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(console.__file__).parent/name, path)
        self.revision, self.tree = "d"*40, "e"*40
        self.archive = self.root/"immutable.tar"
        with tarfile.open(self.archive, "w", format=tarfile.PAX_FORMAT, pax_headers={"comment": self.revision}) as archive:
            for path in sorted(self.source.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(self.source), recursive=False)
        self.base = {service: "sha256:"+letter*64 for service, letter in zip(console.SERVICES, "ab")}
        self.base_file = self.root/"bases.json"
        self.base_file.write_text(json.dumps(self.base))
        self.calls, self.images, self.containers = [], {}, {}
        self.seed_change = False
        self.candidate_seed_change = False
        self.extra_seed_directory = None
        self.bad_payload = False
        self.user = "10001"

    def args(self, billing="false"):
        return SimpleNamespace(repo=str(self.root), output=str(self.root/"candidate"), revision=self.revision,
                               bases=str(self.base_file), console_only=True, security_engine_only=False,
                               engineering_only=False, portal_only=False, preserve_tier1=False,
                               enable_file_detection=False, migration=[], billing_enabled=billing, npm_cache="/home/dev/.npm")

    def fake_run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if "go" in Path(argv[0]).name and argv[1] == "build":
            self.assertEqual(kwargs["env"]["GOPROXY"], "off")
            Path(argv[argv.index("-o")+1]).write_bytes(b"frozen binary")
            return ""
        if argv[:2] == ["npm", "ci"]:
            self.assertIn("--offline", argv)
            return ""
        if argv[:3] == ["npm", "run", "build"]:
            dist = Path(kwargs["cwd"])/"dist"
            dist.mkdir()
            (dist/"index.html").write_text("<main>frozen console</main>")
            return ""
        self.assertEqual(argv[0], "docker")
        self.assertEqual(kwargs["env"]["DOCKER_HOST"], "unix:///var/run/docker.sock")
        if argv[1:3] == ["image", "inspect"]:
            name = argv[3]
            if name in self.images:
                return json.dumps([self.images[name]["record"]])
            service = next(s for s in console.SERVICES if name in (self.base[s], "jjdguard-isolated-base/"+s+":"+self.base[s][7:]))
            return json.dumps([dict(Id=self.base[service], Config=dict(User=self.user))])
        if argv[1] == "build":
            self.assertIn("--network=none", argv)
            self.assertIn("--pull=false", argv)
            context = Path(argv[-1])
            service = context.name
            content = json.dumps({"service": service}).encode()
            image = "sha256:"+hashlib.sha256(content).hexdigest()
            labels = dict(argv[i+1].split("=", 1) for i, value in enumerate(argv) if value == "--label")
            entry = dict(record=dict(Id=image, Config=dict(User=self.user, Labels=labels)), context=context, config=content)
            self.images[argv[argv.index("-t")+1]] = entry
            self.images[image] = entry
            return ""
        if argv[1] == "create":
            name = "fixture-container-"+str(len(self.containers))
            self.containers[name] = argv[2]
            return name
        if argv[1] == "cp":
            name, relative = argv[2].split(":", 1)
            image = self.containers[name]
            target = Path(argv[3])
            if relative == "/etc/uag/seeds":
                shutil.copytree(self.source/"deploy/seeds", target)
                if self.seed_change or (self.candidate_seed_change and image in self.images):
                    (target/"policy.json").write_bytes(b"changed seeds")
                if self.extra_seed_directory == ("candidate" if image in self.images else "base"):
                    (target/"unexpected-empty-directory").mkdir()
            else:
                source = self.images[image]["context"]/"runtime"/relative.lstrip("/")
                shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)
                if self.bad_payload:
                    next(target.rglob("*"), target).write_bytes(b"wrong payload")
            return ""
        if argv[1] == "rm":
            self.containers.pop(argv[2])
            return ""
        if argv[1:3] == ["image", "save"]:
            target = Path(argv[argv.index("-o")+1])
            index = []
            with tarfile.open(target, "w") as archive:
                for tag in argv[5:]:
                    entry = self.images[tag]
                    name = entry["context"].name+".json"
                    info = tarfile.TarInfo(name)
                    info.size = len(entry["config"])
                    archive.addfile(info, io.BytesIO(entry["config"]))
                    index.append(dict(Config=name, RepoTags=[tag], Layers=[]))
                content = json.dumps(index).encode()
                info = tarfile.TarInfo("manifest.json")
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            return ""
        raise AssertionError("不允许的构建夹具命令："+repr(argv))

    def execute(self, billing="false"):
        with patch.object(build, "run", self.fake_run), patch.object(build.fcntl, "flock"), \
                patch.object(build.Path, "open", lambda path, *a, **kw: self.fixture_open(path, *a, **kw)):
            build.build_fixed_source(self.args(billing), self.tree, (self.archive, build.digest(self.archive)))
        return self.root/"candidate/media"

    def fixture_open(self, path, *args, **kwargs):
        if str(path) == "/home/dev/.cache/jjdguard/home-release.lock":
            stream = self.real_open(self.root/"fixture-build.lock", *args, **kwargs)
            self.addCleanup(stream.close)
            return stream
        return self.real_open(path, *args, **kwargs)

    real_open = staticmethod(Path.open)

    def test_full_fake_build_ships_two_images_and_preserves_seeds(self):
        media = self.execute()
        manifest = json.loads((media/"manifest.json").read_text())
        self.assertEqual({p.name for p in media.iterdir()}, set(console.MEDIA_FILES))
        self.assertEqual(set(manifest["services"]), set(console.SERVICES))
        self.assertEqual(manifest["source_archive_sha256"], build.digest(self.archive))
        self.assertEqual(manifest["control_plane_seeds_sha256"], {"/etc/uag/seeds/policy.json": build.digest(self.source/"deploy/seeds/policy.json")})
        self.assertEqual(manifest["control_plane_seed_directories"], ["/etc/uag/seeds"])
        recipe = (self.root/"candidate/build/control-plane/Dockerfile").read_text()
        self.assertNotIn("rm -rf /etc/uag/seeds", recipe)
        self.assertFalse((self.root/"candidate/build/control-plane/runtime/etc").exists())
        self.assertFalse(any(argv[1] in ("run", "exec") for argv, kw in self.calls if argv[0] == "docker"))
        self.assertFalse(self.containers)
        console.validate_manifest(manifest)
        console.check_image_archive(media, manifest)

    def test_full_fake_build_compiles_explicit_true_billing(self):
        manifest = json.loads((self.execute("true")/"manifest.json").read_text())
        self.assertEqual(manifest["billing_enabled"], "true")
        npm = [kw for argv, kw in self.calls if argv[0] == "npm"]
        self.assertTrue(npm)
        self.assertTrue(all(kw["env"]["VITE_BILLING_ENABLED"] == "true" for kw in npm))

    def test_source_seed_change_is_rejected_before_building_an_image(self):
        self.seed_change = True
        with self.assertRaisesRegex(AssertionError, "seeds"):
            self.execute()
        self.assertFalse(any(argv[:2] == ["docker", "build"] for argv, kw in self.calls))
        self.assertFalse(self.containers)

    def test_candidate_seed_change_is_rejected_before_creating_media(self):
        self.candidate_seed_change = True
        with self.assertRaisesRegex(AssertionError, "seeds"):
            self.execute()
        self.assertFalse((self.root/"candidate/media").exists())
        self.assertFalse(self.containers)

    def test_base_extra_empty_seed_directory_is_rejected_before_image_build(self):
        self.extra_seed_directory = "base"
        with self.assertRaisesRegex(AssertionError, "seed"):
            self.execute()
        self.assertFalse(any(argv[:2] == ["docker", "build"] for argv, kw in self.calls))
        self.assertFalse(self.containers)

    def test_candidate_extra_empty_seed_directory_is_rejected_before_media(self):
        self.extra_seed_directory = "candidate"
        with self.assertRaisesRegex(AssertionError, "seed"):
            self.execute()
        self.assertFalse((self.root/"candidate/media").exists())
        self.assertFalse(self.containers)

    def test_third_base_is_rejected_without_building_an_image(self):
        self.base_file.write_text(json.dumps(dict(self.base, **{"security-engine": "sha256:"+"c"*64})))
        with self.assertRaises(AssertionError):
            self.execute()
        self.assertFalse(self.calls)

    def test_root_base_is_rejected_before_building_an_image(self):
        self.user = "root"
        with self.assertRaisesRegex(AssertionError, "non-root"):
            self.execute()
        self.assertFalse(any(argv[:2] == ["docker", "build"] for argv, kw in self.calls))

    def test_image_payload_mismatch_prevents_media_publication(self):
        self.bad_payload = True
        with self.assertRaisesRegex(AssertionError, "payload"):
            self.execute()
        self.assertFalse((self.root/"candidate/media").exists())
        self.assertFalse(self.containers)


class ComposeRenderingTests(unittest.TestCase):
    def test_real_compose_scalar_chain_is_equivalent_without_recreation(self):
        env = dict(console.controlled_environment(), HOME=os.path.expanduser("~"))
        try:
            build.run(["docker", "compose", "version"], env=env)
        except (FileNotFoundError, build.subprocess.CalledProcessError):
            self.skipTest("本机没有 Docker Compose，真实配置渲染需在 home 运行")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root/"base.json"
            value = dict(name="console-render-fixture", services={}, networks={"default": {}})
            for service in console.SERVICES+("postgres",):
                value["services"][service] = dict(image="sha256:"+"a"*64,
                    environment={"FIXTURE_LITERAL": "literal$$dollar", "JJD_COMMIT": "before"},
                    security_opt=["no-new-privileges:true"], command=["sh", "-c", "printf '$$FIXTURE_LITERAL'"],
                    networks={"default": {}})
            base.write_text(json.dumps(value))
            def render(files):
                argv = ["docker", "compose", "--project-directory", str(root)]
                for path in files:
                    argv += ["-f", str(path)]
                return json.loads(build.run(argv+["config", "--format", "json"], env=env, cwd=root))
            before = render([base])
            after = copy.deepcopy(before)
            for service in console.SERVICES:
                after["services"][service].update(image="sha256:"+"b"*64, pull_policy="never")
                after["services"][service]["environment"]["JJD_COMMIT"] = "after"
            overlay = root/"overlay.json"
            overlay.write_text(json.dumps(console.scalar_overlay(before, after)))
            self.assertEqual(render([base, overlay]), after)
            canonical = root/"canonical.json"
            canonical.write_text(json.dumps(after))
            self.assertEqual(render([canonical]), after)
            self.assertEqual(render([base, overlay])["services"]["control-plane"]["security_opt"], ["no-new-privileges:true"])
            self.assertEqual(render([base, overlay])["services"]["postgres"], before["services"]["postgres"])


class RuntimeContractRepresentationTests(unittest.TestCase):
    def row(self):
        return dict(Id="control-plane-old", Name="/control-plane", Path="/app/control-plane", Args=[],
                    Config=dict(Image="sha256:"+"a"*64, User="10001", Env=["SECURITY_AUDIT_ONLY=true"],
                                Cmd=["/app/control-plane"], Labels={}),
                    HostConfig=dict(Binds=["existing-retention:/data/retention:rw", "/installed/seeds:/etc/uag/seeds:ro"],
                                    Dns=None, DnsOptions=None, DnsSearch=None, ReadonlyRootfs=True),
                    Mounts=[dict(Type="volume", Name="existing-retention", Source="/var/lib/docker/volumes/existing-retention/_data",
                                 Destination="/data/retention", RW=True, Mode="rw", Propagation=""),
                            dict(Type="bind", Source="/installed/seeds", Destination="/etc/uag/seeds",
                                 RW=False, Mode="ro", Propagation="rprivate")],
                    NetworkSettings=dict(Networks={}))

    def test_target_runtime_contract_accepts_only_bind_list_order_and_empty_dns_representation(self):
        before = self.row()
        after = copy.deepcopy(before)
        after["HostConfig"]["Binds"].reverse()
        after["Mounts"].reverse()
        for field in ("Dns", "DnsOptions", "DnsSearch"):
            after["HostConfig"][field] = []
        self.assertEqual(console.runtime_contract(before, allow_provenance=True),
                         console.runtime_contract(after, allow_provenance=True))
        self.assertNotEqual(console.runtime_contract(before), console.runtime_contract(after),
                            "preserved non-target runtime evidence must retain raw Docker inputs")

    def test_target_runtime_contract_accepts_each_null_or_empty_dns_list(self):
        for field in ("Dns", "DnsOptions", "DnsSearch"):
            with self.subTest(field=field):
                before = self.row()
                after = copy.deepcopy(before)
                after["HostConfig"][field] = []
                self.assertEqual(console.runtime_contract(before, allow_provenance=True),
                                 console.runtime_contract(after, allow_provenance=True))
                after["HostConfig"].pop(field)
                self.assertEqual(console.runtime_contract(before, allow_provenance=True),
                                 console.runtime_contract(after, allow_provenance=True))

    def test_target_runtime_contract_treats_compose_replace_as_target_provenance(self):
        before = self.row()
        after = copy.deepcopy(before)
        after["Config"]["Labels"]["com.docker.compose.replace"] = "control-plane-1"
        self.assertEqual(console.runtime_contract(before, allow_provenance=True),
                         console.runtime_contract(after, allow_provenance=True))
        self.assertNotEqual(console.runtime_contract(before), console.runtime_contract(after),
                            "non-target fingerprints must retain replacement metadata")
        after["Config"]["Labels"]["application-policy"] = "changed"
        self.assertNotEqual(console.runtime_contract(before, allow_provenance=True),
                            console.runtime_contract(after, allow_provenance=True))

    def test_target_runtime_contract_retains_real_mount_identity_and_options(self):
        mutations = (
            lambda row: row["Mounts"][0].update(Name="different-retention"),
            lambda row: row["Mounts"][0].update(Source="/var/lib/docker/volumes/different-retention/_data"),
            lambda row: row["Mounts"][0].update(Type="bind"),
            lambda row: row["Mounts"][1].update(Source="/other-installation/seeds"),
            lambda row: row["Mounts"][1].update(Destination="/other/seeds"),
            lambda row: row["Mounts"][1].update(RW=True),
            lambda row: row["Mounts"][1].update(Propagation="rshared"),
            lambda row: row["HostConfig"]["Binds"].append("/unexpected:/data/retention:rw"),
            lambda row: row["HostConfig"]["Binds"].append(row["HostConfig"]["Binds"][0]),
            lambda row: row["HostConfig"].update(Mounts=[dict(Type="volume", Source="existing-retention", Target="/data/retention",
                                                           VolumeOptions=dict(NoCopy=True))]),
        )
        before = self.row()
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                after = copy.deepcopy(before)
                mutate(after)
                self.assertNotEqual(console.runtime_contract(before, allow_provenance=True),
                                    console.runtime_contract(after, allow_provenance=True))

    def test_target_runtime_contract_retains_nonempty_dns_values_and_resolver_order(self):
        for field, values in (("Dns", ["192.0.2.1", "192.0.2.2"]), ("DnsOptions", ["timeout:2", "attempts:3"]),
                              ("DnsSearch", ["first.example", "second.example"])):
            with self.subTest(field=field):
                before = self.row()
                after = copy.deepcopy(before)
                after["HostConfig"][field] = values
                self.assertNotEqual(console.runtime_contract(before, allow_provenance=True),
                                    console.runtime_contract(after, allow_provenance=True))
                before["HostConfig"][field] = list(reversed(values))
                self.assertNotEqual(console.runtime_contract(before, allow_provenance=True),
                                    console.runtime_contract(after, allow_provenance=True))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"opt/jjdguard"
        self.media = self.root/"development-releases/dev-test"
        self.media.mkdir(parents=True)
        self.release_root = self.root/"releases/installed"
        self.workdir = self.release_root/"deploy/docker-compose"
        (self.workdir/"active-config").mkdir(parents=True)
        (self.workdir/".upgrade").mkdir()
        (self.workdir/"bin").mkdir()
        for path in (self.workdir/"bin/docker-compose", self.workdir/"compose-wrapper.sh", self.release_root/"jjdctl"):
            path.write_text("fixture startup input\n")
        (self.workdir/".env").write_text("TEST='fixture$literal'\n")
        (self.root/"current").symlink_to(self.release_root, target_is_directory=True)
        self.project = "existing-project"
        self.chain = self.workdir/".upgrade/compose-files"
        self.base = self.workdir/"docker-compose.offline.yml"
        self.old_overlay = self.workdir/"active-config/old-overlay.json"
        self.old = {s: "sha256:"+c*64 for s, c in zip(console.SERVICES, "ab")}
        self.seed_hashes = {"/etc/uag/seeds/policy.json": "7"*64}
        self.configs = {s: json.dumps({"fixture": s}).encode() for s in console.SERVICES}
        self.new = {s: "sha256:"+hashlib.sha256(v).hexdigest() for s, v in self.configs.items()}
        self.model = dict(name=self.project, services={}, networks={"default": {"name": "existing-network"}},
                          volumes={"database": {"name": "existing-database"}})
        self.names = console.SERVICES+("security-engine", "gateway-core", "proxy-server", "worker", "tier1-classifier", "judge", "postgres", "chat-portal-ui", "chat-portal-proxy")
        for service in self.names:
            self.model["services"][service] = dict(image=self.old.get(service, "sha256:"+"c"*64),
                                                   environment={"JJD_COMMIT": "old", "SECRET": "fixture$literal", "BILLING_ENABLED": "false", "SECURITY_AUDIT_ONLY": "true"},
                                                   security_opt=["no-new-privileges:true"], networks={"default": {}},
                                                   volumes=[], read_only=True)
        # 渲染拓扑与现网一致：cp 依赖 postgres/redis，web 依赖 control-plane/gateway-core
        self.model["services"]["control-plane"]["depends_on"] = {
            "postgres": {"condition": "service_healthy"}, "redis": {"condition": "service_healthy"}}
        self.model["services"]["web-console"]["depends_on"] = {
            "gateway-core": {"condition": "service_healthy"}, "control-plane": {"condition": "service_healthy"}}
        self.base.write_text(json.dumps(self.model))
        self.old_overlay.write_text(json.dumps({"services": {}}))
        self.chain.write_text(str(self.old_overlay)+"\n")
        (self.workdir/".upgrade/project-name").write_text(self.project+"\n")
        (self.workdir/".upgrade/project-directory").write_text(str(self.workdir)+"\n")
        self.old_chain = self.chain.read_bytes()
        for path in (self.chain, self.old_overlay, self.workdir/".upgrade/project-name", self.workdir/".upgrade/project-directory"):
            path.chmod(0o600)
        self.rows = [self.row(s) for s in self.names]
        spare = self.row("unrelated")
        spare["Config"]["Labels"] = {}
        spare["State"]["Status"] = "exited"
        self.rows.append(spare)
        self.baseline = copy.deepcopy(self.rows)
        self.policy = {"billing_enabled": "false", "security_audit_only": "true"}
        self.manifest = dict(schema=1, purpose="console-only", console_only=True, release_id="dev-test", revision="d"*40,
                             tree="e"*40, source_archive_sha256="6"*64, version="2.8.0", created_at="now", preserve_tier1=True,
                             migrations={}, migration_preconditions={}, enable_file_detection=False, billing_enabled="false",
                             candidate_validation={"console_payload_verified": True, "control_plane_seeds": "preserved"},
                             services={s: dict(image_id=self.new[s], base_image_id=self.old[s], tag="candidate/"+s+":fixed",
                                               payload_sha256=({"/app/control-plane": "f"*64, "/app/VERSION": "f"*64} if s == "control-plane" else {"/app/dist/index.html": "f"*64, "/app/server.js": "f"*64}))
                                       for s in console.SERVICES}, control_plane_seeds_sha256=self.seed_hashes,
                             control_plane_seed_directories=["/etc/uag/seeds"])
        for name, key in (("vm_development_apply.py", "apply_script_sha256"), ("vm_console_release.py", "console_script_sha256")):
            (self.media/name).write_text("# frozen fixture\n")
            self.manifest[key] = vm.digest(self.media/name)
        self.make_archive()
        (self.media/"manifest.json").write_text(json.dumps(self.manifest))
        self.calls = []
        self.compose_version = "v5.3.0"
        self.docker_binary = self.workdir/"bin/docker"
        self.docker_binary.write_text("fixture docker binary\n")
        self.docker_binary.chmod(0o755)
        (self.workdir/"bin/docker-compose").chmod(0o755)
        self.switch_count = 0
        self.render_hash_override = {}
        self.probe_containers = {}
        self.probe_downs = []
        self.probe_stamp = "old"
        self.daemon_logging = "json-file"
        self.fail_switch = False
        self.fail_restore = False
        self.unhealthy = False
        self.bad_payload = False
        self.bad_seeds = False
        self.wrong_provenance = False
        self.fail_phase = None
        self.patches = [patch.object(vm, "ROOT", self.root), patch.object(console, "protected", self.fixture_protected),
                        patch.object(console, "inspect_all", lambda: copy.deepcopy(self.rows)),
                        patch.object(vm, "run", self.fake_run),
                        patch.object(console.shutil, "which", side_effect=lambda name, path=None: str(self.docker_binary) if name == "docker" else None),
                        patch.object(console.shutil, "disk_usage", return_value=SimpleNamespace(free=10*1024**3))]
        for mocked in self.patches:
            mocked.start()
            self.addCleanup(mocked.stop)
        self.release = console.ConsoleRelease(self.media, vm.digest(self.media/"manifest.json"))
        self.addCleanup(self.release.lock.close)

    def make_archive(self, extra=False):
        with tarfile.open(self.media/"images.tar", "w") as archive:
            index = []
            for service, content in self.configs.items():
                name = service+".json"
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
                index.append(dict(Config=name, RepoTags=[self.manifest["services"][service]["tag"]], Layers=[]))
            if extra:
                index.append(dict(Config="control-plane.json", RepoTags=["third:latest"], Layers=[]))
            content = json.dumps(index).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        self.manifest["images_sha256"] = vm.digest(self.media/"images.tar")

    def fixture_protected(self, path, directory=False):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.root))
        self.assertFalse(path.is_symlink())
        self.assertTrue(path.is_dir() if directory else path.is_file())
        return path

    def row(self, service):
        image = self.old.get(service, "sha256:"+"c"*64)
        item = self.model["services"].get(service, self.model["services"]["postgres"])
        return dict(Id=service+"-old", Image=image, Name="/"+service, Path="/app/"+service, Args=[], RestartCount=0,
                    State=dict(Status="running", StartedAt="before", Health=dict(Status="healthy")),
                    Config=dict(Image=image, Hostname="old-auto-host", User="10001", Cmd=["/app/"+service], Entrypoint=[],
                                Env=[k+"="+v for k, v in item["environment"].items()],
                                Labels={"com.docker.compose.project": self.project, "com.docker.compose.service": service,
                                        "com.docker.compose.project.working_dir": str(self.workdir),
                                        "com.docker.compose.project.config_files": str(self.base)+","+str(self.old_overlay),
                                        "com.docker.compose.config-hash": "old",
                                        # 现网实测：full-release 创建的 cp 容器标签为空串、web 非空
                                        "com.docker.compose.depends_on":
                                            "gateway-core:service_healthy:false,control-plane:service_healthy:false"
                                            if service == "web-console" else ""}),
                    HostConfig=dict(ReadonlyRootfs=True, SecurityOpt=["no-new-privileges:true"]), Mounts=[],
                    NetworkSettings=dict(Networks={"existing-network": {"NetworkID": "stable-network", "Aliases": [service]}}))

    def render(self, files):
        model = {}
        def merge(left, right):
            for key, value in right.items():
                if isinstance(value, dict) and isinstance(left.get(key), dict):
                    merge(left[key], value)
                elif isinstance(value, list) and isinstance(left.get(key), list):
                    left[key] += copy.deepcopy(value)
                else:
                    left[key] = copy.deepcopy(value)
        for path in files:
            merge(model, json.loads(Path(path).read_text()))
        return model

    def fake_run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            name = argv[3]
            service = next((s for s in console.SERVICES if name in (self.manifest["services"][s]["tag"], self.new[s])), None)
            image = self.new[service] if service else name
            labels = {} if not service else {"org.opencontainers.image.revision": self.manifest["revision"],
                                             "com.jjdguard.source.tree": self.manifest["tree"],
                                             "com.jjdguard.base.image": self.old[service], "com.jjdguard.release.id": "dev-test"}
            base_service = next((s for s in self.names if self.model["services"][s]["image"] == image), "control-plane")
            return json.dumps([dict(Id=image, Config=dict(Labels=labels, User="10001", Cmd=["/app/"+(service or base_service)]))])
        if argv[:3] == ["docker", "compose", "version"]:
            raise vm.CommandFailure("command failed: docker compose; details in protected release log")
        if argv[0] == str(self.workdir/"bin/docker-compose") and argv[1:] == ["version", "--short"]:
            return self.compose_version
        if argv[:3] == ["docker", "image", "load"]:
            return "loaded"
        if argv[0] in (str(self.workdir/"bin/docker-compose"), "sh"):
            files = [argv[i+1] for i, v in enumerate(argv) if v == "-f"]
            model = self.render(files)
            if "config" in argv:
                if "--hash" in argv:
                    return argv[-1]+" "+(self.render_hash_override.get(argv[-1], "old"))+"\n"
                if "--no-env-resolution" not in argv:
                    for item in model.get("services", {}).values():
                        item.pop("env_file", None)
                return json.dumps(model)
            if "create" in argv:
                project = argv[argv.index("--project-name")+1]
                self.assertNotIn("--remove-orphans", argv)
                self.assertEqual(project, self.project+"-hashprobe")
                service = argv[-1]
                self.probe_containers.setdefault(project, {})[service] = project+"-"+service+"-probe"
                return ""
            if "down" in argv:
                project = argv[argv.index("--project-name")+1]
                self.assertIn("--volumes", argv)
                self.assertIn("--remove-orphans", argv)
                self.assertEqual(project, self.project+"-hashprobe")
                self.probe_downs.append(project)
                self.probe_containers.pop(project, None)
                return ""
            offset = argv.index("up")
            self.assertEqual(argv[offset:offset+6], ["up", "-d", "--no-deps", "--pull", "never", "--force-recreate"])
            targets = argv[offset+6:]
            self.assertTrue(targets and set(targets) <= set(console.SERVICES))
            self.switch_count += 1
            candidate = model["services"]["control-plane"]["image"] == self.new["control-plane"]
            for service in targets:
                row = next(r for r in self.rows if r["Name"] == "/"+service)
                item = model["services"][service]
                row.update(Id=service+"-new-"+str(self.switch_count), Image=item["image"], RestartCount=0)
                row["State"].update(Status="running", StartedAt="new-"+str(self.switch_count))
                row["State"]["Health"]["Status"] = "unhealthy" if candidate and self.unhealthy else "healthy"
                row["Config"].update(Image=item["image"], Hostname="new-auto-host", Env=[k+"="+str(v) for k, v in item["environment"].items()])
                row["Config"]["Labels"].update({"com.docker.compose.project.config_files": ",".join(files), "com.docker.compose.config-hash": "new"})
                # 现网实测：多服务 up 重建的容器标签非空且键序随文件；单服务
                # restore 重建的容器标签为空串——同一渲染拓扑、不同执行元数据
                row["Config"]["Labels"]["com.docker.compose.depends_on"] = (
                    ("postgres:service_healthy:false,redis:service_healthy:false" if service == "control-plane"
                     else "control-plane:service_healthy:false,gateway-core:service_healthy:false") if candidate else "")
                if candidate:
                    row["Config"]["Labels"].update({"org.opencontainers.image.revision": self.manifest["revision"],
                                                   "com.jjdguard.source.tree": self.manifest["tree"],
                                                   "com.jjdguard.base.image": self.old[service], "com.jjdguard.release.id": "dev-test"})
                    if self.wrong_provenance:
                        row["Config"]["Labels"]["org.opencontainers.image.revision"] = "0"*40
                else:
                    for key in console.IMAGE_LABELS:
                        row["Config"]["Labels"].pop(key, None)
                if service == "control-plane" and ((candidate and self.fail_switch) or (not candidate and self.fail_restore)):
                    raise RuntimeError("simulated partial switch")
            return ""
        if argv[:2] == ["docker", "ps"] and "-a" in argv:
            project = next(f.split("=", 2)[2] for f in argv if f.startswith("label=com.docker.compose.project="))
            service = next((f.split("=", 2)[2] for f in argv if f.startswith("label=com.docker.compose.service=")), None)
            rows = self.probe_containers.get(project, {})
            return "\n".join(identifier+" "+project+"-"+name+"-1"
                             for name, identifier in rows.items() if service is None or name == service)
        if argv[:3] == ["docker", "container", "inspect"]:
            identifier = argv[3]
            matches = [(project, name) for project, rows in self.probe_containers.items()
                       for name, value in rows.items() if value == identifier]
            self.assertEqual(len(matches), 1, "probe container inspect left the probe project scope")
            project, name = matches[0]
            return json.dumps([dict(Id=identifier, Image=self.old.get(name, "sha256:"+"c"*64), State=dict(Status="created"),
                                    Config=dict(Labels={"com.docker.compose.project": project, "com.docker.compose.service": name,
                                                        "com.docker.compose.config-hash": self.probe_stamp}))])
        if argv[:3] == ["docker", "network", "ls"] or argv[:3] == ["docker", "volume", "ls"]:
            project = next(f for f in argv if f.startswith("label=com.docker.compose.project="))
            self.assertTrue(project.endswith("-hashprobe"))
            return ""
        if argv[:4] == ["docker", "info", "--format", "{{.LoggingDriver}}"]:
            return self.daemon_logging
        if argv[:2] == ["docker", "exec"]:
            if "psql" in argv:
                self.assertIn("SELECT", kwargs.get("input", ""))
                self.assertNotIn("UPDATE", kwargs.get("input", ""))
                return json.dumps(self.policy)
            if "sha256sum" in argv:
                paths = argv[argv.index("--")+1:]
                return "\n".join((self.seed_hashes.get(path, "0"*64 if self.bad_payload else "f"*64))+"  "+path for path in paths)
            if "find" in argv:
                return "d /etc/uag/seeds\n"+"\n".join("f "+path for path in ({} if self.bad_seeds else self.seed_hashes))
        raise AssertionError("unexpected command: "+repr(argv))

    def stage_apply(self):
        self.release.stage()
        self.release.apply()
        return vm.digest(self.media/"receipt.json")

    def assert_non_targets_unchanged(self):
        self.assertEqual(self.rows[2:], self.baseline[2:])
        for argv in self.calls:
            self.assertFalse(set(argv) & {"pg_dump", "pg_restore", "stop", "start", "iptables", "migrate"})
            if "psql" in argv:
                self.assertIn("-X", argv)

    def test_success_only_recreates_two_services_and_persists_exact_startup_model(self):
        sha = self.stage_apply()
        for service in console.SERVICES:
            self.assertEqual(next(r for r in self.rows if r["Name"] == "/"+service)["Image"], self.new[service])
        self.assert_non_targets_unchanged()
        overlays = self.chain.read_text().splitlines()
        self.assertEqual(overlays[0], str(self.old_overlay))
        persistent = json.loads(Path(overlays[-1]).read_text())
        self.assertEqual(set(persistent["services"]), set(console.SERVICES))
        self.assertNotIn("security_opt", json.dumps(persistent))
        self.assertEqual(self.render([self.base, *overlays]), json.loads((self.media/"state/candidate.json").read_text()))
        self.assertEqual(self.chain.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(overlays[-1]).stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.release.pointer.read_text())["receipt_sha256"], sha)

    def probe_calls(self, command):
        return [argv for argv in self.calls if command in argv and "--project-name" in argv
                and argv[argv.index("--project-name")+1] == self.project+"-hashprobe"]

    def test_absent_db_billing_row_falls_back_to_frozen_env(self):
        self.policy = {"security_audit_only": "true"}
        sha = self.stage_apply()
        self.assert_non_targets_unchanged()

    def test_absent_db_billing_row_with_mismatching_frozen_env_is_rejected(self):
        self.policy = {"security_audit_only": "true"}
        model = json.loads(self.base.read_text())
        model["services"]["control-plane"]["environment"]["BILLING_ENABLED"] = "true"
        self.base.write_text(json.dumps(model))
        row = next(r for r in self.rows if r["Name"] == "/control-plane")
        row["Config"]["Env"] = [k+"="+str(v) for k, v in model["services"]["control-plane"]["environment"].items()]
        with self.assertRaises(RuntimeError) as caught:
            self.release.stage()
        self.assertIn("billing compile value differs from managed mode", str(caught.exception))

    def test_silent_logging_accepts_only_daemon_default_driver(self):
        next(r for r in self.rows if r["Name"] == "/control-plane")["HostConfig"]["LogConfig"] = dict(Type="json-file", Config={})
        self.stage_apply()
        self.assert_non_targets_unchanged()

    def test_silent_logging_rejects_container_driver_different_from_daemon(self):
        next(r for r in self.rows if r["Name"] == "/control-plane")["HostConfig"]["LogConfig"] = dict(Type="local", Config={})
        with self.assertRaises(RuntimeError) as caught:
            self.release.stage()
        self.assertIn("effective target logging is not explicitly frozen", str(caught.exception))

    def test_explicit_null_entrypoint_and_command_fall_back_to_image_defaults(self):
        self.old_overlay.write_text(json.dumps({"services": {"control-plane": {"entrypoint": None, "command": None}}}))
        sha = self.stage_apply()
        self.assertEqual(next(r for r in self.rows if r["Name"] == "/control-plane")["Config"]["Cmd"], ["/app/control-plane"])
        self.assert_non_targets_unchanged()

    def test_config_hash_direct_match_skips_probe(self):
        self.stage_apply()
        self.assertFalse(self.probe_calls("create"))
        self.assertFalse(self.probe_calls("down"))
        self.assert_non_targets_unchanged()

    def test_config_hash_render_mismatch_with_probe_stamp_match_is_recorded(self):
        self.render_hash_override["control-plane"] = "render-divergent"
        self.probe_stamp = "old"
        sha = self.stage_apply()
        creates, downs = self.probe_calls("create"), self.probe_calls("down")
        self.assertEqual(len(creates), 1)
        self.assertEqual(len(downs), 1)
        self.assertIn("--volumes", downs[0])
        self.assertIn("--remove-orphans", downs[0])
        record = next(item for item in json.loads((self.media/"state/before.json").read_text())["config_hash_exceptions"]
                      if item["service"] == "control-plane")
        self.assertEqual(record["rendered"], "render-divergent")
        self.assertEqual(record["stamp"], "old")
        self.assertEqual(record["label"], "old")
        self.assertEqual(record["probe_project"], self.project+"-hashprobe")
        self.assertTrue(record["timestamp"])
        self.assert_non_targets_unchanged()

    def test_config_hash_render_and_stamp_both_differ_fails_closed(self):
        self.render_hash_override["control-plane"] = "render-divergent"
        self.probe_stamp = "deadbeef"
        with self.assertRaises(RuntimeError) as caught:
            self.release.stage()
        self.assertIn("historical service config hash differs", str(caught.exception))
        self.assertEqual(len(self.probe_calls("down")), 1, "probe cleanup must run before failing closed")
        self.assertEqual(self.rows, self.baseline)

    def test_compose_image_labels_can_change_only_to_the_verified_image(self):
        for row in self.rows:
            row["Config"]["Labels"]["com.docker.compose.image"] = row["Image"]
        self.baseline = copy.deepcopy(self.rows)
        run = self.fake_run
        def actual_labels(argv, **kwargs):
            result = run(argv, **kwargs)
            if "up" in argv:
                for row in self.rows[:2]:
                    row["Config"]["Labels"]["com.docker.compose.image"] = row["Image"]
            return result
        with patch.object(vm, "run", actual_labels):
            sha = self.stage_apply()
            self.release.rollback(sha)
        self.assert_non_targets_unchanged()

    def test_changed_live_config_between_switch_and_verify_is_rejected(self):
        self.release.stage()
        switch = self.release.switch
        def changed():
            switch()
            self.release.live.write_text("{}")
        self.release.switch = changed
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual(self.release.live.read_text(), "{}")
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)

    def test_target_or_non_target_drift_before_up_does_not_recreate_any_container(self):
        self.release.stage()
        publish = self.release.publish_live
        def changed():
            publish()
            self.rows[0]["RestartCount"] = 1
        self.release.publish_live = changed
        with self.assertRaisesRegex(RuntimeError, "runtime|rollback incomplete"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.rows[0]["Id"], self.baseline[0]["Id"])
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_target_runtime_contract_representation_changes_pass_apply_and_rollback(self):
        for path in (self.root.parent, self.root, self.media.parent, self.media,
                     self.root/"releases", self.release_root, self.release_root/"deploy",
                     self.workdir, self.workdir/"active-config", self.workdir/".upgrade", self.workdir/"bin"):
            path.chmod(0o755)
        source = str(self.workdir/"seeds")
        Path(source).mkdir(mode=0o755)
        self.model["volumes"]["retention"] = {"name": "existing-retention"}
        self.model["services"]["control-plane"]["volumes"] = [
            dict(type="volume", source="retention", target="/data/retention", read_only=False),
            dict(type="bind", source=source, target="/etc/uag/seeds", read_only=True,
                 bind=dict(propagation="rprivate", create_host_path=False))]
        self.base.write_text(json.dumps(self.model))
        self.rows[0]["Mounts"] = [
            dict(Type="volume", Name="existing-retention", Source="/var/lib/docker/volumes/existing-retention/_data",
                 Destination="/data/retention", RW=True, Mode="rw", Propagation=""),
            dict(Type="bind", Source=source, Destination="/etc/uag/seeds", RW=False, Mode="ro", Propagation="rprivate")]
        self.rows[0]["HostConfig"]["Binds"] = ["existing-retention:/data/retention:rw", source+":/etc/uag/seeds:ro"]
        for row in self.rows[:2]:
            for field in ("Dns", "DnsOptions", "DnsSearch"):
                row["HostConfig"][field] = None
        self.baseline = copy.deepcopy(self.rows)
        run = self.fake_run
        def recreated(argv, **kwargs):
            value = run(argv, **kwargs)
            if "up" in argv:
                self.rows[0]["HostConfig"]["Binds"].reverse()
                self.rows[0]["Mounts"].reverse()
                for row in self.rows[:2]:
                    for field in ("Dns", "DnsOptions", "DnsSearch"):
                        row["HostConfig"][field] = []
            return value
        with patch.object(vm, "run", recreated):
            receipt = self.stage_apply()
            self.release.rollback(receipt)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual(sorted(self.rows[0]["Mounts"], key=console.object_hash),
                         sorted(self.baseline[0]["Mounts"], key=console.object_hash))
        self.assert_non_targets_unchanged()

    def test_contract_mismatch_reports_field_diff(self):
        self.release.stage()
        switch = self.release.switch
        def switched():
            switch()
            self.rows[0]["Config"]["User"] = "0"
        self.release.switch = switched
        with self.assertRaises(RuntimeError):
            self.release.apply()
        failure = json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["phase"], "verify")
        self.assertIn("target runtime contract changed: config.User", failure["failure_message"])

    def test_target_drift_between_verify_and_commit_is_rejected(self):
        self.release.stage()
        persist = self.release.persist_boot
        def changed():
            persist()
            self.rows[0]["RestartCount"] = 1
        self.release.persist_boot = changed
        with self.assertRaisesRegex(RuntimeError, "target|runtime|receipt"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_pointer_drift_between_verify_and_commit_is_not_overwritten(self):
        self.release.stage()
        persist = self.release.persist_boot
        foreign = json.dumps({"release": "later", "receipt_sha256": "1"*64}).encode()
        def changed():
            persist()
            self.release.pointer.write_bytes(foreign)
        self.release.persist_boot = changed
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual(self.release.pointer.read_bytes(), foreign)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_target_drift_inside_receipt_write_rejects_pointer_publication(self):
        self.release.stage()
        writer = console.write_json
        def receipt_write(path, value):
            result = writer(path, value)
            if path == self.media/"receipt.json":
                self.rows[0]["RestartCount"] = 1
                self.rows[0]["State"]["StartedAt"] = "changed-inside-receipt"
            return result
        with patch.object(console, "write_json", receipt_write), self.assertRaisesRegex(RuntimeError, "target runtime"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()

    def test_pointer_drift_inside_receipt_write_is_never_overwritten(self):
        self.release.stage()
        foreign = json.dumps({"release": "later", "receipt_sha256": "1"*64}).encode()
        writer = console.write_json
        def receipt_write(path, value):
            result = writer(path, value)
            if path == self.media/"receipt.json":
                self.release.pointer.write_bytes(foreign)
            return result
        with patch.object(console, "write_json", receipt_write), self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual(self.release.pointer.read_bytes(), foreign)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()

    def test_target_drift_inside_pointer_write_revokes_success(self):
        self.release.stage()
        writer = console.write_json
        def pointer_write(path, value):
            result = writer(path, value)
            if path == self.release.pointer:
                self.rows[0]["RestartCount"] = 1
                self.rows[0]["State"]["StartedAt"] = "changed-inside-pointer"
            return result
        with patch.object(console, "write_json", pointer_write), self.assertRaisesRegex(RuntimeError, "target runtime"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()

    def test_original_chain_change_during_switch_is_rejected(self):
        self.release.stage()
        switch = self.release.switch
        def changed():
            switch()
            self.chain.write_text(self.old_chain.decode()+str(self.old_overlay)+"\n")
        self.release.switch = changed
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)

    def test_explicit_rollback_restores_old_images_chain_and_previous_pointer(self):
        previous = json.dumps({"release": "old-stale", "receipt_sha256": "1"*64}).encode()
        self.release.pointer.write_bytes(previous)
        sha = self.stage_apply()
        self.release.rollback(sha)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual(self.release.pointer.read_bytes(), previous)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()

    def test_partial_compose_failure_restores_both_targets_and_chain(self):
        self.release.stage()
        self.fail_switch = True
        with self.assertRaisesRegex(RuntimeError, "partial switch"):
            self.release.apply()
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()
        self.assertTrue((self.media/"failure.json").exists())
        self.assertFalse(self.release.pointer.exists())

    def assert_phase_recovers(self, phase):
        self.release.stage()
        original = getattr(self.release, phase)
        def interrupted(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get("rollback"):
                return result
            raise RuntimeError("injected "+phase)
        setattr(self.release, phase, interrupted)
        with self.assertRaisesRegex(RuntimeError, "injected"):
            self.release.apply()
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()

    def test_failure_after_live_publication_recovers(self):
        self.assert_phase_recovers("publish_live")

    def test_failure_after_switch_recovers(self):
        self.assert_phase_recovers("switch")

    def test_failure_after_verify_recovers(self):
        self.assert_phase_recovers("verify")

    def test_failure_after_boot_publication_recovers(self):
        self.assert_phase_recovers("persist_boot")

    def test_failure_after_receipt_publication_recovers(self):
        self.assert_phase_recovers("commit")

    def test_health_failure_recovers_old_images(self):
        self.release.stage()
        self.unhealthy = True
        with patch.object(console.time, "monotonic", side_effect=[0, 999, 1000]), patch.object(console.time, "sleep"):
            with self.assertRaises(RuntimeError):
                self.release.apply()
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assert_non_targets_unchanged()

    def test_depends_on_label_divergence_is_normalized_and_apply_succeeds(self):
        # --no-deps/创建路径导致的 depends_on 标签差异（空串/键序翻转）不再阻塞；
        # stage 冻结渲染拓扑，verify 独立比较通过。
        sha = self.stage_apply()
        recorded = json.loads((self.media/"state/before.json").read_text())["target_depends_on"]
        self.assertEqual(recorded["control-plane"], self.model["services"]["control-plane"]["depends_on"])
        self.assertEqual(recorded["web-console"], self.model["services"]["web-console"]["depends_on"])
        labels = {s: next(r for r in self.rows if r["Name"] == "/"+s)["Config"]["Labels"]["com.docker.compose.depends_on"]
                  for s in console.SERVICES}
        self.assertNotEqual(labels["control-plane"], "")   # pre-apply 为空串，up 后非空
        self.assertNotEqual(labels["web-console"], "gateway-core:service_healthy:false,control-plane:service_healthy:false")
        self.assert_non_targets_unchanged()

    def tamper_live_render(self):
        original = console.ConsoleRelease.render
        def tampered(instance, files):
            model = original(instance, files)
            if tuple(files) == (instance.live,):
                model["services"]["web-console"]["depends_on"] = {"control-plane": {"condition": "service_started"}}
            return model
        return tampered

    def test_rendered_dependency_topology_change_is_rejected_independent_of_labels(self):
        self.release.stage()
        with patch.object(console.ConsoleRelease, "render", self.tamper_live_render()), \
                self.assertRaisesRegex(RuntimeError, "dependency topology"):
            self.release.apply()
        failure = json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["phase"], "verify")
        self.assertIn("target dependency topology differs from staged render", failure["failure_message"])

    def test_failed_apply_after_verify_rolls_back_and_leaves_verifiable_state(self):
        self.release.stage()
        with patch.object(console.ConsoleRelease, "render", self.tamper_live_render()), \
                self.assertRaisesRegex(RuntimeError, "dependency topology"):
            self.release.apply()
        failure = json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["rollback"], "complete")
        self.assertEqual(failure["compensation_errors"], [])
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual(json.loads((self.media/"rollback.json").read_text())["status"], "rolled_back")
        self.assert_non_targets_unchanged()
        # 回滚后 verify(rollback=True) 已在 restore 内通过；同 release_id 重跑
        # stage 被 fail-closed 拒绝；残留 live json 是受控回滚模型的字节。
        with self.assertRaisesRegex(RuntimeError, "release state exists"):
            self.release.stage()
        self.assertEqual(json.loads(self.release.live.read_text()),
                         json.loads((self.media/"state/rollback.json").read_text()))

    def test_business_label_change_on_target_is_still_rejected(self):
        self.release.stage()
        switch = self.release.switch
        def switched():
            switch()
            self.rows[0]["Config"]["Labels"]["com.example.owner"] = "changed"
        self.release.switch = switched
        with self.assertRaises(RuntimeError):
            self.release.apply()
        failure = json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["phase"], "verify")
        self.assertIn("target runtime contract changed", failure["failure_message"])
        # Labels repr 在 failure_message 截断到 100 字符，业务标签键排序在
        # com.docker.compose.* 之后，不必出现在消息里——契约比对本身已覆盖。

    def test_provenance_label_change_is_rejected(self):
        self.release.stage()
        self.wrong_provenance = True
        with self.assertRaisesRegex(RuntimeError, "runtime image provenance differs"):
            self.release.apply()
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_missing_target_depends_on_evidence_fails_closed(self):
        # 新 schema 的 before.json 缺 target_depends_on（证据被削/新版 stage 漏写）
        # 必须 fail-closed，不允许静默跳过拓扑比较；旧历史媒体的回滚走媒体自带
        # 冻结脚本（manifest 绑定其 digest），不受本键约束。
        self.release.stage()
        before = json.loads((self.media/"state/before.json").read_text())
        before.pop("target_depends_on")
        (self.media/"state/before.json").write_text(json.dumps(before))
        os.chmod(self.media/"state/before.json", 0o600)
        with self.assertRaises(RuntimeError):
            self.release.apply()
        failure = json.loads((self.media/"failure.json").read_text())
        self.assertIn("missing target dependency topology", failure["failure_message"])
        self.assertEqual(failure["rollback"], "incomplete")
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_failed_restore_is_reported_without_success_pointer(self):
        self.release.stage()
        self.fail_switch = self.fail_restore = True
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(json.loads((self.media/"failure.json").read_text())["rollback"], "incomplete")

    def test_live_restore_write_failure_does_not_skip_targets_boot_or_pointer(self):
        self.release.stage()
        event = self.release.event
        def late_failure(message):
            if message.startswith("COMMIT"):
                raise OSError("injected commit event failure")
            return event(message)
        self.release.event = late_failure
        atomic = console.atomic_bytes
        rollback = (self.release.state/"rollback.json").read_bytes()
        def blocked_live(path, content):
            if path == self.release.live and content == rollback:
                raise OSError("injected rollback live write failure")
            return atomic(path, content)
        with patch.object(console, "atomic_bytes", blocked_live), self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertFalse(self.release.pointer.exists())
        self.assert_non_targets_unchanged()

    def test_boot_restore_failure_does_not_skip_pointer_restore(self):
        self.release.stage()
        event = self.release.event
        def late_failure(message):
            if message.startswith("COMMIT"):
                raise OSError("injected commit event failure")
            return event(message)
        self.release.event = late_failure
        atomic = console.atomic_bytes
        def blocked_boot(path, content):
            if path == self.chain and content == self.old_chain:
                raise OSError("injected rollback boot write failure")
            return atomic(path, content)
        with patch.object(console, "atomic_bytes", blocked_boot), self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertNotEqual(self.chain.read_bytes(), self.old_chain)
        self.assertFalse(self.release.pointer.exists())
        self.assert_non_targets_unchanged()

    def test_first_restore_target_failure_still_attempts_second_target(self):
        self.release.stage()
        event = self.release.event
        def late_failure(message):
            if message.startswith("COMMIT"):
                raise OSError("injected commit event failure")
            return event(message)
        self.release.event = late_failure
        self.fail_restore = True
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertFalse(self.release.pointer.exists())
        self.assertTrue(any(c[-1] == "web-console" and "up" in c and c[-2] != "control-plane" for c in self.calls))
        self.assert_non_targets_unchanged()

    def test_live_replace_failure_cleans_owned_temp_and_allows_safe_retry(self):
        self.release.stage()
        replace = vm.os.replace
        failed = False
        def replace_once(source, target):
            nonlocal failed
            if Path(target) == self.release.live and not failed:
                failed = True
                raise OSError("injected live os.replace failure")
            return replace(source, target)
        with patch.object(vm.os, "replace", replace_once), self.assertRaisesRegex(OSError, "live os.replace failure"):
            self.release.apply()
        temporary = self.release.live.with_name(self.release.live.name+".development-new")
        self.assertFalse(temporary.exists())
        self.assertFalse(self.release.live.exists())
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.rows, self.baseline)
        self.assertEqual(json.loads((self.media/"failure.json").read_text())["rollback"], "complete")
        self.release.apply()
        self.assertEqual(self.switch_count, 1)
        self.assertTrue(self.release.pointer.is_file())
        self.assert_non_targets_unchanged()

    def test_atomic_fsync_failure_cleans_only_unpublished_owned_temp(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        with patch.object(vm.os, "fsync", side_effect=OSError("injected file fsync failure")), \
                self.assertRaisesRegex(OSError, "file fsync failure"):
            vm.atomic_bytes(target, b"candidate")
        self.assertEqual(target.read_bytes(), b"previous")
        self.assertFalse(temporary.exists())
        vm.atomic_bytes(target, b"candidate")
        self.assertEqual(target.read_bytes(), b"candidate")

    def test_atomic_unknown_preexisting_temp_is_preserved(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        for kind in ("file", "symlink", "directory"):
            with self.subTest(kind=kind):
                if kind == "file":
                    temporary.write_bytes(b"unknown")
                elif kind == "symlink":
                    temporary.symlink_to(target)
                else:
                    temporary.mkdir()
                before = temporary.lstat()
                with patch.object(vm.os, "replace") as replace, self.assertRaisesRegex(RuntimeError, "stale temporary file"):
                    vm.atomic_bytes(target, b"candidate")
                replace.assert_not_called()
                self.assertEqual(temporary.lstat(), before)
                self.assertEqual(target.read_bytes(), b"previous")
                if kind == "file":
                    self.assertEqual(temporary.read_bytes(), b"unknown")
                if kind == "directory":
                    temporary.rmdir()
                else:
                    temporary.unlink()

    def test_atomic_temp_content_or_mode_drift_is_not_deleted(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        for change in ("content", "mode"):
            with self.subTest(change=change):
                def fail_after_drift(source, destination):
                    if change == "content":
                        Path(source).write_bytes(b"foreign-content")
                    else:
                        Path(source).chmod(0o640)
                    raise OSError("injected temp drift")
                with patch.object(vm.os, "replace", fail_after_drift), self.assertRaisesRegex(OSError, "temp drift"):
                    vm.atomic_bytes(target, b"candidate")
                self.assertTrue(temporary.is_file())
                self.assertEqual(target.read_bytes(), b"previous")
                if change == "content":
                    self.assertEqual(temporary.read_bytes(), b"foreign-content")
                else:
                    self.assertEqual(temporary.stat().st_mode & 0o777, 0o640)
                temporary.unlink()

    def test_atomic_replaced_temp_or_new_symlink_is_not_deleted(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        moved = self.media/"owned-moved"
        replace = vm.os.replace
        for change in ("replacement", "symlink"):
            with self.subTest(change=change):
                def fail_after_replacement(source, destination):
                    replace(source, moved)
                    if change == "replacement":
                        Path(source).write_bytes(b"candidate")
                        Path(source).chmod(0o600)
                    else:
                        Path(source).symlink_to(target)
                    raise OSError("injected namespace replacement")
                with patch.object(vm.os, "replace", fail_after_replacement), \
                        self.assertRaisesRegex(OSError, "namespace replacement"):
                    vm.atomic_bytes(target, b"candidate")
                self.assertEqual(target.read_bytes(), b"previous")
                self.assertEqual(moved.read_bytes(), b"candidate")
                self.assertTrue(temporary.is_symlink() if change == "symlink" else temporary.is_file())
                temporary.unlink()
                moved.unlink()

    def test_atomic_temp_metadata_drift_or_extra_hardlink_is_not_deleted(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        alias = self.media/"foreign-hardlink"
        for change in ("rewrite", "hardlink"):
            with self.subTest(change=change):
                def fail_after_drift(source, destination):
                    if change == "rewrite":
                        before = Path(source).stat()
                        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns+1000000000))
                    else:
                        os.link(source, alias)
                    raise OSError("injected temp metadata drift")
                with patch.object(vm.os, "replace", fail_after_drift), self.assertRaisesRegex(OSError, "metadata drift"):
                    vm.atomic_bytes(target, b"candidate")
                self.assertEqual(target.read_bytes(), b"previous")
                self.assertEqual(temporary.read_bytes(), b"candidate")
                if change == "hardlink":
                    self.assertEqual(alias.read_bytes(), b"candidate")
                    alias.unlink()
                temporary.unlink()

    def test_atomic_temp_uid_or_gid_drift_fixture_is_not_deleted(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        fstat = vm.os.fstat
        for field in ("st_uid", "st_gid"):
            with self.subTest(field=field):
                changed = False
                def fail_after_drift(source, destination):
                    nonlocal changed
                    changed = True
                    raise OSError("injected owner metadata drift")
                def metadata(fd):
                    value = fstat(fd)
                    if changed:
                        values = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
                        values[field] += 1
                        return SimpleNamespace(**values)
                    return value
                with patch.object(vm.os, "replace", fail_after_drift), patch.object(vm.os, "fstat", metadata), \
                        self.assertRaisesRegex(OSError, "owner metadata drift"):
                    vm.atomic_bytes(target, b"candidate")
                self.assertEqual(target.read_bytes(), b"previous")
                self.assertEqual(temporary.read_bytes(), b"candidate")
                temporary.unlink()

    def test_directory_fsync_failure_after_atomic_publication_preserves_target(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        fsync = vm.os.fsync
        def fail_directory(fd):
            if vm.os.fstat(fd).st_mode & 0o170000 == 0o040000:
                raise OSError("injected directory fsync failure")
            return fsync(fd)
        with patch.object(vm.os, "fsync", fail_directory), self.assertRaisesRegex(OSError, "directory fsync failure"):
            console.atomic_bytes(target, b"candidate")
        self.assertEqual(target.read_bytes(), b"candidate")
        self.assertFalse(temporary.exists())

    def test_atomic_cleanup_failure_preserves_original_error_and_temp(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        with patch.object(vm.os, "replace", side_effect=OSError("injected replace failure")), \
                patch.object(Path, "unlink", side_effect=OSError("injected cleanup failure")) as unlink, \
                self.assertRaisesRegex(OSError, "replace failure"):
            vm.atomic_bytes(target, b"candidate")
        unlink.assert_called_once()
        self.assertEqual(target.read_bytes(), b"previous")
        self.assertEqual(temporary.read_bytes(), b"candidate")

    def test_atomic_failure_after_publication_does_not_delete_published_or_foreign_bytes(self):
        target = self.media/"atomic-fixture"
        target.write_bytes(b"previous")
        temporary = target.with_name(target.name+".development-new")
        replace = vm.os.replace
        def replace_then_fail(source, destination):
            replace(source, destination)
            Path(source).write_bytes(b"foreign-after-publication")
            raise OSError("injected failure after publication")
        with patch.object(vm.os, "replace", replace_then_fail), self.assertRaisesRegex(OSError, "after publication"):
            vm.atomic_bytes(target, b"candidate")
        self.assertEqual(target.read_bytes(), b"candidate")
        self.assertEqual(temporary.read_bytes(), b"foreign-after-publication")

    def test_no_switch_live_cleanup_failure_still_attempts_boot_and_pointer(self):
        self.release.stage()
        called = []
        publish = self.release.publish_live
        def fail_after_publish():
            publish()
            raise OSError("injected publish event failure")
        self.release.publish_live = fail_after_publish
        with patch.object(self.release, "unlink_atomic", side_effect=OSError("injected unlink failure")), \
                patch.object(self.release, "restore_boot", side_effect=lambda: called.append("boot")), \
                patch.object(self.release, "restore_pointer", side_effect=lambda: called.append("pointer")), \
                self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual(called, ["boot", "pointer"])
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.rows, self.baseline)

    def test_non_target_runtime_or_environment_drift_blocks_apply(self):
        self.release.stage()
        self.rows[2]["Config"]["Env"].append("DRIFT=changed")
        with self.assertRaisesRegex(RuntimeError, "non-target"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_policy_or_env_file_drift_blocks_apply(self):
        self.release.stage()
        self.policy["security_audit_only"] = "false"
        with self.assertRaisesRegex(RuntimeError, "managed"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_billing_mismatch_is_rejected_before_loading_or_switching(self):
        self.release.manifest["billing_enabled"] = "true"
        with self.assertRaisesRegex(RuntimeError, "billing"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))

    def test_base_must_equal_real_live_image_not_stale_development_pointer(self):
        self.release.manifest["services"]["control-plane"]["base_image_id"] = "sha256:"+"9"*64
        with self.assertRaisesRegex(RuntimeError, "base"):
            self.release.stage()
        self.assertEqual(self.switch_count, 0)

    def test_boot_non_target_or_list_drift_is_rejected(self):
        model = json.loads(self.base.read_text())
        model["services"]["security-engine"]["environment"]["SECRET"] = "drift"
        self.base.write_text(json.dumps(model))
        historical = self.workdir/"active-config/live-only.json"
        historical.write_text(json.dumps(self.model))
        for row in self.rows[:-1]:
            row["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(historical)
        with self.assertRaises(RuntimeError):
            self.release.stage()
        self.assertEqual(self.switch_count, 0)

    def persisted_full_boot_fixture(self):
        historical = copy.deepcopy(self.model)
        aliases = {}
        for service in self.names:
            if service not in console.SERVICES:
                reference = "historical/"+service+":fixed"
                historical["services"][service]["image"] = reference
                aliases[reference] = next(row["Image"] for row in self.rows if row["Name"] == "/"+service)
        history = self.workdir/"active-config/full-release-history.json"
        history.write_text(json.dumps(historical))
        history.chmod(0o600)
        self.base.write_text(json.dumps(historical))
        overlay = {"services": {service: {"image": aliases[historical["services"][service]["image"]], "pull_policy": "never"}
                                for service in self.names if service not in console.SERVICES}}
        self.old_overlay.write_text(json.dumps(overlay))
        for row in self.rows[:-1]:
            row["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(history)
        self.baseline = copy.deepcopy(self.rows)
        original_run = self.fake_run
        def alias_run(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if argv[:3] == ["docker", "image", "inspect"] and argv[3] in aliases:
                image = json.loads(result)
                image[0]["Id"] = aliases[argv[3]]
                return json.dumps(image)
            return result
        return historical, history, overlay, alias_run

    def assert_boot_drift_rejected_before_writer(self, pattern="non-target boot"):
        with self.assertRaisesRegex(RuntimeError, pattern):
            self.release.stage()
        self.assertEqual(self.rows, self.baseline)
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertFalse((self.media/"state").exists())
        self.assertFalse(self.release.pointer.exists())
        self.assertFalse(any(argv[:3] == ["docker", "image", "load"] for argv in self.calls))
        self.assertFalse(any(set(argv) & {"create", "up", "down", "stop", "start", "pg_restore", "iptables"} for argv in self.calls))

    def test_console_stage_preserves_full_release_boot_non_targets_with_equivalent_image_and_never(self):
        _, _, _, alias_run = self.persisted_full_boot_fixture()
        boot = self.render([self.base, self.old_overlay])
        with patch.object(vm, "run", alias_run):
            self.release.stage()
        candidate = json.loads((self.media/"state/candidate.json").read_text())
        rollback = json.loads((self.media/"state/rollback.json").read_text())
        overlay = json.loads((self.media/"state/boot-overlay.json").read_text())
        for service in self.names:
            if service not in console.SERVICES:
                self.assertEqual(candidate["services"][service], boot["services"][service])
                self.assertEqual(rollback["services"][service], boot["services"][service])
                self.assertNotIn(service, overlay["services"])
        self.assertEqual(self.rows, self.baseline)
        self.assertEqual(self.switch_count, 0)
        self.assertTrue(set(overlay["services"]) <= set(console.SERVICES))
        self.assertEqual(self.render([self.base, self.old_overlay, self.media/"state/boot-overlay.json"]), candidate)

    def test_console_stage_preserved_boot_rejects_non_target_image_identity_drift_before_writer(self):
        _, _, overlay, alias_run = self.persisted_full_boot_fixture()
        overlay["services"]["postgres"]["image"] = "sha256:"+"9"*64
        self.old_overlay.write_text(json.dumps(overlay))
        with patch.object(vm, "run", alias_run):
            self.assert_boot_drift_rejected_before_writer("non-target boot image")

    def test_console_stage_preserved_boot_rejects_non_target_environment_drift_before_writer(self):
        _, _, overlay, alias_run = self.persisted_full_boot_fixture()
        overlay["services"]["postgres"]["environment"] = {"SECRET": "changed"}
        self.old_overlay.write_text(json.dumps(overlay))
        with patch.object(vm, "run", alias_run):
            self.assert_boot_drift_rejected_before_writer()

    def test_console_stage_preserved_boot_rejects_non_target_list_drift_before_writer(self):
        _, _, overlay, alias_run = self.persisted_full_boot_fixture()
        overlay["services"]["postgres"]["security_opt"] = ["seccomp:unconfined"]
        self.old_overlay.write_text(json.dumps(overlay))
        with patch.object(vm, "run", alias_run):
            self.assert_boot_drift_rejected_before_writer()

    def test_console_stage_preserved_boot_rejects_non_target_dependency_drift_before_writer(self):
        _, _, overlay, alias_run = self.persisted_full_boot_fixture()
        overlay["services"]["postgres"]["depends_on"] = {"control-plane": {"condition": "service_started"}}
        self.old_overlay.write_text(json.dumps(overlay))
        with patch.object(vm, "run", alias_run):
            self.assert_boot_drift_rejected_before_writer()

    def test_console_stage_preserved_boot_rejects_other_pull_policy_changes_before_writer(self):
        historical, history, overlay, alias_run = self.persisted_full_boot_fixture()
        for boot_policy, historical_policy in (("always", None), (None, "never"), ("never", "always"), (None, "missing"), ("never", None)):
            # The last case is a present null, not the permitted absent key.
            with self.subTest(boot=boot_policy, historical=historical_policy):
                live = copy.deepcopy(historical)
                boot = copy.deepcopy(historical)
                delta = copy.deepcopy(overlay)
                if historical_policy is not None:
                    live["services"]["postgres"]["pull_policy"] = historical_policy
                else:
                    live["services"]["postgres"]["pull_policy"] = None
                history.write_text(json.dumps(live))
                delta["services"]["postgres"].pop("pull_policy", None)
                if boot_policy is not None:
                    delta["services"]["postgres"]["pull_policy"] = boot_policy
                self.base.write_text(json.dumps(boot))
                self.old_overlay.write_text(json.dumps(delta))
                with patch.object(vm, "run", alias_run):
                    self.assert_boot_drift_rejected_before_writer()

    def test_console_stage_preserved_boot_keeps_global_resource_comparison_before_writer(self):
        _, _, _, alias_run = self.persisted_full_boot_fixture()
        boot = json.loads(self.base.read_text())
        boot["networks"]["default"]["internal"] = True
        self.base.write_text(json.dumps(boot))
        with patch.object(vm, "run", alias_run):
            self.assert_boot_drift_rejected_before_writer("historical resources differ")

    def test_console_environment_file_metadata_is_equivalent_only_for_targets(self):
        row = self.rows[0]
        with_label = copy.deepcopy(row)
        with_label["Config"]["Labels"]["com.docker.compose.project.environment_file"] = str(self.workdir/".env")
        self.assertEqual(console.runtime_contract(row, allow_provenance=True),
                         console.runtime_contract(with_label, allow_provenance=True))
        self.assertNotEqual(console.runtime_contract(row), console.runtime_contract(with_label),
                            "full fingerprints must still bind non-target metadata")

    def test_console_environment_file_metadata_actual_path_passes_apply_and_rollback(self):
        run = self.fake_run
        def actual_environment_file(argv, **kwargs):
            value = run(argv, **kwargs)
            if "up" in argv:
                for row in self.rows[:2]:
                    row["Config"]["Labels"]["com.docker.compose.project.environment_file"] = str(self.workdir/".env")
            return value
        with patch.object(vm, "run", actual_environment_file):
            receipt = self.stage_apply()
            self.release.rollback(receipt)
        self.assert_non_targets_unchanged()
        self.assertTrue(all(row["Image"] == self.old[service] for row, service in zip(self.rows[:2], console.SERVICES)))
        self.assertEqual(json.loads((self.media/"rollback.json").read_text())["status"], "rolled_back")

    def test_console_environment_file_metadata_accepts_exact_path_at_stage(self):
        for row in self.rows[:2]:
            row["Config"]["Labels"]["com.docker.compose.project.environment_file"] = str(self.workdir/".env")
        self.baseline = copy.deepcopy(self.rows)
        self.release.stage()
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.rows, self.baseline)

    def test_console_environment_file_metadata_rejects_foreign_empty_and_multi_before_probe(self):
        label = "com.docker.compose.project.environment_file"
        for value in ("/tmp/foreign.env", "", str(self.workdir/".env")+",/tmp/other.env",
                      str(self.workdir/"sub/../.env"), [str(self.workdir/".env")]):
            with self.subTest(value=value):
                self.rows[1]["Config"]["Labels"][label] = value
                self.baseline = copy.deepcopy(self.rows)
                self.render_hash_override["control-plane"] = "force-probe-if-validation-is-late"
                with self.assertRaisesRegex(RuntimeError, "environment-file"):
                    self.release.stage()
                self.assertEqual(self.rows, self.baseline)
                self.assertEqual(self.switch_count, 0)
                self.assertFalse((self.media/"state").exists())
                self.assertFalse(self.release.pointer.exists())
                self.assertFalse(any(argv[:3] == ["docker", "image", "load"] for argv in self.calls))
                self.assertFalse(self.probe_calls("create"))

    def test_console_environment_file_metadata_rejects_symlink_input_before_probe(self):
        environment = self.workdir/".env"
        target = self.workdir/"fixture-original.env"
        environment.rename(target)
        environment.symlink_to(target)
        self.rows[0]["Config"]["Labels"]["com.docker.compose.project.environment_file"] = str(environment)
        self.render_hash_override["control-plane"] = "force-probe-if-validation-is-late"
        with self.assertRaisesRegex(RuntimeError, "symlink|environment-file"):
            self.release.stage()
        self.assertFalse(self.probe_calls("create"))
        self.assertEqual(self.switch_count, 0)
        self.assertFalse((self.media/"state").exists())

    def test_console_environment_file_metadata_bad_runtime_label_rejects_verify_and_rollback(self):
        self.release.stage()
        self.release.preflight()
        self.release.publish_live()
        self.release.switch()
        self.rows[0]["Config"]["Labels"]["com.docker.compose.project.environment_file"] = "/tmp/foreign.env"
        calls = len(self.calls)
        with self.assertRaisesRegex(RuntimeError, "environment-file"):
            self.release.verify()
        self.assertFalse(any("up" in argv or "create" in argv for argv in self.calls[calls:]))
        # Recovered old images must pass the same raw-label check.
        for row, service in zip(self.rows[:2], console.SERVICES):
            row["Image"] = self.old[service]
        self.release.restore_live()
        calls = len(self.calls)
        with self.assertRaisesRegex(RuntimeError, "environment-file"):
            self.release.verify(rollback=True)
        self.assertFalse(any("up" in argv or "create" in argv for argv in self.calls[calls:]))

    def test_console_environment_file_metadata_never_hides_other_label_drift(self):
        self.release.stage()
        self.release.preflight()
        self.release.publish_live()
        self.release.switch()
        self.rows[0]["Config"]["Labels"].update({"com.docker.compose.project.environment_file": str(self.workdir/".env"),
                                                "customer.policy": "changed"})
        with self.assertRaisesRegex(RuntimeError, "target runtime contract changed"):
            self.release.verify()

    def test_success_with_true_billing_keeps_policy_and_all_other_services(self):
        self.release.manifest["billing_enabled"] = "true"
        self.policy["billing_enabled"] = "true"
        for row in self.rows:
            row["Config"]["Env"] = ["BILLING_ENABLED=true" if v == "BILLING_ENABLED=false" else v for v in row["Config"]["Env"]]
        for item in self.model["services"].values():
            item["environment"]["BILLING_ENABLED"] = "true"
        self.base.write_text(json.dumps(self.model))
        self.baseline = copy.deepcopy(self.rows)
        self.stage_apply()
        self.assertEqual(self.policy["billing_enabled"], "true")
        self.assert_non_targets_unchanged()

    def test_third_archive_image_is_rejected_before_load(self):
        self.make_archive(extra=True)
        self.release.manifest["images_sha256"] = self.manifest["images_sha256"]
        with self.assertRaisesRegex(RuntimeError, "archive"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))

    def test_candidate_tag_collision_with_non_target_boot_is_rejected_before_load(self):
        collision = "existing-security:current"
        self.manifest["services"]["control-plane"]["tag"] = collision
        self.release.manifest["services"]["control-plane"]["tag"] = collision
        self.model["services"]["security-engine"]["image"] = collision
        self.base.write_text(json.dumps(self.model))
        self.make_archive()
        self.release.manifest["images_sha256"] = self.manifest["images_sha256"]
        loaded = False
        run = self.fake_run
        def retagged(argv, **kwargs):
            nonlocal loaded
            if argv[:3] == ["docker", "image", "inspect"] and argv[3] == collision and not loaded:
                self.calls.append(argv)
                return json.dumps([dict(Id="sha256:"+"c"*64, Config=dict(Labels={}, User="10001"))])
            result = run(argv, **kwargs)
            if argv[:3] == ["docker", "image", "load"]:
                loaded = True
            return result
        with patch.object(vm, "run", retagged), self.assertRaisesRegex(RuntimeError, "non-target.*image|tag collision"):
            self.release.stage()
        self.assertFalse(loaded)
        self.assertEqual(self.rows, self.baseline)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_non_target_boot_reference_retag_after_stage_blocks_apply(self):
        reference = "existing-security:current"
        self.model["services"]["security-engine"]["image"] = reference
        self.base.write_text(json.dumps(self.model))
        drift = False
        run = self.fake_run
        def tagged_image(argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"] and argv[3] == reference:
                self.calls.append(argv)
                return json.dumps([dict(Id="sha256:"+("9" if drift else "c")*64, Config=dict(Labels={}, User="10001"))])
            return run(argv, **kwargs)
        with patch.object(vm, "run", tagged_image):
            self.release.stage()
            drift = True
            with self.assertRaisesRegex(RuntimeError, "non-target.*image"):
                self.release.apply()
        self.assertEqual(self.switch_count, 0)
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.rows, self.baseline)

    def test_normalized_image_tag_aliases_cannot_hide_collision(self):
        self.assertEqual(console.image_reference("existing-security:current"),
                         console.image_reference("docker.io/library/existing-security:current"))
        self.assertEqual(console.image_reference("existing-security"),
                         console.image_reference("index.docker.io/library/existing-security:latest"))
        self.assertEqual(console.image_reference("library/existing-security:current"),
                         console.image_reference("docker.io/library/existing-security:current"))
        self.assertNotEqual(console.image_reference("private.example/existing-security:current"),
                            console.image_reference("existing-security:current"))

    def test_managed_modes_keep_absent_file_key_and_non_target_identities(self):
        self.stage_apply()
        self.assertNotIn("file_content_dlp_enabled", self.policy)
        self.assertEqual(self.policy, {"billing_enabled": "false", "security_audit_only": "true"})
        self.assert_non_targets_unchanged()

    def test_later_release_or_non_target_drift_rejects_recorded_rollback(self):
        sha = self.stage_apply()
        self.release.pointer.write_text(json.dumps({"release": "later", "receipt_sha256": "1"*64}))
        with self.assertRaisesRegex(RuntimeError, "active"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_changed_boot_chain_rejects_receipt_rollback(self):
        sha = self.stage_apply()
        self.chain.write_text(self.chain.read_text()+str(self.old_overlay)+"\n")
        with self.assertRaisesRegex(RuntimeError, "boot"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_replaced_target_container_rejects_receipt_rollback(self):
        sha = self.stage_apply()
        self.rows[0]["Id"] = "foreign-container"
        with self.assertRaisesRegex(RuntimeError, "receipt"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_non_target_restart_after_release_rejects_rollback(self):
        sha = self.stage_apply()
        self.rows[2]["RestartCount"] = 1
        with self.assertRaisesRegex(RuntimeError, "non-target"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_pointer_change_after_rollback_checks_is_rejected_before_target_switch(self):
        sha = self.stage_apply()
        check = self.release.check_boot
        def changed(deployed):
            check(deployed)
            if deployed:
                self.release.pointer.write_text(json.dumps({"release": "later", "receipt_sha256": "1"*64}))
        self.release.check_boot = changed
        with self.assertRaisesRegex(RuntimeError, "active"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_env_file_change_rejects_apply_before_runtime_mutation(self):
        self.release.stage()
        (self.workdir/".env").write_text("TEST=drift\n")
        with self.assertRaisesRegex(RuntimeError, "input|configuration"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_current_root_drift_rejects_apply(self):
        self.release.stage()
        (self.root/"current").unlink()
        (self.root/"current").symlink_to(self.root/"releases/later", target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "root"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_all_console_commands_use_only_the_local_docker_environment(self):
        run = self.fake_run
        def controlled(argv, **kwargs):
            self.assertEqual(kwargs.get("env", {}).get("DOCKER_HOST"), "unix:///var/run/docker.sock")
            self.assertNotIn("DOCKER_CONTEXT", kwargs.get("env", {}))
            self.assertNotIn("COMPOSE_FILE", kwargs.get("env", {}))
            return run(argv, **kwargs)
        with patch.object(vm, "run", controlled):
            sha = self.stage_apply()
            self.release.rollback(sha)

    def test_seed_enumeration_is_compatible_with_alpine_busybox(self):
        run = self.fake_run
        def alpine(argv, **kwargs):
            if argv[:2] == ["docker", "exec"] and "find" in argv:
                self.assertNotIn("-printf", argv, "Alpine BusyBox find 不支持 GNU -printf")
            return run(argv, **kwargs)
        with patch.object(vm, "run", alpine):
            self.stage_apply()

    def test_runtime_seed_list_drift_rejects_stage(self):
        self.bad_seeds = True
        with self.assertRaisesRegex(RuntimeError, "seed"):
            self.release.stage()
        self.assertEqual(self.switch_count, 0)

    def test_runtime_extra_empty_seed_directory_rejects_stage_before_load(self):
        run = self.fake_run
        def extra_directory(argv, **kwargs):
            value = run(argv, **kwargs)
            if argv[:2] == ["docker", "exec"] and "find" in argv:
                value += "\nd /etc/uag/seeds/unexpected-empty-directory"
            return value
        with patch.object(vm, "run", extra_directory), self.assertRaisesRegex(RuntimeError, "seed"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] or "up" in c for c in self.calls))

    def test_compose_implementation_drift_blocks_apply_before_switch(self):
        self.release.stage()
        self.compose_version = "v5.3.1-later"
        with self.assertRaisesRegex(RuntimeError, "Compose|implementation"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_real_runner_plugin_nonzero_reaches_bundled_fallback(self):
        self.release.workdir = self.workdir
        self.release.release_root = self.release_root
        failure = SimpleNamespace(returncode=1, stdout="", stderr="compose plugin unavailable")
        success = SimpleNamespace(returncode=0, stdout=self.compose_version, stderr="")
        with patch.object(vm, "run", REAL_VM_RUN), patch.object(vm.subprocess, "run", side_effect=[failure, success]) as execute:
            implementation = self.release.compose_implementation()
        self.assertEqual(implementation["mode"], "bundled")
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(execute.call_args_list[1].args[0], [str(self.workdir/"bin/docker-compose"), "version", "--short"])

    def test_real_runner_bundled_failure_and_plugin_timeout_fail_closed(self):
        self.release.workdir = self.workdir
        self.release.release_root = self.release_root
        failure = SimpleNamespace(returncode=1, stdout="", stderr="unavailable")
        with patch.object(vm, "run", REAL_VM_RUN), patch.object(vm.subprocess, "run", side_effect=[failure, failure]) as execute:
            with self.assertRaises(RuntimeError):
                self.release.compose_implementation()
            self.assertEqual(execute.call_count, 2)
        with patch.object(vm, "run", REAL_VM_RUN), patch.object(vm.subprocess, "run", side_effect=vm.subprocess.TimeoutExpired("docker", 180)) as execute:
            with self.assertRaises(vm.subprocess.TimeoutExpired):
                self.release.compose_implementation()
            self.assertEqual(execute.call_count, 1)
        with patch.object(vm, "run", side_effect=RuntimeError("unrelated runner failure")) as execute:
            with self.assertRaisesRegex(RuntimeError, "unrelated"):
                self.release.compose_implementation()
            self.assertEqual(execute.call_count, 1)

    def test_target_command_or_mount_drift_is_rejected_before_image_load(self):
        for mutate in (lambda row: row.update(Path="/unexpected", Args=["drift"]),
                       lambda row: row["Mounts"].append(dict(Type="bind", Source="/unexpected", Destination="/app", RW=False))):
            self.rows = copy.deepcopy(self.baseline)
            self.calls.clear()
            mutate(self.rows[0])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(RuntimeError, "command|mount"):
                self.release.stage()
            self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))
            self.assertEqual(self.switch_count, 0)

    def test_bind_propagation_mismatch_rejects_before_load(self):
        source = str(self.workdir/"bound-data")
        self.model["services"]["control-plane"]["volumes"] = [dict(type="bind", source=source,
            target="/bound-data", read_only=True, bind=dict(propagation="rprivate", create_host_path=False))]
        self.base.write_text(json.dumps(self.model))
        self.rows[0]["Mounts"] = [dict(Type="bind", Source=source, Destination="/bound-data", RW=False,
                                      Mode="ro", Propagation="rshared")]
        with self.assertRaisesRegex(RuntimeError, "mount|propagation"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] or "up" in c for c in self.calls))

    def test_unfrozen_effective_logger_rejects_before_load(self):
        self.rows[0]["HostConfig"]["LogConfig"] = {"Type": "syslog", "Config": {"tag": "existing-runtime"}}
        with self.assertRaisesRegex(RuntimeError, "logging"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] or "up" in c for c in self.calls))

    def test_explicit_mount_propagation_and_logging_match_can_restore(self):
        source = str(self.workdir/"bound-data")
        self.model["services"]["control-plane"]["volumes"] = [dict(type="bind", source=source,
            target="/bound-data", read_only=True, bind=dict(propagation="rprivate", create_host_path=False))]
        self.model["services"]["control-plane"]["logging"] = {"driver": "syslog", "options": {"tag": "existing-runtime"}}
        self.base.write_text(json.dumps(self.model))
        self.rows[0]["Mounts"] = [dict(Type="bind", Source=source, Destination="/bound-data", RW=False,
                                      Mode="ro", Propagation="rprivate")]
        self.rows[0]["HostConfig"]["LogConfig"] = {"Type": "syslog", "Config": {"tag": "existing-runtime"}}
        self.baseline = copy.deepcopy(self.rows)
        sha = self.stage_apply()
        self.release.rollback(sha)
        self.assertEqual(self.rows[0]["Mounts"], self.baseline[0]["Mounts"])
        self.assertEqual(self.rows[0]["HostConfig"]["LogConfig"], self.baseline[0]["HostConfig"]["LogConfig"])
        self.assert_non_targets_unchanged()

    def test_declared_logging_options_mismatch_rejects_before_load(self):
        self.model["services"]["control-plane"]["logging"] = {"driver": "syslog", "options": {"tag": "changed"}}
        self.base.write_text(json.dumps(self.model))
        self.rows[0]["HostConfig"]["LogConfig"] = {"Type": "syslog", "Config": {"tag": "existing-runtime"}}
        with self.assertRaisesRegex(RuntimeError, "logging"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] or "up" in c for c in self.calls))

    def test_boot_env_export_code_and_reserved_values_are_rejected(self):
        for content in ("export MODE=true\n", "MODE=$(id)\n", "ROOT=/unexpected\n", "COMPOSE_FILE=/unexpected\n", "MODE=$UNSET\n"):
            (self.workdir/".env").write_text(content)
            with self.subTest(content=content), self.assertRaisesRegex(RuntimeError, "boot env"):
                self.release.stage()
            self.assertEqual(self.switch_count, 0)

    def test_boot_env_embedded_hash_tail_is_rejected_before_load(self):
        content = "MODE=literal# printf %s fixture-command-tail\n"
        env_file = self.workdir/".env"
        env_file.write_text(content)
        with self.assertRaisesRegex(RuntimeError, "boot env"):
            console.validate_boot_env(env_file)
        with self.assertRaisesRegex(RuntimeError, "boot env"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] or "up" in c for c in self.calls))
        self.assertEqual(self.rows, self.baseline)

    def test_boot_env_accepts_only_complete_scalar_and_real_comment_boundary(self):
        env_file = self.workdir/".env"
        for content, expected in (("MODE=literal#value\n", "literal#value"),
                                  ("MODE=literal # ordinary comment\n", "literal"),
                                  ('MODE="literal# with spaces"\n', "literal# with spaces"),
                                  ("MODE='fixture$literal' # comment\n", "fixture$literal"),
                                  ("MODE=\n", "")):
            env_file.write_text(content)
            with self.subTest(content=content):
                console.validate_boot_env(env_file)
                result = vm.subprocess.run(["bash", "--noprofile", "--norc", "-c",
                    'source "$1"; printf "%s" "$MODE"', "env-fixture", str(env_file)],
                    env={"PATH": "/usr/bin:/bin"}, cwd=self.temp.name, capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout, expected)
        for content in ('MODE="literal"suffix\n', "MODE=literal# printf %s tail\n", "MODE=# printf %s tail\n"):
            env_file.write_text(content)
            with self.subTest(content=content), self.assertRaisesRegex(RuntimeError, "boot env"):
                console.validate_boot_env(env_file)

    def test_boot_env_installer_legacy_lines_get_narrow_exceptions(self):
        env_file = self.workdir/".env"
        env_file.write_text("TEST='fixture$literal'\n"
                            'DEFAULT_KEY_SCOPES=["mcp:invoke","mcp:read","billing:usage"]\n'
                            "COMPOSE_PROJECT_NAME=existing-project\n")
        exceptions = console.validate_boot_env(env_file, expected_project="existing-project")
        self.assertEqual([item["exception"] for item in exceptions], ["json-array-allowed", "compose-project-name-allowed"])
        self.assertEqual(exceptions[0]["value"], '["mcp:invoke","mcp:read","billing:usage"]')
        self.assertEqual(exceptions[1]["value"], "existing-project")
        self.assertIn("quote removal", exceptions[0]["note"])
        # evidence for the recorded semantic difference: bash strips the embedded
        # double quotes while the frozen .env keeps them; consumer value is not verified
        result = vm.subprocess.run(["bash", "--noprofile", "--norc", "-c",
            'source "$1"; printf "%s" "$DEFAULT_KEY_SCOPES"', "env-fixture", str(env_file)],
            env={"PATH": "/usr/bin:/bin"}, cwd=self.temp.name, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, "[mcp:invoke,mcp:read,billing:usage]")
        sha = self.stage_apply()
        before = json.loads((self.release.state/"before.json").read_text())
        self.assertEqual(before["boot_env_exceptions"], exceptions)
        self.release.rollback(sha)
        self.assert_non_targets_unchanged()

    def test_boot_env_narrow_exception_boundaries_stay_rejected(self):
        env_file = self.workdir/".env"
        rejected = (
            ("COMPOSE_PROJECT_NAME=other-project\n", "COMPOSE_PROJECT_NAME must exactly equal"),
            ('DEFAULT_KEY_SCOPES=["mcp:invoke","$id"]\n', "complete shell scalar"),
            ("DEFAULT_KEY_SCOPES=[\"mcp:invoke\",`id`]\n", "complete shell scalar"),
            ('DEFAULT_KEY_SCOPES=["mcp:invoke","a\\b"]\n', "complete shell scalar"),
            ('DEFAULT_KEY_SCOPES=["mcp:invoke", "mcp:read"]\n', "complete shell scalar"),
            ("COMPOSE_FILE=/unexpected\n", "cannot override startup/Docker implementation"),
            ("COMPOSE_PROFILES=keep\nCOMPOSE_PROJECT_NAME=other-project\n", "COMPOSE_PROJECT_NAME must exactly equal"),
        )
        for content, message in rejected:
            env_file.write_text("TEST='fixture$literal'\n"+content)
            with self.subTest(content=content), self.assertRaisesRegex(RuntimeError, message):
                console.validate_boot_env(env_file, expected_project="existing-project")
        # fail-closed: without the staged --project-name expectation the key stays rejected
        env_file.write_text("TEST='fixture$literal'\nCOMPOSE_PROJECT_NAME=existing-project\n")
        with self.assertRaisesRegex(RuntimeError, "COMPOSE_PROJECT_NAME must exactly equal"):
            console.validate_boot_env(env_file)
        self.assertEqual(self.switch_count, 0)
        # stage path rejects a mismatched COMPOSE_PROJECT_NAME before any container work
        env_file.write_text("TEST='fixture$literal'\nCOMPOSE_PROJECT_NAME=other-project\n")
        with self.assertRaisesRegex(RuntimeError, "COMPOSE_PROJECT_NAME must exactly equal"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.rows, self.baseline)

    def test_escaped_json_extends_is_rejected_before_image_load(self):
        hidden = self.workdir/"hidden-extends.json"
        hidden.write_text(json.dumps({"services": {"inherited": self.model["services"]["control-plane"]}}))
        model = copy.deepcopy(self.model)
        model["services"]["control-plane"] = {"extends": {"file": str(hidden), "service": "inherited"}}
        self.base.write_text(json.dumps(model).replace('"extends"', '"\\u0065xtends"'))
        render = self.render
        def resolved(files):
            value = render(files)
            for name, item in list(value["services"].items()):
                if "extends" in item:
                    reference = item.pop("extends")
                    inherited = json.loads(Path(reference["file"]).read_text())["services"][reference["service"]]
                    for key, child in item.items():
                        if isinstance(child, dict) and isinstance(inherited.get(key), dict):
                            inherited[key].update(child)
                        else:
                            inherited[key] = child
                    value["services"][name] = inherited
            return value
        self.render = resolved
        with self.assertRaisesRegex(RuntimeError, "include/extends"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.rows, self.baseline)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_escaped_json_include_is_rejected_before_image_load(self):
        hidden = self.workdir/"hidden-include.json"
        hidden.write_text(json.dumps({"services": {"security-engine": self.model["services"]["security-engine"]}}))
        model = copy.deepcopy(self.model)
        model["services"].pop("security-engine")
        model["include"] = [str(hidden)]
        self.base.write_text(json.dumps(model).replace('"include"', '"\\u0069nclude"'))
        render = self.render
        def resolved(files):
            value = render(files)
            for path in value.pop("include", []):
                value["services"].update(json.loads(Path(path).read_text())["services"])
            return value
        self.render = resolved
        with self.assertRaisesRegex(RuntimeError, "include/extends"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))
        self.assertEqual(self.switch_count, 0)
        self.assertEqual(self.rows, self.baseline)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)

    def test_quoted_and_flow_yaml_reference_keys_are_rejected_before_compose(self):
        self.release.workdir = self.workdir
        self.release.release_root = self.release_root
        self.release.absent_inputs = set()
        for content in ("'include': [hidden.yml]\nservices: {}\n",
                        "services:\n  control-plane:\n    'extends': {file: hidden.yml, service: inherited}\n",
                        "services: {control-plane: {extends: {file: hidden.yml, service: inherited}}}\n",
                        '"\\u0069nclude": [hidden.yml]\nservices: {}\n',
                        'services: {control-plane: {"\\x65xtends": {file: hidden.yml, service: inherited}}}\n',
                        'services:\n  control-plane:\n    "\\U00000065xtends": {file: hidden.yml, service: inherited}\n',
                        "include :\n  - hidden.yml\nservices: {}\n",
                        'services: {control-plane: {extends: {file: hidden.yml, service: inherited}}} # no visible key\n',
                        "x-data:\n  -   SCRIPT: |\n        literal\n      extends: {file: hidden.yml, service: inherited}\nservices: {}\n",
                        "x-data:\n  -   SCRIPT: >2\n        literal\n      include: [hidden.yml]\nservices: {}\n"):
            self.base.write_text(content)
            with self.subTest(content=content), patch.object(self.release, "compose", return_value="{}") as compose:
                with self.assertRaisesRegex(RuntimeError, "include/extends|unsupported Compose"):
                    self.release.referenced_inputs((self.base,))
                compose.assert_not_called()

    def test_reference_free_yaml_and_json_reach_compose(self):
        self.release.workdir = self.workdir
        self.release.release_root = self.release_root
        self.release.absent_inputs = set()
        source = Path(console.__file__).parents[1]/"docker-compose/docker-compose.offline.yml"
        for content in (json.dumps(self.model), source.read_text(),
                        "services:\n  control-plane:\n    image: console:fixed # include: [not-a-reference]\n    environment:\n      NOTE: 'include'\n      SCRIPT: |\n        include: literal\n        extends: literal\n",
                        'services: {"control-plane": {image: console:fixed, command: ["extends", "include"], environment: {NOTE: "include: literal"}}}\n',
                        '"\\u0073ervices": {control-plane: {image: console:fixed}}\n',
                        "services:\n  control-plane:\n    image: console:fixed\n    env_file:\n      - path: ./identity-runtime.env\n        required: false\n"):
            self.base.write_text(content)
            with self.subTest(content=content[:100]), patch.object(self.release, "compose", return_value="{}") as compose:
                self.assertEqual(self.release.referenced_inputs((self.base,)), set())
                compose.assert_called_once_with("config", "--no-env-resolution", "--format", "json", files=(self.base,))

    def test_unsupported_yaml_syntax_is_rejected_before_compose(self):
        self.release.workdir = self.workdir
        self.release.release_root = self.release_root
        self.release.absent_inputs = set()
        for content in ("? include\n: [hidden.yml]\nservices: {}\n",
                        "x-reference: &ref {file: hidden.yml, service: inherited}\nservices: {control-plane: {extends: *ref}}\n",
                        "services: {control-plane: {<<: {extends: {file: hidden.yml, service: inherited}}}}\n",
                        '"inclu\\\nde": [hidden.yml]\nservices: {}\n',
                        '"include"\n  : [hidden.yml]\nservices: {}\n',
                        "!!str include: [hidden.yml]\nservices: {}\n",
                        "services: {}\n---\ninclude: [hidden.yml]\n",
                        'services: {}\n"\\xZZ": literal\n',
                        'x-data:\n  - - include: [hidden.yml]\nservices: {}\n',
                        'x-data:\n  - - "\\u0065xtends": {file: hidden.yml, service: inherited}\nservices: {}\n',
                        '  x-data: |\n    literal\n  include: [hidden.yml]\nservices: {}\n'):
            self.base.write_text(content)
            with self.subTest(content=content), patch.object(self.release, "compose", return_value="{}") as compose:
                with self.assertRaisesRegex(RuntimeError, "include/extends|unsupported Compose"):
                    self.release.referenced_inputs((self.base,))
                compose.assert_not_called()

    def test_duplicate_escaped_json_reference_is_rejected_before_compose(self):
        self.release.workdir = self.workdir
        self.release.release_root = self.release_root
        self.release.absent_inputs = set()
        self.base.write_text('{"include": [], "\\u0069nclude": ["hidden.yml"], "services": {}}')
        with patch.object(self.release, "compose", return_value="{}") as compose:
            with self.assertRaisesRegex(RuntimeError, "include/extends"):
                self.release.referenced_inputs((self.base,))
            compose.assert_not_called()

    def test_hidden_env_file_change_blocks_apply_before_switch(self):
        env_file = self.workdir/"identity-runtime.env"
        env_file.write_text("IDENTITY=original\n")
        model = copy.deepcopy(self.model)
        model["services"]["control-plane"]["env_file"] = [{"path": str(env_file), "required": False}]
        self.base.write_text(json.dumps(model))
        self.release.stage()
        env_file.write_text("IDENTITY=drift\n")
        with self.assertRaisesRegex(RuntimeError, "input"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_hidden_optional_env_file_appearance_blocks_apply(self):
        env_file = self.workdir/"identity-runtime.env"
        model = copy.deepcopy(self.model)
        model["services"]["control-plane"]["env_file"] = [{"path": str(env_file), "required": False}]
        self.base.write_text(json.dumps(model))
        self.release.stage()
        env_file.write_text("IDENTITY=appeared\n")
        with self.assertRaisesRegex(RuntimeError, "input"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_healthcheck_or_host_resource_drift_is_rejected_at_stage(self):
        for mutate in (lambda row: row["Config"].update(Healthcheck={"Test": ["NONE"]}),
                       lambda row: row["HostConfig"].update(Memory=128*1024**2)):
            self.rows = copy.deepcopy(self.baseline)
            self.calls.clear()
            mutate(self.rows[0])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(RuntimeError, "healthcheck|host"):
                self.release.stage()
            self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))

    def test_historical_service_hash_drift_is_rejected_before_image_load(self):
        self.rows[0]["Config"]["Labels"]["com.docker.compose.config-hash"] = "later"
        with self.assertRaisesRegex(RuntimeError, "hash|historical"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))

    def test_stage_refuses_changes_during_image_load(self):
        run = self.fake_run
        def drift(argv, **kwargs):
            value = run(argv, **kwargs)
            if argv[:3] == ["docker", "image", "load"]:
                self.rows[2]["RestartCount"] = 1
            return value
        with patch.object(vm, "run", drift), self.assertRaisesRegex(RuntimeError, "stage"):
            self.release.stage()
        self.assertEqual(self.switch_count, 0)

    def test_tampered_saved_old_model_rejects_rollback(self):
        sha = self.stage_apply()
        (self.media/"state/rollback.json").write_text("{}")
        with self.assertRaises(RuntimeError):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_seed_or_payload_verification_failure_never_publishes_success(self):
        self.release.stage()
        self.bad_payload = True
        with self.assertRaises(RuntimeError):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())

    def test_atomic_chain_swap_failure_recovers_targets_and_keeps_original_bytes(self):
        self.release.stage()
        atomic = console.atomic_bytes
        def broken(path, content):
            if path == self.chain and content != self.old_chain:
                raise RuntimeError("injected atomic chain swap")
            return atomic(path, content)
        with patch.object(console, "atomic_bytes", broken), self.assertRaisesRegex(RuntimeError, "atomic chain"):
            self.release.apply()
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assert_non_targets_unchanged()
        self.assertFalse(self.release.pointer.exists())

    def test_drift_during_switch_recovers_targets_but_reports_incomplete_preservation(self):
        self.release.stage()
        switch = self.release.switch
        def drift():
            switch()
            self.rows[2]["RestartCount"] = 1
        self.release.switch = drift
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual({s: self.rows[i]["Image"] for i, s in enumerate(console.SERVICES)}, self.old)
        self.assertEqual(self.chain.read_bytes(), self.old_chain)
        self.assertFalse(self.release.pointer.exists())

    def test_console_transfer_rejects_existing_part_symlink_before_download(self):
        for path in (self.root, self.media.parent, self.media):
            path.chmod(0o700)
        for path in self.media.iterdir():
            if path.is_file():
                path.chmod(0o600)
        outside = Path(self.temp.name)/"untouched"
        outside.write_bytes(b"keep")
        (self.media/"images.tar.part").symlink_to(outside)
        args = SimpleNamespace(repo="/home/dev/reviewed", vm="jjdguard-gateway")
        def guest(domain, code, **kwargs):
            self.assertIn("protected(root.parent", code)
            code = code.replace("/opt/jjdguard", str(self.root)).replace("info.st_uid == 0", "info.st_uid == os.getuid()")
            exec(compile(code, "<console-transfer-bootstrap>", "exec"), {})
        with patch.object(console, "protected", REAL_PROTECTED), patch.object(deploy, "source_gate", return_value=self.manifest["tree"]), \
                patch.object(deploy, "validate_console_source_media"), patch.object(deploy.subprocess, "check_output", return_value='[{"prefsrc":"192.168.56.1"}]'), \
                patch.object(deploy.http.server, "ThreadingHTTPServer") as server, patch.object(deploy.threading, "Thread"), \
                patch.object(deploy, "guest", guest), patch("urllib.request.urlopen") as download, self.assertRaisesRegex(RuntimeError, "unprotected"):
            server.return_value.server_port = 49123
            deploy.deploy(args, self.media, self.manifest)
        download.assert_not_called()
        self.assertEqual(outside.read_bytes(), b"keep")

    @contextlib.contextmanager
    def bootstrap_installation_owner(self, uid=12345, mismatch=False, pointer_uid=None):
        original_stat = Path.stat
        def installed_stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path == self.release_root or (path == self.root/"current" and kwargs.get("follow_symlinks") is False):
                fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
                fields.update(st_uid=uid if path == self.release_root or pointer_uid is None else pointer_uid, st_gid=uid)
                return SimpleNamespace(**fields)
            return value
        account = SimpleNamespace(pw_uid=uid, pw_gid=uid+1 if mismatch else uid, pw_name="fixture-owner")
        with patch.object(Path, "stat", installed_stat), \
                patch.object(Path, "lstat", lambda path: installed_stat(path, follow_symlinks=False)), \
                patch("pwd.getpwuid", return_value=account):
            yield

    def owner_bootstrap_code(self, action):
        for path in (self.root.parent, self.root, self.media.parent, self.media,
                     self.root/"releases", self.release_root, self.release_root/"deploy",
                     self.workdir, self.workdir/"active-config", self.workdir/".upgrade", self.workdir/"bin"):
            path.chmod(0o755)
        receipt = self.stage_apply() if action == "rollback" else None
        for path in (self.root, self.media.parent, self.media):
            path.chmod(0o700)
        for path in self.media.iterdir():
            if path.is_file():
                path.chmod(0o600)
        with patch.object(console, "protected", REAL_PROTECTED):
            code = console.rollback_guest_code("dev-test", receipt) if receipt else \
                console.apply_guest_code("dev-test", vm.digest(self.media/"manifest.json"), action)
        code = code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")")
        # Only evidence ownership is redirected; the installation owner branch
        # still sees the fixture's root or non-root UID and real pointer checks.
        return code.replace("not parent.is_symlink() and info.st_uid == 0",
                            "not parent.is_symlink() and info.st_uid == os.getuid()")

    def test_console_bootstraps_root_owned_installation_keep_direct_execution(self):
        for action in ("stage", "apply", "rollback"):
            with self.subTest(action=action):
                code = self.owner_bootstrap_code(action)
                with self.bootstrap_installation_owner(uid=0), patch("subprocess.run") as execute:
                    exec(compile(code, "<console-owner-bootstrap>", "exec"), {})
                execute.assert_called_once()
                command = execute.call_args.args[0]
                self.assertEqual(command[:2], ["/usr/bin/python3", "-B"])
                self.assertEqual(command[3], action)
                self.assertNotIn("--install-owner-uid", command)
                self.assertEqual(execute.call_args.kwargs["cwd"], "/root")
                self.assertEqual(execute.call_args.kwargs["env"], console.controlled_environment())

    def test_console_bootstraps_user_owned_installation_authenticate_through_sudo(self):
        for action in ("stage", "apply", "rollback"):
            with self.subTest(action=action):
                code = self.owner_bootstrap_code(action)
                with self.bootstrap_installation_owner(), patch("subprocess.run") as execute, \
                        patch.dict(os.environ, {"SUDO_UID": "untrusted", "SUDO_GID": "untrusted", "PYTHONPATH": "/untrusted"}):
                    exec(compile(code, "<console-owner-bootstrap>", "exec"), {})
                execute.assert_called_once()
                command = execute.call_args.args[0]
                self.assertEqual(command[:10], ["/usr/bin/sudo", "-u", "fixture-owner", "-n", "--",
                                               "/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-B"])
                self.assertEqual(command[11], action)
                self.assertEqual(command[-4:], ["--install-owner-uid", "12345", "--install-owner-gid", "12345"])
                self.assertEqual(execute.call_args.kwargs["cwd"], "/")
                self.assertEqual(execute.call_args.kwargs["env"], console.controlled_environment())
                self.assertFalse(any(key.startswith("SUDO_") for key in execute.call_args.kwargs["env"]))
                self.assertNotIn("PYTHONPATH", execute.call_args.kwargs["env"])

    def test_console_bootstraps_reject_mismatched_installation_account_before_execute(self):
        for action in ("stage", "apply", "rollback"):
            with self.subTest(action=action):
                code = self.owner_bootstrap_code(action)
                with self.bootstrap_installation_owner(mismatch=True), patch("subprocess.run") as execute, \
                        self.assertRaisesRegex(RuntimeError, "installation owner account differs"):
                    exec(compile(code, "<console-owner-bootstrap>", "exec"), {})
                execute.assert_not_called()

    def test_console_bootstraps_reject_unrelated_pointer_owner_before_execute(self):
        for action in ("stage", "apply", "rollback"):
            with self.subTest(action=action):
                code = self.owner_bootstrap_code(action)
                with self.bootstrap_installation_owner(pointer_uid=67890), patch("subprocess.run") as execute, \
                        self.assertRaisesRegex(RuntimeError, "installation ownership differs"):
                    exec(compile(code, "<console-owner-bootstrap>", "exec"), {})
                execute.assert_not_called()

    def test_console_bootstraps_reject_missing_sudo_before_execute(self):
        for action in ("stage", "apply", "rollback"):
            with self.subTest(action=action):
                code = self.owner_bootstrap_code(action)
                with self.bootstrap_installation_owner(), patch("os.access", return_value=False), \
                        patch("subprocess.run") as execute, self.assertRaisesRegex(RuntimeError, "sudo unavailable"):
                    exec(compile(code, "<console-owner-bootstrap>", "exec"), {})
                execute.assert_not_called()

    def test_console_bootstraps_propagate_sudo_denial(self):
        for action in ("stage", "apply", "rollback"):
            with self.subTest(action=action):
                code = self.owner_bootstrap_code(action)
                with self.bootstrap_installation_owner(), \
                        patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "sudo")), \
                        self.assertRaises(subprocess.CalledProcessError):
                    exec(compile(code, "<console-owner-bootstrap>", "exec"), {})

    def test_apply_bootstrap_authenticates_media_and_uses_clean_environment(self):
        for path in (self.root, self.media.parent, self.media):
            path.chmod(0o700)
        for path in self.media.iterdir():
            if path.is_file():
                path.chmod(0o600)
        with patch.object(console, "protected", REAL_PROTECTED):
            code = console.apply_guest_code("dev-test", vm.digest(self.media/"manifest.json"), "stage")
        code = code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")")
        code = code.replace("info.st_uid == 0", "info.st_uid == os.getuid()")
        with patch("subprocess.run") as execute:
            exec(compile(code, "<console-apply-bootstrap>", "exec"), {})
            execute.assert_called_once()
            self.assertEqual(execute.call_args.kwargs["env"], console.controlled_environment())
            self.assertEqual(execute.call_args.kwargs["cwd"], "/root")
        (self.media/"vm_console_release.py").write_text("must not execute")
        with patch("subprocess.run") as execute, self.assertRaisesRegex(RuntimeError, "media changed"):
            exec(compile(code, "<console-apply-bootstrap>", "exec"), {})
        execute.assert_not_called()

    def test_apply_bootstrap_rejects_unrecorded_import_file_before_execute(self):
        for path in (self.root, self.media.parent, self.media):
            path.chmod(0o700)
        for path in self.media.iterdir():
            if path.is_file():
                path.chmod(0o600)
        (self.media/"json.py").write_text("must not import\n")
        with patch.object(console, "protected", REAL_PROTECTED):
            code = console.apply_guest_code("dev-test", vm.digest(self.media/"manifest.json"), "stage")
        code = code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")").replace("info.st_uid == 0", "info.st_uid == os.getuid()")
        with patch("subprocess.run") as execute, self.assertRaisesRegex(RuntimeError, "executable/media"):
            exec(compile(code, "<console-apply-bootstrap>", "exec"), {})
        execute.assert_not_called()

    def test_apply_bootstrap_rejects_invalid_action_or_identity(self):
        for release, checksum, action in (("../dev-test", "a"*64, "stage"), ("dev-test", "a"*64, "start"), ("dev-test", "latest", "apply")):
            with self.assertRaises(RuntimeError):
                console.apply_guest_code(release, checksum, action)

    def test_bootstrap_authenticates_recorded_code_before_execute(self):
        sha = self.stage_apply()
        code = self.bootstrap(sha)
        with patch("subprocess.run") as execute:
            exec(compile(code, "<console-rollback-bootstrap>", "exec"), {})
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[0][-4:], ["--release-id", "dev-test", "--receipt-sha256", sha])
            self.assertIn("vm_console_release.py", execute.call_args.args[0][2])

    def test_bootstrap_rejects_tampered_script_without_execution(self):
        sha = self.stage_apply()
        code = self.bootstrap(sha)
        (self.media/"vm_console_release.py").write_text("raise Exception('must not execute')")
        with patch("subprocess.run") as execute:
            with self.assertRaisesRegex(RuntimeError, "media changed"):
                exec(compile(code, "<console-rollback-bootstrap>", "exec"), {})
            execute.assert_not_called()

    def test_bootstrap_rejects_unrecorded_cached_bytecode(self):
        sha = self.stage_apply()
        code = self.bootstrap(sha)
        (self.media/"__pycache__").mkdir()
        with patch("subprocess.run") as execute:
            with self.assertRaisesRegex(RuntimeError, "cached"):
                exec(compile(code, "<console-rollback-bootstrap>", "exec"), {})
            execute.assert_not_called()

    def bootstrap(self, sha):
        for path in (self.root, self.media.parent, self.media):
            path.chmod(0o700)
        for path in self.media.iterdir():
            if path.is_file():
                path.chmod(0o600)
        with patch.object(console, "protected", REAL_PROTECTED):
            code = console.rollback_guest_code("dev-test", sha)
        code = code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")")
        return code.replace("info.st_uid == 0", "info.st_uid == os.getuid()")

    def test_receipt_media_tampering_and_replay_are_rejected(self):
        sha = self.stage_apply()
        self.release.rollback(sha)
        calls = list(self.calls)
        with self.assertRaises((RuntimeError, AssertionError, FileNotFoundError)):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 3)
        self.assertEqual(self.calls, calls)

    def test_scope_cannot_use_security_engine_receipt(self):
        sha = self.stage_apply()
        receipt = json.loads((self.media/"receipt.json").read_text())
        receipt["purpose"] = "security-engine-only"
        vm.write_json(self.media/"receipt.json", receipt)
        bad_sha = vm.digest(self.media/"receipt.json")
        vm.write_json(self.release.pointer, dict(release=str(self.media), receipt_sha256=bad_sha))
        with self.assertRaisesRegex(RuntimeError, "receipt"):
            self.release.rollback(bad_sha)
        self.assertEqual(self.switch_count, 1)


class RuntimeNetworkIPAMTests(unittest.TestCase):
    def validate(self, ipam, requested=None, aliases=None):
        defaults = dict(User="10001", WorkingDir="/app", Cmd=["/app/control-plane"], Env=[], Labels={})
        row = dict(Id="fixture-control-plane", Name="/control-plane", Path="/app/control-plane", Args=[],
                   Config=copy.deepcopy(defaults), HostConfig={}, Mounts=[],
                   NetworkSettings=dict(Networks={"fixture-net": {"Aliases": aliases if aliases is not None else ["control-plane"], "IPAMConfig":ipam}}))
        item = dict(image="fixture", networks={"default":requested or {}})
        console.validate_runtime_model("control-plane", item, {"networks":{"default":{"name":"fixture-net"}}}, row, {"Config":defaults}, "json-file")

    def test_docker_empty_address_fields_are_unconfigured(self):
        for ipam in (None, {}, {"IPv4Address":""}, {"IPv6Address":""}, {"IPv4Address":"", "IPv6Address":""}):
            with self.subTest(ipam=ipam):
                self.validate(ipam)

    def test_static_addresses_still_require_exact_declaration(self):
        self.validate({"IPv4Address":"192.0.2.10", "IPv6Address":""}, {"ipv4_address":"192.0.2.10"})
        for ipam in ({"IPv4Address":"192.0.2.11"}, {"IPv6Address":"2001:db8::11"}, {"LinkLocalIPs":[]}, {"unexpected":""}):
            with self.subTest(ipam=ipam):
                with self.assertRaisesRegex(RuntimeError, "IPAM differs"):
                    self.validate(ipam)
        with self.assertRaisesRegex(RuntimeError, "IPAM differs"):
            self.validate({"IPv4Address":"192.0.2.11"}, {"ipv4_address":"192.0.2.10"})
        with self.assertRaisesRegex(RuntimeError, "network aliases differ"):
            self.validate({"IPv4Address":"", "IPv6Address":""}, aliases=["wrong-service"])


if __name__ == "__main__":
    unittest.main()
