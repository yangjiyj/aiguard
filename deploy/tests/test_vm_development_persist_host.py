"""Host persistence contracts use local fixtures and never contact the VM."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"release"))
import deploy_vm_development as deploy
import vm_development_apply as vm


class HostPersistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.media = Path(self.temp.name)/"media"
        self.media.mkdir()
        self.manifest = dict(purpose="development-vm", release_id="dev-test", revision="a"*40,
                             tree="b"*40, services={name:{} for name in vm.SERVICES},
                             apply_script_sha256="c"*64)
        (self.media/"manifest.json").write_text(json.dumps(self.manifest))
        (self.media/"vm_development_apply.py").write_text("frozen helper")
        self.args = SimpleNamespace(repo="/home/dev/reviewed", vm="jjdguard-gateway", persist_boot=True)
        self.calls = []

    def run_deploy(self, manifest=None, failure=None, slow_apply=False):
        manifest = manifest or self.manifest
        def guest(domain, code, **kwargs):
            self.calls.append(code)
            if slow_apply and "'apply'" in code and kwargs.get("seconds", 900) < 2100:
                raise RuntimeError("guest still running; database backup/rollback outlasted host deadline")
            if "'persist-boot'" in code:
                if failure: raise RuntimeError(failure)
                return "FINAL_RECEIPT_SHA256="+"e"*64+"\n"
            if "APPLY_RECEIPT_SHA256=" in code:
                return "APPLY_RECEIPT_SHA256="+"d"*64+"\n"
            return "verified\n"
        with patch.object(deploy, "source_gate", return_value="b"*40), \
                patch.object(deploy, "validate_persist_source_media", create=True), \
                patch.object(deploy.subprocess, "check_output", return_value='[{"prefsrc":"192.168.56.1"}]'), \
                patch.object(deploy.http.server, "ThreadingHTTPServer") as server, \
                patch.object(deploy.threading, "Thread"), patch.object(deploy, "guest", guest), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            server.return_value.server_port = 49123
            deploy.deploy(self.args, self.media, manifest)
        return output.getvalue()

    def test_slow_database_transaction_remains_observed_until_receipt(self):
        # Real development backup/rollback took over 30 minutes; host must keep
        # observing the bounded guest transaction instead of dropping its lock.
        output = self.run_deploy(slow_apply=True)
        self.assertIs(json.loads(output.splitlines()[-1])["boot_persisted"], True)
        self.assertIn("'persist-boot'", self.calls[-1])

    def test_full_deploy_pins_apply_receipt_then_persists_boot(self):
        output = self.run_deploy()
        self.assertEqual(len(self.calls), 5)
        self.assertIn("APPLY_RECEIPT_SHA256=", self.calls[3])
        self.assertIn("'persist-boot'", self.calls[4])
        self.assertIn("d"*64, self.calls[4])
        result = json.loads(output.splitlines()[-1])
        self.assertEqual(result["receipt_sha256"], "e"*64)
        self.assertIs(result["boot_persisted"], True)

    def test_full_apply_and_persist_bootstraps_authenticate_installation_owner(self):
        self.run_deploy()
        for index in (1, 2, 4):
            with self.subTest(call=index):
                self.assertIn("--install-owner-uid", self.calls[index])
                self.assertIn("/usr/bin/sudo", self.calls[index])
                self.assertNotIn("SUDO_UID=", self.calls[index])

    def test_fence_preflights_live_write_permissions_before_changing_ingress(self):
        release = SimpleNamespace(
            resolve_candidate_images=lambda: None, load_state=lambda: None, manifest={},
            before={"runtime": {}, "compose_files": [], "compose_sha256": {}, "env_sha256": "env"},
            live_files=(), env_file=Path("environment"), live=Path("new-live.json"),
            ledger=lambda: {}, policy=lambda: {}, before_ledger={}, before_policy={},
            chain="fixture", interface="fixture", event=lambda message: None)
        with patch.object(vm, "inspect_runtime", return_value={}), patch.object(vm, "digest", return_value="env"), \
             patch.object(vm, "authenticate_write_paths", side_effect=RuntimeError("unauthorised directory owner")), \
             patch.object(vm, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "unauthorised directory owner"):
                vm.Release.fence(release)
        run.assert_not_called()

    def test_preserve_tier1_deploy_uses_the_same_persistence_contract(self):
        manifest = dict(self.manifest, preserve_tier1=True,
                        services={name:{} for name in vm.SERVICES[:-1]})
        self.run_deploy(manifest)
        self.assertIn("'persist-boot'", self.calls[-1])

    def test_persist_failure_never_emits_a_success_receipt(self):
        with self.assertRaisesRegex(RuntimeError, "boot drift"):
            self.run_deploy(failure="boot drift")

    def test_without_flag_retains_development_pointer_contract(self):
        self.args.persist_boot = False
        self.run_deploy()
        self.assertEqual(len(self.calls), 3)

    def test_narrow_modes_are_rejected_before_transfer(self):
        for mode in ("console_only", "security_engine_only", "engineering_only", "portal_only"):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, "full development release"):
                self.run_deploy(dict(self.manifest, **{mode:True}))
        self.assertEqual(self.calls, [])

    def test_explicit_persistence_uses_the_host_release_lock(self):
        events = []
        @contextlib.contextmanager
        def locked():
            events.append("lock")
            yield
            events.append("unlock")
        argv = ["deploy_vm_development.py", "--repo", self.args.repo,
                "--media", str(self.media), "--persist-boot"]
        with patch.object(sys, "argv", argv), patch.object(deploy, "release_lock", locked), \
                patch.object(deploy, "deploy", side_effect=lambda *args: events.append("deploy")):
            deploy.main()
        self.assertEqual(events, ["lock", "deploy", "unlock"])

    def test_source_helper_must_equal_frozen_git_source(self):
        source = b"frozen helper"
        self.manifest["apply_script_sha256"] = hashlib.sha256(source).hexdigest()
        with patch.object(deploy.subprocess, "check_output", return_value=source):
            deploy.validate_persist_source_media(Path(self.args.repo), self.media, self.manifest)
            (self.media/"vm_development_apply.py").write_text("changed helper")
            with self.assertRaisesRegex(RuntimeError, "frozen source"):
                deploy.validate_persist_source_media(Path(self.args.repo), self.media, self.manifest)

    def test_receipt_output_requires_exactly_one_full_sha(self):
        for output in ("", "APPLY_RECEIPT_SHA256=latest\n",
                       ("APPLY_RECEIPT_SHA256="+"a"*64+"\n")*2):
            with self.subTest(output=output), self.assertRaisesRegex(RuntimeError, "receipt"):
                deploy.receipt_output_pin(output, "APPLY_RECEIPT_SHA256=")

    def test_persist_only_uses_original_media_without_transfer_or_apply(self):
        argv = ["deploy_vm_development.py", "--repo", self.args.repo, "--media", str(self.media),
                "--persist-only", "--receipt-sha256", "d"*64]
        with patch.object(sys, "argv", argv), patch.object(deploy, "release_lock", contextlib.nullcontext), \
                patch.object(deploy, "persist_recorded", create=True) as persist, \
                patch.object(deploy, "deploy") as forward:
            deploy.main()
        persist.assert_called_once()
        forward.assert_not_called()

    def test_persist_only_requires_external_receipt_pin(self):
        argv = ["deploy_vm_development.py", "--repo", self.args.repo,
                "--media", str(self.media), "--persist-only"]
        with patch.object(sys, "argv", argv), patch.object(deploy, "guest") as guest, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            deploy.main()
        guest.assert_not_called()

    def test_persist_recorded_never_transfers_or_reapplies(self):
        self.args.receipt_sha256 = "d"*64
        self.args.media = str(self.media)
        with patch.object(deploy, "source_gate", return_value=self.manifest["tree"]), \
                patch.object(deploy, "validate_persist_source_media"), \
                patch.object(deploy, "guest", return_value="FINAL_RECEIPT_SHA256="+"e"*64+"\n") as guest, \
                patch.object(deploy.http.server, "ThreadingHTTPServer") as server, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            deploy.persist_recorded(self.args)
        guest.assert_called_once()
        self.assertIn("'persist-boot'", guest.call_args.args[1])
        server.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["receipt_sha256"], "e"*64)


class PersistBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"jjdguard"
        self.installed = self.root/"releases"/"installed"
        self.installed.mkdir(parents=True)
        (self.root/"current").symlink_to(self.installed, target_is_directory=True)
        self.media = self.root/"development-releases/dev-test"
        self.media.mkdir(parents=True)
        self.script = self.media/"vm_development_apply.py"
        self.script.write_bytes(b"frozen helper")
        self.apply_sha = hashlib.sha256(self.script.read_bytes()).hexdigest()
        self.manifest = dict(purpose="development-vm", release_id="dev-test", revision="a"*40,
                             tree="b"*40, services={name:{"image_id":"sha256:"+"f"*64} for name in vm.SERVICES},
                             apply_script_sha256=self.apply_sha)
        self.manifest_path = self.media/"manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.manifest_sha = deploy.digest(self.manifest_path)
        self.receipt_path = self.media/"receipt.json"
        self.receipt_path.write_text(json.dumps(dict(status="deployed", release_id="dev-test",
                                                    revision=self.manifest["revision"], manifest_sha256=self.manifest_sha,
                                                    services={name:record["image_id"] for name,record in self.manifest["services"].items()},
                                                    persist_boot=None)))
        self.receipt_sha = deploy.digest(self.receipt_path)
        self.pointer = self.media.parent/"current.json"
        self.pointer.write_text(json.dumps(dict(release=str(self.media), receipt_sha256=self.receipt_sha)))
        for directory in (self.root, self.media.parent, self.media): directory.chmod(0o700)
        for path in self.media.iterdir(): path.chmod(0o600)
        self.pointer.chmod(0o600)

    def bootstrap(self, receipt=True):
        code = deploy.persist_guest_code("dev-test", self.manifest_sha, self.apply_sha,
                                         self.receipt_sha if receipt else None)
        return code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")") \
                   .replace("info.st_uid == 0", "info.st_uid == os.getuid()")

    def execute(self, code):
        with patch("subprocess.run") as child, contextlib.redirect_stdout(io.StringIO()) as output:
            exec(compile(code, "<persist-bootstrap>", "exec"), {})
        return child, output.getvalue()

    def test_oci_receipt_maps_verified_descriptor_to_frozen_config(self):
        raw = json.dumps({'config': {'digest': 'sha256:'+'f'*64}}, separators=(',', ':')).encode()
        image_id = 'sha256:'+hashlib.sha256(raw).hexdigest()
        receipt = json.loads(self.receipt_path.read_text())
        receipt['services'] = {name: image_id for name in self.manifest['services']}
        self.receipt_path.write_text(json.dumps(receipt)); self.receipt_sha = deploy.digest(self.receipt_path)
        self.pointer.write_text(json.dumps(dict(release=str(self.media), receipt_sha256=self.receipt_sha)))
        def result(command, **kwargs):
            if command[0] == '/usr/bin/docker':
                return SimpleNamespace(stdout=json.dumps([{'Id': image_id, 'Descriptor': {'digest': image_id}}]))
            if command[0] == '/usr/bin/ctr': return SimpleNamespace(stdout=raw)
            return SimpleNamespace(returncode=0)
        with patch('subprocess.run', side_effect=result) as child:
            exec(compile(self.bootstrap(), '<oci-persist-bootstrap>', 'exec'), {})
        self.assertEqual(child.call_args.args[0][:4], ['/usr/bin/python3','-I','-B',str(self.script)])

    def test_oci_receipt_rejects_forged_manifest_bytes_before_helper(self):
        image_id='sha256:'+'e'*64
        receipt=json.loads(self.receipt_path.read_text());receipt['services']={name:image_id for name in self.manifest['services']}
        self.receipt_path.write_text(json.dumps(receipt));self.receipt_sha=deploy.digest(self.receipt_path)
        self.pointer.write_text(json.dumps(dict(release=str(self.media),receipt_sha256=self.receipt_sha)))
        def result(command, **kwargs):
            if command[0]=='/usr/bin/docker':return SimpleNamespace(stdout=json.dumps([{'Id':image_id,'Descriptor':{'digest':image_id}}]))
            return SimpleNamespace(stdout=b'{"config":{"digest":"sha256:forged"}}')
        with patch('subprocess.run',side_effect=result) as child, self.assertRaisesRegex(RuntimeError,'OCI manifest digest differs'):
            exec(compile(self.bootstrap(),'<oci-persist-bootstrap>','exec'),{})
        self.assertTrue(all(call.args[0][0]!='/usr/bin/python3' for call in child.call_args_list))

    def test_receipt_snapshot_is_pinned_without_executing_saved_code(self):
        child, output = self.execute(self.bootstrap(receipt=False))
        child.assert_not_called()
        self.assertEqual(output.strip(), "APPLY_RECEIPT_SHA256="+self.receipt_sha)

    def test_bootstrap_authenticates_and_executes_with_isolated_python(self):
        child, _ = self.execute(self.bootstrap())
        child.assert_called_once()
        command = child.call_args.args[0]
        self.assertEqual(command[:4], ["/usr/bin/python3", "-I", "-B", str(self.script)])
        self.assertIn("persist-boot", command)
        self.assertEqual(command[-2:], ["--receipt-sha256", self.receipt_sha])
        self.assertEqual(child.call_args.kwargs["cwd"], "/root")
        self.assertNotIn("PYTHONPATH", child.call_args.kwargs["env"])

    def test_forward_bootstraps_verify_saved_helper_and_control_python_environment(self):
        for action in ("stage", "apply"):
            with self.subTest(action=action):
                code = deploy.forward_guest_code("dev-test", self.manifest_sha, self.apply_sha, action)
                code = code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")") \
                           .replace("info.st_uid == 0", "info.st_uid == os.getuid()")
                child, _ = self.execute(code)
                command = child.call_args.args[0]
                self.assertEqual(command[:5], ["/usr/bin/python3", "-E", "-s", "-B", str(self.script)])
                self.assertIn(action, command)
                self.assertNotIn("PYTHONPATH", child.call_args.kwargs["env"])

    @contextlib.contextmanager
    def installation_owner_fixture(self, mismatch=False, pointer_uid=12345):
        original_stat = Path.stat
        def installed_stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path in (self.installed, self.root/"current"):
                fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
                fields.update(st_uid=pointer_uid if path == self.root/"current" else 12345, st_gid=12345)
                return SimpleNamespace(**fields)
            return value
        account = SimpleNamespace(pw_uid=12345, pw_gid=12346 if mismatch else 12345, pw_name="fixture-owner")
        with patch.object(Path, "stat", installed_stat), \
             patch.object(Path, "lstat", lambda path: installed_stat(path, follow_symlinks=False)), \
             patch("pwd.getpwuid", return_value=account):
            yield

    def test_user_owned_installation_uses_real_sudo_handoff_arguments(self):
        with self.installation_owner_fixture():
            child, _ = self.execute(self.bootstrap())
        command = child.call_args.args[0]
        self.assertEqual(command[:9], ["/usr/bin/sudo", "-u", "fixture-owner", "-n", "--",
                                       "/usr/bin/sudo", "-n", "--", "/usr/bin/python3"])
        self.assertEqual(command[-4:], ["--install-owner-uid", "12345", "--install-owner-gid", "12345"])
        self.assertEqual(child.call_args.kwargs["cwd"], "/")
        self.assertFalse(any(key.startswith("SUDO_") for key in child.call_args.kwargs["env"]))

    def test_mismatched_installation_owner_is_rejected_before_execution(self):
        with self.installation_owner_fixture(mismatch=True), patch("subprocess.run") as child, \
             self.assertRaisesRegex(RuntimeError, "installation owner account differs"):
            exec(compile(self.bootstrap(), "<owner-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_unrelated_installation_pointer_owner_is_rejected_before_execution(self):
        with self.installation_owner_fixture(pointer_uid=67890), \
             patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "installation ownership differs"):
            exec(compile(self.bootstrap(), "<owner-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_missing_sudo_is_rejected_before_execution(self):
        with self.installation_owner_fixture(), patch("os.access", return_value=False), \
             patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "sudo unavailable"):
            exec(compile(self.bootstrap(), "<owner-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_sudo_denial_is_not_reported_as_success(self):
        import subprocess
        with self.installation_owner_fixture(), patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "sudo")), \
             self.assertRaises(subprocess.CalledProcessError):
            exec(compile(self.bootstrap(), "<owner-bootstrap>", "exec"), {})

    def test_installation_pointer_escape_is_rejected_before_execution(self):
        (self.root/"current").unlink()
        (self.root/"current").symlink_to(self.media, target_is_directory=True)
        with patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "pointer escapes"):
            exec(compile(self.bootstrap(), "<owner-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_changed_saved_helper_is_rejected_before_execution(self):
        code = self.bootstrap()
        self.script.write_bytes(b"tampered helper")
        with patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "script"):
            exec(compile(code, "<persist-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_changed_receipt_is_rejected_before_execution(self):
        code = self.bootstrap()
        self.receipt_path.write_bytes(self.receipt_path.read_bytes()+b"\n")
        with patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "receipt"):
            exec(compile(code, "<persist-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_pointer_drift_is_rejected_before_execution(self):
        code = self.bootstrap()
        self.pointer.write_text(json.dumps(dict(release="another-release", receipt_sha256=self.receipt_sha)))
        with patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "active"):
            exec(compile(code, "<persist-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_symlinked_saved_helper_is_rejected_before_execution(self):
        code = self.bootstrap()
        outside = Path(self.temp.name)/"outside.py"
        outside.write_bytes(self.script.read_bytes())
        self.script.unlink()
        self.script.symlink_to(outside)
        with patch("subprocess.run") as child, self.assertRaisesRegex(RuntimeError, "unprotected"):
            exec(compile(code, "<persist-bootstrap>", "exec"), {})
        child.assert_not_called()

    def test_invalid_identity_is_rejected_at_host(self):
        for release, manifest, script, receipt in (("../dev-test", self.manifest_sha, self.apply_sha, self.receipt_sha),
                                                  ("dev-test", "latest", self.apply_sha, self.receipt_sha),
                                                  ("dev-test", self.manifest_sha, "latest", self.receipt_sha),
                                                  ("dev-test", self.manifest_sha, self.apply_sha, "latest")):
            with self.subTest(release=release), self.assertRaises(RuntimeError):
                deploy.persist_guest_code(release, manifest, script, receipt)

    def test_isolated_saved_helper_cannot_import_an_unrecorded_neighbor(self):
        self.script.write_bytes(b"import json\nprint('FINAL_RECEIPT_SHA256='+'e'*64)\n")
        self.apply_sha = deploy.digest(self.script)
        self.manifest["apply_script_sha256"] = self.apply_sha
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.manifest_sha = deploy.digest(self.manifest_path)
        receipt = json.loads(self.receipt_path.read_text())
        receipt["manifest_sha256"] = self.manifest_sha
        self.receipt_path.write_text(json.dumps(receipt))
        self.receipt_sha = deploy.digest(self.receipt_path)
        self.pointer.write_text(json.dumps(dict(release=str(self.media), receipt_sha256=self.receipt_sha)))
        (self.media/"json.py").write_text("raise RuntimeError('unrecorded import executed')\n")
        code = self.bootstrap().replace("cwd='/root'", "cwd="+repr(self.temp.name))
        exec(compile(code, "<persist-bootstrap-isolated>", "exec"), {})


if __name__ == "__main__":
    unittest.main()
