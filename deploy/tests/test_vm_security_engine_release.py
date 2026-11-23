"""SE-only transactions against a fake Docker/Compose VM; never contact a real VM."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"release"))
import build_vm_development as build
import deploy_vm_development as deploy
import vm_development_apply as vm
import vm_security_engine_release as se
REAL_PROTECTED = se.protected


class ScopeTests(unittest.TestCase):
    def test_mount_order_is_not_configuration_drift_but_mount_values_are(self):
        row = dict(Id="container", Image="image", Config={}, HostConfig={}, NetworkSettings={},
                   State=dict(StartedAt="now", Status="running"), RestartCount=0,
                   Mounts=[dict(Destination="/a", Source="/data/a", RW=False),
                           dict(Destination="/b", Source="/data/b", RW=True)])
        reordered = copy.deepcopy(row)
        reordered["Mounts"].reverse()
        self.assertEqual(se.fingerprints([row]), se.fingerprints([reordered]))
        changed = copy.deepcopy(row)
        changed["Mounts"][0]["RW"] = True
        self.assertNotEqual(se.fingerprints([row]), se.fingerprints([changed]))
        self.assertNotEqual(se.runtime_contract(row), se.runtime_contract(changed))

    def args(self, **changes):
        value = dict(security_engine_only=True, engineering_only=False, portal_only=False,
                     preserve_tier1=False, migration=[], enable_file_detection=False)
        return SimpleNamespace(**dict(value, **changes))

    def test_builder_and_guest_accept_only_se_and_no_mode_changes(self):
        self.assertEqual(build.release_services(self.args()), (se.SERVICE,))
        good = dict(security_engine_only=True, preserve_tier1=True, services={se.SERVICE: {}})
        self.assertEqual(vm.release_service_sets(good)[0], (se.SERVICE,))
        for change in (dict(portal_only=True), dict(engineering_only=True), dict(migration=["001.sql"]),
                       dict(enable_file_detection=True)):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                build.release_services(self.args(**change))
        for change in (dict(security_engine_only=1), dict(preserve_tier1=False), dict(migrations={"001.sql":"x"}),
                       dict(engineering_only=True), dict(portal_only=True), dict(enable_file_detection=True),
                       dict(services={se.SERVICE:{}, "gateway-core":{}})):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                vm.release_service_sets(dict(good, **change))

    def test_rollback_never_contacts_guest_when_live_source_gate_fails(self):
        args = SimpleNamespace(repo="/home/dev/checkout", rollback_release_id="dev-test", receipt_sha256="a"*64, vm="jjdguard-gateway")
        with patch.object(deploy.subprocess, "check_output", return_value="b"*40), \
                patch.object(deploy, "source_gate", side_effect=RuntimeError("dirty")) as gate, \
                patch.object(deploy, "guest") as guest:
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                deploy.rollback_recorded(args)
            gate.assert_called_once_with(Path(args.repo), "b"*40)
            guest.assert_not_called()

    def test_rollback_id_and_receipt_are_not_shell_or_path_inputs(self):
        for release, digest in (("../dev-x", "a"*64), ("dev-x", "latest"), ("dev-x;touch /tmp/x", "a"*64)):
            with self.assertRaises(RuntimeError):
                se.rollback_guest_code(release, digest)

    def test_build_keeps_live_source_gates_before_and_after_frozen_build(self):
        calls = []
        args = SimpleNamespace(repo="/home/dev/frozen-worktree", revision="a"*40)
        with patch.object(build, "source_gate", side_effect=lambda *a: calls.append("gate") or "tree"), \
                patch.object(build, "build_fixed_source", side_effect=lambda *a: calls.append("build")):
            build.build(args)
        self.assertEqual(calls, ["gate", "build", "gate"])

    def test_models_change_only_se_image_and_build_provenance(self):
        model = dict(services={se.SERVICE:dict(image="old", environment={"MODE":"keep", "SECRET":"fixture$literal"}),
                              "postgres":dict(image="old-db", command=["literal$$VALUE"]),
                              "judge":dict(image="old-judge", environment={"WORKERS":"4"})}, networks={"n":{}})
        manifest = dict(revision="b"*40, version="2.6.7", created_at="now")
        old, new = se.frozen_models(model, manifest, "old-fixed", "new-fixed")
        self.assertEqual(new["services"]["postgres"], model["services"]["postgres"])
        self.assertEqual(new["services"]["judge"], model["services"]["judge"])
        for value in (old, new):
            self.assertEqual(value["services"][se.SERVICE]["environment"]["SECRET"], "fixture$literal")
            self.assertEqual(value["services"][se.SERVICE]["environment"]["MODE"], "keep")

    def test_new_evidence_rejects_non_root_owner(self):
        with patch.object(vm, "ROOT", Path('/opt/jjdguard')), \
                patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=1000, st_mode=0o100600)), \
                patch.object(Path, "is_symlink", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "unprotected"):
                REAL_PROTECTED(Path('/opt/jjdguard/development-releases/dev-x/receipt.json'))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"opt/jjdguard"
        self.media = self.root/"development-releases/dev-test"
        self.media.mkdir(parents=True)
        self.workdir = self.root/"releases/installed"
        (self.workdir/"active-config").mkdir(parents=True)
        (self.workdir/"bin").mkdir()
        (self.workdir/"bin/docker-compose").write_text("fake binary")
        (self.workdir/".env").write_text("TEST=fixture\n")
        self.base = self.workdir/"active-config/old.json"
        self.project = "existing-project"
        self.old = "sha256:"+"a"*64
        config = b'{"fixture":"candidate"}'
        self.new = "sha256:"+hashlib.sha256(config).hexdigest()
        self.model = dict(name=self.project, services={s:dict(image=self.old, environment={"JJD_COMMIT":"old", "SECRET":"fixture-only"})
                                                     for s in (se.SERVICE, "gateway-core", "tier1-classifier", "judge", "postgres")},
                          networks={"default":{"name":"existing-network"}})
        self.base.write_text(json.dumps(self.model))
        self.rows = [self.row(s) for s in self.model["services"]]
        # A stopped non-Compose container must also remain byte-for-byte stable.
        spare = self.row("unrelated")
        spare["Config"]["Labels"] = {}
        spare["State"]["Status"] = "exited"
        self.rows.append(spare)
        legacy = self.row("proxy-server-vm")
        legacy["State"]["Status"] = "exited"
        self.rows.append(legacy)
        self.baseline = copy.deepcopy(self.rows)
        self.manifest = dict(schema=1, purpose="development-vm", release_id="dev-test", revision="b"*40, tree="c"*40,
                             version="2.6.7", created_at="now", security_engine_only=True, preserve_tier1=True,
                             migrations={}, migration_preconditions={}, enable_file_detection=False,
                             candidate_validation=dict(file_selftest_passed=True, file_http_selftest_passed=True, tier1="preserved_not_touched"),
                             services={se.SERVICE:dict(image_id=self.new, base_image_id=self.old, tag="candidate:fixed",
                                                      payload_sha256={"/app/app/main.py":"d"*64})})
        for name, key in (("vm_development_apply.py", "apply_script_sha256"), ("vm_security_engine_release.py", "security_engine_script_sha256")):
            (self.media/name).write_text("# frozen fixture\n")
            self.manifest[key] = vm.digest(self.media/name)
        with tarfile.open(self.media/"images.tar", "w") as archive:
            for name, content in (("config.json", config), ("manifest.json", json.dumps([dict(Config="config.json", RepoTags=["candidate:fixed"], Layers=[])]).encode())):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.manifest["images_sha256"] = vm.digest(self.media/"images.tar")
        (self.media/"manifest.json").write_text(json.dumps(self.manifest))
        self.calls = []
        self.switch_count = 0
        self.fail_candidate = False
        self.fail_restore = False
        self.unready_candidate = False
        self.patches = [patch.object(vm, "ROOT", self.root), patch.object(se, "protected", self.fixture_protected),
                        patch.object(se, "inspect_all", lambda: copy.deepcopy(self.rows)),
                        patch.object(vm, "run", self.fake_run), patch.object(se.shutil, "disk_usage", return_value=SimpleNamespace(free=10*1024**3))]
        for mocked in self.patches:
            mocked.start()
            self.addCleanup(mocked.stop)
        self.release = se.SecurityEngineRelease(self.media, vm.digest(self.media/"manifest.json"))
        self.addCleanup(self.release.lock.close)

    def fixture_protected(self, path, directory=False):
        path = Path(path)
        self.assertTrue(path.is_relative_to(self.root))
        self.assertFalse(path.is_symlink())
        self.assertTrue(path.is_dir() if directory else path.is_file())
        return path

    def row(self, service):
        return dict(Id=service+"-old", Image=self.old, Name="/"+service, Path="python", Args=[], RestartCount=0,
                    State=dict(Status="running", StartedAt="before", Health=dict(Status="healthy")),
                    Config=dict(Image=self.old, Hostname="old-auto-host", Env=["JJD_COMMIT=old", "SECRET=fixture-only"],
                                Labels={"com.docker.compose.project":self.project, "com.docker.compose.service":service,
                                        "com.docker.compose.project.working_dir":str(self.workdir),
                                        "com.docker.compose.project.config_files":str(self.base), "com.docker.compose.config-hash":"old"}),
                    HostConfig=dict(ReadonlyRootfs=True), Mounts=[], NetworkSettings=dict(Networks={"existing-network":{}}))

    def fake_run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            name = argv[3]
            image = self.new if name == "candidate:fixed" else name
            labels = {"org.opencontainers.image.revision":self.manifest["revision"], "com.jjdguard.source.tree":self.manifest["tree"],
                      "com.jjdguard.base.image":self.old, "com.jjdguard.release.id":"dev-test"}
            return json.dumps([dict(Id=image, Config=dict(Labels=labels))])
        if argv[:3] == ["docker", "image", "load"]:
            return "loaded"
        if argv[0] == str(self.workdir/"bin/docker-compose"):
            file = Path(argv[argv.index("-f")+1])
            model = json.loads(file.read_text())
            if "config" in argv:
                return json.dumps(model)
            self.assertEqual(argv[-7:], ["up", "-d", "--no-deps", "--pull", "never", "--force-recreate", se.SERVICE])
            self.switch_count += 1
            item = model["services"][se.SERVICE]
            row = self.rows[0]
            row.update(Id="se-new-"+str(self.switch_count), Image=item["image"], RestartCount=0)
            row["State"].update(Status="running", StartedAt="new-"+str(self.switch_count))
            row["State"]["Health"]["Status"] = "healthy"
            row["Config"].update(Image=item["image"], Hostname="new-auto-host", Env=[k+"="+str(v) for k,v in item["environment"].items()])
            row["Config"]["Labels"].update({"com.docker.compose.project.config_files":str(file), "com.docker.compose.config-hash":"new"})
            if (item["image"] == self.new and self.fail_candidate) or (item["image"] == self.old and self.fail_restore):
                raise RuntimeError("simulated partial Compose failure")
            return ""
        if argv[:2] == ["docker", "exec"]:
            if argv[3] == "sha256sum":
                return "d"*64+"  /app/app/main.py"
            if argv[3:5] == ["python", "-c"]:
                return "unready" if self.unready_candidate and self.rows[0]["Image"] == self.new else "ready"
        raise AssertionError("unexpected command: "+repr(argv))

    def stage_apply(self):
        self.release.stage()
        self.release.apply()
        return vm.digest(self.media/"receipt.json")

    def test_success_recreates_only_se_preserves_every_other_container_and_configuration(self):
        sha = self.stage_apply()
        self.assertEqual(self.rows[0]["Image"], self.new)
        self.assertEqual(self.rows[1:], self.baseline[1:])
        candidate = json.loads((self.media/"state/candidate.json").read_text())
        for service in set(self.model["services"])-{se.SERVICE}:
            self.assertEqual(candidate["services"][service], self.model["services"][service])
        self.assertEqual(json.loads(self.release.pointer.read_text())["receipt_sha256"], sha)
        self.assertEqual(self.switch_count, 1)
        for command in self.calls:
            self.assertFalse(set(command) & {"psql", "pg_dump", "pg_restore", "stop", "start", "iptables"})

    def test_explicit_rollback_restores_old_se_and_previous_pointer_without_database(self):
        previous = json.dumps({"release":"previous-recorded-release", "receipt_sha256":"e"*64}).encode()
        self.release.pointer.write_bytes(previous)
        sha = self.stage_apply()
        self.rows[0]["RestartCount"] = 2
        self.rows[0]["State"]["Health"]["Status"] = "unhealthy"
        # Unhealthy/restarted SE must not block restoring the same receipt's container.
        self.rows[0]["NetworkSettings"]["SandboxID"] = "restarted-sandbox"
        self.release.rollback(sha)
        self.assertEqual(self.rows[0]["Image"], self.old)
        self.assertEqual(self.rows[1:], self.baseline[1:])
        self.assertEqual(self.release.pointer.read_bytes(), previous)
        self.assertEqual(json.loads((self.media/"rollback.json").read_text())["status"], "rolled_back")

    def test_partial_switch_failure_rolls_back_only_se(self):
        self.release.stage()
        self.fail_candidate = True
        with self.assertRaisesRegex(RuntimeError, "partial Compose failure"):
            self.release.apply()
        self.assertEqual(self.switch_count, 2)
        self.assertEqual(self.rows[0]["Image"], self.old)
        self.assertEqual(self.rows[1:], self.baseline[1:])
        self.assertFalse(self.release.pointer.exists())

    def test_runtime_readiness_failure_rolls_back(self):
        self.release.stage()
        self.unready_candidate = True
        with self.assertRaisesRegex(RuntimeError, "not ready"):
            self.release.apply()
        self.assertEqual(self.rows[0]["Image"], self.old)

    def test_failed_recovery_is_reported_and_never_publishes_a_success_pointer(self):
        self.release.stage()
        self.fail_candidate = self.fail_restore = True
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertFalse((self.media/"rollback.json").exists())

    def test_preflight_drift_never_mutates_runtime(self):
        self.release.stage()
        self.rows[1]["RestartCount"] = 1
        with self.assertRaisesRegex(RuntimeError, "non-target"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_config_only_drift_is_detected_even_when_identity_is_unchanged(self):
        self.release.stage()
        self.rows[1]["Config"]["Env"].append("DRIFT=changed")
        with self.assertRaisesRegex(RuntimeError, "configuration changed"):
            self.release.apply()
        self.assertEqual(self.switch_count, 0)

    def test_original_compose_change_blocks_post_test_rollback(self):
        sha = self.stage_apply()
        self.base.write_text(self.base.read_text()+"\n")
        with self.assertRaisesRegex(RuntimeError, "Compose/environment"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_stale_receipt_cannot_rollback_a_later_release(self):
        sha = self.stage_apply()
        self.release.pointer.write_text(json.dumps(dict(release="later", receipt_sha256="f"*64)))
        with self.assertRaisesRegex(RuntimeError, "active recorded"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_tampered_saved_old_configuration_is_rejected_before_recreation(self):
        sha = self.stage_apply()
        (self.media/"state/rollback.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "saved rollback"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_tampered_receipt_and_manifest_are_rejected(self):
        sha = self.stage_apply()
        path = self.media/"manifest.json"
        path.write_text(path.read_text()+"\n")
        with self.assertRaisesRegex(RuntimeError, "manifest changed"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_rollback_of_replaced_se_container_is_rejected(self):
        sha = self.stage_apply()
        self.rows[0]["Id"] = "unrelated-replacement"
        with self.assertRaisesRegex(RuntimeError, "no longer belongs"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_failure_after_receipt_publication_restores_previous_pointer(self):
        self.release.stage()
        commit = self.release.commit
        def interrupted(after):
            commit(after)
            raise RuntimeError("interrupted commit")
        self.release.commit = interrupted
        with self.assertRaisesRegex(RuntimeError, "interrupted commit"):
            self.release.apply()
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.rows[0]["Image"], self.old)

    def test_replay_rejected_without_touching_runtime(self):
        sha = self.stage_apply()
        self.release.rollback(sha)
        with self.assertRaises((RuntimeError, AssertionError, FileNotFoundError)):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 2)

    def test_recorded_before_snapshot_is_anchored_to_the_receipt(self):
        sha = self.stage_apply()
        path = self.media/"state/before.json"
        value = json.loads(path.read_text())
        value["old_image"] = "sha256:"+"f"*64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, "evidence changed"):
            self.release.rollback(sha)
        self.assertEqual(self.switch_count, 1)

    def test_extra_image_in_archive_rejected_before_docker_load(self):
        with tarfile.open(self.media/"images.tar", "a") as archive:
            content = json.dumps([dict(Config="config.json", RepoTags=["candidate:fixed", "unrelated:latest"])]).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        self.release.manifest["images_sha256"] = vm.digest(self.media/"images.tar")
        with self.assertRaisesRegex(RuntimeError, "other images"):
            self.release.stage()
        self.assertFalse(any(c[:3] == ["docker", "image", "load"] for c in self.calls))

    def test_candidate_config_identity_mismatch_rejected(self):
        self.release.record["image_id"] = "sha256:"+"f"*64
        with self.assertRaisesRegex(RuntimeError, "archive image config"):
            self.release.stage()
        self.assertEqual(self.switch_count, 0)

    def test_non_target_drift_during_switch_never_reports_success(self):
        self.release.stage()
        replace = self.release.replace
        def drift(name):
            replace(name)
            self.rows[1]["RestartCount"] = 1
        self.release.replace = drift
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.release.apply()
        self.assertEqual(self.rows[0]["Image"], self.old)
        self.assertFalse(self.release.pointer.exists())

    def bootstrap(self, sha):
        for path in (self.root, self.media.parent, self.media):
            path.chmod(0o700)
        for path in self.media.iterdir():
            if path.is_file(): path.chmod(0o600)
        with patch.object(se, "protected", REAL_PROTECTED):
            code = se.rollback_guest_code("dev-test", sha)
        code = code.replace("Path('/opt/jjdguard')", "Path("+repr(str(self.root))+")")
        # Tests run unprivileged. Only their temporary evidence owner is substituted.
        return code.replace("info.st_uid == 0", "info.st_uid == os.getuid()")

    def test_bootstrap_checks_pinned_chain_before_executing_saved_code(self):
        sha = self.stage_apply()
        code = self.bootstrap(sha)
        with patch('subprocess.run') as execute:
            exec(compile(code, '<rollback-bootstrap>', 'exec'), {})
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[0][-4:], ["--release-id", "dev-test", "--receipt-sha256", sha])

    def test_bootstrap_rejects_tampered_script_without_executing_it(self):
        sha = self.stage_apply()
        code = self.bootstrap(sha)
        (self.media/"vm_security_engine_release.py").write_text("raise Exception('must not execute')")
        with patch('subprocess.run') as execute:
            with self.assertRaisesRegex(RuntimeError, "script changed"):
                exec(compile(code, '<rollback-bootstrap>', 'exec'), {})
            execute.assert_not_called()

    def test_bootstrap_rejects_unrecorded_bytecode(self):
        sha = self.stage_apply()
        code = self.bootstrap(sha)
        (self.media/"__pycache__").mkdir()
        with patch('subprocess.run') as execute:
            with self.assertRaisesRegex(RuntimeError, "cached release code"):
                exec(compile(code, '<rollback-bootstrap>', 'exec'), {})
            execute.assert_not_called()


class ParallelCapacityRollbackTests(unittest.TestCase):
    def test_only_engine_changes_capacity_and_rollback_keeps_original(self):
        model={"services":{"security-engine":{"image":"old", "environment":{"SECURITY_JUDGE_WORKERS":"4","SECURITY_JUDGE_CAPACITY":"4","SECURITY_SEMANTIC_MAX_WINDOWS":"128"}},"gateway-core":{"image":"gateway-original"}}}
        manifest={"services":{"security-engine":{}},"revision":"revision", "version":"version", "created_at":"now", "semantic_window_parallelism":8}
        old,new=se.frozen_models(model,manifest,"old-image","new-image")
        self.assertEqual(old["services"]["security-engine"]["environment"],model["services"]["security-engine"]["environment"])
        self.assertEqual(new["services"]["security-engine"]["environment"]["SECURITY_JUDGE_WORKERS"],"8")
        self.assertEqual(new["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_MAX_WINDOWS"],"128")
        self.assertEqual(new["services"]["gateway-core"],model["services"]["gateway-core"])


class PerformanceCapacityTests(unittest.TestCase):
    def test_input_and_queue_changes_are_recorded_and_rollback_preserves_values(self):
        model={"services":{"security-engine":{"image":"old", "environment":{"SECURITY_INPUT_WORKERS":"8","SECURITY_INPUT_CAPACITY":"32","SECURITY_JUDGE_QUEUE_CAPACITY":"8"}}}}
        manifest={"services":{"security-engine":{}},"revision":"r","version":"v","created_at":"now","semantic_window_parallelism":16,"security_input_workers":16,"security_input_capacity":128,"judge_queue_capacity":64}
        old,new=se.frozen_models(model,manifest,"old-image","new-image")
        self.assertEqual(old["services"]["security-engine"]["environment"],model["services"]["security-engine"]["environment"])
        env=new["services"]["security-engine"]["environment"]
        for key,value in {"SECURITY_INPUT_WORKERS":"16","SECURITY_INPUT_CAPACITY":"128","SECURITY_JUDGE_QUEUE_CAPACITY":"64","SECURITY_JUDGE_WORKERS":"16"}.items():self.assertEqual(env[key],value)
        for key in ("security_input_workers","security_input_capacity","judge_queue_capacity"):
            for bad in (0,-1,True,"16"):
                with self.assertRaises(RuntimeError):vm.semantic_parallel_environment(dict(manifest,**{key:bad}))


class BudgetEnvelopeTests(unittest.TestCase):
    def test_narrow_release_records_budget_and_per_request_limit_and_restores_old_values(self):
        model = {"services": {"security-engine": {"image": "old", "environment": {
            "SECURITY_BATCH_BUDGET_SECONDS": "8", "SECURITY_SEMANTIC_REQUEST_PARALLELISM": "16"}},
            "gateway-core": {"image": "unchanged", "environment": {"LIMIT": "keep"}}}}
        manifest = dict(revision="b"*40, version="2.6.12", created_at="now", services={"security-engine": {}},
                        security_batch_budget_seconds=20, semantic_request_parallelism=4)
        old, new = se.frozen_models(model, manifest, "old-fixed", "new-fixed")
        self.assertEqual(old["services"]["security-engine"]["environment"]["SECURITY_BATCH_BUDGET_SECONDS"], "8")
        self.assertEqual(new["services"]["security-engine"]["environment"]["SECURITY_BATCH_BUDGET_SECONDS"], "20")
        self.assertEqual(new["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_REQUEST_PARALLELISM"], "4")
        self.assertEqual(new["services"]["gateway-core"], model["services"]["gateway-core"])

    def test_invalid_budgets_cannot_enter_release_manifest(self):
        for field in ["security_batch_budget_seconds", "semantic_request_parallelism"]:
            for value in [0, -1, True, "20", 1.5]:
                with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                    vm.semantic_parallel_environment({"services": {"security-engine": {}}, field: value})


if __name__ == "__main__":
    unittest.main()
