"""Failed pre-receipt identity/chat recovery authenticates old state before unfencing."""
import contextlib, copy, hashlib, importlib, io, json, os, shutil, sys, unittest
from pathlib import Path
from unittest.mock import patch
import test_vm_identity_chat_release as fixture
vm=fixture.vm
try:
    import vm_failed_identity_chat_recovery as recovery
except ModuleNotFoundError:
    recovery=None

ERROR="identity-chat non-target identity or runtime changed"

class FailedIdentityChatRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.IdentityChatApplyTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        for name in ("proxy-server","worker"):
            self.case.rig.rows[name]["RestartCount"]=1
        release=self.case.stage()
        (release.media/"receipt.json").unlink()
        self.case.fail_verify=True
        original_restore=release.restore
        def legacy_restore():
            original_restore()
            (release.media/"rollback.json").unlink()
            log=release.media/"apply.log"
            log.write_text("\n".join(line for line in log.read_text().splitlines() if not line.endswith("ROLLBACK completed"))+"\n")
            raise RuntimeError(ERROR)
        release.restore=legacy_restore
        def legacy_verify():
            release.event("VERIFY runtime health, image identities and policies")
            raise RuntimeError(ERROR)
        release.verify=legacy_verify
        with self.assertRaisesRegex(RuntimeError,ERROR):
            vm.perform(release)
        self.case.fail_verify=False
        release.lock_file.close()
        self.media=release.media
        self.assertEqual(json.loads((self.media/"failure.json").read_text())["rollback"],"incomplete")
        self.assertTrue(all(self.case.rig.rows[name]["Image"]==self.case.common.OLD for name in fixture.TARGETS))
        self.assertIsNotNone(recovery,"a controlled failed-apply recovery entry is required")
        self.addCleanup(patch.stopall)
        self.validator_source=Path(vm.__file__).read_bytes()
        self.helper_source=Path(recovery.__file__).read_bytes()
        self.home=self.media.parent/"failed-apply-recoveries"/(self.media.name+"-"+"d"*12)
        self.home.mkdir(parents=True,mode=0o700)
        self.home.parent.chmod(0o700)
        self.helper=self.home/"vm_failed_identity_chat_recovery.py"
        self.validator=self.home/"vm_development_apply.py"
        self.helper.write_bytes(self.helper_source);self.helper.chmod(0o600)
        self.validator.write_bytes(self.validator_source);self.validator.chmod(0o600)
        patch.object(recovery,"vm",vm).start()
        patch.object(recovery,"__file__",str(self.helper)).start()
        self.revision="d"*40
        self.manifest_pin=vm.digest(self.media/"manifest.json")
        self.failure_pin=vm.digest(self.media/"failure.json")
        self.original_pin=self.case.m["apply_script_sha256"]
        self.helper_pin=vm.digest(self.helper)
        self.validator_pin=vm.digest(self.validator)
        self.stage_pin=recovery.stage_digest(self.media)
        self.case.rig.iptables.clear()

    def run_recovery(self,checkpoint=None):
        return recovery.perform(self.media,self.manifest_pin,self.failure_pin,self.stage_pin,
            self.original_pin,self.revision,self.helper_pin,self.validator_pin,checkpoint)

    def assert_fenced(self):
        self.assertFalse(any("-D" in args for args in self.case.rig.iptables))

    def test_recovers_only_verified_old_runtime_and_preserves_frozen_evidence(self):
        protected=[self.media/"manifest.json",self.media/"vm_development_apply.py",self.media/"failure.json",
                   self.media/"state/before.json",self.media/"state/rollback.json",self.media/"state/database.dump"]
        hashes={str(p):vm.digest(p) for p in protected}
        before_commands=len(self.case.subprocess_commands)
        receipt=self.run_recovery()
        self.assertEqual(receipt["status"],"restored_failed_apply")
        self.assertEqual(receipt["ingress"],vm.FENCE_CLEARED)
        self.assertEqual([a[1] for a in self.case.rig.iptables if a[0]=="iptables"],["-D","-F","-X"])
        self.assertEqual(hashes,{str(p):vm.digest(p) for p in protected})
        self.assertEqual(before_commands,len(self.case.subprocess_commands))
        self.assertEqual(receipt["migrations"],self.case.rig.before_ledger)

    def test_host_metadata_guest_executes_and_emits_only_artifact_pins(self):
        program=fixture.deploy.failed_identity_chat_metadata_guest_code(self.media.name)
        program=program.replace("/opt/jjdguard",str(self.case.rig.root))
        original=Path.lstat
        def root_owned(path):
            info=original(path)
            if path.is_relative_to(self.case.rig.root):
                fields=list(info);fields[4]=0;return os.stat_result(fields)
            return info
        output=io.StringIO()
        with patch.object(Path,"lstat",root_owned),contextlib.redirect_stdout(output):
            exec(compile(program,"<metadata-guest>","exec"),{})
        value=json.loads(output.getvalue().split("=",1)[1])
        self.assertEqual(set(value),{"revision","manifest_sha256","failure_sha256","original_apply_sha256"})
        self.assertEqual(value["manifest_sha256"],self.manifest_pin)
        self.assertNotIn("PRIVATE_SECRET",output.getvalue())

    def test_missing_or_changed_manifest_failure_and_stage_pins_refuse_before_unfence(self):
        for field in ("manifest_pin","failure_pin","stage_pin","original_pin","helper_pin","validator_pin"):
            original=getattr(self,field)
            setattr(self,field,"0"*64)
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                self.run_recovery()
            setattr(self,field,original)
            self.assert_fenced()

    def test_unknown_failure_cannot_use_counter_reset_recovery(self):
        path=self.media/"failure.json"
        d=json.loads(path.read_text());d["failure_message"]="unrelated payload corruption"
        vm.write_json(path,d);self.failure_pin=vm.digest(path)
        with self.assertRaisesRegex(RuntimeError,"failure|scope"):
            self.run_recovery()
        self.assert_fenced()

    def test_old_target_image_health_or_automatic_restart_refuses_unfence(self):
        original=copy.deepcopy(self.case.rig.rows["gateway-core"])
        for change in ("image","health","restarts","contract"):
            row=self.case.rig.rows["gateway-core"]
            if change=="image":row["Image"]="sha256:"+"9"*64
            elif change=="health":row["State"]["Health"]["Status"]="unhealthy"
            elif change=="restarts":row["RestartCount"]=1
            else:row["Config"]["Env"].append("UNAPPROVED=true")
            with self.subTest(change=change),self.assertRaises(RuntimeError):
                self.run_recovery()
            self.case.rig.rows["gateway-core"]=copy.deepcopy(original)
            self.assert_fenced()

    def test_paused_writer_new_automatic_restart_and_unpaused_counter_reset_refuse(self):
        for name,count in (("proxy-server",1),("worker",2),("llm-judge",1)):
            original=copy.deepcopy(self.case.rig.rows[name])
            self.case.rig.rows[name]["RestartCount"]=count
            with self.subTest(name=name,count=count),self.assertRaises(RuntimeError):
                self.run_recovery()
            self.case.rig.rows[name]=original
            self.assert_fenced()

    def test_migration_ledger_and_managed_policy_drift_refuse(self):
        self.case.rig.current_ledger["unapproved"]="0"*64
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_fenced()
        self.case.rig.current_ledger=dict(self.case.rig.before_ledger)
        self.case.rig.before_policy["security_audit_only"]="false"
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_fenced()

    def test_original_compose_env_boot_chain_and_live_drift_refuse(self):
        before=json.loads((self.media/"state/before.json").read_text())
        paths=[Path(next(iter(before["compose_sha256"]))),vm.staged_env_file(before),self.case.rig.chain,
               Path(before["live"])]
        for path in paths:
            raw=path.read_bytes();path.write_bytes(raw+b"\n ")
            with self.subTest(path=path.name),self.assertRaises(RuntimeError):self.run_recovery()
            path.write_bytes(raw);self.assert_fenced()

    def test_protected_evidence_symlink_and_writable_file_refuse(self):
        path=self.media/"state/before.json"
        path.chmod(0o666)
        with self.assertRaises((RuntimeError,OSError)):self.run_recovery()
        path.chmod(0o600)
        original=path.read_bytes();path.unlink()
        target=self.home/"outside-before.json";target.write_bytes(original);target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises((RuntimeError,OSError)):self.run_recovery()
        self.assert_fenced()

    def test_extra_inventory_container_refuses(self):
        self.case.rig.rows["unapproved"]=copy.deepcopy(self.case.rig.rows["llm-judge"])
        self.case.rig.rows["unapproved"]["Id"]="unapproved-container"
        with self.assertRaises(RuntimeError):self.run_recovery()
        self.assert_fenced()

    def test_unfence_failure_records_real_residue_and_requires_pinned_checkpoint(self):
        original=self.case.fake_run
        def run(argv,**kwargs):
            if argv[:2]==["iptables","-F"]:raise RuntimeError("simulated flush failure")
            return original(argv,**kwargs)
        with patch.object(vm,"run",side_effect=run),self.assertRaisesRegex(RuntimeError,"cleanup|unfence"):
            self.run_recovery()
        state=json.loads((self.home/"recovery-failure.json").read_text())
        self.assertEqual(state["ingress"],"open")
        self.assertEqual(state["fence_residual"],vm.FENCE_UNLINKED_RULES)
        with self.assertRaisesRegex(RuntimeError,"checkpoint"):self.run_recovery()
        receipt=self.run_recovery(vm.digest(self.home/"recovery-checkpoint.json"))
        self.assertEqual(receipt["ingress"],vm.FENCE_CLEARED)
        self.assertEqual(len([a for a in self.case.rig.iptables if "-D" in a]),1)

    def test_missing_writer_pause_evidence_cannot_grant_resumption_exception(self):
        path=self.media/"apply.log"
        path.write_text("\n".join(line for line in path.read_text().splitlines() if not line.endswith("STOP application writers"))+"\n")
        self.stage_pin=recovery.stage_digest(self.media)
        with self.assertRaisesRegex(RuntimeError,"transition evidence"):
            self.run_recovery()
        self.assert_fenced()

    def test_protected_backup_content_drift_refuses(self):
        path=self.media/"state/database.dump"
        path.write_bytes(path.read_bytes()+b"unapproved")
        with self.assertRaisesRegex(RuntimeError,"backup"):
            self.run_recovery()
        self.assert_fenced()

    def test_changed_paused_writer_identity_contract_and_backwards_time_refuse(self):
        original=copy.deepcopy(self.case.rig.rows["worker"])
        for field in ("Id","Image","Config","StartedAt"):
            row=self.case.rig.rows["worker"]
            if field=="Id":row[field]="replacement-worker"
            elif field=="Image":row[field]="sha256:"+"9"*64
            elif field=="Config":row[field]["Env"].append("UNAPPROVED=true")
            else:row["State"][field]="2026-10-10T13:00:00.000000000Z"
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                self.run_recovery()
            self.case.rig.rows["worker"]=copy.deepcopy(original)
            self.assert_fenced()

    def test_completed_receipt_is_rechecked_without_duplicate_unfence(self):
        self.run_recovery()
        count=len(self.case.rig.iptables)
        pin=vm.digest(self.home/"recovery-checkpoint.json")
        result=self.run_recovery(pin)
        self.assertEqual(result["status"],"restored_failed_apply")
        self.assertEqual(len(self.case.rig.iptables),count)
        self.case.rig.rows["worker"]["RestartCount"]=1
        with self.assertRaises(RuntimeError):self.run_recovery(pin)

class FailedRecoveryHostTests(unittest.TestCase):
    def test_host_exposes_controlled_recovery_mode(self):
        import subprocess
        result=subprocess.run([sys.executable,"-B",str(Path(fixture.deploy.__file__)),"--help"],
                              capture_output=True,text=True,check=True)
        self.assertIn("--recover-failed-identity-chat-release-id",result.stdout)
        self.assertIn("--checkpoint-sha256",result.stdout)

    def test_cli_refuses_conflicting_actions_before_guest_access(self):
        import subprocess
        cases=(["--recover-failed-identity-chat-release-id","dev-fixture","--media","/tmp/unused"],
               ["--recover-failed-identity-chat-release-id","dev-fixture","--persist-boot"],
               ["--checkpoint-sha256","0"*64])
        for extra in cases:
            with self.subTest(extra=extra):
                result=subprocess.run([sys.executable,"-B",str(Path(fixture.deploy.__file__)),"--repo","/tmp/unused",*extra],
                                      capture_output=True,text=True)
                self.assertEqual(result.returncode,2)
                self.assertNotIn("guest_pid=",result.stdout)

    def test_guest_builder_rejects_unsafe_identifiers_and_partial_pins(self):
        metadata={"manifest_sha256":"1"*64,"failure_sha256":"2"*64,"original_apply_sha256":"3"*64}
        files={name:b"reviewed-code" for name in ("vm_development_apply.py","vm_failed_identity_chat_recovery.py")}
        changes=(("../escape","5"*40,metadata,None,None),
                 ("dev-fixture","invalid",metadata,None,None),
                 ("dev-fixture","5"*40,dict(metadata,failure_sha256="short"),None,None),
                 ("dev-fixture","5"*40,metadata,"short",None),
                 ("dev-fixture","5"*40,metadata,"4"*64,"short"))
        for values in changes:
            with self.subTest(values=values),self.assertRaises(RuntimeError):
                fixture.deploy.failed_identity_chat_recovery_guest_code(values[0],values[1],values[2],files,values[3],values[4])

    def test_guest_rejects_decoded_and_compressed_limit_before_virsh(self):
        code="pass\n"+"#"+fixture.deploy.base64.b64encode(os.urandom(200000)).decode()
        for program in ("#"+("a"*(2*1024*1024)),code):
            with self.subTest(size=len(program)),patch.object(fixture.deploy,"qga") as qga:
                with self.assertRaisesRegex(RuntimeError,"limit"):
                    fixture.deploy.guest("jjdguard-gateway",program)
                qga.assert_not_called()

    def test_real_recovery_closure_crosses_linux_single_argument_limit(self):
        import subprocess
        metadata={"manifest_sha256":"1"*64,"failure_sha256":"2"*64,"original_apply_sha256":"3"*64}
        source=Path(fixture.deploy.__file__).parent
        files={name:(source/name).read_bytes() for name in ("vm_development_apply.py","vm_failed_identity_chat_recovery.py")}
        program=fixture.deploy.failed_identity_chat_recovery_guest_code("dev-fixture","5"*40,metadata,files)
        self.assertGreater(sum(len(content) for content in files.values()),131072)
        self.assertLess(len(program.encode()),120*1024)
        marker="transport-real-recovery-closure-ok"
        code="print("+repr(marker)+");raise SystemExit(0)\n"+program
        outputs={}
        captured=[]
        def qga(domain,request):
            if request["execute"]=="guest-exec":
                args=request["arguments"]["arg"]
                value=args[args.index("-c")+1]
                captured.append(value)
                process=subprocess.run([sys.executable,"-c",value],capture_output=True,text=True)
                outputs.update(exited=True,exitcode=process.returncode,
                    **{"out-data":fixture.deploy.base64.b64encode(process.stdout.encode()).decode(),
                       "err-data":fixture.deploy.base64.b64encode(process.stderr.encode()).decode()})
                return {"pid":1}
            return outputs
        with patch.object(fixture.deploy,"qga",side_effect=qga):
            result=fixture.deploy.guest("jjdguard-gateway",code)
        self.assertIn(marker,result)
        self.assertLess(len(captured[0].encode()),120*1024)

    def test_guest_programs_are_syntax_valid_and_source_pinned(self):
        metadata={"manifest_sha256":"1"*64,"failure_sha256":"2"*64,"original_apply_sha256":"3"*64}
        files={name:b"reviewed-code" for name in ("vm_development_apply.py","vm_failed_identity_chat_recovery.py")}
        programs=[fixture.deploy.failed_identity_chat_metadata_guest_code("dev-fixture")]
        for stage in (None,"4"*64):
            program=fixture.deploy.failed_identity_chat_recovery_guest_code("dev-fixture","5"*40,metadata,files,stage)
            compile(program,"<recovery-guest>","exec")
            self.assertIn("O_NOFOLLOW",program)
            self.assertIn("--recovery-helper-sha256",program)
            self.assertIn("--validator-sha256",program)
            self.assertNotIn("iptables",program)
            programs.append(program)
        for program in programs:compile(program,"<recovery-guest>","exec")

if __name__=="__main__":unittest.main()
