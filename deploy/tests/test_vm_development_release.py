import copy
import hashlib
import os
import shutil
import sys
import json
from unittest.mock import patch
import importlib.util
import tempfile
import unittest
import contextlib
import io
from types import SimpleNamespace
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("vm_apply",ROOT/"deploy/release/vm_development_apply.py")
vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
build_spec=importlib.util.spec_from_file_location("vm_build",ROOT/"deploy/release/build_vm_development.py")
builder=importlib.util.module_from_spec(build_spec);build_spec.loader.exec_module(builder)

sys.path.insert(0,str(ROOT/"deploy/release"))
import build_vm_isolated as isolated

class FormalInstallationOwnerTests(unittest.TestCase):
    def invoke(self,action,authorised=True,partial=False):
        with tempfile.TemporaryDirectory() as directory:
            media=Path(directory)
            (media/"manifest.json").write_text("{}")
            argv=["vm_development_apply.py",action,"--media",str(media),"--manifest-sha256","a"*64,
                  "--install-owner-uid","1000"]
            if not partial: argv += ["--install-owner-gid","1000"]
            if action=="persist-boot": argv += ["--receipt-sha256","b"*64]
            token=vm.INSTALL_OWNER.set(None)
            def verify_owner(*args):
                self.assertEqual(vm.INSTALL_OWNER.get(),(1000,1000))
            try:
                with patch.object(sys,"argv",argv),patch.object(vm.os,"geteuid",return_value=0),\
                     patch.dict(os.environ,{"SUDO_UID":"1000","SUDO_GID":"1000","SUDO_USER":"yj"}),\
                     patch.object(vm.pwd,"getpwuid",return_value=SimpleNamespace(pw_name="yj" if authorised else "other",pw_gid=1000)),\
                     patch.object(vm,"digest",return_value="a"*64),patch.object(vm,"Release") as release,\
                     patch.object(vm,"perform",side_effect=verify_owner) as apply,\
                     patch.object(vm,"perform_persist_boot",side_effect=verify_owner) as persist:
                    release.return_value.stage.side_effect=verify_owner
                    if not authorised or partial:
                        with self.assertRaisesRegex(RuntimeError,"authenticated sudo caller"): vm.main()
                        release.assert_not_called(); apply.assert_not_called(); persist.assert_not_called()
                    else:
                        vm.main()
                        if action=="stage": release.return_value.stage.assert_called_once_with()
                        elif action=="apply": apply.assert_called_once_with(release.return_value)
                        else: persist.assert_called_once_with(media,"a"*64,"b"*64)
            finally:
                vm.INSTALL_OWNER.reset(token)

    def test_formal_stage_authenticates_sudo_installation_owner(self):
        self.invoke("stage")

    def test_formal_apply_authenticates_sudo_installation_owner(self):
        self.invoke("apply")

    def test_formal_persist_authenticates_sudo_installation_owner(self):
        self.invoke("persist-boot")

    def test_formal_forward_actions_reject_forged_owner_before_write(self):
        for action in ("stage","apply","persist-boot"):
            with self.subTest(action=action): self.invoke(action,authorised=False)

    def test_formal_forward_actions_require_both_owner_credentials(self):
        for action in ("stage","apply","persist-boot"):
            with self.subTest(action=action): self.invoke(action,partial=True)

class MigrationRuntimeTests(unittest.TestCase):
    def test_runner_dependency_is_shipped_verified_and_executable(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            media=Path(d)
            manifest={}
            builder.copy_migration_runtime(ROOT,media,manifest)
            vm.verify_migration_runtime(media,manifest)
            result=subprocess.run(["bash",str(media/"migration-runner.sh"),"--help"],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("Usage:",result.stdout)
            (media/"migration-version.sh").write_text("tampered")
            with self.assertRaisesRegex(RuntimeError,"migration runtime differs"):
                vm.verify_migration_runtime(media,manifest)
            (media/"migration-version.sh").unlink()
            with self.assertRaisesRegex(RuntimeError,"migration runtime differs"):
                vm.verify_migration_runtime(media,manifest)

class IsolatedBuildTests(unittest.TestCase):
    def test_containerd_config_identity_is_verified_not_assumed(self):
        import hashlib
        config="sha256:"+"a"*64
        raw=json.dumps({"config":{"digest":config}})
        manifest_id="sha256:"+hashlib.sha256(raw.encode()).hexdigest()
        image={"Id":manifest_id,"Descriptor":{"digest":manifest_id}}
        with patch.object(builder,"run",return_value=raw),patch.object(vm,"run",return_value=raw):
            self.assertEqual(builder.portable_image_id(image),config)
            self.assertEqual(vm.portable_image_id(image),config)
        with patch.object(builder,"run",return_value=raw+" "),patch.object(vm,"run",return_value=raw+" "):
            with self.assertRaises(RuntimeError):builder.portable_image_id(image)
            with self.assertRaises(RuntimeError):vm.portable_image_id(image)
    def test_loaded_candidate_cannot_change_config_behind_its_tag(self):
        release=vm.Release.__new__(vm.Release)
        release.manifest={"services":{"gateway-core":{"tag":"candidate:fixed","image_id":"sha256:"+"a"*64}}}
        with patch.object(vm,"run",return_value=json.dumps([{"Id":"sha256:"+"b"*64}])):
            with self.assertRaisesRegex(RuntimeError,"config differs"):release.resolve_candidate_images()
    def test_classic_image_identity_is_unchanged(self):
        image={"Id":"sha256:"+"a"*64}
        self.assertEqual(builder.portable_image_id(image),image["Id"])
        self.assertEqual(vm.portable_image_id(image),image["Id"])

    def test_bases_reject_extra_services_and_mutable_tags(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bases.json"
            valid={s:"sha256:"+"a"*64 for s in builder.ENGINEERING_SERVICES}
            p.write_text(json.dumps(valid))
            self.assertEqual(isolated.checked_bases(p),valid)
            for invalid in (dict(valid,**{"control-plane":"sha256:"+"b"*64}),dict(valid,**{"tier1-classifier":"latest"})):
                p.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):isolated.checked_bases(p)
    def test_returned_media_rejects_scope_source_and_image_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"images.tar").write_bytes(b"fixed-image-archive")
            bases={s:"sha256:"+"a"*64 for s in builder.ENGINEERING_SERVICES}
            manifest=dict(revision="b"*40,tree="c"*40,engineering_only=True,migrations={},enable_file_detection=False,isolated_source_sha256="d"*64,images_sha256=isolated.digest(root/"images.tar"),services={s:dict(base_image_id=v) for s,v in bases.items()})
            def verify(value):
                (root/"manifest.json").write_text(json.dumps(value))
                return isolated.validate_media(root,"b"*40,"c"*40,bases,"d"*64)
            self.assertEqual(verify(manifest),manifest)
            for field,value in (("revision","e"*40),("tree","e"*40),("isolated_source_sha256","e"*64),("images_sha256","e"*64),("services",{}),("migrations",{"001.sql":"x"}),("enable_file_detection",True)):
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):verify(dict(manifest,**{field:value}))
    def test_source_gate_failure_never_contacts_vm(self):
        args=type("Args",(),dict(repo="/home/dev/repo",output="/home/dev/new-isolated-output",revision="a"*40))()
        with patch.object(isolated,"source_gate",side_effect=RuntimeError("source rejected")),patch.object(isolated,"remote") as remote:
            with self.assertRaisesRegex(RuntimeError,"source rejected"):isolated.build(args)
            remote.assert_not_called()
    def test_remote_arguments_are_shell_quoted(self):
        with patch.object(isolated.subprocess,"run") as run:
            isolated.remote(["python3","-c","print('literal $HOME')"])
            import shlex
            self.assertEqual(shlex.split(run.call_args.args[0][-1]),["python3","-c","print('literal $HOME')"])

class Fake:
    def __init__(self,fail=None,restore_fail=False):
        self.calls=[];self.fail=fail;self.restore_fail=restore_fail
    def __getattr__(self,name):
        def call():
            self.calls.append(name)
            if name==self.fail or name=="restore" and self.restore_fail:raise RuntimeError(name)
        return call

PORTAL_BASE="sha256:"+"2"*64
PORTAL_RUNTIME="registry.example/library/node:22-alpine@sha256:"+"e"*64
PORTAL_CONFIG={
    "User":"portal",
    "Entrypoint":["docker-entrypoint.sh"],
    "ExposedPorts":{"3100/tcp":{}},
    "WorkingDir":"/app",
    "Env":[
        "NODE_ENV=production",
        "npm_config_registry=https://registry.npmjs.org",
        "PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1",
        "PRISMA_SCHEMA_ENGINE_BINARY=/app/node_modules/@prisma/engines/schema-engine-linux-musl-openssl-3.0.x",
        "PRISMA_QUERY_ENGINE_LIBRARY=/app/node_modules/@prisma/engines/libquery_engine-linux-musl-openssl-3.0.x.so.node",
    ],
}

class ReleaseTests(unittest.TestCase):
    def test_engineering_scope_is_exact_and_keeps_tier1_application_update(self):
        args=type("Args",(),dict(engineering_only=True,portal_only=False,preserve_tier1=False,migration=[],enable_file_detection=False))()
        expected=("gateway-core","security-engine","tier1-classifier")
        self.assertEqual(builder.release_services(args),expected)
        target,preserved=vm.release_service_sets(dict(engineering_only=True,services={s:{} for s in expected}))
        self.assertEqual(target,expected)
        self.assertEqual(preserved,())
        for extra in ("control-plane","web-console"):
            with self.assertRaises(RuntimeError):
                vm.release_service_sets(dict(engineering_only=True,services={s:{} for s in expected+(extra,)}))
    def test_engineering_scope_rejects_configuration_and_migration_changes(self):
        for change in ({"migrations":{"001_change.sql":"x"}},{"enable_file_detection":True},{"preserve_tier1":True},{"portal_only":True},{"engineering_only":1}):
            manifest=dict(engineering_only=True,services={s:{} for s in builder.ENGINEERING_SERVICES})
            manifest.update(change)
            with self.assertRaises(RuntimeError):vm.release_service_sets(manifest)
    def test_engineering_backup_quiesces_all_writers_and_switch_restarts_unchanged_images(self):
        with tempfile.TemporaryDirectory() as d:
            release=vm.Release.__new__(vm.Release)
            release.manifest={"engineering_only":True}
            release.target_services=vm.ENGINEERING_SERVICES
            release.rows={s:{} for s in vm.WRITERS}
            release.live=Path(d)/"active.json"
            release.state_dir=Path(d)
            (release.state_dir/"candidate.json").write_text('{"services":{}}')
            calls=[]
            release.event=lambda text:None
            release.compose=lambda *args,**kwargs:calls.append((args,kwargs))
            release.stop_writers()
            self.assertEqual(set(calls[0][0][3:]),set(vm.WRITERS))
            release.switch()
            self.assertEqual(calls[1][0][-3:],vm.ENGINEERING_SERVICES)
            self.assertEqual(set(calls[2][0][1:]),set(vm.WRITERS)-set(vm.ENGINEERING_SERVICES))

    def test_success_opens_ingress_only_after_verified_commit(self):
        a=Fake();vm.perform(a)
        self.assertEqual(a.calls,["fence","stop_writers","backup","migrate","switch","verify","commit","unfence"])
    def test_preflight_drift_does_not_stop_any_service(self):
        a=Fake("fence")
        with self.assertRaises(RuntimeError):vm.perform(a)
        self.assertEqual(a.calls,["fence"])
    def test_backup_failure_restarts_without_database_restore(self):
        a=Fake("backup")
        with self.assertRaises(RuntimeError):vm.perform(a)
        self.assertEqual(a.calls[-2:],["restart_original","unfence"])
        self.assertNotIn("restore",a.calls)
    def test_each_mutating_failure_rolls_back_before_opening_ingress(self):
        for point in ("migrate","switch","verify","commit"):
            with self.subTest(point=point):
                a=Fake(point)
                with self.assertRaises(RuntimeError):vm.perform(a)
                self.assertEqual(a.calls[-2:],["restore","unfence"])
    def test_failed_restore_keeps_ingress_fenced(self):
        a=Fake("verify",restore_fail=True)
        with self.assertRaises(RuntimeError):vm.perform(a)
        self.assertNotIn("unfence",a.calls)
    def fixture(self):
        model={"name":"stable-project","services":{s:{"image":"mutable:latest","environment":{"SECURITY_AUDIT_ONLY":"false","SECRET":"literal$credential"},"build":{"context":"."},"env_file":[".env"]} for s in vm.SERVICES}}
        model["services"]["control-plane"]["environment"]["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"]="test-signed-inspection-scope-key"
        model["services"]["postgres"]={"image":"postgres:16","volumes":[{"type":"volume","source":"existing","target":"/var/lib/postgresql/data"}]}
        rows={s:{"Image":"sha256:"+"a"*64} for s in model["services"]}
        manifest={"revision":"c"*40,"created_at":"fixed","version":"2.6.5","enable_file_detection":True,"services":{s:{"image_id":"sha256:"+"b"*64} for s in vm.SERVICES}}
        return model,rows,manifest
    def test_model_preserves_policy_secret_volume_and_non_target_image(self):
        model,rows,m=self.fixture();old=copy.deepcopy(model)
        new=vm.build_model(model,m,rows)
        self.assertEqual(model,old)
        self.assertEqual(new["services"]["postgres"]["image"],rows["postgres"]["Image"])
        self.assertEqual(new["services"]["postgres"]["volumes"],old["services"]["postgres"]["volumes"])
        for s in vm.SERVICES:
            item=new["services"][s]
            self.assertEqual(item["environment"]["SECURITY_AUDIT_ONLY"],"false")
            self.assertEqual(item["environment"]["SECRET"],"literal$credential")
            self.assertEqual(item["pull_policy"],"never")
            self.assertNotIn("build",item);self.assertNotIn("env_file",item)
    def test_preserve_tier1_selects_only_non_model_services(self):
        args=type("Args",(),{"preserve_tier1":True,"portal_only":False})()
        self.assertEqual(builder.release_services(args),builder.SERVICES[:-1])
        target,preserved=vm.release_service_sets({
            "preserve_tier1":True,
            "services":{s:{} for s in vm.SERVICES[:-1]},
        })
        self.assertEqual(target,vm.SERVICES[:-1])
        self.assertEqual(preserved,("tier1-classifier",))
    def test_portal_only_selects_chat_ui_and_preserves_tier1(self):
        args=type("Args",(),{"preserve_tier1":True,"portal_only":True})()
        self.assertEqual(builder.release_services(args),("chat-portal-ui",))
        target,preserved=vm.release_service_sets({
            "portal_only":True,
            "preserve_tier1":True,
            "services":{"chat-portal-ui":{}},
        })
        self.assertEqual(target,("chat-portal-ui",))
        self.assertEqual(preserved,("tier1-classifier",))
    def test_portal_only_requires_preserved_model_service(self):
        with self.assertRaises(RuntimeError):
            vm.release_service_sets({
                "portal_only":True,
                "preserve_tier1":False,
                "services":{"chat-portal-ui":{}},
            })
    def test_portal_dependency_snapshot_allows_absent_foreign_optional_packages(self):
        expected={"packages":{
            "":{"dependencies":{"one":"^1"},"devDependencies":{"dev":"^2"}},
            "node_modules/one":{"version":"1.2.0"},
            "node_modules/dev":{"version":"2.1.0"},
            "node_modules/foreign-optional":{"version":"3.0.0","optional":True},
        }}
        installed={"packages":{
            "node_modules/one":{"version":"1.2.0"},
            "node_modules/dev":{"version":"2.1.0"},
        }}
        builder.validate_installed_portal_dependencies(installed,expected)
    def test_portal_dependency_snapshot_rejects_missing_or_drifted_root_package(self):
        expected={"packages":{
            "":{"dependencies":{"one":"^1"}},
            "node_modules/one":{"version":"1.2.0"},
        }}
        for installed in (
            {"packages":{}},
            {"packages":{"node_modules/one":{"version":"1.3.0"}}},
        ):
            with self.assertRaises(AssertionError):
                builder.validate_installed_portal_dependencies(installed,expected)
    def test_preserve_tier1_rejects_model_image_in_candidate(self):
        with self.assertRaises(RuntimeError):
            vm.release_service_sets({
                "preserve_tier1":True,
                "services":{s:{} for s in vm.SERVICES},
            })
    def test_preserved_tier1_identity_must_not_change(self):
        identity={
            "tier1-classifier":{"id":"old","image":"sha256:"+"a"*64,"started_at":"before","restarts":0,"status":"running","health":"healthy"},
        }
        vm.verify_preserved_identities(identity,copy.deepcopy(identity),("tier1-classifier",))
        changed=copy.deepcopy(identity);changed["tier1-classifier"]["id"]="new"
        with self.assertRaises(RuntimeError):
            vm.verify_preserved_identities(identity,changed,("tier1-classifier",))
    def test_only_file_capability_and_provenance_are_changed(self):
        model,rows,m=self.fixture()
        new=vm.build_model(model,m,rows)
        self.assertEqual(new["services"]["security-engine"]["environment"]["SECURITY_FILE_CONTENT_DLP_ENABLED"],"true")
        self.assertNotIn("SECURITY_FILE_CONTENT_DLP_ENABLED",new["services"]["web-console"]["environment"])
        self.assertEqual(new["services"]["gateway-core"]["environment"]["JJD_COMMIT"],m["revision"])
        self.assertEqual(new["services"]["proxy-server"]["environment"]["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"],model["services"]["control-plane"]["environment"]["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"])

    def test_proxy_scope_refuses_missing_or_conflicting_attestation(self):
        model,rows,m=self.fixture()
        del model["services"]["control-plane"]["environment"]["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"]
        with self.assertRaisesRegex(RuntimeError,"attestation key"):
            vm.build_model(model,m,rows)
        model,rows,m=self.fixture()
        model["services"]["proxy-server"]["environment"]["JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"]="different-config-attestation-key"
        with self.assertRaisesRegex(RuntimeError,"differs"):
            vm.build_model(model,m,rows)
    def test_file_enablement_mounts_only_missing_scan_tmpfs(self):
        model,rows,m=self.fixture()
        new=vm.build_model(model,m,rows)
        item=new["services"]["security-engine"]
        self.assertEqual(len(item["tmpfs"]),1)
        self.assertIn("uid=10001",item["tmpfs"][0])
        again=vm.build_model(new,m,rows)
        self.assertEqual(again["services"]["security-engine"]["tmpfs"],item["tmpfs"])
    def test_existing_scan_volume_is_preserved(self):
        model,rows,m=self.fixture()
        volume={"type":"volume","source":"scan","target":"/var/lib/jjdguard/scan-store"}
        model["services"]["security-engine"]["volumes"]=[volume]
        new=vm.build_model(model,m,rows)["services"]["security-engine"]
        self.assertEqual(new["volumes"],[volume])
        self.assertEqual(new["tmpfs"],[])
    def test_custom_scan_path_requires_review(self):
        model,rows,m=self.fixture()
        model["services"]["security-engine"]["environment"]["SECURITY_SCAN_STORE_DIR"]="/custom"
        with self.assertRaises(RuntimeError):vm.build_model(model,m,rows)
    def test_mutable_candidate_is_rejected(self):
        model,rows,m=self.fixture();m["services"]["gateway-core"]["image_id"]="gateway:latest"
        with self.assertRaises(RuntimeError):vm.build_model(model,m,rows)
    def test_missing_service_is_rejected(self):
        model,rows,m=self.fixture();del model["services"]["tier1-classifier"]
        with self.assertRaises(RuntimeError):vm.build_model(model,m,rows)
    def test_normalized_dollars_are_preserved_without_reescaping(self):
        model,rows,m=self.fixture()
        model["services"]["worker"]["environment"]["SECRET"]="literal$$TOKEN"
        model["services"]["worker"]["command"]=["sh","-c","echo $$TOKEN"]
        new=vm.build_model(model,m,rows)
        self.assertEqual(new["services"]["worker"]["environment"]["SECRET"],"literal$$TOKEN")
        self.assertEqual(new["services"]["worker"]["command"],["sh","-c","echo $$TOKEN"])
    def test_atomic_file_mode_and_refusal_of_stale_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/"config"
            vm.atomic_bytes(target,b"first")
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            vm.atomic_bytes(target,b"second")
            self.assertEqual(target.read_bytes(),b"second")
            target.with_name(target.name+".development-new").symlink_to(target)
            with self.assertRaises(RuntimeError):vm.atomic_bytes(target,b"third")
            self.assertEqual(target.read_bytes(),b"second")

    def test_engineering_historical_chain_requires_equivalent_service_and_resources(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);current=root/"current.json";old=root/"old.yml"
            current.write_text("{}");old.write_text("{}")
            names=vm.ENGINEERING_SERVICES
            rows={s:{"Image":"sha256:"+"a"*64,"Config":{"Env":["TOKEN=same"],"Labels":{"com.docker.compose.project.config_files":str(old if s=="tier1-classifier" else current)}}} for s in names}
            service={"image":"sha256:"+"a"*64,"environment":{"TOKEN":"same"},"networks":{"private":{}},"volumes":[{"type":"volume","source":"models","target":"/models"}],"pull_policy":"never"}
            canonical={"name":"project","services":{s:copy.deepcopy(service) for s in names},"networks":{"private":{"internal":True}},"volumes":{"models":{"name":"fixed"}}}
            historical=copy.deepcopy(canonical)
            historical["services"]["tier1-classifier"]["image"]="original:tag"
            historical["services"]["tier1-classifier"].pop("pull_policy")
            render=lambda files:canonical if files==(current,) else historical
            identify=lambda name:"sha256:"+"a"*64
            selected,inputs=vm.resolve_release_compose(rows,root,names,True,render,identify)
            self.assertEqual(selected,(current,))
            self.assertEqual(set(inputs),{current,old})
            for mutation in ("environment","network","volume","image"):
                altered=copy.deepcopy(historical)
                if mutation=="environment":altered["services"]["tier1-classifier"]["environment"]["TOKEN"]="changed"
                if mutation=="network":altered["networks"]["private"]["internal"]=False
                if mutation=="volume":altered["volumes"]["models"]["name"]="different"
                if mutation=="image":altered["services"]["tier1-classifier"]["image"]="wrong"
                with self.subTest(mutation=mutation):
                    with self.assertRaises(RuntimeError):
                        vm.resolve_release_compose(rows,root,names,True,lambda files:canonical if files==(current,) else altered,lambda name:"sha256:"+"b"*64 if name=="wrong" else identify(name))
            # A normal release may follow an engineering-only release. Its
            # historical per-service chains must pass the same equivalence gate.
            selected,inputs=vm.resolve_release_compose(rows,root,names,False,render,identify)
            self.assertEqual(selected,(current,))
            self.assertEqual(set(inputs),{current,old})
            for mutation in ("environment","network","volume","image"):
                altered=copy.deepcopy(historical)
                if mutation=="environment":altered["services"]["tier1-classifier"]["environment"]["TOKEN"]="changed"
                if mutation=="network":altered["networks"]["private"]["internal"]=False
                if mutation=="volume":altered["volumes"]["models"]["name"]="different"
                if mutation=="image":altered["services"]["tier1-classifier"]["image"]="wrong"
                with self.subTest(normal_release_mutation=mutation):
                    with self.assertRaises(RuntimeError):
                        vm.resolve_release_compose(rows,root,names,False,lambda files:canonical if files==(current,) else altered,lambda name:"sha256:"+"b"*64 if name=="wrong" else identify(name))

    def test_full_release_uses_current_engine_model_after_se_only_release(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);old=root/'full.json';current=root/'se-only.json'
            old.write_text('{}');current.write_text('{}')
            old_image='sha256:'+'a'*64;new_image='sha256:'+'b'*64
            old_model={'name':'project','services':{
                'gateway-core':{'image':old_image,'environment':{'REV':'old'}},
                'security-engine':{'image':old_image,'environment':{'REV':'old'}},
            }}
            new_model=copy.deepcopy(old_model)
            new_model['services']['security-engine']={'image':new_image,'environment':{'REV':'new'}}
            rows={
                'gateway-core':{'Image':old_image,'Config':{'Env':['REV=old'],'Labels':{'com.docker.compose.project.config_files':str(old)}}},
                'security-engine':{'Image':new_image,'Config':{'Env':['REV=new'],'Labels':{'com.docker.compose.project.config_files':str(current)}}},
            }
            render=lambda files:new_model if files==(current,) else old_model
            selected,inputs=vm.resolve_release_compose(rows,root,tuple(rows),False,render,lambda image:image)
            self.assertEqual(selected,(current,))
            self.assertEqual(set(inputs),{old,current})
            tampered=copy.deepcopy(new_model)
            tampered['services']['security-engine']['environment']['REV']='unapplied'
            with self.assertRaisesRegex(RuntimeError,'live environment differs'):
                vm.resolve_release_compose(rows,root,tuple(rows),False,lambda files:tampered if files==(current,) else old_model,lambda image:image)

    def test_portal_single_service_chain_does_not_require_gateway(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/"portal.json";path.write_text("{}")
            rows={"chat-portal-ui":{"Image":"fixed","Config":{"Labels":{"com.docker.compose.project.config_files":str(path)}}}}
            model={"name":"project","services":{"chat-portal-ui":{"image":"fixed"}}}
            selected,inputs=vm.resolve_release_compose(rows,root,("chat-portal-ui",),False,lambda files:model,lambda image:image)
            self.assertEqual(selected,(path,))
            self.assertEqual(inputs,(path,))

    def test_identical_multi_file_compose_chain_is_preserved_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            workdir=Path(d).resolve()
            base=workdir/"docker-compose.offline.yml"
            override=workdir/"active-config/release-images.override.yml"
            override.parent.mkdir()
            base.write_text("services: {}\n")
            override.write_text("services: {}\n")
            labels={"com.docker.compose.project.config_files":f"{base},{override}"}
            rows={
                "gateway-core":{"Config":{"Labels":dict(labels)}},
                "security-engine":{"Config":{"Labels":dict(labels)}},
            }
            selected=("gateway-core","security-engine")
            self.assertEqual(vm.resolve_compose_chain(rows,workdir,selected),(base,override))

    def test_compose_chain_label_accepts_up_to_governed_boot_limit(self):
        # 每次 --persist-boot 发布都会给未重建的服务标签追加一个文件；
        # 标签上限必须与受管启动链上限一致，不能比它更小。
        with tempfile.TemporaryDirectory() as d:
            workdir=Path(d).resolve()
            (workdir/"active-config").mkdir()
            files=[]
            for index in range(vm.MAX_GOVERNED_BOOT_FILES):
                path=workdir/"active-config"/f"f{index}.yml"
                path.write_text("services: {}\n")
                files.append(path)
            def rows_for(items):
                labels={"com.docker.compose.project.config_files":",".join(str(i) for i in items)}
                return {"gateway-core":{"Config":{"Labels":labels}}}
            self.assertEqual(vm.resolve_compose_chain(rows_for(files[:9]),workdir,("gateway-core",)),tuple(files[:9]))
            self.assertEqual(vm.resolve_compose_chain(rows_for(files),workdir,("gateway-core",)),tuple(files))
            with self.assertRaisesRegex(RuntimeError,"invalid Compose file chain"):
                vm.resolve_compose_chain(rows_for(files+[files[0]]),workdir,("gateway-core",))

    def test_mismatched_compose_chains_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            workdir=Path(d).resolve()
            base=workdir/"docker-compose.offline.yml"
            override=workdir/"active-config/release-images.override.yml"
            other=workdir/"active-config/other.override.yml"
            override.parent.mkdir()
            for path in (base,override,other):path.write_text("services: {}\n")
            rows={
                "gateway-core":{"Config":{"Labels":{"com.docker.compose.project.config_files":f"{base},{override}"}}},
                "security-engine":{"Config":{"Labels":{"com.docker.compose.project.config_files":f"{base},{other}"}}},
            }
            with self.assertRaisesRegex(RuntimeError,"Compose file chain differs"):
                vm.resolve_compose_chain(rows,workdir,("gateway-core","security-engine"))

    def test_compose_chain_rejects_escape_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            workdir=Path(d,"runtime").resolve()
            workdir.mkdir()
            outside=Path(d,"outside.yml")
            outside.write_text("services: {}\n")
            rows={"gateway-core":{"Config":{"Labels":{"com.docker.compose.project.config_files":str(outside)}}}}
            with self.assertRaisesRegex(RuntimeError,"escapes runtime"):
                vm.resolve_compose_chain(rows,workdir,("gateway-core",))
            target=workdir/"compose.yml"
            target.symlink_to(outside)
            rows["gateway-core"]["Config"]["Labels"]["com.docker.compose.project.config_files"]=str(target)
            with self.assertRaisesRegex(RuntimeError,"symbolic link"):
                vm.resolve_compose_chain(rows,workdir,("gateway-core",))

    def test_empty_migration_manifest_skips_runner(self):
        release=vm.Release.__new__(vm.Release)
        release.manifest={"migrations":{}}
        events=[]
        release.event=events.append
        release.migration(dry=True)
        release.migration(dry=False)
        self.assertEqual(events,[
            "MIGRATE no pending files",
            "MIGRATE no pending files",
        ])

    def test_switch_force_recreates_every_target_service(self):
        with tempfile.TemporaryDirectory() as d:
            release=vm.Release.__new__(vm.Release)
            release.live=Path(d)/"active-config.json"
            release.state_dir=Path(d)/"state"
            release.state_dir.mkdir()
            (release.state_dir/"candidate.json").write_text('{"services":{}}\n')
            release.rows={}
            release.manifest={}
            release.target_services=vm.SERVICES
            calls=[]
            release.event=lambda text:None
            release.compose=lambda *args,**kwargs:calls.append((args,kwargs))
            release.switch()
            self.assertEqual(calls,[(
                (
                    "up","-d","--no-deps","--pull","never","--force-recreate",
                    *vm.SERVICES,
                ),
                {"file":release.live},
            )])

    def test_switch_preserve_tier1_does_not_recreate_model_service(self):
        with tempfile.TemporaryDirectory() as d:
            release=vm.Release.__new__(vm.Release)
            release.live=Path(d)/"active-config.json"
            release.state_dir=Path(d)/"state"
            release.state_dir.mkdir()
            (release.state_dir/"candidate.json").write_text('{"services":{}}\n')
            release.rows={}
            release.manifest={}
            release.target_services=vm.SERVICES[:-1]
            calls=[]
            release.event=lambda text:None
            release.compose=lambda *args,**kwargs:calls.append((args,kwargs))
            release.switch()
            self.assertEqual(calls[0][0][-len(vm.SERVICES[:-1]):],vm.SERVICES[:-1])
            self.assertNotIn("tier1-classifier",calls[0][0])

    def test_disabled_managed_file_detection_skips_live_file_probe(self):
        with tempfile.TemporaryDirectory() as d:
            release=vm.Release.__new__(vm.Release)
            release.manifest={"enable_file_detection":False}
            release.state_dir=Path(d)
            release.log=Path(d)/"apply.log"
            release.verify_file_runtime({})
            result=__import__("json").loads((Path(d)/"file-http-probe.json").read_text())
            self.assertEqual(result,{
                "status":"not_requested",
                "reason":"managed_file_detection_disabled",
            })

    def portal_lines(self):
        return builder.portal_dockerfile(PORTAL_BASE,PORTAL_RUNTIME,PORTAL_CONFIG,"portal",["JJD_COMMIT="+"c"*40])

    def test_portal_candidate_does_not_build_on_the_previous_portal_image(self):
        lines=self.portal_lines()
        stages=[line for line in lines if line.startswith("FROM ")]
        self.assertEqual(stages[-1],"FROM "+PORTAL_RUNTIME+" AS portal-runtime")
        self.assertEqual([s for s in stages if PORTAL_BASE in s],["FROM "+PORTAL_BASE+" AS portal-dependencies"])
        self.assertNotIn("USER root",lines)
        self.assertFalse([line for line in lines if line.startswith("RUN rm -rf /app")])
        self.assertTrue(any(line.startswith("COPY --from=portal-dependencies /app/node_modules /tmp/") for line in lines))
        self.assertTrue(any(line.startswith("COPY --from=portal-prisma-cli --chown=portal /app/node_modules") for line in lines))
        self.assertTrue(any("addgroup -S portal && adduser -S portal -G portal" in line for line in lines))
        self.assertIn("COPY --chown=portal runtime/ /",lines)
        self.assertEqual(lines[-1],"USER portal")
        with self.assertRaises(AssertionError):
            builder.portal_dockerfile(PORTAL_BASE,PORTAL_BASE,PORTAL_CONFIG,"portal",[])

    def test_portal_runtime_env_accepts_the_product_base_without_static_engine_paths(self):
        config={"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                       "NODE_VERSION=22.22.3","YARN_VERSION=1.22.22",
                       "npm_config_registry=https://registry.npmjs.org",
                       "PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1","NODE_ENV=production"]}
        self.assertEqual(builder.portal_runtime_env(config),
                         ['NODE_ENV="production"','npm_config_registry="https://registry.npmjs.org"',
                          'PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING="1"'])
        for required in ("NODE_ENV","npm_config_registry","PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING"):
            incomplete={"Env":[item for item in config["Env"] if not item.startswith(required+"=")]}
            with self.subTest(required=required),self.assertRaisesRegex(AssertionError,required):
                builder.portal_runtime_env(incomplete)

    def test_portal_runtime_env_preserves_each_existing_engine_path_without_adding_the_other(self):
        for key,path in (("PRISMA_SCHEMA_ENGINE_BINARY","/app/node_modules/@prisma/engines/schema-engine-linux-musl-openssl-3.0.x"),
                         ("PRISMA_QUERY_ENGINE_LIBRARY","/app/node_modules/@prisma/engines/libquery_engine-linux-musl-openssl-3.0.x.so.node")):
            config={"Env":["NODE_ENV=production","npm_config_registry=https://registry.npmjs.org",
                           "PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1",key+"="+path]}
            result=builder.portal_runtime_env(config)
            with self.subTest(key=key):
                self.assertEqual(len(result),4)
                self.assertIn(key+'="'+path+'"',result)

    def test_portal_runtime_stage_keeps_prisma_cli_and_musl_engine_configuration(self):
        recipe="\n".join(self.portal_lines())
        self.assertIn("node /tmp/prisma-closure.js",recipe)
        self.assertIn("cp -a /tmp/portal-node_modules/.prisma node_modules/.prisma",recipe)
        self.assertIn("cp -a /tmp/portal-node_modules/.bin/prisma node_modules/.bin/prisma",recipe)
        self.assertIn('PRISMA_QUERY_ENGINE_LIBRARY="/app/node_modules/@prisma/engines/libquery_engine-linux-musl-openssl-3.0.x.so.node"',recipe)
        self.assertIn('PRISMA_SCHEMA_ENGINE_BINARY="/app/node_modules/@prisma/engines/schema-engine-linux-musl-openssl-3.0.x"',recipe)
        with self.assertRaises(AssertionError):
            builder.portal_runtime_env({"Env":["NODE_ENV=production"]})

    def test_portal_runtime_content_contract_requires_prisma_cli_and_musl_engines(self):
        builder.verify_portal_runtime_contents(set(builder.PORTAL_RUNTIME_REQUIRED))
        for required in builder.PORTAL_RUNTIME_REQUIRED:
            with self.assertRaises(AssertionError):
                builder.verify_portal_runtime_contents(set(builder.PORTAL_RUNTIME_REQUIRED)-{required})

    def test_portal_candidate_image_must_fit_the_size_contract(self):
        builder.verify_portal_image_size(builder.PORTAL_IMAGE_LIMIT)
        self.assertEqual(builder.PORTAL_IMAGE_LIMIT,500*1024*1024)
        with self.assertRaises(AssertionError):
            builder.verify_portal_image_size(builder.PORTAL_IMAGE_LIMIT+1)
        with self.assertRaises(AssertionError):
            builder.verify_portal_image_size(599516565)

    def test_portal_candidate_must_not_reuse_previous_portal_layers(self):
        runtime=["sha256:"+"1"*64,"sha256:"+"2"*64]
        dependency=runtime+["sha256:"+"3"*64]
        builder.verify_portal_layers(runtime+["sha256:"+"4"*64],dependency,runtime)
        with self.assertRaises(AssertionError):
            builder.verify_portal_layers(dependency+["sha256:"+"4"*64],dependency,runtime)
        with self.assertRaises(AssertionError):
            builder.verify_portal_layers(["sha256:"+"9"*64]+runtime,dependency,runtime)

    def test_portal_candidate_may_share_runtime_setup_layers_with_rebuilt_base(self):
        runtime=["sha256:"+"1"*64,"sha256:"+"2"*64]
        workdir,group=["sha256:"+"5"*64,"sha256:"+"6"*64]
        dependency=runtime+[workdir,group,"sha256:"+"7"*64,"sha256:"+"8"*64]
        builder.verify_portal_layers(runtime+[workdir,group,"sha256:"+"a"*64,"sha256:"+"b"*64],dependency,runtime)
        with self.assertRaises(AssertionError):
            builder.verify_portal_layers(runtime+[workdir,group,"sha256:"+"7"*64,"sha256:"+"b"*64],dependency,runtime)
        with self.assertRaises(AssertionError):
            builder.verify_portal_layers(runtime+[workdir,group,"sha256:"+"a"*64,"sha256:"+"8"*64],dependency,runtime)

    def portal_media(self):
        manifest={
            "services":{"chat-portal-ui":{"tag":"jjdguard-dev/chat-portal-ui:dev-1"}},
            "portal_only":True,"preserve_tier1":True,"migrations":{},
        }
        names=["manifest.json","images.tar","migration-runner.sh","vm_development_apply.py","migrations"]
        return manifest,names,[["jjdguard-dev/chat-portal-ui:dev-1"]]

    def test_portal_only_media_ships_only_the_portal_service(self):
        manifest,names,tags=self.portal_media()
        builder.verify_portal_only_release(manifest,names,tags)
        extra=copy.deepcopy(manifest);extra["services"]["tier1-classifier"]={"tag":"jjdguard-dev/tier1-classifier:dev-1"}
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(extra,names,tags)
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(manifest,names+["tier1-window-smoke.py"],tags)
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(manifest,names+["tier1-candidate-smoke.log"],tags)
        probe=copy.deepcopy(manifest);probe["tier1_probe_sha256"]="a"*64
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(probe,names,tags)
        migrated=copy.deepcopy(manifest);migrated["migrations"]={"821_serialize_customer_content_projection.sql":"b"*64}
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(migrated,names,tags)
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(manifest,names,tags+[["jjdguard-dev/tier1-classifier:dev-1"]])
        relaxed=copy.deepcopy(manifest);relaxed["preserve_tier1"]=False
        with self.assertRaises(AssertionError):
            builder.verify_portal_only_release(relaxed,names,tags)

    def test_portal_runtime_base_and_prisma_closure_come_from_the_portal_dockerfile(self):
        recipe=(ROOT/"enterprise-ai-portal/Dockerfile").read_text()
        base=builder.portal_runtime_base(recipe)
        self.assertRegex(base,r"@sha256:[0-9a-f]{64}$")
        self.assertIn("FROM "+base+" AS base",recipe)
        self.assertIn("copyPackage('prisma');",builder.portal_prisma_closure(recipe))
        with self.assertRaises(AssertionError):
            builder.portal_runtime_base("FROM node:22-alpine AS base\n")
        with self.assertRaises(AssertionError):
            builder.portal_prisma_closure("FROM node:22-alpine AS base\n")

    def test_controlled_node_build_has_fixed_heap_limit_and_rejects_inherited_options(self):
        env = builder.npm_environment({"PATH":"/usr/bin",
                                       "NODE_OPTIONS":"--require /unapproved.js --max-old-space-size=32768"},
                                      "true", "/tmp/user", "/tmp/global")
        self.assertEqual(env["NODE_OPTIONS"], "--max-old-space-size=2048")
        self.assertEqual(env["NEXT_PUBLIC_BILLING_ENABLED"], "true")

    def test_portal_build_environment_declares_the_billing_flag(self):
        env=builder.npm_environment({"PATH":"/usr/bin"},"true","/tmp/user","/tmp/global")
        self.assertEqual(env["NEXT_PUBLIC_BILLING_ENABLED"],"true")
        self.assertEqual(env["VITE_BILLING_ENABLED"],"true")
        self.assertEqual(env["PATH"],"/usr/bin")
        self.assertEqual(builder.npm_environment({},"false","/tmp/u","/tmp/g")["NEXT_PUBLIC_BILLING_ENABLED"],"false")

    def test_portal_surface_requires_customer_centre_routes_and_matching_billing_flag(self):
        routes={route:route for route in vm.PORTAL_ROUTES}
        result=vm.portal_surface({"NEXT_PUBLIC_BILLING_ENABLED":"true"},routes,"true")
        self.assertEqual(result["status"],"portal_only")
        self.assertEqual(result["billing_enabled"],"true")
        with self.assertRaises(RuntimeError):
            vm.portal_surface({"NEXT_PUBLIC_BILLING_ENABLED":"false"},routes,"true")
        with self.assertRaises(RuntimeError):
            vm.portal_surface({},routes,"true")
        with self.assertRaises(RuntimeError):
            vm.portal_surface({"NEXT_PUBLIC_BILLING_ENABLED":"true"},{"/page":"/"},"true")





class GovernedHistoricalChainTests(unittest.TestCase):
    def fixture(self, root):
        names = vm.SERVICES[:-1]
        historical = root / "full.json"
        console = root / "console.json"
        base = root / "docker-compose.offline.yml"
        overlay = root / "active-config" / "console-boot.json"
        pointer = root / ".upgrade" / "compose-files"
        overlay.parent.mkdir()
        pointer.parent.mkdir()
        for path in (historical, console, base, overlay):
            path.write_text("{}")
        pointer.write_text(str(overlay) + "\n")
        old_image = "sha256:" + "a" * 64
        new_image = "sha256:" + "b" * 64
        item = {
            "image": old_image,
            "environment": {"JJD_COMMIT": "old", "TOKEN": "same"},
            "networks": {"private": {}},
            "volumes": [{"type": "volume", "source": "data", "target": "/data"}],
        }
        old = {
            "name": "project", "services": {s: copy.deepcopy(item) for s in names},
            "networks": {"private": {"internal": True}},
            "volumes": {"data": {"name": "fixed"}},
        }
        current = copy.deepcopy(old)
        for name in ("control-plane", "web-console"):
            current["services"][name]["image"] = new_image
            current["services"][name]["environment"]["JJD_COMMIT"] = "console"
        rows = {
            name: {
                "Image": current["services"][name]["image"],
                "Config": {
                    "Env": [k + "=" + v for k, v in current["services"][name]["environment"].items()],
                    "Labels": {"com.docker.compose.project.config_files": str(
                        console if name in ("control-plane", "web-console") else historical)},
                },
            } for name in names
        }
        models = {(historical,): old, (console,): current, (base, overlay): copy.deepcopy(current)}
        return names, rows, models, (base, overlay), {historical, console, base, overlay, pointer}

    def test_full_release_after_console_only_uses_equivalent_governed_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names, rows, models, boot, frozen = self.fixture(root)
            selected, inputs = vm.resolve_release_compose(
                rows, root, names, False, lambda files: models[files], lambda image: image)
            self.assertEqual(selected, boot)
            self.assertEqual(set(inputs), frozen)

    def long_governed_fixture(self, root, count=12):
        names, rows, models, original, frozen = self.fixture(root)
        additional = tuple(root/"active-config"/("managed-"+str(i)+".json") for i in range(count-len(original)))
        for path in additional: path.write_text("{}")
        boot = original+additional
        (root/".upgrade/compose-files").write_text("".join(str(path)+"\n" for path in boot[1:]))
        models[boot] = copy.deepcopy(models[original])
        return names, rows, models, boot, frozen|set(additional)

    def test_equivalent_twelve_file_governed_boot_chain_is_frozen_completely(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names, rows, models, boot, frozen = self.long_governed_fixture(root)
            selected, inputs = vm.resolve_release_compose(rows,root,names,False,lambda files:models[files],lambda image:image)
            self.assertEqual(selected,boot)
            self.assertEqual(set(inputs),frozen)

    def test_long_governed_chain_still_checks_all_historical_and_live_contracts(self):
        for mutation in ("environment", "image", "network", "volume"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                names, rows, models, boot, _ = self.long_governed_fixture(root)
                model = models[boot]
                if mutation=="environment": model["services"]["web-console"]["environment"]["TOKEN"]="changed"
                if mutation=="image": model["services"]["web-console"]["image"]="sha256:"+"c"*64
                if mutation=="network": model["networks"]["private"]["internal"]=False
                if mutation=="volume": model["volumes"]["data"]["name"]="changed"
                with self.assertRaisesRegex(RuntimeError,"differ"):
                    vm.resolve_release_compose(rows,root,names,False,lambda files:models[files],lambda image:image)

    def test_long_governed_chain_rejects_duplicate_inputs_before_render(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names, rows, models, boot, _ = self.long_governed_fixture(root)
            pointer = root/".upgrade/compose-files"
            pointer.write_text(pointer.read_text()+str(boot[-1])+"\n")
            with self.assertRaisesRegex(RuntimeError,"invalid governed boot chain"):
                vm.resolve_release_compose(rows,root,names,False,lambda files:models[files],lambda image:image)

    def test_governed_chain_over_thirty_two_files_is_rejected_before_render(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names, rows, models, boot, _ = self.long_governed_fixture(root,33)
            def render(files):
                if files==boot: self.fail("oversized governed chain must not be rendered")
                return models[files]
            with self.assertRaisesRegex(RuntimeError,"invalid governed boot chain"):
                vm.resolve_release_compose(rows,root,names,False,render,lambda image:image)

    def test_governed_fallback_still_rejects_historical_and_live_drift(self):
        for mutation in ("image", "environment", "network", "volume", "project",
                         "live_image", "live_environment", "historical_environment"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                names, rows, models, boot, _ = self.fixture(root)
                model = models[boot]
                service = model["services"]["control-plane"]
                if mutation == "image": service["image"] = "sha256:" + "c" * 64
                if mutation == "environment": service["environment"]["TOKEN"] = "changed"
                if mutation == "network": model["networks"]["private"]["internal"] = False
                if mutation == "volume": model["volumes"]["data"]["name"] = "changed"
                if mutation == "project": model["name"] = "changed"
                if mutation == "live_image": rows["control-plane"]["Image"] = "sha256:" + "c" * 64
                if mutation == "live_environment": rows["control-plane"]["Config"]["Env"] = ["JJD_COMMIT=console", "TOKEN=changed"]
                if mutation == "historical_environment": models[(root / "console.json",)]["services"]["control-plane"]["environment"]["TOKEN"] = "changed"
                with self.assertRaisesRegex(RuntimeError, "differ"):
                    vm.resolve_release_compose(rows, root, names, False, lambda files: models[files], lambda image: image)

    def test_governed_fallback_refuses_symlink_inputs(self):
        for target in ("pointer", "overlay", "ancestor", "traversal"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                names, rows, models, boot, _ = self.fixture(root)
                pointer = root / ".upgrade" / "compose-files"
                if target == "ancestor":
                    boot[1].parent.rename(root / "real-config")
                    boot[1].parent.symlink_to(root / "real-config", target_is_directory=True)
                elif target == "traversal":
                    pointer.write_text(str(boot[1].parent / ".." / "console.json") + "\n")
                else:
                    path = pointer if target == "pointer" else boot[1]
                    path.unlink()
                    path.symlink_to(root / "console.json")
                with self.assertRaisesRegex(RuntimeError, "governed boot chain"):
                    vm.resolve_release_compose(rows, root, names, False, lambda files: models[files], lambda image: image)

    def test_unpersisted_engine_release_keeps_verified_historical_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names, rows, models, boot, _ = self.fixture(root)
            current = root / "console.json"
            service = models[(current,)]["services"]["security-engine"]
            service["image"] = "sha256:" + "c" * 64
            service["environment"]["JJD_COMMIT"] = "engine"
            rows["security-engine"]["Image"] = service["image"]
            rows["security-engine"]["Config"]["Env"] = ["JJD_COMMIT=engine", "TOKEN=same"]
            rows["security-engine"]["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(current)
            selected, inputs = vm.resolve_release_compose(
                rows, root, names, False, lambda files: models[files], lambda image: image)
            self.assertEqual(selected, (current,))
            self.assertEqual(set(inputs), {root / "full.json", current})

    def test_fence_rejects_governed_chain_pointer_changed_after_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, rows, _, boot, _ = self.fixture(root)
            pointer = root / ".upgrade" / "compose-files"
            environment = root / ".env"
            environment.write_text("TOKEN=same\n")
            release = vm.Release.__new__(vm.Release)
            release.manifest = {}
            release.live_files = boot
            release.env_file = environment
            runtime = {"control-plane": {"id": "unchanged"}}
            release.before = {
                "runtime": runtime, "compose_files": [str(path) for path in boot],
                "compose_sha256": {str(pointer): vm.digest(pointer)},
                "env_sha256": vm.digest(environment),
            }
            pointer.write_text(str(boot[1]) + "\n\n")
            with patch.object(release, "resolve_candidate_images"), patch.object(release, "load_state"), \
                 patch.object(vm, "inspect_runtime", return_value=rows), \
                 patch.object(vm, "safe_identity", return_value=runtime), patch.object(vm, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "runtime configuration changed since stage"):
                    release.fence()
                run.assert_not_called()


class SemanticWindowReleaseTests(unittest.TestCase):
    def test_explicit_capacity_only_changes_engine_and_rollback_restores(self):
        model = {"services": {name: {"environment": {"SECURITY_SEMANTIC_MAX_WINDOWS":"32", "security_audit_only":"true"}} for name in vm.SERVICES}}
        manifest = {"services":{"security-engine":{"image_id":"sha256:"+"a"*64}}, "revision":"r", "version":"v", "created_at":"now", "semantic_max_windows":128}
        new = vm.build_model(model,manifest,{})
        self.assertEqual(new["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_MAX_WINDOWS"],"128")
        self.assertEqual(model["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_MAX_WINDOWS"],"32")
        for name in vm.SERVICES:
            if name != "security-engine":self.assertEqual(new["services"][name],model["services"][name])
        rollback = vm.build_model(model,dict(manifest,services={},semantic_max_windows=None),{})
        self.assertEqual(rollback,model)
        for invalid in [True,0,-1,"128"]:
            with self.assertRaises(RuntimeError):vm.build_model(model,dict(manifest,semantic_max_windows=invalid),{})
        with self.assertRaises(RuntimeError):vm.build_model(model,dict(manifest,services={}),{})


class SemanticParallelReleaseTests(unittest.TestCase):
    def test_parallel_override_is_explicit_bounded_and_engine_only(self):
        self.assertEqual(vm.semantic_parallel_environment({}), {})
        manifest={"security_engine_only":True,"services":{"security-engine":{}},"semantic_window_parallelism":8}
        values=vm.semantic_parallel_environment(manifest)
        self.assertEqual(set(values), {"SECURITY_SEMANTIC_WINDOW_PARALLELISM","SECURITY_JUDGE_WORKERS","SECURITY_JUDGE_CAPACITY"})
        self.assertEqual(set(values.values()), {"8"})
        for invalid in [True,0,-1,"8"]:
            with self.assertRaises(RuntimeError):vm.semantic_parallel_environment(dict(manifest,semantic_window_parallelism=invalid))
        for invalid in [{"services":{}},{"portal_only":True},{"engineering_only":True}]:
            with self.assertRaises(RuntimeError):vm.semantic_parallel_environment(dict(manifest,**invalid))


class CustomerCapacityTests(unittest.TestCase):
    def test_large_customer_values_survive_cli_and_release_projection(self):
        for count in (16,64,512,4096):
            self.assertEqual(builder.positive_integer_argument(str(count)),count)
            manifest={"services":{"security-engine":{"image_id":"sha256:"+"a"*64}}, "revision":"r", "version":"v", "created_at":"now", "semantic_window_parallelism":count,"semantic_max_windows":count}
            model={"services":{name:{"environment":{}} for name in vm.SERVICES}}
            result=vm.build_model(model,manifest,{})["services"]["security-engine"]["environment"]
            for key in ("SECURITY_SEMANTIC_WINDOW_PARALLELISM","SECURITY_JUDGE_WORKERS","SECURITY_JUDGE_CAPACITY","SECURITY_SEMANTIC_MAX_WINDOWS"):
                self.assertEqual(result[key],str(count))
        import argparse
        for invalid in ("0","-1","1.5","oops"):
            with self.assertRaises(argparse.ArgumentTypeError):builder.positive_integer_argument(invalid)


class LongInspectionEnvelopeTests(unittest.TestCase):
    def manifest(self):
        return dict(services={"gateway-core": {"image_id": "sha256:"+"a"*64}, "security-engine": {"image_id": "sha256:"+"b"*64}},
                    revision="c"*40, version="2.6.12", created_at="now", gateway_security_budget_seconds=60,
                    security_engine_client_timeout_seconds=59, security_input_budget_seconds=58, security_batch_budget_seconds=55)

    def test_gateway_and_engine_budgets_are_applied_together_without_touching_other_settings(self):
        model = {"services": {name: {"image": "old", "environment": {"KEEP": "value"}} for name in vm.SERVICES}}
        result = vm.build_model(model, self.manifest(), {})
        self.assertEqual(result["services"]["gateway-core"]["environment"]["GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT"], "60s")
        self.assertEqual(result["services"]["gateway-core"]["environment"]["SECURITY_ENGINE_TIMEOUT"], "59s")
        self.assertEqual(result["services"]["security-engine"]["environment"]["SECURITY_INPUT_BUDGET_SECONDS"], "58")
        self.assertEqual(result["services"]["security-engine"]["environment"]["SECURITY_BATCH_BUDGET_SECONDS"], "55")
        self.assertEqual(result["services"]["worker"], model["services"]["worker"])

    def test_invalid_or_inverted_envelope_is_rejected(self):
        for patch in [dict(gateway_security_budget_seconds=True), dict(security_engine_client_timeout_seconds="59"),
                      dict(gateway_security_budget_seconds=50), dict(security_input_budget_seconds=60),
                      dict(security_batch_budget_seconds=59), dict(security_engine_client_timeout_seconds=None),
                      dict(security_engine_only=True)]:
            with self.subTest(patch=patch), self.assertRaises(RuntimeError):
                vm.gateway_budget_environment(dict(self.manifest(), **patch))

    def test_absent_overrides_preserve_existing_customer_deadlines(self):
        self.assertEqual(vm.gateway_budget_environment({"services": {}}), {})


if __name__ == "__main__":
    unittest.main()


def merge_models(files):
    model={}
    def merge(left,right):
        for key,value in right.items():
            if isinstance(value,dict) and isinstance(left.get(key),dict): merge(left[key],value)
            elif isinstance(value,list) and isinstance(left.get(key),list): left[key]+=copy.deepcopy(value)
            else: left[key]=copy.deepcopy(value)
    for path in files: merge(model,json.loads(Path(path).read_text()))
    return model

OLD="sha256:"+"a"*64
NEW="sha256:"+"b"*64

class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.media=self.root/"development-releases"/"dev-rollback-test"
        (self.media/"state"/"original-compose").mkdir(parents=True)
        self.workdir=self.root/"releases"/"installed"/"deploy"/"docker-compose"
        (self.workdir/"active-config").mkdir(parents=True)
        (self.workdir/".upgrade").mkdir(parents=True)
        (self.workdir/"bin").mkdir()
        self.compose_bin=self.workdir/"bin/docker-compose"
        self.compose_bin.write_text("fixture compose\n"); self.compose_bin.chmod(0o755)
        self.base=self.workdir/"docker-compose.offline.yml"
        (self.workdir/".env").write_text("SECURITY_AUDIT_ONLY=true\n")
        self.services=vm.SERVICES+("postgres","chat-portal-ui","chat-portal-proxy")
        env={"JJD_COMMIT":"old","SECURITY_AUDIT_ONLY":"true"}
        base_model={"name":"stable-project","services":{s:{"image":OLD,"environment":dict(env)} for s in self.services}}
        self.base.write_text(json.dumps(base_model))
        self.candidate={"name":"stable-project","services":{}}
        for s in self.services:
            # build_model 只对 manifest 服务更新 provenance env；非目标服务环境不变
            item={"image":NEW if s in vm.SERVICES else OLD,
                  "environment":{"JJD_COMMIT":"c"*40 if s in vm.SERVICES else "old","SECURITY_AUDIT_ONLY":"true"}}
            self.candidate["services"][s]=item
        self.live=self.workdir/"active-config"/"dev-rollback-test.json"
        self.live.write_text(json.dumps(self.candidate))
        self.before_ledger={"001_init":"1"*64}
        self.before_policy={"security_audit_only":"true"}
        self.before={"runtime":{s:{"id":s+"-old","image":OLD,"started_at":"t","restarts":0,
                                   "status":"running","health":"healthy"} for s in self.services},
                     "ledger":self.before_ledger,"policy":self.before_policy,
                     "compose_files":[str(self.base)],
                     "compose_sha256":{str(self.base):vm.digest(self.base)},
                     "env_file":str(self.workdir/".env"),"env_sha256":vm.digest(self.workdir/".env"),"live":str(self.live),
                     "project":"stable-project"}
        (self.media/"state"/"before.json").write_text(json.dumps(self.before))
        (self.media/"state"/"candidate.json").write_text(json.dumps(self.candidate))
        (self.media/"state"/"rollback.json").write_text(json.dumps(base_model))
        snapshot=self.media/"state"/"original-compose"/"00-docker-compose.offline.yml"
        snapshot.write_bytes(self.base.read_bytes()); os.chmod(snapshot,0o600)
        vm.write_json(self.media/"state"/"compose-snapshots.json",{str(self.base):snapshot.name})
        self.previous_pointer='{"release": "old-release", "receipt_sha256": "'+"1"*64+'"}'
        vm.write_json(self.media/"state"/"previous-current.json",self.previous_pointer)
        # stage 也会冻结原始 env 副本与备份摘要；receipt 的绑定集合包含它们
        (self.media/"state"/"original-env").write_bytes((self.workdir/".env").read_bytes())
        os.chmod(self.media/"state"/"original-env",0o600)
        (self.media/"state"/"database.dump").write_bytes(b"fixture dump")
        vm.write_json(self.media/"state"/"backup.json",{"sha256":vm.digest(self.media/"state"/"database.dump"),
                                                         "size":len(b"fixture dump")})
        self.manifest={"schema":1,"purpose":"development-vm","release_id":"dev-rollback-test","revision":"c"*40,
                       "tree":"d"*40,"version":"2.8.0","created_at":"fixed","enable_file_detection":False,
                       "migrations":{},"migration_preconditions":{},"preserve_tier1":False,
                       "services":{s:{"image_id":NEW,"tag":"candidate/"+s+":fixed"} for s in vm.SERVICES}}
        source=self.media/"vm_development_apply.py"
        source.write_bytes(b"sealed original media fixture\n"); source.chmod(0o600)
        self.manifest["apply_script_sha256"]=vm.digest(source)
        (self.media/"manifest.json").write_text(json.dumps(self.manifest))
        self.receipt={"status":"deployed","release_id":"dev-rollback-test","revision":"c"*40,"version":"2.8.0",
                      "services":{s:{"image_id":NEW} for s in vm.SERVICES},"preserved_services":[],"migrations":{},
                      "policy":self.before_policy,"backup":str(self.media/"state"/"database.dump"),
                      "compose_sha256":vm.digest(self.live),"persist_boot":None}
        # receipt 反向绑定 stage 证据：用工具自己的计算函数，夹具不复制实现逻辑
        self.receipt["manifest_sha256"]=vm.digest(self.media/"manifest.json")
        self.receipt["stage_binding"]=vm.stage_binding_digests(self.media/"state")
        (self.media/"receipt.json").write_text(json.dumps(self.receipt))
        self.receipt_sha=vm.digest(self.media/"receipt.json")
        self.pointer=self.root/"development-releases"/"current.json"
        self.pointer.write_text(json.dumps({"release":str(self.media),"receipt_sha256":self.receipt_sha}))
        self.chain=self.workdir/".upgrade"/"compose-files"
        # 与 jjdctl 真实链形一致：offline 基础隐式在最前，清单只含 active-config 条目
        self.chain.write_text("")
        self.rows={}
        for s in self.services:
            self.rows[s]={"Id":s+"-1","Image":NEW if s in vm.SERVICES else OLD,"Name":"/"+s,"RestartCount":0,
                          "State":{"Status":"running","StartedAt":"now","Health":{"Status":"healthy"}},
                          "Config":{"Env":["POSTGRES_DB=jjd","POSTGRES_USER=jjd"] if s=="postgres" else ["JJD_COMMIT="+"c"*40],
                                    "Labels":{"com.docker.compose.service":s}},
                          "HostConfig":{}}
        self.current_ledger=dict(self.before_ledger)
        self.drain_active={}
        self.drain_prepared={}
        self.iptables=[]
        self.ups=[]
        self.stops=[]
        self.starts=[]
        self.psql_inputs=[]
        self.fail_up_for=set()
        # 与生产 media 权限一致：不受测试主机 umask 影响
        os.chmod(self.media,0o700)
        os.chmod(self.media/"manifest.json",0o600)
        os.chmod(self.media/"receipt.json",0o600)
        os.chmod(self.media/"state",0o700)
    def persist_record(self,overlay):
        """与 perform_persist_boot 写下的绑定字段一致的认证 persist 证据。"""
        return {"manifest_sha256":vm.digest(self.media/"manifest.json"),
                "receipt_sha256":self.receipt_sha,
                "before_sha256":vm.digest(self.media/"state"/"before.json"),
                "candidate_sha256":vm.digest(self.media/"state"/"candidate.json"),
                "previous_current_sha256":vm.digest(self.media/"state"/"previous-current.json"),
                "overlay":str(overlay),"overlay_sha256":vm.digest(overlay),
                "chain_sha256":vm.digest(self.chain),
                "previous_chain_sha256":vm.digest(self.media/"state"/"boot-chain.previous")}
    def fake_run(self,argv,input=None,timeout=180,log=None,cwd=None,env=None):
        if argv[:3]==["docker","image","inspect"]:
            name=argv[3]
            image_id=NEW if name==NEW else (OLD if name==OLD else name)
            if image_id not in (OLD,NEW) and not name.startswith("sha256:"): image_id=name
            return json.dumps([{"Id":image_id}])
        if argv[:2]==["docker","ps"] and "-q" in argv: return "\n".join(row["Id"] for row in self.rows.values())
        if argv[:2]==["docker","inspect"]:
            found=[]
            for identifier in argv[2:]:
                for s,row in self.rows.items():
                    if row["Id"]==identifier: found.append(row)
            if len(found)!=len(argv)-2: raise vm.CommandFailure("inspect failed")
            return json.dumps(found)
        if argv[:2]==["docker","exec"] and "psql" in argv:
            self.psql_inputs.append(input)
            tables=dict(getattr(self,"transaction_rows",{}))
            tables["schema_migrations"]=[{"version":version,"checksum":checksum} for version,checksum in self.current_ledger.items()]
            if "to_regclass" in input:
                return json.dumps({name:name in tables for name in ("wallet_ledger","releaseit_post_apply_tx","releaseit_marker","schema_migrations")})
            if "json_agg(to_jsonb(t)" in input:
                rows=next(rows for name,rows in tables.items() if "FROM public."+name+" t" in input)
                return json.dumps([row if isinstance(row,str) else json.dumps(row,sort_keys=True) for row in rows])
            if "pg_stat_activity" in input:
                return json.dumps({"active":json.dumps(self.drain_active),"prepared":json.dumps(self.drain_prepared)})
            if "schema_migrations" in input: return json.dumps(self.current_ledger)
            if "system_settings" in input: return json.dumps(self.before_policy)
            raise AssertionError("unexpected psql: "+repr(input))
        if argv[:1]==["ip"]: return json.dumps([{"dev":"eth0"}])
        if argv==["iptables-save"]:
            return getattr(self,"fence_snapshot","*filter\n:DOCKER-USER - [0:0]\nCOMMIT\n")
        if argv[:1]==["iptables"]:
            self.iptables.append(argv)
            lines=getattr(self,"fence_snapshot","*filter\n:DOCKER-USER - [0:0]\nCOMMIT\n").splitlines()
            op=argv[1]
            if op=="-N": lines.insert(lines.index("COMMIT"),":"+argv[2]+" - [0:0]")
            elif op=="-A":
                tokens=argv[1:]
                if "REJECT" in tokens and "--reject-with" not in tokens: tokens=tokens+["--reject-with","icmp-port-unreachable"]
                lines.insert(lines.index("COMMIT")," ".join(tokens))
            elif op=="-I":
                rule=" ".join(["-A",argv[2],*argv[4:]])
                position=next((i for i,line in enumerate(lines) if line.startswith("-A ")),lines.index("COMMIT"))
                lines.insert(position,rule)
            elif op=="-D": lines.remove(" ".join(["-A",*argv[2:]]))
            elif op=="-F": lines=[line for line in lines if not line.startswith("-A "+argv[2]+" ")]
            elif op=="-X": lines=[line for line in lines if not line.startswith(":"+argv[2]+" ")]
            self.fence_snapshot="\n".join(lines)+"\n"
            return ""
        if argv[0]==str(self.compose_bin):
            if "config" in argv:
                files=[argv[i+1] for i,v in enumerate(argv) if v=="-f"]
                return json.dumps(merge_models(files))
            if "up" in argv:
                self.ups.append(argv)
                service=argv[-1]
                if service in self.fail_up_for: raise vm.CommandFailure("simulated compose up failure")
                files=[argv[i+1] for i,v in enumerate(argv) if v=="-f"]
                rendered=merge_models(files)["services"][service]
                row=self.rows[service]
                row.update({"Id":service+"-r","Image":rendered["image"],"RestartCount":0})
                row["State"]={"Status":"running","StartedAt":"r","Health":{"Status":"healthy"}}
                row["Config"]["Env"]=["%s=%s"%(k,v) for k,v in rendered.get("environment",{}).items()]
                return ""
            if "stop" in argv or "start" in argv:
                action="stop" if "stop" in argv else "start"
                rest=argv[argv.index(action)+1:]
                names=[a for a in rest if not a.startswith("-") and a!="25"]
                for name in names:
                    row=self.rows.get(name)
                    if row is not None:
                        row["State"]["Status"]="exited" if action=="stop" else "running"
                (self.stops if action=="stop" else self.starts).append(argv)
                return ""
            raise AssertionError("unexpected compose: "+repr(argv))
        raise AssertionError("unexpected command: "+repr(argv))
    def rollback(self):
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",self.fake_run):
            vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha)
    def persist(self):
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",self.fake_run):
            final_pin=vm.perform_persist_boot(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha)
            self.apply_receipt_sha=self.receipt_sha
            self.receipt_sha=final_pin
            return final_pin
    def repin(self):
        """改过 stage 证据后重新封一次 receipt（等价于重新 commit 落定那份内容）。
        用于测试「内容本身不被接受」的场景：先让 receipt 认可这份内容，
        再验证后续守卫（标量差量/资源漂移等）按内容拒绝。"""
        receipt=json.loads((self.media/"receipt.json").read_text())
        receipt["stage_binding"]=vm.stage_binding_digests(self.media/"state")
        (self.media/"receipt.json").write_text(json.dumps(receipt))
        self.receipt_sha=vm.digest(self.media/"receipt.json")
        self.pointer.write_text(json.dumps({"release":str(self.media),"receipt_sha256":self.receipt_sha}))

    def install_persist(self):
        """把一次成功的 persist-boot 现场装好：受管链引用持久化 overlay，
        并留下与 receipt 绑定的认证记录。返回 (overlay, chain 前字节)。"""
        self.persist()
        overlay=self.live.parent/(self.media.name+"-persistent.json")
        return overlay,self.chain.read_bytes()

    def test_persist_boot_undoes_every_write_when_a_later_step_fails(self):
        # 逐写失败负例：overlay 写盘成功但链渲染校验失败时，链、overlay、
        # 链前值、认证记录都必须回到原状，不留「链引用无证据」的现场。
        overlay=self.live.parent/(self.media.name+"-persistent.json")
        before_chain=self.chain.read_bytes()
        real_render=vm.render_compose
        with patch.object(vm,"render_compose",lambda *a,**k: (_ for _ in ()).throw(RuntimeError("render exploded"))):
            with self.assertRaisesRegex(RuntimeError,"render exploded"):
                self.persist()
        self.assertEqual(self.chain.read_bytes(),before_chain)
        self.assertFalse(overlay.exists())
        self.assertFalse((self.media/"state"/"boot-chain.previous").exists())
        self.assertFalse((self.media/"state"/"persist-boot.json").exists())

    def test_persist_boot_keeps_no_partial_record_when_record_write_fails(self):
        # 认证记录是最后一步写入；它失败时前面三步必须全部撤销
        overlay=self.live.parent/(self.media.name+"-persistent.json")
        before_chain=self.chain.read_bytes()
        real_write_json=vm.write_json
        def fail_on_record(path,value):
            if str(path).endswith("persist-boot.json"): raise OSError("disk full")
            return real_write_json(path,value)
        with patch.object(vm,"write_json",fail_on_record):
            with self.assertRaises(OSError):
                self.persist()
        self.assertEqual(self.chain.read_bytes(),before_chain)
        self.assertFalse(overlay.exists())
        self.assertFalse((self.media/"state"/"boot-chain.previous").exists())

    def test_rollback_archive_conflict_leaves_pointer_and_chain_untouched(self):
        # 归档冲突是「别人已经归档过同一 release 的 live 证据」。它必须：
        # 拒绝、保留他人归档、且不消耗 rollback pointer（否则这次发布再也回不去）。
        self.install_persist()
        archive_dir=self.root/"development-releases"/"archived-live"
        archive_dir.mkdir(parents=True)
        archive=archive_dir/(self.media.name+"-live.json")
        archive.write_text("{\"prior\": true}\n")
        pointer_before=self.pointer.read_bytes()
        chain_before=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"live evidence archive already exists"):
            self.rollback()
        # 指针、链、他人归档全部原样
        self.assertEqual(self.pointer.read_bytes(),pointer_before)
        self.assertEqual(self.chain.read_bytes(),chain_before)
        self.assertEqual(archive.read_text(),"{\"prior\": true}\n")
        self.assertFalse((self.media/"rollback.json").exists())

    def test_rollback_pointer_survives_a_failure_after_it_is_written(self):
        # 指针已按 stage 证据恢复、之后才失败：失败补偿必须把指针放回本次
        # rollback 之前的值，不能让「恢复到旧指针」被半途消费。
        self.install_persist()
        pointer_before=self.pointer.read_bytes()
        chain_before=self.chain.read_bytes()
        self.fail_up_for={"worker"}
        with self.assertRaisesRegex(RuntimeError,"rollback incomplete"):
            self.rollback()
        self.assertEqual(self.pointer.read_bytes(),pointer_before)
        self.assertEqual(self.chain.read_bytes(),chain_before)
        self.assertFalse((self.media/"rollback.json").exists())
        # 指针仍是有效的、可再次驱动 rollback
        self.fail_up_for=set()
        self.rollback()
        self.assertTrue((self.media/"rollback.json").exists())

    def test_rollback_refuses_when_staged_before_evidence_changed_after_commit(self):
        # receipt 反向绑定：before.json 是外部固定摘要的覆盖对象，
        # 事后改动（哪怕同时改 receipt 内的自存 hash）也不构成认证。
        before_path=self.media/"state"/"before.json"
        tampered=json.loads(before_path.read_text())
        tampered["env_sha256"]="1"*64
        before_path.write_text(json.dumps(tampered))
        # receipt 未动（其摘要被调用方在锁外固定），因此 receipt 里的固定摘要
        # 与磁盘现值不符 —— 篡改被发现
        with self.assertRaisesRegex(RuntimeError,"staged evidence changed after commit"):
            self.rollback()
        self.assertEqual(self.iptables,[])

    def test_rollback_refuses_when_candidate_evidence_changed_after_commit(self):
        # candidate 同理：回滚目标必须就是本次发布的候选配置
        candidate_path=self.media/"state"/"candidate.json"
        candidate=json.loads(candidate_path.read_text())
        candidate["services"]["control-plane"]["image"]="sha256:"+"9"*64
        candidate_path.write_text(json.dumps(candidate))
        with self.assertRaisesRegex(RuntimeError,"staged evidence changed after commit"):
            self.rollback()
        self.assertEqual(self.iptables,[])

    def test_persist_boot_refuses_when_candidate_evidence_changed_after_commit(self):
        candidate_path=self.media/"state"/"candidate.json"
        candidate=json.loads(candidate_path.read_text())
        candidate["services"]["control-plane"]["image"]="sha256:"+"9"*64
        candidate_path.write_text(json.dumps(candidate))
        with self.assertRaisesRegex(RuntimeError,"staged evidence changed after commit"):
            self.persist()
        self.assertEqual(self.chain.read_bytes(),b"")

    def test_record_self_stored_hashes_are_not_authentication(self):
        # persist 认证记录里的 before/candidate 摘要可以一起被改；真正的
        # 认证来自 receipt 的反向绑定（其摘要由调用方在锁外固定）。
        self.install_persist()
        forged=self.persist_record(self.live.parent/(self.media.name+"-persistent.json"))
        forged["before_sha256"]="0"*64
        forged["candidate_sha256"]="0"*64
        vm.write_json(self.media/"state"/"persist-boot.json",forged)
        # 只改 record 里的自存 hash：它与磁盘上的 before/candidate 实值不符，
        # 立即被拒 —— record 不是认证来源，真正的锚点是 receipt 的反向绑定
        # （其摘要由调用方在锁外固定）。
        with self.assertRaisesRegex(RuntimeError,
                "persist evidence is not bound to the staged before evidence"
                "|persisted overlay evidence changed"
                "|authenticated persist evidence changed"):
            self.rollback()
        self.assertEqual(self.iptables,[])

    def test_rollback_refuses_receipt_without_stage_binding(self):
        # 旧格式 receipt（无 stage_binding）不构成认证：不得因为
        # 「record 内自存 hash」而放行
        receipt=json.loads((self.media/"receipt.json").read_text())
        receipt.pop("stage_binding")
        (self.media/"receipt.json").write_text(json.dumps(receipt))
        self.receipt_sha=vm.digest(self.media/"receipt.json")
        self.pointer.write_text(json.dumps({"release":str(self.media),"receipt_sha256":self.receipt_sha}))
        with self.assertRaisesRegex(RuntimeError,"receipt lacks stage binding"):
            self.rollback()
        self.assertEqual(self.iptables,[])

    def test_rollback_refuses_when_pointer_file_absent(self):
        # 指针缺失必须给可读的 RuntimeError，而不是裸 FileNotFoundError
        self.pointer.unlink()
        with self.assertRaisesRegex(RuntimeError,"no active recorded development release"):
            self.rollback()
        self.assertEqual(self.iptables,[])

    def test_rollback_restores_original_images_pointer_and_never_touches_database(self):
        self.rollback()
        self.assertEqual(len(self.ups),len(vm.SERVICES))
        for argv in self.ups:
            self.assertIn("-f",argv)
            self.assertIn(str(self.base),argv)
        for s in vm.SERVICES: self.assertEqual(self.rows[s]["Image"],OLD)
        self.assertEqual(self.pointer.read_text(),self.previous_pointer)
        # live 证据归档保留：原文件不删除，受保护归档副本 digest 与 pinned receipt 一致
        self.assertTrue(self.live.exists())
        archive=self.root/"development-releases"/"archived-live"/"dev-rollback-test-live.json"
        self.assertTrue(archive.is_file())
        self.assertEqual(vm.digest(archive),self.receipt["compose_sha256"])
        rolled=json.loads((self.media/"rollback.json").read_text())
        self.assertEqual(rolled["status"],"rolled_back")
        self.assertTrue(rolled["pointer_restored"])
        self.assertFalse(rolled["boot_chain_restored"])
        self.assertEqual(rolled["live_evidence"]["archived"],str(archive))
        self.assertEqual(rolled["live_evidence"]["archived_sha256"],vm.digest(archive))
        self.assertEqual(rolled["writers_drained"],
                         [s for s in vm.WRITERS if s in self.rows])
        for statement in self.psql_inputs:
            self.assertIn("SELECT",statement)
        joined=" ".join(self.psql_inputs)
        self.assertNotIn("pg_restore",joined)
        self.assertNotIn("UPDATE",joined)
        self.assertTrue(any(a[:1]==["iptables"] and "-X" in a for a in self.iptables))
    def test_rollback_refuses_legacy_media_without_previous_pointer(self):
        (self.media/"state"/"previous-current.json").unlink()
        with self.assertRaisesRegex(RuntimeError,"previous pointer|stage evidence missing for receipt binding"):
            self.rollback()
        self.assertEqual(self.ups,[])
        self.assertNotIn("pg_restore",self.psql_inputs)
    def test_rollback_refuses_ledger_regression(self):
        self.current_ledger={}
        with self.assertRaisesRegex(RuntimeError,"migration ledger changed"):
            self.rollback()
        self.assertEqual(self.ups,[])
    def test_rollback_refuses_when_pointer_points_elsewhere(self):
        self.pointer.write_text(json.dumps({"release":"other","receipt_sha256":self.receipt_sha}))
        with self.assertRaisesRegex(RuntimeError,"only the active recorded"):
            self.rollback()
        self.assertEqual(self.ups,[])
    def test_rollback_fail_closes_when_boot_chain_references_release_without_persist_evidence(self):
        self.chain.write_text(str(self.live.parent/"dev-rollback-test-persistent.json")+"\n")
        with self.assertRaisesRegex(RuntimeError,"authenticated persist evidence"):
            self.rollback()
        self.assertEqual(self.ups,[])
    def test_rollback_restores_authenticated_persist_backup(self):
        overlay,_=self.install_persist()
        self.rollback()
        self.assertEqual(self.chain.read_text(),"")
        rolled=json.loads((self.media/"rollback.json").read_text())
        self.assertTrue(rolled["boot_chain_restored"])
    def test_failed_rollback_keeps_ingress_fenced_and_writes_failure_evidence(self):
        self.fail_up_for={"gateway-core"}
        with self.assertRaisesRegex(RuntimeError,"rollback incomplete"):
            self.rollback()
        failure=json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["ingress"],"fenced")
        self.assertFalse(any(a[:1]==["iptables"] and "-D" in a for a in self.iptables))
        self.assertTrue(self.live.exists())
    def test_persist_boot_registers_authenticated_overlay_and_verifies_render(self):
        self.persist()
        overlay=self.live.parent/"dev-rollback-test-persistent.json"
        self.assertTrue(overlay.exists())
        overlay_model=json.loads(overlay.read_text())
        self.assertEqual(overlay_model["services"]["control-plane"]["image"],NEW)
        self.assertEqual(overlay_model["services"]["control-plane"]["environment"]["JJD_COMMIT"],"c"*40)
        self.assertEqual(self.chain.read_text(),str(overlay)+"\n")
        record=json.loads((self.media/"state"/"persist-boot.json").read_text())
        self.assertEqual(record["chain_sha256"],vm.digest(self.chain))
        self.assertEqual(record["overlay_sha256"],vm.digest(overlay))
        self.assertEqual(record["previous_chain_sha256"],vm.digest(self.media/"state"/"boot-chain.previous"))
        # persist 证据与 manifest/receipt/stage 证据摘要绑定，不能独立自证
        self.assertEqual(record["manifest_sha256"],vm.digest(self.media/"manifest.json"))
        self.assertEqual(record["receipt_sha256"],self.apply_receipt_sha)
        self.assertNotEqual(self.receipt_sha,self.apply_receipt_sha)
        self.assertEqual(vm.digest(self.media/"receipt.json"),self.receipt_sha)
        self.assertEqual(record["before_sha256"],vm.digest(self.media/"state"/"before.json"))
        self.assertEqual(record["candidate_sha256"],vm.digest(self.media/"state"/"candidate.json"))
    def test_persist_boot_rejects_resource_drift_and_leaves_chain_untouched(self):
        drifted=copy.deepcopy(self.candidate)
        drifted["services"]["control-plane"]["volumes"]=[{"type":"volume","source":"x","target":"/x"}]
        (self.media/"state"/"candidate.json").write_text(json.dumps(drifted))
        self.repin()  # 让 receipt 认可这份候选，才能测到内容守卫本身
        original_chain=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"boot/live differs outside permitted target scalars"):
            self.persist()
        self.assertEqual(self.chain.read_bytes(),original_chain)
        self.assertFalse((self.live.parent/"dev-rollback-test-persistent.json").exists())
    def test_persist_boot_rejects_environment_key_removal(self):
        drifted=copy.deepcopy(self.candidate)
        del drifted["services"]["control-plane"]["environment"]["SECURITY_AUDIT_ONLY"]
        (self.media/"state"/"candidate.json").write_text(json.dumps(drifted))
        self.repin()
        original_chain=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"environment key removal"):
            self.persist()
        self.assertEqual(self.chain.read_bytes(),original_chain)
    def test_rollback_refuses_tampered_persist_record_digests(self):
        overlay,_=self.install_persist()
        record=json.loads((self.media/"state"/"persist-boot.json").read_text())
        record["chain_sha256"]="0"*64
        vm.write_json(self.media/"state"/"persist-boot.json",record)
        chain_bytes=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"authenticated persist evidence changed"):
            self.rollback()
        self.assertEqual(self.ups,[])
        self.assertEqual(self.stops,[])
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.chain.read_bytes(),chain_bytes)
    def test_rollback_refuses_persist_record_not_bound_to_manifest_receipt_or_stage(self):
        overlay,_=self.install_persist()
        chain_bytes=self.chain.read_bytes()
        for field,message in (("manifest_sha256","not bound to this release manifest"),
                              ("receipt_sha256","not bound to this release manifest"),
                              ("before_sha256","not bound to the staged before evidence")):
            record=self.persist_record(overlay)
            record[field]="0"*64
            vm.write_json(self.media/"state"/"persist-boot.json",record)
            with self.assertRaisesRegex(RuntimeError,"authenticated persist evidence changed: record"):
                self.rollback()
            self.assertEqual(self.ups,[])
            self.assertEqual(self.iptables,[])
        self.assertEqual(self.chain.read_bytes(),chain_bytes)
    def test_rollback_refuses_compose_drift_before_any_mutation_when_snapshot_missing(self):
        # 快照与原文件不符：漂移无法对照 staged 值，直接拒绝
        self.base.write_text(json.dumps(json.loads(self.base.read_text()),indent=2)+"\n")
        snapshot=self.media/"state"/"original-compose"/"00-docker-compose.offline.yml"
        snapshot.write_text("{}\n")
        # 快照本身也在 receipt 的反向绑定范围内，绑定守卫先命中
        with self.assertRaisesRegex(RuntimeError,"staged evidence changed after commit"):
            self.rollback()
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.stops,[])
        self.assertEqual(self.ups,[])

    def test_rollback_refuses_to_overwrite_third_party_drift_even_with_matching_snapshot(self):
        # 关键回归：staged 快照与原文件一致，但有人在发布期间改了它。快照存在
        # 不得成为覆盖该改动的授权 —— 快照只证明「stage 时它是什么」。
        drifted=self.base.read_bytes()+b"\n# third-party edit\n"
        self.base.write_bytes(drifted)
        with self.assertRaisesRegex(RuntimeError,"matches a staged snapshot but overwriting someone else"):
            self.rollback()
        # 拒绝发生在任何变更之前，且他人改动原样保留
        self.assertEqual(self.base.read_bytes(),drifted)
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.stops,[])
        self.assertEqual(self.ups,[])

    def test_rollback_refuses_when_release_environment_file_drifted(self):
        env=self.workdir/".env"
        env.write_text("SECURITY_AUDIT_ONLY=true\nINJECTED=1\n")
        with self.assertRaisesRegex(RuntimeError,"release environment file drifted since stage"):
            self.rollback()
        self.assertEqual(env.read_text(),"SECURITY_AUDIT_ONLY=true\nINJECTED=1\n")
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.stops,[])
    def test_failed_rollback_reverses_file_mutations_and_restarts_drained_writers(self):
        overlay,_=self.install_persist()
        chain_bytes=self.chain.read_bytes()
        # 不用漂移触发失败（漂移现在在前置就被拒绝），改为让目标服务重建失败
        self.fail_up_for={"worker"}
        with self.assertRaisesRegex(RuntimeError,"rollback incomplete"):
            self.rollback()
        # 已执行的文件变更被回退：启动链恢复为引用本 release 的原字节
        self.assertEqual(self.chain.read_bytes(),chain_bytes)
        failure=json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["ingress"],"fenced")
        self.assertFalse(any(a[:1]==["iptables"] and "-D" in a for a in self.iptables))
        self.assertFalse((self.media/"rollback.json").exists())
        # 被排空的非目标 writer 被尽力重启
        self.assertEqual(len(self.starts),1)
        for name in ("chat-portal-ui","chat-portal-proxy"):
            self.assertIn(name,self.starts[0])
    def test_rollback_drains_all_writers_and_restarts_only_non_targets(self):
        self.rollback()
        self.assertEqual(len(self.stops),1)
        self.assertIn("stop",self.stops[0])
        for writer in vm.WRITERS:
            if writer in self.rows: self.assertIn(writer,self.stops[0])
        self.assertEqual(len(self.starts),1)
        for name in ("chat-portal-ui","chat-portal-proxy"):
            self.assertIn(name,self.starts[0])
        for service in vm.SERVICES:
            self.assertNotIn(service,self.starts[0])
        # 非目标容器（含 postgres）容器 ID 未变化：排空是 stop/start 而不是重建
        for service in self.rows:
            if service in vm.SERVICES: continue
            self.assertEqual(self.rows[service]["Id"],service+"-1")
    def test_duplicate_rollback_is_refused_before_any_mutation(self):
        vm.write_json(self.media/"rollback.json",{"status":"rolled_back"})
        with self.assertRaisesRegex(RuntimeError,"duplicate rollback refused"):
            self.rollback()
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.stops,[])
        self.assertEqual(self.ups,[])
    def test_rollback_serializes_on_the_release_lock(self):
        import fcntl
        lock_path=self.root/"development-releases"/".release.lock"
        with lock_path.open("a") as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try:
                with self.assertRaisesRegex(RuntimeError,"release lock"):
                    self.rollback()
            finally:
                fcntl.flock(stream,fcntl.LOCK_UN)
        self.assertEqual(self.ups,[])
        self.assertEqual(self.iptables,[])
    def test_rollback_refuses_media_outside_governed_root_or_permissive_members(self):
        outside=self.root/"elsewhere"/"dev-rollback-test"
        shutil.copytree(self.media,outside)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",self.fake_run):
            with self.assertRaisesRegex(RuntimeError,"must live directly under"):
                vm.perform_rollback(outside,vm.digest(outside/"manifest.json"),self.receipt_sha)
        (self.media/"manifest.json").chmod(0o664)
        try:
            with self.assertRaisesRegex(RuntimeError,"group or world writable"):
                self.rollback()
        finally:
            (self.media/"manifest.json").chmod(0o600)
    def test_snapshot_current_pointer_records_and_restores_null(self):
        state=self.media/"state"
        with patch.object(vm,"ROOT",self.root):
            self.assertEqual(vm.snapshot_current_pointer(state),self.pointer.read_text())
            self.pointer.unlink()
            self.assertEqual(vm.snapshot_current_pointer(state),None)
        self.assertEqual(json.loads((state/"previous-current.json").read_text()),None)

    def test_persist_boot_rejects_chain_entry_outside_active_config(self):
        # jjdctl 只接受 active-config/ 下的普通文件条目；把 offline 基础显式
        # 写进清单（旧错误链形）或任何外部路径都必须 fail-closed。
        self.chain.write_text(str(self.base)+"\n")
        original_chain=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"active-config file"):
            self.persist()
        self.assertEqual(self.chain.read_bytes(),original_chain)
        self.assertFalse((self.live.parent/"dev-rollback-test-persistent.json").exists())

    def test_persist_boot_rejects_non_provenance_environment_delta(self):
        drifted=copy.deepcopy(self.candidate)
        drifted["services"]["control-plane"]["environment"]["EVIL_INJECTED_KEY"]="1"
        (self.media/"state"/"candidate.json").write_text(json.dumps(drifted))
        self.repin()
        original_chain=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"environment delta not manifest-approved"):
            self.persist()
        self.assertEqual(self.chain.read_bytes(),original_chain)
        self.assertFalse((self.live.parent/"dev-rollback-test-persistent.json").exists())

    def test_persist_boot_rejects_provenance_key_with_unapproved_value(self):
        # 键在批准集合内但值与 manifest 不符：JJD_COMMIT 必须精确等于 manifest revision
        drifted=copy.deepcopy(self.candidate)
        drifted["services"]["control-plane"]["environment"]["JJD_COMMIT"]="d"*40
        (self.media/"state"/"candidate.json").write_text(json.dumps(drifted))
        self.repin()
        with self.assertRaisesRegex(RuntimeError,"environment delta not manifest-approved"):
            self.persist()
        self.assertFalse((self.live.parent/"dev-rollback-test-persistent.json").exists())

    def test_persist_boot_accepts_manifest_approved_capacity_value(self):
        # manifest 批准的容量键值组合精确通过：semantic_max_windows=8 → 值 "8"
        self.manifest["semantic_max_windows"]=8
        (self.media/"manifest.json").write_text(json.dumps(self.manifest))
        drifted=copy.deepcopy(self.candidate)
        drifted["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_MAX_WINDOWS"]="8"
        (self.media/"state"/"candidate.json").write_text(json.dumps(drifted))
        self.repin()
        self.persist()
        overlay=self.live.parent/"dev-rollback-test-persistent.json"
        self.assertEqual(json.loads(overlay.read_text())["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_MAX_WINDOWS"],"8")

    def test_persist_boot_rejects_unapproved_capacity_value(self):
        self.manifest["semantic_max_windows"]=8
        (self.media/"manifest.json").write_text(json.dumps(self.manifest))
        drifted=copy.deepcopy(self.candidate)
        drifted["services"]["security-engine"]["environment"]["SECURITY_SEMANTIC_MAX_WINDOWS"]="9"
        (self.media/"state"/"candidate.json").write_text(json.dumps(drifted))
        self.repin()
        with self.assertRaisesRegex(RuntimeError,"environment delta not manifest-approved"):
            self.persist()

    def test_persist_boot_requires_caller_pinned_receipt(self):
        # persist-boot 必须由调用者传入最终 receipt 摘要，且与指针/receipt.json 双向一致
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",self.fake_run):
            self.pointer.write_text(json.dumps({"release":str(self.media),"receipt_sha256":"0"*64}))
            with self.assertRaisesRegex(RuntimeError,"receipt hash differs"):
                vm.perform_persist_boot(self.media,vm.digest(self.media/"manifest.json"),"0"*64)
            self.pointer.write_text(json.dumps({"release":str(self.media),"receipt_sha256":self.receipt_sha}))
            with self.assertRaisesRegex(RuntimeError,"only the active recorded"):
                vm.perform_persist_boot(self.media,vm.digest(self.media/"manifest.json"),
                                        vm.digest(self.media/"manifest.json"))

    def test_persist_boot_rejects_missing_previous_pointer_evidence(self):
        (self.media/"state"/"previous-current.json").unlink()
        original_chain=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"previous pointer|stage evidence missing for receipt binding"):
            self.persist()
        self.assertEqual(self.chain.read_bytes(),original_chain)

    def test_rollback_refuses_prepared_transactions_before_any_mutation(self):
        # fence 前只读预检：存在未决 prepared 事务即拒绝，零变更。
        self.drain_prepared={"gid-1":"tx-1"}
        with self.assertRaisesRegex(RuntimeError,"prepared transactions present"):
            self.rollback()
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.stops,[])
        self.assertEqual(self.ups,[])
        self.assertFalse((self.media/"failure.json").exists())

    def test_rollback_refuses_when_drain_cannot_be_confirmed_after_stop(self):
        # stop 后 pg_stat_activity 仍有活动后端：无法确认排空，拒绝并保持 fenced。
        self.drain_active={"4242":{"usename":"jjd","state":"idle in transaction","query":"INSERT ..."}}
        with self.assertRaisesRegex(RuntimeError,"rollback incomplete"):
            self.rollback()
        self.assertEqual(len(self.stops),1)
        self.assertEqual(self.ups,[])
        self.assertFalse(any(a[:1]==["iptables"] and "-D" in a for a in self.iptables))
        failure=json.loads((self.media/"failure.json").read_text())
        self.assertEqual(failure["ingress"],"fenced")
        self.assertIn("drain could not be confirmed",failure["failure_message"])

    def test_full_loop_persist_then_rollback_round_trip(self):
        # 全环正样本：post-apply 现场（candidate live + pinned receipt）→ persist
        # （真实链渲染验收）→ rollback（恢复原链/镜像/指针，live 证据归档）。
        self.persist()
        overlay=self.live.parent/"dev-rollback-test-persistent.json"
        record=json.loads((self.media/"state"/"persist-boot.json").read_text())
        self.assertEqual(record["previous_current_sha256"],vm.digest(self.media/"state"/"previous-current.json"))
        self.assertEqual(self.chain.read_text(),str(overlay)+"\n")
        self.rollback()
        # 回滚后链恢复为 persist 前字节（空清单，offline 基础隐式）
        self.assertEqual(self.chain.read_text(),"")
        for s in vm.SERVICES: self.assertEqual(self.rows[s]["Image"],OLD)
        self.assertEqual(self.pointer.read_text(),self.previous_pointer)
        self.assertTrue(self.live.exists())
        archive=self.root/"development-releases"/"archived-live"/"dev-rollback-test-live.json"
        self.assertEqual(vm.digest(archive),self.receipt["compose_sha256"])
        rolled=json.loads((self.media/"rollback.json").read_text())
        self.assertTrue(rolled["boot_chain_restored"])
        self.assertEqual(rolled["live_evidence"]["archived_sha256"],vm.digest(archive))
        # rollback.json 落盘后重复回滚拒绝
        with self.assertRaisesRegex(RuntimeError,"duplicate rollback refused"):
            self.rollback()

    def test_final_pin_replaces_apply_pin_and_drives_successful_rollback(self):
        apply_pin=self.receipt_sha
        final_pin=self.persist()
        self.assertNotEqual(final_pin,apply_pin)
        receipt=json.loads((self.media/"receipt.json").read_text())
        binding=receipt["persist_boot"]
        self.assertEqual(binding["apply_receipt_sha256"],apply_pin)
        self.assertEqual(binding["record_sha256"],vm.digest(self.media/"state"/"persist-boot.json"))
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",self.fake_run):
            with self.assertRaisesRegex(RuntimeError,"only the active recorded"):
                vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),apply_pin)
        self.assertEqual(self.iptables,[])
        self.rollback()
        self.assertEqual(self.chain.read_bytes(),b"")
        self.assertTrue((self.media/"rollback.json").is_file())

    def test_final_pin_rejects_previous_chain_and_record_rewrite(self):
        self.persist()
        prior=self.media/"state"/"boot-chain.previous"
        vm.atomic_bytes(prior,b"unapproved-chain\n")
        record_path=self.media/"state"/"persist-boot.json"
        record=json.loads(record_path.read_text())
        record["previous_chain_sha256"]=vm.digest(prior)
        vm.write_json(record_path,record)
        with self.assertRaisesRegex(RuntimeError,"authenticated persist evidence changed: record"):
            self.rollback()
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.ups,[])

    def test_final_pin_requires_persist_evidence_even_after_reference_removed(self):
        self.persist()
        self.chain.write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError,"authenticated persist evidence changed: chain"):
            self.rollback()
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.ups,[])

    def test_persist_refuses_foreign_compose_and_env_drift_before_writes(self):
        base_bytes=self.base.read_bytes()
        self.base.write_bytes(base_bytes+b"\n")
        with self.assertRaisesRegex(RuntimeError,"release input drifted since stage"):
            self.persist()
        self.assertEqual(self.base.read_bytes(),base_bytes+b"\n")
        self.assertEqual(self.chain.read_bytes(),b"")
        self.base.write_bytes(base_bytes)
        env=self.workdir/".env"
        env.write_bytes(env.read_bytes()+b"FOREIGN=1\n")
        with self.assertRaisesRegex(RuntimeError,"release environment file drifted since stage"):
            self.persist()
        self.assertFalse((self.media/"state"/"boot-chain.previous").exists())

    def consecutive_before(self):
        historical=self.live.parent/"dev-prior.json"
        shutil.copy2(self.base,historical)
        before=json.loads((self.media/"state/before.json").read_text())
        before["compose_files"]=[str(historical)]
        before["compose_sha256"]={str(historical):vm.digest(historical)}
        (self.media/"state/before.json").write_text(json.dumps(before))
        self.repin()
        return before

    def test_consecutive_environment_uses_install_root_and_round_trips(self):
        before=self.consecutive_before()
        self.assertEqual(vm.staged_env_file(before),self.workdir/".env")
        self.persist()
        self.rollback()
        self.assertTrue((self.media/"rollback.json").is_file())

    def test_legacy_environment_missing_path_uses_install_root(self):
        before=self.consecutive_before()
        before.pop("env_file")
        (self.media/"state/before.json").write_text(json.dumps(before))
        self.repin()
        self.assertEqual(vm.staged_env_file(before),self.workdir/".env")
        self.persist()
        self.rollback()

    def test_explicit_environment_path_cannot_redirect_to_active_config(self):
        before=self.consecutive_before()
        substitute=self.live.parent/".env"
        substitute.write_bytes((self.workdir/".env").read_bytes())
        before["env_file"]=str(substitute)
        (self.media/"state/before.json").write_text(json.dumps(before))
        self.repin()
        for operation in (self.persist,self.rollback):
            with self.assertRaisesRegex(RuntimeError,"environment file path differs"):
                operation()
        self.assertEqual(self.iptables,[])

    def test_consecutive_drift_cannot_be_hidden_by_active_config_environment(self):
        self.consecutive_before()
        substitute=self.live.parent/".env"
        substitute.write_bytes((self.workdir/".env").read_bytes())
        env=self.workdir/".env"
        env.write_bytes(env.read_bytes()+b"FOREIGN=1\n")
        for operation in (self.persist,self.rollback):
            with self.assertRaisesRegex(RuntimeError,"release environment file drifted"):
                operation()
        substitute.unlink()
        substitute.symlink_to(self.media/"state/original-env")
        for operation in (self.persist,self.rollback):
            with self.assertRaisesRegex(RuntimeError,"release environment file drifted"):
                operation()
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.chain.read_bytes(),b"")

    def test_installed_environment_symlink_and_missing_file_are_refused(self):
        before=self.consecutive_before()
        env=self.workdir/".env"
        env.unlink()
        for operation in (self.persist,self.rollback):
            with self.assertRaisesRegex(RuntimeError,"regular non-symlink"):
                operation()
        env.symlink_to(self.media/"state/original-env")
        for operation in (self.persist,self.rollback):
            with self.assertRaisesRegex(RuntimeError,"regular non-symlink"):
                operation()
        self.assertEqual(self.iptables,[])

    def prepare_resume(self):
        source=self.media/"vm_development_apply.py"
        source.write_bytes(b"original sealed media source\n")
        source.chmod(0o600)
        self.original_source_sha=vm.digest(source)
        self.manifest["apply_script_sha256"]=self.original_source_sha
        vm.write_json(self.media/"manifest.json",self.manifest)
        self.receipt["manifest_sha256"]=vm.digest(self.media/"manifest.json")
        vm.write_json(self.media/"receipt.json",self.receipt)
        self.receipt_sha=vm.digest(self.media/"receipt.json")
        vm.write_json(self.pointer,{"release":str(self.media),"receipt_sha256":self.receipt_sha})
        self.persist()
        self.failure=self.media/"failure.json"
        vm.write_json(self.failure,{"status":"rollback_incomplete","release_id":self.media.name,
                                   "failure_type":"TimeoutExpired","failure_message":"old failure","ingress":"fenced"})
        self.failure.chmod(0o600)
        self.chain_name="JJDDEV"+hashlib.sha256(self.media.name.encode()).hexdigest()[:10].upper()
        self.fence_snapshot="*filter\n:DOCKER-USER - [0:0]\n:"+self.chain_name+" - [0:0]\n-A DOCKER-USER -i eth0 -j "+self.chain_name+"\n"
        for port in ("3000","443","8080","8082","3128"):
            self.fence_snapshot+="-A "+self.chain_name+" -p tcp -m conntrack --ctorigdstport "+port+" --ctdir ORIGINAL -j REJECT --reject-with icmp-port-unreachable\n"
        self.fence_snapshot+="COMMIT\n"
        self.attempt=self.root/"development-releases/rollback-attempts/unique-attempt"
        self.old_failure=self.failure.read_bytes()

    def resume(self):
        original_lstat=Path.lstat
        def owned(path):
            info=original_lstat(path)
            if path==self.failure or path==self.attempt.parent or path==self.media/"vm_development_apply.py":
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",self.fake_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                True,self.attempt,self.original_source_sha)

    def test_resume_fenced_success_preserves_old_failure_and_source(self):
        self.prepare_resume()
        source=(self.media/"vm_development_apply.py").read_bytes()
        self.resume()
        self.assertEqual(self.failure.read_bytes(),self.old_failure)
        self.assertEqual((self.media/"vm_development_apply.py").read_bytes(),source)
        self.assertTrue((self.attempt/"completed.json").is_file())
        authentication=json.loads((self.attempt/"authentication.json").read_text())
        self.assertEqual(authentication["original_apply_sha256"],self.original_source_sha)
        self.assertEqual(authentication["execution_sha256"],vm.digest(Path(vm.__file__)))
        self.assertFalse(any(a[1] in ("-N","-A","-I") for a in self.iptables))
        self.assertTrue(any(a[1]=="-D" for a in self.iptables))
        self.assertFalse(any("pg_restore" in q or "DELETE" in q for q in self.psql_inputs))
        self.assertEqual(self.pointer.read_text(),self.previous_pointer)

    def test_resume_fenced_missing_chain_refuses_without_writes(self):
        self.prepare_resume(); self.fence_snapshot="*filter\nCOMMIT\n"
        with self.assertRaisesRegex(RuntimeError,"existing filter fence"): self.resume()
        self.assertEqual(self.iptables,[]); self.assertEqual(self.stops,[])
        self.assertFalse(self.attempt.exists())

    def test_resume_fenced_foreign_rules_and_references_refused(self):
        self.prepare_resume(); original=self.fence_snapshot
        mutations=[original.replace("3000","3001"),original.replace("-i eth0","-i eth1"),
                   original.replace("-A DOCKER-USER","-A DOCKER-USER -j ACCEPT\n-A DOCKER-USER",1),
                   original.replace("COMMIT","-A OUTPUT -j "+self.chain_name+"\nCOMMIT"),
                   original+"*nat\n-A PREROUTING -j "+self.chain_name+"\nCOMMIT\n",
                   original.replace("COMMIT","-A DOCKER-USER -i eth0 -j "+self.chain_name+"\nCOMMIT"),
                   original.replace("--ctdir ORIGINAL","--ctdir REPLY"),
                   original.replace("-p tcp","-s 127.0.0.1 -p tcp",1),
                   original.replace("COMMIT","-A "+self.chain_name+" -j ACCEPT\nCOMMIT"),
                   original.replace("3000","TEMP").replace("443","3000").replace("TEMP","443"),
                   original+"*nat\n:"+self.chain_name+" - [0:0]\nCOMMIT\n"]
        for snapshot in mutations:
            with self.subTest(snapshot=snapshot):
                self.fence_snapshot=snapshot
                with self.assertRaises(RuntimeError): self.resume()
                self.assertFalse(self.attempt.exists()); self.assertEqual(self.iptables,[])

    def test_resume_fenced_unsafe_failure_and_duplicate_attempt_refused(self):
        self.prepare_resume(); self.failure.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,"root-owned"): self.resume()
        self.failure.chmod(0o600)
        self.attempt.mkdir(parents=True)
        self.attempt.parent.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError,"already exists"): self.resume()
        self.assertEqual(self.stops,[]); self.assertEqual(self.iptables,[])

    def test_resume_fenced_failure_preserves_old_evidence_and_fence(self):
        self.prepare_resume(); self.fail_up_for.add("gateway-core")
        before=self.chain.read_bytes(); pointer=self.pointer.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"rollback incomplete"): self.resume()
        self.assertEqual(self.failure.read_bytes(),self.old_failure)
        self.assertTrue((self.attempt/"failure.json").is_file())
        self.assertEqual(self.chain.read_bytes(),before); self.assertEqual(self.pointer.read_bytes(),pointer)
        self.assertFalse(any(a[1]=="-D" for a in self.iptables))

    def test_resume_fenced_tampered_receipt_refused_without_attempt(self):
        self.prepare_resume(); receipt=json.loads((self.media/"receipt.json").read_text())
        receipt["revision"]="wrong"
        vm.write_json(self.media/"receipt.json",receipt)
        with self.assertRaises(RuntimeError): self.resume()
        self.assertFalse(self.attempt.exists()); self.assertEqual(self.stops,[])

    def test_resume_fenced_wrong_original_source_pin_refused(self):
        self.prepare_resume(); self.original_source_sha="0"*64
        with self.assertRaisesRegex(RuntimeError,"external pin"): self.resume()
        self.assertFalse(self.attempt.exists()); self.assertEqual(self.iptables,[])

    def test_resume_fenced_failure_fields_and_symlink_refused(self):
        self.prepare_resume()
        for field,value in (("release_id","foreign"),("ingress","open"),("status","deployed"),("failure_type",None)):
            record=json.loads(self.old_failure); record[field]=value
            vm.write_json(self.failure,record)
            with self.assertRaises(RuntimeError): self.resume()
            self.assertFalse(self.attempt.exists())
        target=self.media/"original-failure"
        target.write_bytes(self.old_failure); self.failure.unlink(); self.failure.symlink_to(target)
        with self.assertRaises(RuntimeError): self.resume()
        self.assertFalse(self.attempt.exists())

    def test_resume_fenced_managed_write_failure_compensates(self):
        self.prepare_resume(); original=vm.atomic_bytes; pointer=self.pointer.read_bytes(); chain=self.chain.read_bytes()
        def injected(path,data):
            original(path,data)
            if Path(path).name==self.media.name+"-live.json": raise OSError("after publish")
        with patch.object(vm,"atomic_bytes",injected):
            with self.assertRaisesRegex(RuntimeError,"rollback incomplete"): self.resume()
        self.assertEqual(self.pointer.read_bytes(),pointer); self.assertEqual(self.chain.read_bytes(),chain)
        self.assertFalse((self.root/"development-releases/archived-live"/(self.media.name+"-live.json")).exists())
        self.assertEqual(self.failure.read_bytes(),self.old_failure)
        self.assertFalse(any(a[1]=="-D" for a in self.iptables))

    def test_resume_fenced_ordinary_rollback_refuses_existing_fence(self):
        self.prepare_resume()
        with self.assertRaisesRegex(RuntimeError,"explicit resume"): self.rollback()
        self.assertEqual(self.stops,[]); self.assertEqual(self.iptables,[])

    def test_full_loop_negative_tampered_overlay_after_persist_is_refused(self):
        self.persist()
        overlay=self.live.parent/"dev-rollback-test-persistent.json"
        overlay.write_text(json.dumps({"services":{}})+"\n")
        chain_bytes=self.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"persisted overlay evidence changed"):
            self.rollback()
        self.assertEqual(self.ups,[])
        self.assertEqual(self.stops,[])
        self.assertEqual(self.iptables,[])
        self.assertEqual(self.chain.read_bytes(),chain_bytes)

    # ── r6：解封失败取证 + finish-only 严格认证 + 审计覆盖 ──────────────────
    # r5 之前的解封三条命令在 try/except 之外：-D 失败时 rollback.json 已落盘
    # 谎报完成，且所有重入都被 duplicate 检查拒绝。r6 把解封纳入受保护范围，
    # 失败按实测残留取证，并留受保护 checkpoint 供 finish 收尾。

    def r6_state_run(self,base_run,argv,input,timeout,log,cwd,env):
        """把 iptables 变更建模到夹具快照上：-D 摘 link、-F 清规则、-X 删链。"""
        if argv==["iptables-save"]:
            return self.r6_snapshot
        if argv[:1]==["iptables"]:
            op=argv[1]
            if op=="-D":
                self.r6_snapshot=self.r6_snapshot.replace(
                    "-A DOCKER-USER -i eth0 -j "+self.chain_name+chr(10),"",1)
                self.r6_linked=False
            elif op=="-F":
                self.r6_snapshot=self.r6_rebuild(rules=False,declare=True)
            elif op=="-X":
                self.r6_snapshot=self.r6_rebuild(rules=False,declare=False)
            return ""
        return base_run(argv,input=input,timeout=timeout,log=log,cwd=cwd,env=env)

    def r6_audited_resume(self,attempt=None):
        """跑一次 resume，但保留真实 run() 的审计记录：只把底层 subprocess 换掉。
        这样 subprocess.jsonl 里的 argv/exit 才是 r6 真实会写出的形状。"""
        self.r6_snapshot=self.fence_snapshot
        self.r6_linked=("-A DOCKER-USER -i eth0 -j "+self.chain_name) in self.fence_snapshot
        chain=self.chain_name
        snapshot_holder={}
        real_run=vm.run

        class Result:
            def __init__(self,out): self.stdout=out; self.stderr=""; self.returncode=0

        def fake_subprocess_run(args,input=None,capture_output=True,text=True,timeout=None,cwd=None,env=None):
            a=list(args)
            if a==["iptables-save"]:
                return Result(snapshot_holder["snap"])
            if a[:1]==["iptables"]:
                if a[1]=="-D":
                    snapshot_holder["snap"]=snapshot_holder["snap"].replace(
                        "-A DOCKER-USER -i eth0 -j "+chain+chr(10),"",1)
                elif a[1]=="-F":
                    self.r6_linked=False
                    snapshot_holder["snap"]=self.r6_rebuild(rules=False,declare=True)
                elif a[1]=="-X":
                    snapshot_holder["snap"]=self.r6_rebuild(rules=False,declare=False)
                return Result("")
            if a[:2]==["docker","ps"] and "-q" in a:
                return Result(chr(10).join(r["Id"] for r in self.rows.values()))
            if a[:2]==["docker","inspect"]:
                found=[]
                for identifier in a[2:]:
                    for _s,row in self.rows.items():
                        if row["Id"]==identifier: found.append(row)
                return Result(json.dumps(found))
            if a[:3]==["docker","image","inspect"]:
                return Result(json.dumps([{"Id":a[3]}]))
            if a[:2]==["docker","exec"] and "psql" in a:
                q=input or ""
                if "to_regclass" in q or "json_agg(to_jsonb(t)" in q: return Result(self.fake_run(a,input))
                if "pg_stat_activity" in q:
                    return Result(json.dumps({"active":json.dumps(self.drain_active),
                                              "prepared":json.dumps(self.drain_prepared)}))
                if "schema_migrations" in q: return Result(json.dumps(self.current_ledger))
                if "system_settings" in q: return Result(json.dumps(self.before_policy))
                raise AssertionError("unexpected psql: "+repr(q))
            if a[:1]==["ip"]: return Result(json.dumps([{"dev":"eth0"}]))
            if a[0]==str(self.compose_bin):
                if "up" in a:
                    self.ups.append(a)
                    service=a[-1]
                    files=[a[i+1] for i,v in enumerate(a) if v=="-f"]
                    rendered=merge_models(files)["services"][service]
                    row=self.rows[service]
                    row.update({"Id":service+"-r","Image":rendered["image"],"RestartCount":0})
                    row["State"]={"Status":"running","StartedAt":"r","Health":{"Status":"healthy"}}
                    row["Config"]["Env"]=["%s=%s"%(k,v) for k,v in rendered.get("environment",{}).items()]
                elif "stop" in a or "start" in a:
                    action="stop" if "stop" in a else "start"
                    rest=a[a.index(action)+1:]
                    for name in [x for x in rest if not x.startswith("-") and x!="25"]:
                        row=self.rows.get(name)
                        if row is not None:
                            row["State"]["Status"]="exited" if action=="stop" else "running"
                    (self.stops if action=="stop" else self.starts).append(a)
                elif "config" in a:
                    files=[a[i+1] for i,v in enumerate(a) if v=="-f"]
                    return Result(json.dumps(merge_models(files)))
                return Result("")
            raise AssertionError("unexpected command: "+repr(a))

        snapshot_holder["snap"]=self.fence_snapshot
        original_lstat=Path.lstat
        target=self.attempt if attempt is None else attempt
        watched=(self.failure,self.attempt.parent,self.media/"vm_development_apply.py",
                 target/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        with patch.object(vm,"ROOT",self.root),patch.object(vm.subprocess,"run",fake_subprocess_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                True,target,self.original_source_sha)
        return snapshot_holder["snap"]

    def r6_resume(self,failing):
        original_lstat=Path.lstat
        checkpoint=self.attempt/"recovery-checkpoint.json"
        # 从夹具当前的 fence 快照初始化内核状态，-D/-F/-X 在其上真实演进。
        self.r6_snapshot=self.fence_snapshot
        self.r6_linked=("-A DOCKER-USER -i eth0 -j "+self.chain_name) in self.fence_snapshot
        watched=(self.failure,self.attempt.parent,self.media/"vm_development_apply.py",checkpoint)
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        base_run=self.fake_run
        # 真实内核语义：-D 摘掉 DOCKER-USER 的 link，-F 清空链内规则，-X 删除链。
        # 夹具必须建模这一步，否则「-D 成功 ⇒ ingress 已开放」根本无法被观测 ——
        # 那正是 r6 要防的谎报场景。
        def evolving_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv==["iptables-save"]:
                return self.r6_snapshot
            if argv[:1]==["iptables"]:
                op=argv[1]
                if op==failing:
                    self.iptables.append(argv)
                    raise vm.CommandFailure("simulated iptables failure")
                self.iptables.append(argv)
                if op=="-D":
                    self.r6_snapshot=self.r6_snapshot.replace(
                        "-A DOCKER-USER -i eth0 -j "+self.chain_name+"\n","",1)
                elif op=="-F":
                    self.r6_snapshot=self.r6_rebuild(rules=False,declare=True)
                elif op=="-X":
                    self.r6_snapshot=self.r6_rebuild(rules=False,declare=False)
                return ""
            return base_run(argv,input=input,timeout=timeout,log=log,cwd=cwd,env=env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",evolving_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                True,self.attempt,self.original_source_sha)

    def r6_rebuild(self,rules,declare):
        unrelated=[line for line in self.fence_snapshot.splitlines() if line.startswith("-A ") and
                   not line.startswith("-A "+self.chain_name+" ") and
                   line!="-A DOCKER-USER -i eth0 -j "+self.chain_name]
        lines=["*filter",":DOCKER-USER - [0:0]"]
        if declare:
            lines.append(":"+self.chain_name+" - [0:0]")
        if self.r6_linked:
            lines.append("-A DOCKER-USER -i eth0 -j "+self.chain_name)
        if rules:
            for port in ("3000","443","8080","8082","3128"):
                lines.append("-A "+self.chain_name+" -p tcp -m conntrack --ctdir ORIGINAL"
                             " --ctorigdstport "+port+" -j REJECT --reject-with icmp-port-unreachable")
        lines.extend(unrelated)
        lines.append("COMMIT")
        return "\n".join(lines)+"\n"

    def r6_checkpoint(self):
        return json.loads((self.attempt/"recovery-checkpoint.json").read_text())

    def r6_restore_fence(self,state):
        self.r6_linked=(state==vm.FENCE_LINKED)
        self.r6_snapshot=self.r6_rebuild(rules=state in (vm.FENCE_LINKED,vm.FENCE_UNLINKED_RULES),
                                         declare=state!=vm.FENCE_CLEARED)
        self.fence_snapshot=self.r6_snapshot

    def r6_pending(self,residual):
        """跑出一次 checkpoint 落盘但未收尾的状态，并把现场复原成指定残留。"""
        self.prepare_resume()
        with self.assertRaises(RuntimeError): self.r6_resume("-D")
        self.r6_restore_fence(residual)
        return vm.digest(self.attempt/"recovery-checkpoint.json")

    def r6_finish(self,checkpoint_sha):
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        base_run=self.fake_run
        def evolving_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv==["iptables-save"]:
                return self.r6_snapshot
            if argv[:1]==["iptables"]:
                op=argv[1]
                self.iptables.append(argv)
                if op=="-D":
                    self.r6_snapshot=self.r6_snapshot.replace(
                        "-A DOCKER-USER -i eth0 -j "+self.chain_name+"\n","",1)
                    self.r6_linked=False
                elif op=="-F":
                    self.r6_snapshot=self.r6_rebuild(rules=False,declare=True)
                elif op=="-X":
                    self.r6_snapshot=self.r6_rebuild(rules=False,declare=False)
                return ""
            return base_run(argv,input=input,timeout=timeout,log=log,cwd=cwd,env=env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",evolving_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                       self.attempt,self.original_source_sha,checkpoint_sha)

    def test_r6_delete_failure_keeps_checkpoint_and_refuses_false_completion(self):
        self.prepare_resume()
        with self.assertRaisesRegex(RuntimeError,"unfence incomplete"): self.r6_resume("-D")
        # 关键回归：r5 在此情形会写 rollback.json 谎报完成，并堵死一切重入。
        self.assertFalse((self.media/"rollback.json").is_file())
        self.assertTrue((self.attempt/"recovery-checkpoint.json").is_file())
        evidence=json.loads((self.attempt/"unfence-failure.json").read_text())
        # -D 未成功 ⇒ 入口确实仍隔离。
        self.assertEqual(evidence["ingress"],"fenced")
        self.assertEqual(evidence["fence_residual"],vm.FENCE_LINKED)
        self.assertEqual(evidence["status"],"cleanup_pending")
        self.assertTrue(evidence["checkpoint_sha256"])
        # 原媒体 failure 与旧 source 不得被覆盖。
        self.assertEqual(self.failure.read_bytes(),self.old_failure)

    def test_r6_flush_failure_after_delete_records_open_not_fenced(self):
        self.prepare_resume()
        with self.assertRaisesRegex(RuntimeError,"unfence incomplete"): self.r6_resume("-F")
        evidence=json.loads((self.attempt/"unfence-failure.json").read_text())
        # -D 已成功 ⇒ ingress 实际已开放；此时写 fenced 才是撒谎。
        self.assertEqual(evidence["ingress"],"open")
        self.assertEqual(evidence["fence_residual"],vm.FENCE_UNLINKED_RULES)
        self.assertEqual(evidence["status"],"cleanup_pending")
        self.assertFalse((self.media/"rollback.json").is_file())

    def test_r6_checkpoint_records_dynamic_facts_not_stage_derivable(self):
        self.prepare_resume()
        # 现场 postgres 的 Id 早已不是 stage 时刻的值：stage receipt 推导不出它。
        self.rows["postgres"]["Id"]="postgres-long-lived"
        # stage 之后新增了迁移 302：完整账本必须被 checkpoint 记录。
        self.current_ledger=dict(self.before_ledger)
        self.current_ledger["302_new"]="2"*64
        with self.assertRaises(RuntimeError): self.r6_resume("-D")
        record=self.r6_checkpoint()
        self.assertEqual(record["status"],"runtime_restored_cleanup_pending")
        self.assertEqual(record["preserved_ids"]["postgres"],"postgres-long-lived")
        self.assertEqual(record["ledger_before"]["302_new"],"2"*64)
        self.assertEqual(record["ledger_after"]["302_new"],"2"*64)
        self.assertEqual(record["interface"],"eth0")
        self.assertEqual(record["iptables_chain"],self.chain_name)
        self.assertEqual(record["execution_sha256"],vm.digest(Path(vm.__file__)))
        self.assertIn("current_bytes_b64",record)
        self.assertTrue(record["env_path"].endswith(".env"))
        self.assertIn(str(self.base),record["compose_identity"])
        self.assertTrue(record["previous_chain_sha256"])
        self.assertTrue(record["unrelated_user_rules_sha256"])
        self.assertTrue(record["foreign_rules_sha256"])

    def test_r6_finish_only_requires_external_checkpoint_pin(self):
        self.prepare_resume()
        with self.assertRaises(RuntimeError): self.r6_resume("-D")
        # 错误格式的 pin 直接拒。
        with self.assertRaisesRegex(RuntimeError,"external recovery checkpoint SHA256"):
            self.r6_finish("not-a-sha")
        # 自存摘要不能当认证：改 checkpoint 内容后旧 pin 立刻失效。
        checkpoint=self.attempt/"recovery-checkpoint.json"
        record=json.loads(checkpoint.read_text())
        record["preserved_ids"]["postgres"]="attacker"
        vm.write_json(checkpoint,record)
        with self.assertRaisesRegex(RuntimeError,"differs from the external pin"):
            self.r6_finish("0"*64)

    def test_r6_finish_only_completes_linked_residue_without_recreate(self):
        pin=self.r6_pending(vm.FENCE_LINKED)
        ups_before=list(self.ups)
        stops_before=list(self.stops)
        iptables_before=len(self.iptables)
        sql_before=len(self.psql_inputs)
        self.r6_finish(pin)
        # 收尾只补齐解封：绝不重建容器、绝不 stop、绝不消费 pointer、绝不写 SQL。
        self.assertEqual(self.ups,ups_before)
        self.assertEqual(self.stops,stops_before)
        # linked 残留：-D 摘 link，再由 readback 驱动 -F / -X；绝不建链。
        issued=[a[1] for a in self.iptables[iptables_before:]]
        self.assertEqual(issued,["-D","-F","-X"])
        self.assertNotIn("-N",issued)
        self.assertNotIn("-I",issued)
        # finish 期间只允许只读 SELECT：核验 policy、完整账本、stage 绑定都不写库。
        added=self.psql_inputs[sql_before:]
        self.assertTrue(added)
        for query in added:
            self.assertTrue(query.lstrip().upper().startswith("SELECT"), query[:80])
            self.assertNotIn("pg_restore",query)
            for write in ("INSERT","UPDATE","DELETE","DROP","ALTER","TRUNCATE","CREATE"):
                self.assertNotIn(write,query.upper())
        self.assertTrue((self.media/"rollback.json").is_file())
        completed=json.loads((self.attempt/"completed.json").read_text())
        self.assertEqual(completed["status"],"rolled_back")
        self.assertEqual(completed["checkpoint_sha256"],pin)

    def test_r6_finish_only_clears_chain_only_when_link_already_gone(self):
        pin=self.r6_pending(vm.FENCE_UNLINKED_RULES)
        ups_before=list(self.ups)
        issued=[]
        base_run=self.fake_run
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv[1])
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                       self.attempt,self.original_source_sha,pin)
        # link 已被摘掉：绝不能重跑 -D，只清链。
        self.assertNotIn("-D",issued)
        self.assertIn("-F",issued)
        self.assertEqual(self.ups,ups_before)
        self.assertTrue((self.attempt/"completed.json").is_file())

    def test_r6_finish_only_accepts_fourth_state_unfence_already_complete(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        # 无链无引用＝解封已完成但记录未写：第四种合法状态，必须能重入收尾。
        issued=[]
        base_run=self.fake_run
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv[1])
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                       self.attempt,self.original_source_sha,pin)
        self.assertTrue((self.attempt/"completed.json").is_file())
        # 解封早已完成：一条 iptables 命令都不该发。
        self.assertEqual(issued,[])

    def test_r6_finish_only_clears_empty_chain_residue(self):
        pin=self.r6_pending(vm.FENCE_UNLINKED_EMPTY)
        issued=[]
        base_run=self.fake_run
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv[1])
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
            vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                       self.attempt,self.original_source_sha,pin)
        # 空链只剩 -X，绝不重跑 -D。
        self.assertNotIn("-D",issued)
        self.assertIn("-X",issued)
        self.assertTrue((self.attempt/"completed.json").is_file())

    def test_r6_finish_only_refuses_unknown_residue_without_blind_cleanup(self):
        pin=self.r6_pending(vm.FENCE_LINKED)
        iptables_before=len(self.iptables)
        issued=[]
        base_run=self.fake_run
        def no_readback(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv)
            if argv==["iptables-save"]: raise vm.CommandFailure("iptables-save unavailable")
            return base_run(argv,input=input,timeout=timeout,log=log,cwd=cwd,env=env)
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",no_readback),patch.object(Path,"lstat",owned):
            with self.assertRaisesRegex(RuntimeError,"cleanup pending"):
                vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                           self.attempt,self.original_source_sha,pin)
        # 读回失败＝不可推断：零盲清，一条 iptables 命令都不能发。
        self.assertEqual(issued,[])
        self.assertEqual(len(self.iptables),iptables_before)
        evidence=json.loads((self.attempt/"finish-failure.json").read_text())
        self.assertEqual(evidence["fence_residual"],vm.FENCE_UNKNOWN)
        # readback 失败写 unknown，不写「仍隔离」——不可推断不等于仍隔离。
        self.assertEqual(evidence["ingress"],"unknown")
        self.assertEqual(evidence["status"],"cleanup_pending")
    def test_r6_probe_fence_residual_classifies_four_states_and_refuses_foreign(self):
        chain="JJDDEFTEST"
        iface="eth0"
        ports=("3000","443","8080","8082","3128")
        rules="".join("-A "+chain+" -p tcp -m conntrack --ctdir ORIGINAL --ctorigdstport "+p
                      +" -j REJECT --reject-with icmp-port-unreachable\n" for p in ports)
        link="-A DOCKER-USER -i "+iface+" -j "+chain+"\n"
        declare=":"+chain+" - [0:0]\n"
        def snap(body): return "*filter\n:DOCKER-USER - [0:0]\n"+body+"COMMIT\n"
        self.assertEqual(vm.probe_fence_residual(snap(declare+link+rules),chain,iface),vm.FENCE_LINKED)
        self.assertEqual(vm.probe_fence_residual(snap(declare+rules),chain,iface),vm.FENCE_UNLINKED_RULES)
        self.assertEqual(vm.probe_fence_residual(snap(declare),chain,iface),vm.FENCE_UNLINKED_EMPTY)
        self.assertEqual(vm.probe_fence_residual(snap(""),chain,iface),vm.FENCE_CLEARED)
        # foreign 引用：盲目清链会误删他人规则，必须 unknown。
        self.assertEqual(vm.probe_fence_residual(snap(declare+link+rules+"-A OUTPUT -j "+chain+"\n"),chain,iface),
                         vm.FENCE_UNKNOWN)
        # nat 表里的 foreign 引用同样是 unknown。
        self.assertEqual(vm.probe_fence_residual(
            "*filter\n"+declare+link+rules+"COMMIT\n*nat\n-A PREROUTING -j "+chain+"\nCOMMIT\n",chain,iface),
            vm.FENCE_UNKNOWN)
        # link 不在首位：跳转关系无法确认，unknown。
        self.assertEqual(vm.probe_fence_residual(snap(declare+"-A DOCKER-USER -j RETURN\n"+link+rules),chain,iface),
                         vm.FENCE_UNKNOWN)
        # interface 不符：unknown。
        self.assertEqual(vm.probe_fence_residual(snap(declare+link.replace(iface,"ens3")+rules),chain,iface),
                         vm.FENCE_UNKNOWN)
        # 原规则被篡改：unknown。
        self.assertEqual(vm.probe_fence_residual(snap(declare+link+rules.replace("3000","3001")),chain,iface),
                         vm.FENCE_UNKNOWN)
        # 少一条规则：unknown。
        self.assertEqual(vm.probe_fence_residual(snap(declare+link+"".join(rules.splitlines(True)[:4])),chain,iface),
                         vm.FENCE_UNKNOWN)
        # 链 policy 非 '-'：unknown。
        self.assertEqual(vm.probe_fence_residual(snap(declare.replace(" - [0:0]"," DROP [0:0]")+link+rules),chain,iface),
                         vm.FENCE_UNKNOWN)
        self.assertEqual(vm.probe_fence_residual(None,chain,iface),vm.FENCE_UNKNOWN)

    def test_r6_finish_only_refuses_changed_preserved_identity(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        self.rows["postgres"]["Id"]="postgres-recreated-since"
        with self.assertRaisesRegex(RuntimeError,"preserved container identity changed"):
            self.r6_finish(pin)
        self.assertFalse((self.attempt/"completed.json").is_file())

    def test_r6_finish_only_refuses_ledger_drift(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        self.current_ledger=dict(self.current_ledger)
        self.current_ledger["303_new"]="3"*64
        with self.assertRaisesRegex(RuntimeError,"migration ledger changed"):
            self.r6_finish(pin)
        self.assertFalse((self.attempt/"completed.json").is_file())

    def test_r6_finish_only_refuses_pointer_bytes_not_matching_checkpoint(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        vm.write_json(self.pointer,{"release":str(self.media),"receipt_sha256":"0"*64})
        with self.assertRaisesRegex(RuntimeError,"pointer bytes differ"):
            self.r6_finish(pin)

    def test_r6_finish_only_refuses_compose_identity_drift(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        self.base.write_bytes(self.base.read_bytes()+b"\n")
        with self.assertRaisesRegex(RuntimeError,"compose identity changed"):
            self.r6_finish(pin)

    def test_r6_finish_only_refuses_foreign_execution_image(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        checkpoint=self.attempt/"recovery-checkpoint.json"
        record=json.loads(checkpoint.read_text())
        record["execution_sha256"]="0"*64
        vm.write_json(checkpoint,record)
        forged=vm.digest(checkpoint)
        with self.assertRaisesRegex(RuntimeError,"different execution image"):
            self.r6_finish(forged)

    def test_r6_finish_only_is_idempotent_without_mutating_checkpoint(self):
        pin=self.r6_pending(vm.FENCE_CLEARED)
        checkpoint=self.attempt/"recovery-checkpoint.json"
        before=checkpoint.read_bytes()
        self.r6_finish(pin)
        # 幂等绝不依赖改 immutable checkpoint。
        self.assertEqual(checkpoint.read_bytes(),before)
        self.r6_finish(pin)
        self.assertEqual(checkpoint.read_bytes(),before)
        self.assertTrue((self.attempt/"completed.json").is_file())

    def test_r6_audit_covers_preauth_commands_from_the_first_one(self):
        # 走 r6_audited_resume：保留真实 run() 的审计外壳，只替换底层
        # subprocess.run，这样 subprocess.jsonl 才是 r6 真实写出的形状。
        self.prepare_resume()
        self.r6_audited_resume()
        lines=[json.loads(l) for l in (self.attempt/"subprocess.jsonl").read_text().splitlines() if l.strip()]
        argv0=[r["argv"][0] for r in lines if r["phase"]=="start"]
        self.assertTrue(argv0)
        # 第一条真实命令就被记录：preauth 阶段不再有审计盲区。
        self.assertEqual(argv0[0],"docker")
        self.assertIn("iptables-save",argv0)
        self.assertIn("ip",argv0)
        # 每条 start 都有对应真实 exit。
        self.assertEqual(len([r for r in lines if r["phase"]=="exit"]),
                         len([r for r in lines if r["phase"]=="start"]))
        # preauth 的 ip route（定 interface）确实落在证据里，且在解封之前。
        self.assertLess(argv0.index("ip"),len(argv0)-1)

    def test_r6_audit_collector_does_not_leak_across_invocations(self):
        # 两次独立事务：各自的审计必须自成一份。用两套完全独立的夹具 ——
        # 第一次会把 boot chain / current 恢复掉（真实且正确的行为），同一夹具
        # 上跑第二次会被前置校验 fail-closed，测不到审计本身。
        self.prepare_resume()
        first_attempt=self.attempt
        self.r6_audited_resume()
        first_text=(first_attempt/"subprocess.jsonl").read_text()
        self.assertTrue(first_text.strip())
        first_argv0=[json.loads(l)["argv"][0]
                     for l in first_text.splitlines() if l.strip() and json.loads(l)["phase"]=="start"]
        self.assertEqual(first_argv0[0],"docker")

        self.setUp()
        self.prepare_resume()
        second=self.attempt.parent/"second-attempt"
        self.r6_audited_resume(attempt=second)
        # 第二次用的是自己的 attempt（夹具重建后名字相同），因此改用内容证明
        # 两次审计互不污染：第二次的记录里不得含第一次的注入失败痕迹。
        second_text=(second/"subprocess.jsonl").read_text()
        self.assertTrue(second_text.strip())
        self.assertNotIn("simulated",second_text)
        second_argv0=[json.loads(l)["argv"][0]
                      for l in second_text.splitlines() if l.strip() and json.loads(l)["phase"]=="start"]
        self.assertEqual(second_argv0[0],"docker")
        self.assertIn("iptables-save",second_argv0)

    # ── r7：主审独立复现的 5 个阻断的负测 ─────────────────────────────────
    # 1) unhealthy_target：Id/Image/RestartCount 全不变，仅 Health.Status 转
    #    unhealthy —— 只比身份会放行坏容器通过收尾。
    # 2) persist_record_drift：state/persist-boot.json 仅追加一个 LF 即摘要漂移。
    # 3) foreign_rollback_record：media/rollback.json 预置 status:not_rolled_back /
    #    release_id:foreign 的伪记录，finish 不得解封、不得保留该伪记录。
    # 4) attempt_parent_symlink：rollback-attempts 改名后原路径换回 symlink。
    # 5) 真 run 审计外壳下 -D 成功 / -F 真实 returncode 17：finish-failure 的
    #    ingress 须为 open，且 subprocess.jsonl 必须含全部 cleanup argv/exit。

    def r7_finish_pending(self,residual=vm.FENCE_CLEARED):
        """跑出 checkpoint 落盘但未收尾的状态，并把现场复原成指定残留。"""
        self.prepare_resume()
        with self.assertRaises(RuntimeError): self.r6_resume("-D")
        # 实现的 attempt 目录是 0700；显式对齐，避免把 umask 巧合当成认证通过。
        self.attempt.chmod(0o700)
        self.attempt.parent.chmod(0o700)
        self.r6_restore_fence(residual)
        return vm.digest(self.attempt/"recovery-checkpoint.json")

    def test_r7_unhealthy_target_is_refused_without_any_iptables_command(self):
        pin=self.r7_finish_pending()
        # 身份三元组完全不变，只有健康状态坏掉。
        for service in vm.SERVICES:
            row=self.rows[service]
            row["State"]={"Status":"running","StartedAt":"r","Health":{"Status":"unhealthy"}}
        issued=[]
        base_run=self.fake_run
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv[1])
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
            with self.assertRaisesRegex(RuntimeError,"not healthy"):
                vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                           self.attempt,self.original_source_sha,pin)
        # 认证闸没过：一条 iptables 命令都不能发。
        self.assertEqual(issued,[])
        self.assertFalse((self.attempt/"completed.json").is_file())

    def test_r7_not_running_target_is_refused(self):
        pin=self.r7_finish_pending()
        self.rows[vm.SERVICES[0]]["State"]={"Status":"exited","StartedAt":"r",
                                           "Health":{"Status":"healthy"}}
        with self.assertRaisesRegex(RuntimeError,"not running|not healthy"):
            self.r6_finish(pin)
        self.assertFalse((self.attempt/"completed.json").is_file())

    def test_r7_persist_record_drift_is_refused_without_iptables(self):
        pin=self.r7_finish_pending()
        # 只追加一个字节：内容语义没变，但摘要已漂移。
        record=self.media/"state"/"persist-boot.json"
        record.write_bytes(record.read_bytes()+b"\n")
        issued=[]
        base_run=self.fake_run
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv[1])
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
            with self.assertRaisesRegex(RuntimeError,"persist evidence changed: record"):
                vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                           self.attempt,self.original_source_sha,pin)
        self.assertEqual(issued,[])
        self.assertFalse((self.attempt/"completed.json").is_file())

    def test_r7_foreign_rollback_record_blocks_unfence_and_is_not_kept(self):
        pin=self.r7_finish_pending()
        # 预置一条不属于本次回滚的伪记录。
        vm.write_json(self.media/"rollback.json",{"status":"not_rolled_back","release_id":"foreign"})
        issued=[]
        base_run=self.fake_run
        original_lstat=Path.lstat
        watched=(self.attempt,self.attempt.parent,self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: issued.append(argv[1])
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
            with self.assertRaisesRegex(RuntimeError,"rollback record does not belong"):
                vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                           self.attempt,self.original_source_sha,pin)
        self.assertEqual(issued,[])
        self.assertFalse((self.attempt/"completed.json").is_file())
        # 伪记录必须原样保留，不得被 finish 覆盖或删除。
        record=json.loads((self.media/"rollback.json").read_text())
        self.assertEqual(record["status"],"not_rolled_back")
        self.assertEqual(record["release_id"],"foreign")

    def test_r7_attempt_parent_symlink_is_refused_without_writes(self):
        pin=self.r7_finish_pending()
        parent=self.attempt.parent
        moved=parent.parent/"rollback-attempts-moved"
        parent.rename(moved)
        parent.symlink_to(moved)
        try:
            issued=[]
            base_run=self.fake_run
            original_lstat=Path.lstat
            watched=(self.attempt,self.media/"vm_development_apply.py",
                     self.attempt/"recovery-checkpoint.json")
            def owned(path):
                info=original_lstat(path)
                if path in watched:
                    fields=list(info); fields[4]=0; return os.stat_result(fields)
                return info
            def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
                if argv[:1]==["iptables"]: issued.append(argv[1])
                return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
            with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned):
                with self.assertRaisesRegex(RuntimeError,"path component is not a real directory"):
                    vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                               self.attempt,self.original_source_sha,pin)
            self.assertEqual(issued,[])
            self.assertFalse((self.attempt/"completed.json").is_file())
        finally:
            parent.unlink()
            moved.rename(parent)

    def test_r7_real_run_audit_records_cleanup_argv_when_flush_fails(self):
        # 真 run 审计外壳：-D 成功、-F 真实 returncode 17。
        self.prepare_resume()
        self.r6_snapshot=self.fence_snapshot
        self.r6_linked=("-A DOCKER-USER -i eth0 -j "+self.chain_name) in self.fence_snapshot
        chain=self.chain_name
        holder={}

        class Result:
            def __init__(self,out,code=0):
                self.stdout=out; self.stderr=""; self.returncode=code

        def fake_subprocess_run(args,input=None,capture_output=True,text=True,timeout=None,cwd=None,env=None):
            a=list(args)
            if a==["iptables-save"]:
                return Result(holder["snap"])
            if a[:1]==["iptables"]:
                if a[1]=="-D":
                    holder["snap"]=holder["snap"].replace(
                        "-A DOCKER-USER -i eth0 -j "+chain+chr(10),"",1)
                    return Result("")
                if a[1]=="-F":
                    # 真实非零退出：模拟 iptables 的 EBUSY/资源占用。
                    return Result("",17)
                return Result("")
            if a[:2]==["docker","ps"] and "-q" in a:
                return Result(chr(10).join(r["Id"] for r in self.rows.values()))
            if a[:2]==["docker","inspect"]:
                found=[]
                for identifier in a[2:]:
                    for _s,row in self.rows.items():
                        if row["Id"]==identifier: found.append(row)
                return Result(json.dumps(found))
            if a[:3]==["docker","image","inspect"]:
                return Result(json.dumps([{"Id":a[3]}]))
            if a[:2]==["docker","exec"] and "psql" in a:
                q=input or ""
                if "to_regclass" in q or "json_agg(to_jsonb(t)" in q: return Result(self.fake_run(a,input))
                if "pg_stat_activity" in q:
                    return Result(json.dumps({"active":json.dumps(self.drain_active),
                                              "prepared":json.dumps(self.drain_prepared)}))
                if "schema_migrations" in q: return Result(json.dumps(self.current_ledger))
                if "system_settings" in q: return Result(json.dumps(self.before_policy))
                raise AssertionError("unexpected psql: "+repr(q))
            if a[:1]==["ip"]: return Result(json.dumps([{"dev":"eth0"}]))
            if a[0]==str(self.compose_bin):
                if "up" in a:
                    self.ups.append(a)
                    service=a[-1]
                    files=[a[i+1] for i,v in enumerate(a) if v=="-f"]
                    rendered=merge_models(files)["services"][service]
                    row=self.rows[service]
                    row.update({"Id":service+"-r","Image":rendered["image"],"RestartCount":0})
                    row["State"]={"Status":"running","StartedAt":"r","Health":{"Status":"healthy"}}
                    row["Config"]["Env"]=["%s=%s"%(k,v) for k,v in rendered.get("environment",{}).items()]
                elif "stop" in a or "start" in a:
                    action="stop" if "stop" in a else "start"
                    rest=a[a.index(action)+1:]
                    for name in [x for x in rest if not x.startswith("-") and x!="25"]:
                        row=self.rows.get(name)
                        if row is not None:
                            row["State"]["Status"]="exited" if action=="stop" else "running"
                elif "config" in a:
                    files=[a[i+1] for i,v in enumerate(a) if v=="-f"]
                    return Result(json.dumps(merge_models(files)))
                return Result("")
            raise AssertionError("unexpected command: "+repr(a))

        holder["snap"]=self.fence_snapshot
        original_lstat=Path.lstat
        watched=(self.failure,self.attempt,self.attempt.parent,
                 self.media/"vm_development_apply.py",
                 self.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            fields=list(info)
            if path in watched:
                fields[4]=0
                if path in (self.attempt,self.attempt.parent):
                    fields[2]=0o40700
                return os.stat_result(fields)
            return info
        with patch.object(vm,"ROOT",self.root),patch.object(vm.subprocess,"run",fake_subprocess_run),patch.object(Path,"lstat",owned):
            with self.assertRaises(RuntimeError):
                vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                    True,self.attempt,self.original_source_sha)
        self.attempt.chmod(0o700)
        self.attempt.parent.chmod(0o700)
        pin=vm.digest(self.attempt/"recovery-checkpoint.json")
        # finish 阶段：-D 成功（ingress 转 open），-F 真实 returncode 17。
        with patch.object(vm,"ROOT",self.root),patch.object(vm.subprocess,"run",fake_subprocess_run),patch.object(Path,"lstat",owned):
            with self.assertRaisesRegex(RuntimeError,"cleanup pending"):
                vm.perform_rollback_finish(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                           self.attempt,self.original_source_sha,pin)
        evidence=json.loads((self.attempt/"finish-failure.json").read_text())
        # -D 已成功 ⇒ ingress 已开放。
        self.assertEqual(evidence["ingress"],"open")
        self.assertEqual(evidence["status"],"cleanup_pending")
        # 关键：cleanup 的 argv/exit 必须在 subprocess.jsonl 里，不能是空数组。
        lines=[json.loads(l) for l in (self.attempt/"subprocess.jsonl").read_text().splitlines() if l.strip()]
        cleanup=[r for r in lines if r["phase"]=="exit" and r["argv"][:1]==["iptables"]]
        self.assertTrue(cleanup)
        argv1=[r["argv"][1] for r in cleanup if r["argv"][1]=="-D"]
        self.assertTrue(argv1,"cleanup -D exit missing")
        flushes=[r for r in cleanup if r["argv"][1]=="-F"]
        self.assertTrue(flushes,"cleanup -F exit missing")
        # 真实 returncode 17 必须被记录（不写死出现次数：主路径与 finally 各按
        # collector 真实顺序落盘，可能出现重复条目）。
        self.assertTrue(all(r["returncode"]==17 for r in flushes))
        self.assertIn(17,[r["returncode"] for r in flushes])

    def test_r7_checkpoint_write_failure_compensates_before_commit(self):
        # checkpoint 写失败必须走正常补偿：不能进入不可回退的解封阶段。
        self.prepare_resume()
        self.r6_snapshot=self.fence_snapshot
        self.r6_linked=("-A DOCKER-USER -i eth0 -j "+self.chain_name) in self.fence_snapshot
        original_atomic=vm.atomic_bytes
        def failing_atomic(path,content,mode=0o600):
            if Path(path).name=="recovery-checkpoint.json":
                raise OSError("simulated checkpoint write failure")
            return original_atomic(path,content,mode=mode)
        original_lstat=Path.lstat
        watched=(self.failure,self.attempt.parent,self.media/"vm_development_apply.py")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        base_run=self.fake_run
        def watch_run(argv,input=None,timeout=180,log=None,cwd=None,env=None):
            if argv[:1]==["iptables"]: self.iptables.append(argv)
            return self.r6_state_run(base_run,argv,input,timeout,log,cwd,env)
        with patch.object(vm,"ROOT",self.root),patch.object(vm,"run",watch_run),patch.object(Path,"lstat",owned),patch.object(vm,"atomic_bytes",failing_atomic):
            with self.assertRaises(RuntimeError):
                vm.perform_rollback(self.media,vm.digest(self.media/"manifest.json"),self.receipt_sha,
                                    True,self.attempt,self.original_source_sha)
        self.attempt.chmod(0o700)
        # checkpoint 没写成 ⇒ 绝不能有 -D，解封一步都不能发。
        self.assertFalse(any(a[1] in ("-D","-F","-X") for a in self.iptables))
        self.assertFalse((self.attempt/"recovery-checkpoint.json").exists())
        self.assertFalse((self.media/"rollback.json").exists())
        # 补偿必须把 writer 放回来。
        self.assertTrue(any("start" in a for a in self.starts))


class R8RecoveryTests(unittest.TestCase):
    def setUp(self):
        previous_umask=os.umask(0o077)
        self.addCleanup(os.umask,previous_umask)
        self.case=RollbackTests(methodName="runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def pending(self,state=vm.FENCE_LINKED):
        return self.case.r7_finish_pending(state)

    def finish(self,pin,fail=None):
        case=self.case
        original_lstat=Path.lstat
        watched=(case.attempt,case.attempt.parent,case.media/"vm_development_apply.py",case.attempt/"recovery-checkpoint.json")
        def owned(path):
            info=original_lstat(path)
            if path in watched:
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        def child(args,input=None,capture_output=True,text=True,timeout=None,cwd=None,env=None):
            argv=list(args)
            if argv==["iptables-save"] and fail=="readback":
                return subprocess.CompletedProcess(argv,17,"","injected readback failure")
            if argv[:1]==["iptables"]:
                case.iptables.append(argv)
                if argv[1]==fail: return subprocess.CompletedProcess(argv,17,"","injected failure")
            out=case.r6_state_run(case.fake_run,argv,input,timeout,None,cwd,env)
            return subprocess.CompletedProcess(argv,0,out,"")
        with patch.object(vm,"ROOT",case.root),patch.object(vm.subprocess,"run",child),patch.object(Path,"lstat",owned):
            return vm.perform_rollback_finish(case.media,vm.digest(case.media/"manifest.json"),case.receipt_sha,
                                              case.attempt,case.original_source_sha,pin)

    def test_r8_unrelated_added_rule_refuses_zero_mutations(self):
        pin=self.pending()
        self.case.r6_snapshot=self.case.r6_snapshot.replace("COMMIT","-A DOCKER-USER -j ACCEPT\nCOMMIT")
        count=len(self.case.iptables)
        with self.assertRaisesRegex(RuntimeError,"unrelated firewall"): self.finish(pin)
        self.assertEqual(self.case.iptables[count:],[])
        self.assertFalse((self.case.attempt/"completed.json").exists())

    def test_r8_rule_delete_order_duplicate_first_and_foreign(self):
        snapshot="*filter\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j ACCEPT\n-A DOCKER-USER -j RETURN\nCOMMIT\n"
        identity=vm.unrelated_fence_identity(snapshot,"OWN","eth0")
        variations=(snapshot.replace("-A DOCKER-USER -j ACCEPT\n",""),
                    snapshot.replace("ACCEPT","TEMP").replace("RETURN","ACCEPT").replace("TEMP","RETURN"),
                    snapshot.replace("COMMIT","-A DOCKER-USER -j ACCEPT\nCOMMIT"),
                    snapshot.replace("COMMIT","-A OUTPUT -j ACCEPT\nCOMMIT"))
        for changed in variations: self.assertNotEqual(vm.unrelated_fence_identity(changed,"OWN","eth0"),identity)
        with self.assertRaises(RuntimeError):
            vm.unrelated_fence_identity(snapshot.replace("COMMIT","-A OUTPUT -j OWN\nCOMMIT"),"OWN","eth0")

    def test_r8_four_states_preserve_unrelated_identity(self):
        pin=self.pending()
        checkpoint=self.case.r6_checkpoint()
        for state in (vm.FENCE_LINKED,vm.FENCE_UNLINKED_RULES,vm.FENCE_UNLINKED_EMPTY,vm.FENCE_CLEARED):
            self.case.r6_restore_fence(state)
            self.assertEqual(vm.verify_fence_identity(checkpoint,self.case.attempt,self.case.r6_snapshot),state)
        before=len(self.case.iptables)
        self.assertEqual(self.finish(pin),"completed")
        self.assertEqual(self.case.iptables[before:],[])
        self.assertEqual(self.finish(pin),"already-completed")
        lines=[json.loads(line) for line in (self.case.attempt/"subprocess.jsonl").read_text().splitlines()]
        calls={r["invocation"] for r in lines}
        self.assertEqual(len(calls),2)
        for invocation in calls:
            records=[r for r in lines if r["invocation"]==invocation]
            self.assertEqual(records[0]["argv"][:2],["docker","ps"])
            self.assertEqual(sum(r["phase"]=="start" for r in records),sum(r["phase"]=="exit" for r in records))

    def test_r8_symlink_audit_refuses_victim_unchanged(self):
        pin=self.pending()
        victim=self.case.root/"victim"
        victim.write_bytes(b"keep\n")
        audit=self.case.attempt/"subprocess.jsonl"
        audit.unlink(); audit.symlink_to(victim)
        before=len(self.case.iptables)
        with self.assertRaises((RuntimeError,OSError)): self.finish(pin)
        self.assertEqual(victim.read_bytes(),b"keep\n")
        self.assertEqual(self.case.iptables[before:],[])

    def test_r8_hardlink_audit_refuses_victim_unchanged(self):
        pin=self.pending()
        victim=self.case.root/"victim"
        victim.write_bytes(b"keep\n"); victim.chmod(0o600)
        audit=self.case.attempt/"subprocess.jsonl"
        audit.unlink(); os.link(victim,audit)
        before=len(self.case.iptables)
        with self.assertRaises(RuntimeError): self.finish(pin)
        self.assertEqual(victim.read_bytes(),b"keep\n")
        self.assertEqual(self.case.iptables[before:],[])

    def test_r8_parent_symlink_and_open_time_replacement(self):
        directory=self.case.root/"private"; directory.mkdir(mode=0o700)
        path=directory/"audit"
        vm.safe_append(path,b"original\n")
        moved=directory.with_name("moved")
        original_open=os.open; swapped=[]
        def replacing(name,flags,*args,**kwargs):
            fd=original_open(name,flags,*args,**kwargs)
            if name=="audit" and not swapped:
                directory.rename(moved); directory.symlink_to(moved); swapped.append(True)
            return fd
        with patch.object(vm.os,"open",replacing):
            with self.assertRaises(RuntimeError): vm.safe_append(path,b"BAD")
        self.assertEqual((moved/"audit").read_bytes(),b"original\n")
        with self.assertRaises(OSError): vm.safe_append(path,b"BAD")

    def test_r8_safe_create_append_replace_and_temporary_symlink(self):
        path=self.case.root/"audit"
        vm.safe_append(path,b"first\n"); vm.safe_append(path,b"second\n")
        self.assertEqual(path.read_bytes(),b"first\nsecond\n")
        vm.atomic_bytes(path,b"replacement\n")
        temporary=path.with_name(path.name+".development-new")
        victim=self.case.root/"victim"; victim.write_bytes(b"keep")
        temporary.symlink_to(victim)
        with self.assertRaises((OSError,RuntimeError)): vm.atomic_bytes(path,b"BAD")
        self.assertEqual(victim.read_bytes(),b"keep")
        self.assertEqual(path.read_bytes(),b"replacement\n")

    def test_r8_main_completed_failure_then_finish_real_records(self):
        case=self.case; case.prepare_resume()
        original=vm.write_json
        def failing(path,value):
            if Path(path).name=="completed.json": raise OSError("injected completed failure")
            return original(path,value)
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch.object(vm,"write_json",failing):
            with self.assertRaises(RuntimeError): case.r6_audited_resume()
        pins=[line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256=")]
        self.assertEqual(len(pins),1)
        case.attempt.chmod(0o700); case.attempt.parent.chmod(0o700)
        case.r6_restore_fence(vm.FENCE_CLEARED)
        old_pointer=case.pointer.read_bytes(); old_chain=case.chain.read_bytes(); ups=len(case.ups); iptables=len(case.iptables)
        self.assertEqual(self.finish(pins[0]),"completed")
        self.assertEqual(case.iptables[iptables:],[]); self.assertEqual(len(case.ups),ups)
        self.assertEqual(case.pointer.read_bytes(),old_pointer); self.assertEqual(case.chain.read_bytes(),old_chain)

    def test_r8_payload_dual_pin_and_completed_conflicts(self):
        pin=self.pending(vm.FENCE_CLEARED); self.finish(pin)
        for name,mutate in (("rollback.json",lambda r:r.update(checkpoint_sha256="0"*64)),
                            ("rollback.json",lambda r:r["ledger"].update(extra="bad")),
                            ("completed.json",lambda r:r.update(unexpected=True))):
            path=self.case.media/name if name=="rollback.json" else self.case.attempt/name
            old=path.read_bytes(); record=json.loads(old); mutate(record); vm.write_json(path,record)
            changed=path.read_bytes(); count=len(self.case.iptables)
            with self.assertRaisesRegex(RuntimeError,"conflicting"): self.finish(pin)
            self.assertEqual(path.read_bytes(),changed); self.assertEqual(self.case.iptables[count:],[])
            path.write_bytes(old)

    def test_r8_checkpoint_ledger_current_and_non_target_omission(self):
        pin=self.pending(vm.FENCE_CLEARED); path=self.case.attempt/"recovery-checkpoint.json"; original=path.read_bytes()
        mutations=(lambda r:r["ledger_after"].update(extra="bad"),
                   lambda r:r["ledger_before"].update(extra="bad"),
                   lambda r:r["preserved_ids"].pop("postgres"),
                   lambda r:r.update(current_bytes_b64=vm.base64.b64encode(b"different\n").decode()))
        for mutation in mutations:
            record=json.loads(original); mutation(record); path.write_text(json.dumps(record))
            count=len(self.case.iptables)
            with self.assertRaises(RuntimeError): self.finish(vm.digest(path))
            self.assertEqual(self.case.iptables[count:],[])
            path.write_bytes(original)
        self.assertEqual(self.finish(pin),"completed")

    def test_r8_cleanup_nonzero_records_this_invocation_and_keeps_runtime(self):
        pin=self.pending(); pointer=self.case.pointer.read_bytes(); chain=self.case.chain.read_bytes()
        with self.assertRaisesRegex(RuntimeError,"cleanup pending"): self.finish(pin,"-F")
        lines=[json.loads(line) for line in (self.case.attempt/"subprocess.jsonl").read_text().splitlines()]
        failures=[r for r in lines if r["phase"]=="exit" and r["returncode"]==17]
        self.assertEqual(len(failures),1); self.assertEqual(failures[0]["argv"][1],"-F")
        self.assertEqual(self.case.pointer.read_bytes(),pointer); self.assertEqual(self.case.chain.read_bytes(),chain)
        self.assertEqual(json.loads((self.case.attempt/"finish-failure.json").read_text())["ingress"],"open")

    def test_r8_audit_failure_cannot_report_success_or_undo(self):
        pin=self.pending(vm.FENCE_CLEARED); pointer=self.case.pointer.read_bytes(); chain=self.case.chain.read_bytes()
        with patch.object(vm.AuditCollector,"flush",side_effect=OSError("audit persistence failed")):
            with self.assertRaises(OSError): self.finish(pin)
        self.assertEqual(self.case.pointer.read_bytes(),pointer); self.assertEqual(self.case.chain.read_bytes(),chain)
        self.assertFalse((self.case.attempt/"completed.json").exists())

    def test_r8_rule_drift_variants_reject_without_cleanup(self):
        for kind in ("delete","order","duplicate","foreign"):
            case=RollbackTests(methodName="runTest"); case.setUp(); self.addCleanup(case.doCleanups); self.case=case
            case.prepare_resume()
            case.fence_snapshot=case.fence_snapshot.replace("COMMIT","-A DOCKER-USER -j ACCEPT\n-A DOCKER-USER -j RETURN\nCOMMIT")
            with self.assertRaises(RuntimeError): case.r6_resume("-D")
            case.attempt.chmod(0o700); case.attempt.parent.chmod(0o700)
            pin=vm.digest(case.attempt/"recovery-checkpoint.json")
            snap=case.r6_snapshot
            if kind=="delete": snap=snap.replace("-A DOCKER-USER -j ACCEPT\n","")
            if kind=="order": snap=snap.replace("-j ACCEPT","-j TEMP").replace("-j RETURN","-j ACCEPT").replace("-j TEMP","-j RETURN")
            if kind=="duplicate": snap=snap.replace("COMMIT","-A DOCKER-USER -j ACCEPT\nCOMMIT")
            if kind=="foreign": snap=snap.replace("COMMIT","-A OUTPUT -j "+case.chain_name+"\nCOMMIT")
            case.r6_snapshot=snap; count=len(case.iptables)
            with self.assertRaises(RuntimeError): self.finish(pin)
            self.assertEqual(case.iptables[count:],[])

    def test_r8_each_residual_performs_only_legal_cleanup(self):
        for state,commands in ((vm.FENCE_LINKED,["-D","-F","-X"]),(vm.FENCE_UNLINKED_RULES,["-F","-X"]),
                               (vm.FENCE_UNLINKED_EMPTY,["-X"]),(vm.FENCE_CLEARED,[])):
            case=RollbackTests(methodName="runTest"); case.setUp(); self.addCleanup(case.doCleanups); self.case=case
            pin=self.pending(state); count=len(case.iptables); ups=len(case.ups)
            self.assertEqual(self.finish(pin),"completed")
            self.assertEqual([a[1] for a in case.iptables[count:]],commands)
            self.assertEqual(len(case.ups),ups)

    def test_r8_current_null_string_whitespace_and_stage_byte_binding(self):
        for previous in (None,' { "release" : "old" } \n'):
            case=RollbackTests(methodName="runTest"); case.setUp(); self.addCleanup(case.doCleanups); self.case=case
            vm.write_json(case.media/"state/previous-current.json",previous)
            case.receipt["stage_binding"]=vm.stage_binding_digests(case.media/"state")
            case.prepare_resume()
            with self.assertRaises(RuntimeError): case.r6_resume("-D")
            case.attempt.chmod(0o700); case.attempt.parent.chmod(0o700); case.r6_restore_fence(vm.FENCE_CLEARED)
            path=case.attempt/"recovery-checkpoint.json"; pin=vm.digest(path)
            if previous is not None:
                original=path.read_bytes(); record=json.loads(original)
                altered=previous.encode()+b" \n"; case.pointer.write_bytes(altered)
                record["current_bytes_b64"]=vm.base64.b64encode(altered).decode(); path.write_text(json.dumps(record))
                with self.assertRaisesRegex(RuntimeError,"staged previous"): self.finish(vm.digest(path))
                path.write_bytes(original); case.pointer.write_bytes(previous.encode())
            self.assertEqual(self.finish(pin),"completed")
            self.assertEqual(case.pointer.read_bytes() if case.pointer.exists() else None,None if previous is None else previous.encode())

    def test_r8_checkpoint_write_failure_compensates_and_no_detach(self):
        case=self.case; case.prepare_resume(); pointer=case.pointer.read_bytes(); chain=case.chain.read_bytes()
        original=vm.atomic_bytes
        def failing(path,content,mode=0o600):
            if Path(path).name=="recovery-checkpoint.json": raise OSError("checkpoint failure")
            return original(path,content,mode)
        with patch.object(vm,"atomic_bytes",failing):
            with self.assertRaises(RuntimeError): case.r6_audited_resume()
        self.assertEqual(case.pointer.read_bytes(),pointer); self.assertEqual(case.chain.read_bytes(),chain)
        records=[json.loads(line) for line in (case.attempt/"subprocess.jsonl").read_text().splitlines()]
        self.assertFalse(any(r["argv"][:2] in (["iptables","-D"],["iptables","-F"],["iptables","-X"]) for r in records))
        self.assertFalse((case.attempt/"recovery-checkpoint.json").exists())

    def test_r8_checkpoint_immutable_and_historical_terminal(self):
        pin=self.pending(vm.FENCE_CLEARED); case=self.case; path=case.attempt/"recovery-checkpoint.json"; original=path.read_bytes()
        with self.assertRaises(FileExistsError): vm.atomic_bytes(path,b"overwrite")
        self.assertEqual(path.read_bytes(),original)
        record=json.loads(original)
        for key in ("schema","runtime_identity","preserved_identity","transaction_evidence","preserved_inventory"): record.pop(key)
        record["foreign_rules_sha256"]=hashlib.sha256(b"").hexdigest()
        record["unrelated_user_rules_sha256"]=hashlib.sha256(b"").hexdigest()
        # A historical immutable checkpoint is constructed as a separate authenticated fixture.
        path.write_bytes((json.dumps(record,indent=2)+"\n").encode()); historical_pin=vm.digest(path)
        with patch.object(vm,"ROOT",case.root):
            terminal,done=vm.recovery_terminal_records(record,historical_pin,case.media,case.live,
                case.root/"development-releases/archived-live"/(case.media.name+"-live.json"),case.rows)
        vm.write_json(case.media/"rollback.json",terminal)
        self.assertEqual(self.finish(historical_pin),"completed")
        self.assertEqual(json.loads((case.attempt/"completed.json").read_text()),done)

    def test_r8_final_record_failure_after_detach_does_not_undo(self):
        pin=self.pending(); case=self.case; pointer=case.pointer.read_bytes(); chain=case.chain.read_bytes()
        original=vm.write_json
        def failing(path,value):
            if Path(path).name=="completed.json": raise OSError("terminal failure")
            return original(path,value)
        with patch.object(vm,"write_json",failing):
            with self.assertRaises(OSError): self.finish(pin)
        self.assertEqual(vm.probe_fence_residual(case.r6_snapshot,case.chain_name,"eth0"),vm.FENCE_CLEARED)
        self.assertEqual(case.pointer.read_bytes(),pointer); self.assertEqual(case.chain.read_bytes(),chain)
        self.assertEqual(self.finish(pin),"completed")

    def test_r8_atomic_replace_failure_keeps_victim_and_retry_works(self):
        path=self.case.root/"record"; vm.atomic_bytes(path,b"old")
        with patch.object(vm.os,"replace",side_effect=OSError("replace failed")):
            with self.assertRaises(OSError): vm.atomic_bytes(path,b"new")
        self.assertEqual(path.read_bytes(),b"old")
        vm.atomic_bytes(path,b"new"); self.assertEqual(path.read_bytes(),b"new")
        victim=self.case.root/"victim"; victim.write_bytes(b"KEEP"); victim.chmod(0o600)
        path.unlink(); os.link(victim,path)
        with self.assertRaises(RuntimeError): vm.atomic_bytes(path,b"BAD")
        self.assertEqual(victim.read_bytes(),b"KEEP")

    def test_r8_readback_failure_and_incomplete_snapshot_are_unknown(self):
        self.assertEqual(vm.probe_fence_residual("","OWN","eth0"),vm.FENCE_UNKNOWN)
        pin=self.pending(); count=len(self.case.iptables)
        with self.assertRaises(vm.CommandFailure): self.finish(pin,"readback")
        self.assertEqual(self.case.iptables[count:],[])
        records=[json.loads(line) for line in (self.case.attempt/"subprocess.jsonl").read_text().splitlines()]
        exits=[r for r in records if r["phase"]=="exit" and r["argv"]==["iptables-save"]]
        self.assertEqual(len(exits),1); self.assertEqual(exits[0]["returncode"],17)

    def test_r8_completed_without_rollback_repairs_only_missing_record(self):
        pin=self.pending(vm.FENCE_CLEARED); self.finish(pin)
        (self.case.media/"rollback.json").unlink()
        count=len(self.case.iptables); ups=len(self.case.ups)
        self.assertEqual(self.finish(pin),"completed")
        self.assertEqual(self.case.iptables[count:],[]); self.assertEqual(len(self.case.ups),ups)


class R9RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture=R8RecoveryTests(methodName="runTest"); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups); self.case=self.fixture.case

    def test_r9_private_directory_mode_verified_on_real_fd(self):
        pin=self.fixture.pending(vm.FENCE_CLEARED); case=self.case
        case.attempt.chmod(0o755)
        original_lstat=Path.lstat
        def lie(path):
            info=original_lstat(path)
            if path==case.attempt:
                fields=list(info); fields[0]=0o40700; return os.stat_result(fields)
            return info
        with patch.object(Path,"lstat",lie):
            with self.assertRaisesRegex(RuntimeError,"protected.*directory|directory.*700"):
                self.fixture.finish(pin)
        self.assertFalse((case.attempt/"completed.json").exists())

    def normal_rollback(self,checkpoint_ack=False,finish_pending=False):
        case=self.case
        source=case.media/"vm_development_apply.py"; source.write_bytes(b"sealed original source\n"); source.chmod(0o600)
        case.original_source_sha=vm.digest(source); case.manifest["apply_script_sha256"]=case.original_source_sha
        vm.write_json(case.media/"manifest.json",case.manifest)
        case.receipt["manifest_sha256"]=vm.digest(case.media/"manifest.json")
        vm.write_json(case.media/"receipt.json",case.receipt); case.receipt_sha=vm.digest(case.media/"receipt.json")
        vm.write_json(case.pointer,{"release":str(case.media),"receipt_sha256":case.receipt_sha})
        case.attempt=case.root/"development-releases/rollback-attempts/r9-normal"
        case.chain_name="JJDDEV"+hashlib.sha256(case.media.name.encode()).hexdigest()[:10].upper()
        def child(args,input=None,capture_output=True,text=True,timeout=None,cwd=None,env=None):
            output=case.fake_run(list(args),input,timeout,None,cwd,env)
            return subprocess.CompletedProcess(args,0,output,"")
        original_lstat=Path.lstat
        def owned(path):
            info=original_lstat(path)
            if path in (case.attempt,case.attempt.parent,source,case.attempt/"recovery-checkpoint.json"):
                fields=list(info); fields[4]=0; return os.stat_result(fields)
            return info
        with patch.object(vm,"ROOT",case.root),patch.object(vm.subprocess,"run",child),patch.object(Path,"lstat",owned):
            try:
                return vm.perform_rollback(case.media,vm.digest(case.media/"manifest.json"),case.receipt_sha,
                                           attempt=case.attempt,original_apply_sha=case.original_source_sha,checkpoint_ack=checkpoint_ack,finish_pending=finish_pending)
            finally: case.r6_snapshot=getattr(case,"fence_snapshot","")

    def test_r9_normal_rollback_seals_checkpoint_and_audits_before_detach(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.normal_rollback()
        pins=[line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256=")]
        self.assertEqual(len(pins),1)
        checkpoint=self.case.attempt/"recovery-checkpoint.json"
        self.assertEqual(vm.digest(checkpoint),pins[0])
        records=[json.loads(line) for line in (self.case.attempt/"subprocess.jsonl").read_text().splitlines()]
        self.assertEqual(records[0]["argv"][:2],["docker","ps"])
        self.assertTrue(any(r["phase"]=="exit" and r["argv"][:2]==["iptables","-D"] for r in records))
        self.assertEqual(self.fixture.finish(pins[0]),"already-completed")

    def test_r9_normal_completed_failure_then_finish_unpersisted(self):
        original=vm.write_json
        def fail(path,value):
            if Path(path).name=="completed.json": raise OSError("completed failure")
            return original(path,value)
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch.object(vm,"write_json",fail):
            with self.assertRaises(RuntimeError): self.normal_rollback()
        pin=next(line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256="))
        self.case.r6_snapshot=self.case.fence_snapshot
        before=len(self.case.iptables); ups=len(self.case.ups)
        self.assertEqual(self.fixture.finish(pin),"completed")
        self.assertEqual(self.case.iptables[before:],[]); self.assertEqual(len(self.case.ups),ups)

    def test_r9_normal_checkpoint_failure_has_no_detach(self):
        original=vm.atomic_bytes
        hit=[]
        def fail(path,content,mode=0o600):
            if Path(path).name=="recovery-checkpoint.json":
                hit.append(True); raise OSError("checkpoint failure")
            return original(path,content,mode)
        with patch.object(vm,"atomic_bytes",fail):
            with self.assertRaises(RuntimeError): self.normal_rollback()
        self.assertFalse(any(a[1] in ("-D","-F","-X") for a in self.case.iptables))
        self.assertEqual(hit,[True])

    def test_r9_checkpoint_requires_saved_external_pin_ack_before_detach(self):
        output=io.StringIO()
        with patch.object(vm.select,"select",return_value=([sys.stdin],[],[])),patch.object(vm.sys,"stdin",io.StringIO("ACK_CHECKPOINT=wrong\n")),contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError,"acknowledgement missing"): self.normal_rollback(True)
        pin=next(line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256="))
        self.assertFalse(any(a[1] in ("-D","-F","-X") for a in self.case.iptables))
        self.assertEqual(self.case.pointer.read_bytes(),self.case.previous_pointer.encode())
        self.assertEqual(self.fixture.finish(pin),"completed")

    def test_r9_transactions_are_bound_and_drift_refuses_finish(self):
        self.case.transaction_rows={"wallet_ledger":[{"id":"tx1","amount":25}],"releaseit_post_apply_tx":[{"id":"sentinel","note":"keep"}]}
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.normal_rollback()
        pin=next(line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256="))
        checkpoint=json.loads((self.case.attempt/"recovery-checkpoint.json").read_text())
        self.assertEqual(checkpoint["transaction_evidence"]["wallet_ledger"]["rows"],1)
        self.case.transaction_rows["wallet_ledger"][0]["amount"]=26
        before=len(self.case.iptables)
        with self.assertRaisesRegex(RuntimeError,"transactions changed"): self.fixture.finish(pin)
        self.assertEqual(self.case.iptables[before:],[])

    def test_r9_same_lock_finish_preserves_external_pin_and_separate_audit(self):
        output=io.StringIO(); original=vm.write_json; failures=[]
        def fail_once(path,value):
            if Path(path).name=="completed.json" and not failures:
                failures.append(True); raise OSError("completed failure")
            return original(path,value)
        class HostPin:
            def readline(inner):
                pin=next(line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256="))
                return "FINISH_CHECKPOINT="+pin+"\n"
        with contextlib.redirect_stdout(output),patch.object(vm,"write_json",fail_once),patch.object(vm.sys,"stdin",HostPin()),patch.object(vm.select,"select",return_value=([0],[],[])):
            self.assertEqual(self.normal_rollback(finish_pending=True),"completed")
        self.assertEqual(output.getvalue().count("RELEASE_LOCK_HELD="),1)
        records=[json.loads(line) for line in (self.case.attempt/"subprocess.jsonl").read_text().splitlines()]
        self.assertEqual(len({record["invocation"] for record in records}),2)

    def test_r9_transaction_numeric_precision_is_preserved(self):
        self.case.transaction_rows={"wallet_ledger":['{"id":"tx1","amount":1.0000000000000000001}']}
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.normal_rollback()
        pin=next(line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256="))
        self.case.transaction_rows["wallet_ledger"]=['{"id":"tx1","amount":1.0000000000000000002}']
        with self.assertRaisesRegex(RuntimeError,"transactions changed"): self.fixture.finish(pin)

    def test_r9_volume_inode_drift_refuses_finish(self):
        data=self.case.root/"pg-data"; data.mkdir()
        self.case.rows["postgres"]["Mounts"]=[{"Type":"volume","Name":"pg","Source":str(data),"Destination":"/data"}]
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.normal_rollback()
        pin=next(line.split("=",1)[1] for line in output.getvalue().splitlines() if line.startswith("FINAL_ROLLBACK_CHECKPOINT_SHA256="))
        data.rename(data.with_name("preserved-old-data")); data.mkdir()
        with self.assertRaisesRegex(RuntimeError,"volume inventory changed"): self.fixture.finish(pin)

    def test_r9_authorised_installation_owner_does_not_relax_audit_directory(self):
        directory=self.case.root/"releases"/"owner-layout"; directory.mkdir(mode=0o775); directory.chmod(0o775)
        path=directory/"state"; path.write_bytes(b"KEEP"); path.chmod(0o600)
        token=vm.INSTALL_OWNER.set((os.geteuid(),os.getegid()))
        try:
            with patch.object(vm,"ROOT",self.case.root):
                self.assertEqual(vm.safe_read(path),b"KEEP")
                directory.chmod(0o777)
                with self.assertRaisesRegex(RuntimeError,"unauthorised writable"): vm.safe_read(path)
                directory.chmod(0o775)
                with patch.object(vm.grp,"getgrgid",return_value=type("Group",(),{"gr_mem":["nobody"]})()):
                    with self.assertRaisesRegex(RuntimeError,"write-capable"): vm.safe_read(path)
        finally: vm.INSTALL_OWNER.reset(token)

    def test_r9_mount_output_order_is_nonsemantic_but_duplicates_and_fields_are_bound(self):
        first={"Type":"volume","Name":"pg","Source":"/data/pg","Destination":"/pg","RW":True}
        second={"Type":"bind","Source":"/config","Destination":"/config","RW":False}
        row={"Id":"id","Image":"image","Mounts":[first,second]}
        expected=vm.protected_identity(row)
        self.assertEqual(vm.protected_identity({**row,"Mounts":[second,first]}),expected)
        self.assertNotEqual(vm.protected_identity({**row,"Mounts":[first,second,first]}),expected)
        self.assertNotEqual(vm.protected_identity({**row,"Mounts":[first,{**second,"RW":True}]}),expected)
        pin=self.fixture.pending(vm.FENCE_CLEARED)
        self.case.attempt.chmod(0o755)
        token=vm.INSTALL_OWNER.set((os.geteuid(),os.getegid()))
        try:
            with self.assertRaisesRegex(RuntimeError,"directory.*700"): self.fixture.finish(pin)
        finally: vm.INSTALL_OWNER.reset(token)
