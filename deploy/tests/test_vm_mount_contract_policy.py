"""Only proven-disabled SELinux named-volume labels have an inert encoding."""
import copy,json,os,stat,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_vm_identity_chat_release as fixture
vm=fixture.vm

DISABLED={"schema":1,"selinux":"disabled","daemon_id":"fixture-daemon","docker_security_options":["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"],"kernel_enforce":"absent"}

def volume(mode='z',rw=True):
    return {"Type":"volume","Name":"project_retention","Source":"/var/lib/docker/volumes/project_retention/_data","Destination":"/var/lib/jjdguard/retention","Driver":"local","RW":rw,"Mode":mode,"Propagation":""}

def row(mode='z',rw=True):
    return {"Id":"a"*64,"Config":{"Env":["SECURITY_AUDIT_ONLY=false"],"Labels":{}},"HostConfig":{"Binds":["project_retention:/var/lib/jjdguard/retention:"+mode],"Privileged":False,"ReadonlyRootfs":True,"SecurityOpt":["no-new-privileges:true"],"CapDrop":["ALL"]},"Mounts":[volume(mode,rw)],"NetworkSettings":{"Networks":{}},"Path":"/app/gateway-core","Args":[]}

class MountPolicyObservationTests(unittest.TestCase):
    def test_disabled_requires_both_daemon_and_kernel_evidence(self):
        cases=[(["name=apparmor"],'absent','disabled'),(["name=selinux"],'absent','enabled'),(["name=apparmor"],'0','enabled'),(["name=apparmor"],'1','enabled'),(["name=apparmor"],'unknown','unknown'),(None,'absent','unknown')]
        for options,kernel,want in cases:
            with self.subTest(options=options,kernel=kernel),patch.object(vm,'run',return_value=json.dumps({'ID':'daemon','SecurityOptions':options})),patch.object(vm,'selinux_enforce_state',return_value=kernel):
                policy=vm.read_identity_chat_mount_policy()
                self.assertEqual(policy['selinux'],want)
                self.assertEqual(vm.disabled_selinux_mount_policy(policy),want=='disabled')
        with patch.object(vm,'run',side_effect=vm.CommandFailure('unavailable')):
            self.assertEqual(vm.read_identity_chat_mount_policy()['selinux'],'unknown')
    def test_kernel_absence_is_distinct_from_unreadable_or_symlink(self):
        with patch.object(Path,'lstat',side_effect=FileNotFoundError):self.assertEqual(vm.selinux_enforce_state(),'absent')
        with patch.object(Path,'lstat',side_effect=PermissionError):self.assertEqual(vm.selinux_enforce_state(),'unknown')
        with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFLNK)),patch.object(Path,'read_text') as read:
            self.assertEqual(vm.selinux_enforce_state(),'unknown');read.assert_not_called()
    def test_inconsistent_disabled_claim_is_not_a_policy(self):
        for change in ({'kernel_enforce':'0'},{'docker_security_options':['name=selinux']},{'daemon_id':None},{'schema':True}):
            with self.subTest(change=change):self.assertFalse(vm.disabled_selinux_mount_policy(dict(DISABLED,**change)))

class NamedVolumeContractTests(unittest.TestCase):
    def contract(self,value,policy=DISABLED):return vm.identity_chat_runtime_contract(value,True,policy)
    def test_only_inert_named_label_encodings_canonicalize(self):
        for old,new,rw in [('z','rw',True),('Z','rw',True),('rw,z','rw',True),('ro,z','ro',False),('Z,ro','ro',False)]:
            with self.subTest(old=old,new=new):self.assertEqual(self.contract(row(old,rw)),self.contract(row(new,rw)))
        self.assertNotEqual(self.contract(row('z'),None),self.contract(row('rw'),None))
        self.assertNotEqual(self.contract(row('')),self.contract(row('rw')))
    def test_enabled_unknown_and_bind_mounts_keep_exact_modes(self):
        for state in ('enabled','unknown'):
            policy=dict(DISABLED,selinux=state)
            with self.subTest(state=state):self.assertNotEqual(self.contract(row('z'),policy),self.contract(row('rw'),policy))
        old,new=row('z'),row('rw')
        for value in (old,new):value['Mounts'][0]['Type']='bind';value['HostConfig']['Binds']=['/host:/var/lib/jjdguard/retention:'+value['Mounts'][0]['Mode']]
        self.assertNotEqual(self.contract(old),self.contract(new))
    def test_ro_identity_driver_and_all_host_security_remain_bound(self):
        baseline=row('z')
        changes=[('RW',False),('Name','other'),('Source','/var/lib/docker/volumes/other/_data'),('Destination','/elsewhere'),('Driver','other')]
        for key,value in changes:
            current=row('rw');current['Mounts'][0][key]=value
            with self.subTest(field=key):self.assertNotEqual(self.contract(baseline),self.contract(current))
        for key,value in [('Privileged',True),('ReadonlyRootfs',False),('SecurityOpt',[]),('CapDrop',[])]:
            current=row('rw');current['HostConfig'][key]=value
            with self.subTest(field=key):self.assertNotEqual(self.contract(baseline),self.contract(current))
    def test_unknown_options_and_anonymous_volumes_are_not_normalized(self):
        for old,new in [('z,nocopy','rw,nocopy'),('z,Z','rw'),('z,ro,rw','rw')]:
            with self.subTest(old=old):self.assertNotEqual(self.contract(row(old)),self.contract(row(new)))
        old,new=row('z'),row('rw')
        old['Mounts'][0].pop('Name');new['Mounts'][0].pop('Name')
        self.assertNotEqual(self.contract(old),self.contract(new))
    def test_non_target_named_mounts_are_never_normalized(self):
        self.assertNotEqual(vm.identity_chat_runtime_contract(row('z'),False,DISABLED),vm.identity_chat_runtime_contract(row('rw'),False,DISABLED))

class StageMountPolicyTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.IdentityChatApplyTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
    def install_volume(self,mode='z'):
        value=self.case.rig.rows['gateway-core'];value['Mounts']=[volume(mode)];value['HostConfig']['Binds']=['project_retention:/var/lib/jjdguard/retention:'+mode]
    def test_disabled_named_volume_transition_passes_apply_and_saves_policy(self):
        self.install_volume();release=self.case.stage()
        before=json.loads((release.state_dir/'before.json').read_text())
        self.assertEqual(before['identity_chat_runtime']['mount_policy'],DISABLED)
        vm.validate_identity_chat_contract_witness(before)
        release.fence();release.stop_writers();release.backup();release.migrate();release.switch()
        self.install_volume('rw');release.verify()
    def test_unproven_or_unsafe_label_modes_refuse_stage_before_fencing(self):
        for state,kind,mode in [('enabled','volume','z'),('unknown','volume','z'),('disabled','bind','z'),('disabled','volume','z,nocopy')]:
            self.install_volume(mode);self.case.rig.rows['gateway-core']['Mounts'][0]['Type']=kind
            policy=dict(DISABLED,selinux=state)
            with self.subTest(state=state,kind=kind,mode=mode),patch.object(vm,'read_identity_chat_mount_policy',return_value=policy):
                with self.assertRaisesRegex(RuntimeError,'before fencing'):vm.preflight_identity_chat_mount_modes(self.case.rig.rows,fixture.TARGETS,policy)
            self.assertFalse(self.case.rig.iptables);self.assertFalse(self.case.rig.stops)
    def test_enabled_selinux_legacy_volume_is_rejected_by_real_stage_before_stops(self):
        self.install_volume()
        with patch.object(vm,'read_identity_chat_mount_policy',return_value=dict(DISABLED,selinux='enabled')):
            with self.assertRaisesRegex(RuntimeError,'before fencing'):self.case.stage()
        self.assertFalse(self.case.rig.iptables);self.assertFalse(self.case.rig.stops)
    def test_daemon_policy_change_between_stage_and_fence_is_refused(self):
        self.install_volume();release=self.case.stage()
        with patch.object(vm,'read_identity_chat_mount_policy',return_value=dict(DISABLED,daemon_id='different-daemon')):
            with self.assertRaisesRegex(RuntimeError,'mount policy changed'):release.fence()
        self.assertFalse(self.case.rig.iptables);self.assertFalse(self.case.rig.stops)
    def test_original_inputs_keep_explicit_uid_gid_and_mode(self):
        release=self.case.stage();before=json.loads((release.state_dir/'before.json').read_text())
        for path,value in before['original_input_metadata'].items():
            actual=os.lstat(path)
            self.assertEqual(value,{'uid':actual.st_uid,'gid':actual.st_gid,'mode':stat.S_IMODE(actual.st_mode)})
        vm.validate_original_input_metadata(before)
        path=Path(next(iter(before['compose_sha256'])))
        original=stat.S_IMODE(path.stat().st_mode);path.chmod(original^0o040)
        try:
            with self.assertRaisesRegex(RuntimeError,'ownership or mode'):release.fence()
            self.assertFalse(self.case.rig.iptables);self.assertFalse(self.case.rig.stops)
        finally:path.chmod(original)

if __name__=='__main__':unittest.main()
