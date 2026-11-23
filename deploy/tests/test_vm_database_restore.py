"""Database rollback owns its actual pg_restore process, not only docker exec."""
import contextlib,json,os,stat,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_vm_identity_chat_release as fixture
vm=fixture.vm

class DatabaseRestoreTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask,os.umask(0o077))
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=Path(self.temp.name);self.backup=self.state/'database.dump'
        self.backup.write_bytes(b'compressed-database-fixture');self.backup.chmod(0o600)
        self.clock=0;self.mode='success';self.alive=True;self.signals=[];self.calls=[];self.events=[]
        self.expected=['pg_restore','--clean','--if-exists','--create','--exit-on-error','-U','app','-d','postgres']
        self.identity_reads=0;self.client=None
        self.context=contextlib.ExitStack();self.addCleanup(self.context.close)
        self.context.enter_context(patch.object(vm,'run',self.fake_run))
        self.context.enter_context(patch.object(vm.subprocess,'Popen',self.popen))
        self.context.enter_context(patch.object(vm.time,'monotonic',lambda:self.clock))
        self.context.enter_context(patch.object(vm.time,'sleep',self.sleep))

    def sleep(self,seconds):self.clock+=seconds
    def popen(self,argv,**kwargs):
        self.argv=argv;self.marker=argv[10];self.client=FakeRestoreClient(self)
        self.assertEqual(argv[:5],['docker','exec','-i','-e',argv[4]])
        self.assertTrue(argv[4].startswith('PGAPPNAME=jjdguard-restore-'))
        self.assertEqual(argv[6:10],['sh','-c',vm.DATABASE_RESTORE_LAUNCHER,'--'])
        self.assertEqual(argv[11:],self.expected)
        self.assertEqual(kwargs['stdin'].read(),self.backup.read_bytes())
        self.assertEqual(stat.S_IMODE(os.stat(kwargs['stderr'].name).st_mode),0o600)
        return self.client
    def fake_run(self,argv,**kwargs):
        self.calls.append(argv)
        if argv[3]=='cat' and argv[-1].startswith('/tmp/jjdguard-restore-'):
            if self.mode=='missing-marker':raise vm.CommandFailure('marker not yet available')
            return '123'
        if argv[3]=='cat' and argv[-1].endswith('/cmdline'):
            if not self.alive:raise vm.CommandFailure('no such process')
            if self.mode=='wrong-command':return 'unrelated\0--private\0'
            return '\0'.join(self.expected)+'\0'
        if argv[3]=='cat' and argv[-1].endswith('/stat'):
            self.identity_reads+=1
            start='999' if self.mode=='reused-pid' and self.identity_reads>1 else '100'
            return '123 (pg_restore) '+ ' '.join(['S']+['0']*18+[start])
        if argv[3]=='sh':
            if self.mode=='unknown-absence':raise vm.CommandFailure('Docker unavailable')
            return 'present' if self.alive else 'absent'
        if argv[3]=='kill':
            sig=argv[4];self.signals.append(sig);self.events.append('container:'+sig)
            if sig=='-KILL' or self.mode!='term-ignored':self.alive=False
            return ''
        raise AssertionError('unexpected fixture command: '+repr(argv))
    def restore(self):return vm.run_database_restore('pg','app',self.backup,self.state,3600,self.events.append)
    def attempt(self):return json.loads(next(self.state.glob('restore-attempt-*.json')).read_text())

    def test_current_customer_dump_uses_at_least_one_hour_restore_budget(self):
        self.assertEqual(vm.Release.database_restore_timeout(288979039),3600)
        self.assertGreaterEqual(vm.Release.database_restore_timeout(100*1024**3),3600)
        self.assertEqual(vm.Release.database_timeout(288979039),300)
    def test_success_waits_for_child_exit_and_writes_private_attempt(self):
        result=self.restore()
        self.assertEqual(result['status'],'database_restored');self.assertEqual(result['exit_code'],0)
        self.assertEqual(self.signals,[])
        self.assertEqual(self.attempt(),result)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode)==0o600 for path in self.state.iterdir()))
    def test_timeout_stops_authenticated_container_child_before_docker_client(self):
        self.mode='timeout'
        with self.assertRaises(subprocess.TimeoutExpired):self.restore()
        self.assertEqual(self.signals,['-TERM']);self.assertFalse(self.alive)
        self.assertLess(self.events.index('container:-TERM'),self.events.index('client:TERM'))
        self.assertIsNone(self.attempt()['cleanup_failure_type'])
    def test_ignored_term_escalates_only_the_same_container_process(self):
        self.mode='term-ignored'
        with self.assertRaises(subprocess.TimeoutExpired):self.restore()
        self.assertEqual(self.signals,['-TERM','-KILL']);self.assertFalse(self.alive)
        self.assertLess(self.events.index('container:-KILL'),self.events.index('client:TERM'))
    def test_reused_pid_is_not_signalled(self):
        self.mode='reused-pid'
        with self.assertRaisesRegex(RuntimeError,'cleanup incomplete'):self.restore()
        self.assertEqual(self.signals,[]);self.assertEqual(self.attempt()['cleanup_failure_type'],'RuntimeError')
    def test_wrong_argv_is_not_signalled(self):
        self.mode='wrong-command'
        with self.assertRaisesRegex(RuntimeError,'cleanup incomplete'):self.restore()
        self.assertEqual(self.signals,[])
    def test_missing_start_marker_never_signals_an_unidentified_process(self):
        self.mode='missing-marker'
        with self.assertRaisesRegex(RuntimeError,'cleanup incomplete'):self.restore()
        self.assertEqual(self.signals,[])
    def test_failed_client_does_not_report_database_restored(self):
        self.mode='failure'
        with self.assertRaisesRegex(RuntimeError,'restore failed'):self.restore()
        self.assertEqual(self.attempt()['status'],'failed')
    def test_failed_docker_command_is_not_interpreted_as_process_absence(self):
        self.mode='unknown-absence';self.alive=False
        with self.assertRaises(vm.CommandFailure):vm.database_restore_process_identity('pg','123',self.expected,'marker')
    def test_launcher_preserves_stdin_and_refuses_an_existing_marker(self):
        # This test deliberately exercises a real shell, not Docker or PostgreSQL.
        self.context.close()
        marker=self.state/'pid'
        argv=['sh','-c',vm.DATABASE_RESTORE_LAUNCHER,'--',str(marker),'sh','-c','cat']
        result=subprocess.run(argv,input=b'archive-bytes',capture_output=True,check=True)
        self.assertEqual(result.stdout,b'archive-bytes');self.assertTrue(marker.read_text().strip().isdigit())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode),0o600)
        result=subprocess.run(argv,input=b'other',capture_output=True)
        self.assertEqual(result.returncode,73);self.assertEqual(result.stdout,b'')

class FakeRestoreClient:
    def __init__(self,rig):self.rig=rig;self.returncode=None
    def poll(self):return self.returncode
    def wait(self,timeout):
        if self.returncode is not None:return self.returncode
        if self.rig.mode in ('success','failure'):
            self.returncode=0 if self.rig.mode=='success' else 1;self.rig.alive=False;return self.returncode
        self.rig.clock+=timeout
        raise subprocess.TimeoutExpired('docker exec fixture',timeout)
    def terminate(self):self.rig.events.append('client:TERM');self.returncode=-15
    def kill(self):self.rig.events.append('client:KILL');self.returncode=-9

class IdentityChatContractWitnessTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.IdentityChatApplyTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
    def test_creator_metadata_transition_does_not_change_target_runtime_semantics(self):
        for service in fixture.TARGETS:
            self.case.rig.rows[service]['Config']['Labels'].update({'com.docker.compose.version':'2.24.6','com.docker.compose.replace':'a'*64})
        release=self.case.stage();release.fence();release.stop_writers();release.backup();release.migrate();release.switch()
        for service in fixture.TARGETS:
            self.case.rig.rows[service]['Config']['Labels'].update({'com.docker.compose.version':'5.3.0','com.docker.compose.replace':service+'-1'})
        release.verify()
    def test_non_target_creator_metadata_is_still_exact(self):
        self.case.rig.rows['proxy-server']['Config']['Labels']['com.docker.compose.version']='2.24.6'
        release=self.case.stage();self.case.rig.rows['proxy-server']['Config']['Labels']['com.docker.compose.version']='5.3.0'
        with self.assertRaisesRegex(RuntimeError,'runtime contract'):release.fence()
        self.assertEqual(self.case.rig.iptables,[])
    def test_stage_records_complete_private_contract_witness_bound_to_before_hashes(self):
        release=self.case.stage();before=json.loads((release.state_dir/'before.json').read_text())
        vm.validate_identity_chat_contract_witness(before)
        witness=before['identity_chat_contract_witness']
        self.assertEqual(len(witness['containers']),len(self.case.rig.rows))
        row=self.case.rig.rows['gateway-core']
        self.assertEqual(witness['containers'][row['Id']]['contract'],vm.identity_chat_runtime_contract(row,True))
        self.assertEqual(stat.S_IMODE((release.state_dir/'before.json').stat().st_mode),0o600)
    def test_changed_witness_cannot_be_used_as_an_unauthenticated_conversion(self):
        release=self.case.stage();path=release.state_dir/'before.json';before=json.loads(path.read_text())
        identifier=before['identity_chat_runtime']['runtime']['gateway-core']['id']
        before['identity_chat_contract_witness']['containers'][identifier]['contract']['host']['Privileged']=True
        vm.write_json(path,before)
        with self.assertRaisesRegex(RuntimeError,'contract witness'):release.fence()
        self.assertEqual(self.case.rig.iptables,[])
    def test_target_security_and_mount_drift_are_not_metadata(self):
        release=self.case.stage();release.fence();release.stop_writers();release.backup();release.migrate();release.switch()
        original=dict(self.case.rig.rows['gateway-core'].get('HostConfig') or {})
        self.case.rig.rows['gateway-core']['HostConfig']['Privileged']=True
        with self.assertRaisesRegex(RuntimeError,'runtime contract'):release.verify()
        self.case.rig.rows['gateway-core']['HostConfig']=original
        self.case.rig.rows['gateway-core']['Mounts']=[{'Type':'volume','Name':'retention','Destination':'/var/lib','RW':False,'Mode':'ro'}]
        with self.assertRaisesRegex(RuntimeError,'runtime contract'):release.verify()

if __name__=='__main__':unittest.main()
