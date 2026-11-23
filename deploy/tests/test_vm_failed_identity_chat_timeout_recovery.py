"""Timed-out full rollback recovery never treats partial PostgreSQL state as complete."""
import copy, json, os, subprocess, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_vm_failed_identity_chat_recovery as legacy
recovery=legacy.recovery
vm=legacy.vm
fixture=legacy.fixture
ORIGINAL_RUN_FULL_RESTORE=recovery.run_full_restore

class TimeoutRecoveryTests(unittest.TestCase):
    run_recovery=legacy.FailedIdentityChatRecoveryTests.run_recovery
    assert_fenced=legacy.FailedIdentityChatRecoveryTests.assert_fenced
    def setUp(self):
        legacy.FailedIdentityChatRecoveryTests.setUp(self)
        before=json.loads((self.media/'state/before.json').read_text())
        old=self.case.rig.rows['postgres']['Id'];identifier='a'*64
        self.case.rig.rows['postgres']['Id']=identifier
        before['runtime']['postgres']['id']=identifier
        before['identity_chat_runtime']['runtime']['postgres']['id']=identifier
        entry=before['identity_chat_runtime']['inventory'].pop(old)
        entry['id']=identifier;before['identity_chat_runtime']['inventory'][identifier]=entry
        vm.write_json(self.media/'state/before.json',before)
        self.before=before
        user=dict(v.split('=',1) for v in self.case.rig.rows['postgres']['Config']['Env'] if '=' in v)['POSTGRES_USER']
        self.command=['docker','exec','-i',identifier,'pg_restore','--clean','--if-exists','--create','--exit-on-error','-U',user,'-d','postgres']
        failure=json.loads((self.media/'failure.json').read_text())
        failure.update(failure_message=recovery.RESTORE_FAILURE,restore_failure_type='TimeoutExpired',restore_failure_message=str(subprocess.TimeoutExpired(self.command,299.9999807551503)))
        vm.write_json(self.media/'failure.json',failure);self.failure_pin=vm.digest(self.media/'failure.json')
        self.stage_pin=recovery.stage_digest(self.media)
        self.writers,self.other=vm.release_writer_sets(self.case.m,self.case.rig.rows,vm.IDENTITY_CHAT_SERVICES)
        for name in self.writers:
            self.case.rig.rows[name]['State']['Status']='exited'
            self.case.rig.rows[name]['State']['Running']=False
        self.quiet=patch.object(recovery,'database_quiescent',return_value=(identifier,user,'test')).start()
        self.processes=patch.object(recovery,'no_restore_processes').start()
        self.contracts=patch.object(recovery,'verify_legacy_target_contracts',return_value={'fixture':'strict validation is tested independently'}).start()
        self.restore=patch.object(recovery,'run_full_restore',side_effect=self.fake_restore).start()
    def fake_restore(self,media,home,rows,backup,binding):
        self.case.rig.current_ledger=dict(self.case.rig.before_ledger)
        return {'status':'database_restored','exit_code':0,'backup':backup,'binding':binding,'timeout_seconds':recovery.RESTORE_TIMEOUT}
    def test_precise_timeout_branch_fully_restores_before_originals_and_unfence(self):
        self.assertTrue(recovery.timeout_failure(json.loads((self.media/'failure.json').read_text())))
        protected=[self.media/name for name in ('manifest.json','failure.json','apply.log','vm_development_apply.py','state/database.dump','state/before.json')]
        pins={str(path):vm.digest(path) for path in protected}
        result=self.run_recovery()
        self.assertEqual(result['status'],'restored_failed_apply')
        self.restore.assert_called_once()
        self.assertEqual(pins,{str(path):vm.digest(path) for path in protected})
        self.assertEqual(json.loads((self.home/'database-restore-complete.json').read_text())['exit_code'],0)
        self.assertEqual(result['migrations'],self.case.rig.before_ledger)
    def test_preserved_writer_switch_resume_is_allowed_only_for_exact_recorded_writers(self):
        result=self.run_recovery()
        self.assertEqual(result['status'],'restored_failed_apply')
        self.assertTrue(all(self.case.rig.rows[name]['RestartCount']==0 for name in self.other))
    def test_unknown_timeout_command_user_or_budget_is_not_a_restore_permission(self):
        original=json.loads((self.media/'failure.json').read_text())
        for change in ('command','budget','reason'):
            failure=copy.deepcopy(original)
            if change=='command':failure['restore_failure_message']=str(subprocess.TimeoutExpired(self.command+['--disable-triggers'],300))
            elif change=='budget':failure['restore_failure_message']=str(subprocess.TimeoutExpired(self.command,1800))
            else:failure['failure_message']='unrelated database corruption'
            vm.write_json(self.media/'failure.json',failure);self.failure_pin=vm.digest(self.media/'failure.json')
            with self.subTest(change=change),self.assertRaises(RuntimeError):self.run_recovery()
            self.restore.assert_not_called();self.assert_fenced()
    def test_running_writer_foreign_identity_or_automatic_restart_refuses_before_restore(self):
        for name,field in (('worker','running'),('llm-judge','image'),('worker','restart')):
            old=copy.deepcopy(self.case.rig.rows[name])
            if field=='running':self.case.rig.rows[name]['State']['Status']='running'
            elif field=='image':self.case.rig.rows[name]['Image']='sha256:'+'f'*64
            else:self.case.rig.rows[name]['RestartCount']=2
            with self.subTest(field=field),self.assertRaises(RuntimeError):self.run_recovery()
            self.case.rig.rows[name]=old;self.restore.assert_not_called();self.assert_fenced()
    def test_live_restore_or_database_session_refuses_before_overwrite(self):
        for check in ('no_restore_processes','database_quiescent'):
            with patch.object(recovery,check,side_effect=RuntimeError('not quiescent')),self.assertRaises(RuntimeError):self.run_recovery()
            self.restore.assert_not_called();self.assert_fenced()
    def test_restore_failure_leaves_all_writers_stopped_and_fence_intact(self):
        self.restore.side_effect=subprocess.TimeoutExpired('authenticated pg_restore',3600)
        with self.assertRaises(subprocess.TimeoutExpired):self.run_recovery()
        self.assertTrue(all(self.case.rig.rows[name]['State']['Status']=='exited' for name in self.writers))
        self.assertFalse((self.home/'database-restore-complete.json').exists());self.assert_fenced()
    def test_original_restore_health_or_policy_failure_cannot_unfence(self):
        self.restore.side_effect=lambda *args: {'status':'database_restored','exit_code':0}
        self.case.rig.current_ledger={'partial':'incorrect'}
        with self.assertRaisesRegex(RuntimeError,'ledger|policy'):self.run_recovery()
        self.assertTrue(all(self.case.rig.rows[name]['State']['Status']=='exited' for name in self.writers));self.assert_fenced()
    def test_existing_cleanup_checkpoint_does_not_replay_database(self):
        self.run_recovery();self.restore.reset_mock()
        result=self.run_recovery(vm.digest(self.home/'recovery-checkpoint.json'))
        self.restore.assert_not_called();self.assertEqual(result['status'],'restored_failed_apply')

    def test_full_restore_consumes_protected_dump_and_records_exit_zero_private_stderr(self):
        source=(self.media/'state/database.dump').read_bytes();calls=[]
        class Complete:
            def __init__(self,argv,**kwargs):
                calls.append(argv)
                if kwargs['stdin'].read()!=source:raise AssertionError('protected dump was not connected to child stdin')
                kwargs['stderr'].write(b'private diagnostic fixture\n');self.returncode=0
            def poll(self):return self.returncode
        backup=json.loads((self.media/'state/backup.json').read_text())
        with patch.object(recovery.subprocess,'Popen',Complete):
            result=ORIGINAL_RUN_FULL_RESTORE(self.media,self.home,self.case.rig.rows,backup,{'test':'binding'})
        self.assertEqual(result['exit_code'],0);self.assertEqual(result['status'],'database_restored')
        self.assertEqual(result['timeout_seconds'],3600)
        self.assertIn('PGAPPNAME=',next(value for value in calls[0] if value.startswith('PGAPPNAME=')))
        self.assertEqual(calls[0][calls[0].index('sh')+2],recovery.RESTORE_LAUNCHER)
        self.assertEqual((self.home/result['stderr_file']).stat().st_mode&0o777,0o600)
        self.assertEqual((self.home/result['stderr_file']).read_bytes(),b'private diagnostic fixture\n')
    def test_restore_timeout_stops_authenticated_container_process_before_docker_client(self):
        order=[]
        class Hanging:
            def __init__(self,*args,**kwargs):self.returncode=None
            def poll(self):return self.returncode
            def wait(self,timeout):
                if self.returncode is None:raise subprocess.TimeoutExpired('docker fixture',timeout)
                return self.returncode
            def terminate(self):order.append('docker-terminate');self.returncode=-15
            def kill(self):order.append('docker-kill');self.returncode=-9
        backup=json.loads((self.media/'state/backup.json').read_text())
        identity={'pid':123,'start_time':'900','phase':'restore','argv_sha256':'f'*64}
        with patch.object(recovery.subprocess,'Popen',Hanging),patch.object(recovery,'process_identity',return_value=identity),\
                patch.object(recovery,'stop_restore_process',side_effect=lambda *args:order.append('container-stop')),\
                patch.object(recovery.time,'monotonic',side_effect=[0,3601]),self.assertRaises(subprocess.TimeoutExpired):
            ORIGINAL_RUN_FULL_RESTORE(self.media,self.home,self.case.rig.rows,backup,{'test':'binding'})
        self.assertEqual(order,['container-stop','docker-terminate'])
        results=[json.loads(path.read_text()) for path in self.home.glob('restore-attempt-*.json')]
        self.assertEqual(len(results),1);self.assertEqual(results[0]['status'],'failed');self.assertEqual(results[0]['failure_type'],'TimeoutExpired')
        self.assertFalse((self.home/'database-restore-complete.json').exists())

    def test_failed_independent_historical_target_proof_keeps_writers_stopped(self):
        self.contracts.side_effect=RuntimeError('target mount differs from historical model')
        with self.assertRaisesRegex(RuntimeError,'mount'):self.run_recovery()
        self.assertTrue(all(self.case.rig.rows[name]['State']['Status']=='exited' for name in self.writers));self.assert_fenced()
    def test_installed_live_configuration_cannot_be_changed_before_restore(self):
        Path(self.before['live']).write_text('{"changed":true}')
        with self.assertRaisesRegex(RuntimeError,'live configuration'):self.run_recovery()
        self.restore.assert_not_called();self.assert_fenced()

class TimeoutProcessTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(recovery,'vm',vm).start()
    def test_launcher_preserves_stdin_and_writes_a_numeric_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'restore.pid'
            result=subprocess.run(['/bin/sh','-c',recovery.RESTORE_LAUNCHER,'--',str(marker),'/bin/cat'],input=b'protected-archive-bytes',capture_output=True,check=True)
            self.assertEqual(result.stdout,b'protected-archive-bytes')
            self.assertTrue(marker.read_text().strip().isdigit(),repr(marker.read_bytes()))

    def test_reading_apply_source_is_not_execution(self):
        for argv in (["cat","/safe/vm_development_apply.py"],["rg","rule","/safe/vm_development_apply.py"],["sh","-c","cat /safe/vm_development_apply.py"]):
            self.assertFalse(recovery.is_restore_executable(argv))
        for argv in (["python3","-I","-B","/safe/vm_development_apply.py"],["/usr/bin/pg_restore","--clean"],["docker","exec","-i","pg","pg_restore","--clean"]):
            self.assertTrue(recovery.is_restore_executable(argv))


    def test_authenticated_shell_to_exec_transition_keeps_same_process_identity(self):
        marker='/tmp/jjdguard-recovery-fixture.pid'
        expected=['pg_restore','--clean','--create','-U','fixture','-d','postgres']
        shell=['sh','-c',recovery.RESTORE_LAUNCHER,'--',marker,*expected]
        stat='123 (sh) '+' '.join(['S']+['0']*18+['900']+['0']*3)
        with patch.object(vm,'run',side_effect=[chr(0).join(shell)+chr(0),stat,chr(0).join(expected)+chr(0),stat]):
            starting=recovery.process_identity('pg','123',expected,marker)
            running=recovery.process_identity('pg','123',expected,marker)
        self.assertEqual(starting['phase'],'starting');self.assertEqual(running['phase'],'restore')
        self.assertEqual(starting['pid'],running['pid']);self.assertEqual(starting['start_time'],running['start_time'])
    def test_unknown_or_reused_restore_process_is_not_signalled(self):
        identity={'pid':123,'start_time':'900','phase':'restore','argv_sha256':'f'*64}
        with patch.object(recovery,'process_identity',return_value=dict(identity,start_time='901')),patch.object(vm,'run') as run,self.assertRaisesRegex(RuntimeError,'reused'):
            recovery.stop_restore_process('pg',identity,['pg_restore'])
        run.assert_not_called()
    def test_timeout_scope_exactly_matches_the_reported_postgres_restore(self):
        command=['docker','exec','-i','a'*64,'pg_restore','--clean','--if-exists','--create','--exit-on-error','-U','newapi','-d','postgres']
        record={'restore_failure_type':'TimeoutExpired','failure_message':recovery.RESTORE_FAILURE,'restore_failure_message':str(subprocess.TimeoutExpired(command,299.9999807551503))}
        self.assertTrue(recovery.timeout_failure(record))
        for field in ('restore_failure_type','failure_message'):
            bad=dict(record);bad[field]='unknown';self.assertFalse(recovery.timeout_failure(bad))
    def test_restore_deadline_is_at_least_1800_and_host_outer_wait_is_larger(self):
        self.assertGreaterEqual(recovery.RESTORE_TIMEOUT,1800)
        source=Path(fixture.deploy.__file__).read_text()
        self.assertIn('files,stage_pin,checkpoint,database_resume=database_resume),seconds=4800)',source)


class HistoricalTargetContractTests(unittest.TestCase):
    def setUp(self):
        self.defaults={'User':'10001','WorkingDir':'/app','Cmd':['/app/service'],'Env':['PATH=/bin'],'Labels':{'app':'fixture'}}
        self.item={'image':'sha256:fixture','environment':{'JJD_COMMIT':'old'},'networks':{'default':{}},'profiles':['chat'],
                   'extra_hosts':['host.docker.internal=host-gateway'],'read_only':True,'security_opt':['no-new-privileges:true'],
                   'cap_drop':['ALL'],'restart':'always','ports':[{'target':8080,'published':'18080'}],
                   'volumes':[{'type':'volume','source':'data','target':'/data'},{'type':'bind','source':'/certs','target':'/certs','read_only':True}]}
        self.model={'networks':{'default':{'name':'fixture-net'}},'volumes':{'data':{'name':'fixture-data'}}}
        self.row={'Id':'fixture','Name':'/control-plane','Path':'/app/service','Args':[],
                  'Config':dict(copy.deepcopy(self.defaults),Env=['PATH=/bin','JJD_COMMIT=old'],ExposedPorts={'8080/tcp':{}}),
                  'HostConfig':{'ReadonlyRootfs':True,'SecurityOpt':['no-new-privileges:true'],'CapDrop':['ALL'],
                                'RestartPolicy':{'Name':'always','MaximumRetryCount':0},'ExtraHosts':['host.docker.internal:host-gateway'],
                                'LogConfig':{'Type':'json-file','Config':{}},'PortBindings':{'8080/tcp':[{'HostIp':'','HostPort':'18080'}]}},
                  'Mounts':[{'Type':'volume','Name':'fixture-data','Source':'/var/lib/docker/volumes/fixture-data/_data','Destination':'/data','RW':True,'Propagation':'','Mode':'rw'},
                            {'Type':'bind','Source':'/certs','Destination':'/certs','RW':False,'Propagation':'rprivate','Mode':'ro'}],
                  'NetworkSettings':{'Networks':{'fixture-net':{'Aliases':['control-plane'],'IPAMConfig':{'IPv4Address':''}}}}}
    def validate(self):recovery.validate_historical_target('control-plane',self.item,self.model,self.row,{'Config':self.defaults},'json-file')
    def test_exact_historical_model_accepts_derived_compose_labels_and_named_volume_mode(self):
        for mode in ('z','rw'):
            self.row['Mounts'][0]['Mode']=mode
            self.row['Config']['Labels'].update({'com.docker.compose.version':'5.3.0','com.docker.compose.replace':'control-plane-1'})
            self.validate()
    def test_business_environment_mount_permissions_hosts_and_security_remain_strict(self):
        baseline=copy.deepcopy(self.row)
        for kind in ('env','command','mount-rw','mount-source','privileged','capabilities','hosts','port','network','logging','restart'):
            self.row=copy.deepcopy(baseline)
            if kind=='env':self.row['Config']['Env'].append('UNAPPROVED=true')
            elif kind=='command':self.row['Args']=['--unapproved']
            elif kind=='mount-rw':self.row['Mounts'][1]['RW']=True
            elif kind=='mount-source':self.row['Mounts'][0]['Name']='foreign-volume'
            elif kind=='privileged':self.row['HostConfig']['Privileged']=True
            elif kind=='capabilities':self.row['HostConfig']['CapDrop']=[]
            elif kind=='hosts':self.row['HostConfig']['ExtraHosts']=['host.docker.internal:127.0.0.1']
            elif kind=='port':self.row['HostConfig']['PortBindings']['8080/tcp'][0]['HostPort']='18081'
            elif kind=='network':self.row['NetworkSettings']['Networks']['fixture-net']['Aliases'].append('foreign')
            elif kind=='logging':self.row['HostConfig']['LogConfig']={'Type':'foreign','Config':{}}
            else:self.row['HostConfig']['RestartPolicy']['Name']='no'
            with self.subTest(kind=kind),self.assertRaises(RuntimeError):self.validate()
    def test_unknown_frozen_runtime_fields_fail_closed(self):
        self.item['unreviewed_resource']=True
        with self.assertRaisesRegex(RuntimeError,'unsupported historical'):self.validate()

if __name__=='__main__':unittest.main()
