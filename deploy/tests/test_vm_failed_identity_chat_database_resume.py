"""A completed private restore resumes exact old containers without replay or broad firewall exemptions."""
import ast,copy,hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_vm_failed_identity_chat_recovery as legacy
recovery=legacy.recovery
real_vm=legacy.vm

class CompletedDatabaseResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.media=self.root/'development-releases'/'dev-resume';self.media.mkdir(parents=True)
        self.prior=self.media.parent/'failed-apply-recoveries'/('dev-resume-'+'a'*12);self.prior.mkdir(parents=True,mode=0o700)
        self.home=self.prior.parent/('dev-resume-'+'b'*12);self.home.mkdir(mode=0o700)
        self.work=self.root/'releases/original/deploy/docker-compose';self.live=self.work/'active-config/failed.json';self.live.parent.mkdir(parents=True)
        self.writers=('control-plane','worker');self.chain='JJDDEV'+recovery.sha(self.media.name.encode())[:10].upper();self.interface='eth0'
        self.rows={}
        for number,name in enumerate((*self.writers,'postgres'),2):
            endpoint={'NetworkID':'c'*64,'IPAddress':'172.18.0.'+str(number),'Aliases':[name]}
            self.rows[name]={'Id':str(number)*64,'Image':'sha256:'+'d'*64,'Name':'/'+name,'RestartCount':0,
              'State':{'Status':'exited' if name in self.writers else 'running','Running':name not in self.writers,'StartedAt':'2026-10-16T00:00:00Z'},
              'Config':{'Env':['POSTGRES_USER=newapi','POSTGRES_DB=app'],'Labels':{'com.docker.compose.project':'project','com.docker.compose.service':name}},
              'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{'default':endpoint}}}
        self.old_rows=copy.deepcopy(self.rows)
        for row in self.old_rows.values():row['State'].update(Status='running',Running=True)
        self.before={'project':'project','runtime':{name:{'id':row['Id'],'image':row['Image']} for name,row in self.rows.items()},'live':str(self.live),'ledger':{'old':'hash'},'policy':{'safe':True}}
        self.binding={'manifest_sha256':'1'*64,'failure_sha256':'2'*64,'stage_sha256':'3'*64,'original_apply_sha256':'4'*64,'recovery_revision':'b'*40,'recovery_helper_sha256':'5'*64,'validator_sha256':'6'*64}
        self.proof={'revision':'a'*40}
        self.backup={'sha256':'7'*64,'size':123}
        self.write(self.prior/'vm_failed_identity_chat_recovery.py',b'prior frozen helper');self.proof['helper_sha256']=self.pin(self.prior/'vm_failed_identity_chat_recovery.py')
        self.write(self.prior/'vm_development_apply.py',b'prior frozen validator');self.proof['validator_sha256']=self.pin(self.prior/'vm_development_apply.py')
        nonce='e'*32
        self.database={'status':'database_restored','exit_code':0,'timeout_seconds':recovery.RESTORE_TIMEOUT,'application_name':'jjdguard-recovery-'+nonce,
          'stderr_file':'pg-restore-'+nonce+'.stderr.log','stderr_sha256':hashlib.sha256(b'').hexdigest(),'backup':self.backup,
          'binding':{**self.binding,'recovery_revision':self.proof['revision'],'recovery_helper_sha256':self.proof['helper_sha256'],'validator_sha256':self.proof['validator_sha256']}}
        self.write(self.prior/self.database['stderr_file'],b'');self.attempt=self.prior/('restore-attempt-'+nonce+'.json');self.save_database()
        rules=''.join('-A '+self.chain+' -p tcp -m conntrack --ctdir ORIGINAL --ctorigdstport '+str(port)+' -j REJECT --reject-with icmp-port-unreachable\n' for port in (3000,443,8080,8082,3128))
        self.filter='*filter\n:DOCKER-USER - [0:0]\n:'+self.chain+' - [0:0]\n-A DOCKER-USER -i eth0 -j '+self.chain+'\n'+rules+'COMMIT\n'
        self.stopped='*raw\n:PREROUTING ACCEPT [10:20]\nCOMMIT\n'+self.filter
        endpoints=''.join('-A PREROUTING -d 172.18.0.'+str(number)+'/32 ! -i br-'+('c'*12)+' -j DROP\n' for number in (2,3))
        self.running='*raw\n:PREROUTING ACCEPT [100:200]\n'+endpoints+'COMMIT\n'+self.filter
        self.write(self.prior/'restore-fence-before.txt',self.stopped.encode());self.proof['firewall_sha256']=self.pin(self.prior/'restore-fence-before.txt')
        stop=[str(self.prior/'original-compose-executable'),'--project-directory',str(self.work),'-p','project','-f',str(self.live),'stop','--timeout','25',*self.writers]
        commands=[(['docker','inspect',*[row['Id'] for row in self.old_rows.values()]],json.dumps(list(self.old_rows.values()))),(['iptables-save'],self.running),(stop,'')]
        self.audit=[]
        for argv,stdout in commands:
            self.audit.append({'invocation':'f'*32,'sequence':len(self.audit),'phase':'start','argv':argv})
            self.audit.append({'invocation':'f'*32,'sequence':len(self.audit),'phase':'exit','argv':argv,'returncode':0,'stdout':stdout,'stderr':''})
        self.save_audit()
        self.addCleanup(patch.stopall)
        source=SimpleNamespace(ROOT=self.root,safe_read=lambda path,**kwargs:Path(path).read_bytes(),authenticated_fence=real_vm.authenticated_fence,
          unrelated_fence_identity=real_vm.unrelated_fence_identity,identity_chat_contract_hash=real_vm.identity_chat_contract_hash,
          read_migration_ledger=lambda rows:self.before['ledger'],read_policy=lambda rows,**kwargs:self.before['policy'],
          write_json=lambda path,value:self.write(path,json.dumps(value).encode()),atomic_bytes=lambda path,data:self.write(path,data),
          inspect_runtime=lambda:self.old_rows,identity_chat_snapshot=lambda rows,m:{'fixture':'snapshot'})
        patch.object(recovery,'vm',source).start();patch.object(recovery,'verify_legacy_target_contracts',return_value={'verified':True}).start()
    @staticmethod
    def write(path,data):path.write_bytes(data);path.chmod(0o600)
    @staticmethod
    def pin(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    def save_database(self):
        self.write(self.prior/'database-restore-complete.json',json.dumps(self.database).encode());self.write(self.attempt,json.dumps(self.database).encode())
        self.proof['database_sha256']=self.pin(self.prior/'database-restore-complete.json');self.proof['attempt_sha256']=self.pin(self.attempt)
    def save_audit(self):
        self.write(self.prior/'subprocess.jsonl',(''.join(json.dumps(row)+'\n' for row in self.audit)).encode());self.proof['audit_sha256']=self.pin(self.prior/'subprocess.jsonl')
    def authenticate(self):
        return recovery.authenticate_database_resume(self.media,self.home,{},self.before,self.binding,self.rows,self.backup,self.proof,self.stopped,self.chain,self.interface,self.writers)
    def test_authenticates_complete_restore_and_exact_running_firewall_start_order(self):
        database,firewall,order=self.authenticate();self.assertEqual(database,self.database);self.assertEqual(firewall,self.running.strip());self.assertEqual(order,list(self.writers))
    def test_multiple_networks_use_unique_exact_frozen_endpoint_rule(self):
        rows=copy.deepcopy(self.old_rows)
        rows['control-plane']['NetworkSettings']['Networks']['internal']={'NetworkID':'d'*64,'IPAddress':'172.21.0.2','Aliases':['control-plane']}
        self.assertEqual(recovery.resume_writer_order(self.running,rows,self.writers),list(self.writers))
    def test_multiple_matching_network_endpoint_rules_are_ambiguous(self):
        rows=copy.deepcopy(self.old_rows)
        rows['control-plane']['NetworkSettings']['Networks']['internal']={'NetworkID':'d'*64,'IPAddress':'172.21.0.2','Aliases':['control-plane']}
        extra='-A PREROUTING -d 172.21.0.2/32 ! -i br-'+('d'*12)+' -j DROP\n'
        firewall=self.running.replace('COMMIT\n',extra+'COMMIT\n',1)
        with self.assertRaisesRegex(RuntimeError,'ambiguous'):recovery.resume_writer_order(firewall,rows,self.writers)
    def prepare_recent_runtime(self):
        recent=self.prior.parent/('dev-resume-'+'c'*12);recent.mkdir(mode=0o700)
        runtime={'revision':'c'*40}
        base={key:self.proof[key] for key in recovery.DATABASE_RESUME_FIELDS}
        for filename,key in (('vm_failed_identity_chat_recovery.py','helper_sha256'),('vm_development_apply.py','validator_sha256'),('database-restore-complete.json','database_sha256'),('restore-fence-before.txt','firewall_sha256')):
            self.write(recent/filename,(self.prior/filename).read_bytes());runtime[key]=self.pin(recent/filename)
        self.write(recent/'database-resume-proof.json',json.dumps(base).encode());runtime['resume_proof_sha256']=self.pin(recent/'database-resume-proof.json')
        latest=copy.deepcopy(self.old_rows)
        for name in self.writers:
            latest[name]['State']['StartedAt']='2026-10-17T00:00:00Z';self.rows[name]['State']['StartedAt']='2026-10-17T00:00:00Z'
        latest['control-plane']['NetworkSettings']['Networks']['default']['IPAddress']='172.18.0.3'
        latest['worker']['NetworkSettings']['Networks']['default']['IPAddress']='172.18.0.2'
        audit=copy.deepcopy(self.audit);audit[1]['stdout']=json.dumps(list(latest.values()))
        for record in audit[-2:]:record['argv'][0]=str(recent/'original-compose-executable')
        self.write(recent/'subprocess.jsonl',(''.join(json.dumps(row)+'\n' for row in audit)).encode());runtime['audit_sha256']=self.pin(recent/'subprocess.jsonl')
        self.proof['runtime']=runtime;self.old_rows=latest;self.recent=recent
        return runtime
    def test_recent_runtime_proof_allows_exact_latest_started_at_without_database_replay(self):
        runtime=self.prepare_recent_runtime();self.proof.pop('runtime')
        with self.assertRaisesRegex(RuntimeError,'container changed'):self.authenticate()
        self.proof['runtime']=runtime
        database,firewall,order=self.authenticate();self.assertEqual(database,self.database);self.assertEqual(order,list(reversed(self.writers)));self.assertEqual(firewall,self.running.strip())
        commands=self.run_resume();self.assertEqual(commands,[('docker','start',self.rows[name]['Id']) for name in reversed(self.writers)])
    def test_recent_runtime_requires_every_external_pin(self):
        runtime=self.prepare_recent_runtime()
        for key in runtime:
            original=runtime[key];runtime[key]='0'*len(original)
            with self.subTest(key=key),self.assertRaises((RuntimeError,FileNotFoundError)):self.authenticate()
            runtime[key]=original
        original=runtime.pop('audit_sha256')
        with self.assertRaisesRegex(RuntimeError,'external'):self.authenticate()
        runtime['audit_sha256']=original
    def test_recent_runtime_cannot_substitute_database_completion_or_base_proof(self):
        runtime=self.prepare_recent_runtime();path=self.recent/'database-restore-complete.json';raw=path.read_bytes()
        self.write(path,raw+b'\n');runtime['database_sha256']=self.pin(path)
        with self.assertRaisesRegex(RuntimeError,'completion differs'):self.authenticate()
        self.write(path,raw);runtime['database_sha256']=self.pin(path)
        saved={key:self.proof[key] for key in recovery.DATABASE_RESUME_FIELDS};saved['audit_sha256']='0'*64
        path=self.recent/'database-resume-proof.json';self.write(path,json.dumps(saved).encode());runtime['resume_proof_sha256']=self.pin(path)
        with self.assertRaisesRegex(RuntimeError,'different database'):self.authenticate()
    def test_exact_docker_start_waits_for_health_and_rejects_automatic_restart(self):
        name='control-plane';identifier=self.rows[name]['Id'];healthy=copy.deepcopy(self.old_rows[name]);starting=copy.deepcopy(healthy);starting['State']['Health']={'Status':'starting'}
        with patch.object(recovery.vm,'run',side_effect=[identifier,json.dumps([starting]),json.dumps([healthy])],create=True) as run,patch.object(recovery.time,'sleep'):
            recovery.start_authenticated_writer(self.home,self.rows,name)
        self.assertEqual(run.call_args_list[0].args[0],['docker','start',identifier])
        restarted=copy.deepcopy(healthy);restarted['RestartCount']=1
        with patch.object(recovery.vm,'run',side_effect=[identifier,json.dumps([restarted])],create=True),self.assertRaisesRegex(RuntimeError,'changed while starting'):
            recovery.start_authenticated_writer(self.home,self.rows,name)
    def test_missing_or_changed_any_external_pin_refuses(self):
        for field in self.proof:
            saved=self.proof[field];self.proof[field]='0'*len(saved)
            with self.subTest(field=field),self.assertRaises((RuntimeError,FileNotFoundError)):self.authenticate()
            self.proof[field]=saved
        saved=self.proof.pop('audit_sha256')
        with self.assertRaisesRegex(RuntimeError,'external'):self.authenticate()
        self.proof['audit_sha256']=saved
    def test_partial_nonzero_wrong_backup_or_binding_cannot_skip_restore(self):
        original=copy.deepcopy(self.database)
        for key,value in (('status','failed'),('exit_code',1),('exit_code',False),('backup',{'sha256':'0'*64,'size':123}),('binding',{}),('stderr_sha256',None)):
            self.database={**copy.deepcopy(original),key:value};self.save_database()
            with self.subTest(field=key,value=value),self.assertRaises(RuntimeError):self.authenticate()
        self.database=original;self.save_database()
    def test_mismatched_attempt_or_stderr_refuses(self):
        self.write(self.attempt,b'{}');self.proof['attempt_sha256']=self.pin(self.attempt)
        with self.assertRaisesRegex(RuntimeError,'attempt'):self.authenticate()
        self.save_database();self.write(self.prior/self.database['stderr_file'],b'changed')
        with self.assertRaisesRegex(RuntimeError,'pin'):self.authenticate()
    def test_prior_audit_must_end_in_successful_exact_writer_stop(self):
        for change in ('stop','exit','sequence','extra'):
            original=copy.deepcopy(self.audit)
            if change=='stop':self.audit[-1]['argv']=self.audit[-1]['argv'][:-1]
            elif change=='exit':self.audit[-1]['returncode']=1
            elif change=='sequence':self.audit[-1]['sequence']=99
            else:self.audit.append({**self.audit[-1],'sequence':len(self.audit),'argv':['unknown']})
            self.save_audit()
            with self.subTest(change=change),self.assertRaises(RuntimeError):self.authenticate()
            self.audit=original;self.save_audit()
    def test_current_container_identity_config_or_starttime_change_refuses(self):
        for field,value in (('Id','x'*64),('Image','sha256:wrong'),('RestartCount',1),('Config',{'Env':['INJECTED=yes']}),('State',{'StartedAt':'2026-10-17T00:00:00Z'})):
            old=copy.deepcopy(self.rows['control-plane']);self.rows['control-plane'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):self.authenticate()
            self.rows['control-plane']=old
    def test_foreign_stopped_firewall_or_ambiguous_writer_endpoint_refuses(self):
        self.stopped=self.stopped.replace('PREROUTING ACCEPT','PREROUTING DROP')
        with self.assertRaisesRegex(RuntimeError,'firewall'):self.authenticate()
        self.stopped=self.stopped.replace('PREROUTING DROP','PREROUTING ACCEPT')
        self.audit[3]['stdout']=self.running.replace('172.18.0.2/32','172.18.0.99/32');self.save_audit()
        with self.assertRaisesRegex(RuntimeError,'endpoint'):self.authenticate()
    def run_resume(self,final_firewall=None):
        command=['docker','exec','-i',self.rows['postgres']['Id'],'pg_restore','--clean','--if-exists','--create','--exit-on-error','-U','newapi','-d','postgres']
        self.write(self.media/'failure.json',json.dumps({'restore_failure_message':str(subprocess.TimeoutExpired(command,300))}).encode());self.write(self.media/'state-rollback.json',b'{}')
        (self.media/'state').mkdir();self.write(self.media/'state/rollback.json',b'{}')
        commands=[]
        def run(argv,**kwargs):
            if argv==['ip','-j','route','show','default']:return '[{"dev":"eth0"}]'
            if argv==['iptables-save']:return self.stopped if not commands else (final_firewall or self.running)
            if argv[:2]==['docker','start']:
                commands.append(tuple(argv));return argv[2]
            if argv[:2]==['docker','inspect']:
                return json.dumps([row for row in self.old_rows.values() if row['Id']==argv[2]])
            raise AssertionError(argv)
        with patch.object(recovery,'inspect_stopped_runtime',return_value=self.rows),patch.object(recovery,'stopped_restore_scope',return_value=self.writers),patch.object(recovery,'restore_inputs',return_value=self.backup),patch.object(recovery,'no_restore_processes'),patch.object(recovery,'database_quiescent'),patch.object(recovery.vm,'run',side_effect=run,create=True),patch.object(recovery,'compose_original',side_effect=lambda home,before,*args:commands.append(args)),patch.object(recovery,'run_full_restore') as replay,patch.object(recovery,'verify_restored'):
            try:recovery.restore_timed_out_database(self.media,self.home,{},self.before,self.binding,self.proof)
            finally:self.commands=commands;replay.assert_not_called()
        return commands
    def test_resume_starts_only_existing_writers_without_database_replay(self):
        commands=self.run_resume();self.assertEqual(commands,[('docker','start',self.rows[name]['Id']) for name in self.writers]);self.assertTrue((self.home/'restored-runtime-complete.json').exists())
    def test_host_bootstrap_forwards_complete_resume_proof_and_rejects_incomplete_proof(self):
        deploy=legacy.fixture.deploy
        metadata={key:self.binding[key] for key in ('manifest_sha256','failure_sha256','original_apply_sha256')}
        files={'vm_development_apply.py':b'validator','vm_failed_identity_chat_recovery.py':b'helper'}
        program=deploy.failed_identity_chat_recovery_guest_code(self.media.name,'b'*40,metadata,files,'3'*64,database_resume=self.proof)
        tree=ast.parse(program);call=next(node.value for node in tree.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='run_failed_recovery_helper')
        argv=ast.literal_eval(call.args[0]);self.assertEqual(json.loads(argv[argv.index('--database-resume-proof')+1]),self.proof)
        with self.assertRaisesRegex(RuntimeError,'external'):deploy.failed_identity_chat_recovery_guest_code(self.media.name,'b'*40,metadata,files,database_resume={})
    def test_any_final_foreign_rule_change_rejects_and_stops_all_writers(self):
        changed=self.running.replace(':PREROUTING ACCEPT',':PREROUTING DROP')
        with self.assertRaisesRegex(RuntimeError,'unrelated firewall'):self.run_resume(changed)
        self.assertEqual(self.commands[-1],('stop','--timeout','25',*self.writers));self.assertFalse((self.home/'restored-runtime-complete.json').exists())

if __name__=='__main__':unittest.main()
