import copy,hashlib,json,sys,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"release"))
import vm_development_apply as vm
import vm_failed_identity_chat_recovery as recovery
ROOT=Path('/opt/jjdguard/releases/fixture/deploy/docker-compose')
KEY='com.docker.compose.project.working_dir'
def row(name,directory):
 return {'Id':'original-'+name,'Image':'image-'+name,'RestartCount':0,'State':{'Status':'running','StartedAt':'2026-10-18T00:00:00Z','Health':{'Status':'healthy'}},'Config':{'Env':[],'Labels':{KEY:str(directory)}},'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{}},'Path':'/app/server','Args':[]}
def case(include_proxy=True):
 services=vm.IDENTITY_CHAT_SERVICES+(('proxy-server',) if include_proxy else ())
 manifest={'purpose':'development-vm','preserve_tier1':True,'identity_chat_only':True,'include_proxy_server':include_proxy,'services':{n:{} for n in services}}
 rows={n:row(n,ROOT/'active-config' if n=='gateway-core' else ROOT) for n in services}
 snapshot={'runtime':{},'inventory':{}};witness={'schema':1,'containers':{}}
 for name,value in rows.items():
  contract=vm.identity_chat_runtime_contract(value,True)
  digest=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  snapshot['runtime'][name]={'id':value['Id'],'image':value['Image'],'contract':digest}
  witness['containers'][value['Id']]={'contract':contract}
 before={'live':str(ROOT/'active-config/live.json'),'identity_chat_runtime':snapshot,'identity_chat_contract_witness':witness}
 actual=copy.deepcopy(rows);actual['gateway-core']['Config']['Labels'][KEY]=str(ROOT)
 return services,manifest,rows,actual,before
class OriginalDirectories(unittest.TestCase):
 def test_contiguous_groups_keep_dependency_order(self):
  services,_,rows,_,_=case()
  groups=vm.original_project_directory_groups(rows,services,ROOT)
  self.assertEqual(groups,[(ROOT,['control-plane']),(ROOT/'active-config',['gateway-core']),(ROOT,list(services[2:]))])
 def test_same_directory_preserves_single_compose_call(self):
  services,_,rows,_,_=case()
  for value in rows.values():value['Config']['Labels'][KEY]=str(ROOT)
  self.assertEqual(vm.original_project_directory_groups(rows,services,ROOT),[(ROOT,list(services))])
 def test_unfrozen_path_shapes_rejected(self):
  for directory in ['/tmp/elsewhere','relative','/opt/jjdguard/releases/../outside']:
   with self.subTest(directory=directory):
    rows={'gateway-core':row('gateway-core',directory)}
    with self.assertRaises(RuntimeError):vm.original_project_directory_groups(rows,('gateway-core',),ROOT)
 def test_switch_and_restore_share_grouped_recreation(self):
  services,_,rows,_,_=case();release=vm.Release.__new__(vm.Release);release.rows=rows;release.target_services=services;release.workdir=ROOT;release.compose=Mock()
  release.recreate_targets(ROOT/'active-config/candidate.json')
  self.assertEqual(release.compose.call_count,3)
  args,kwargs=release.compose.call_args_list[1]
  self.assertEqual(args[-1],'gateway-core');self.assertEqual(kwargs['project_directory'],ROOT/'active-config')
 def test_runtime_contract_still_checks_creator_directory(self):
  _,_,rows,actual,_=case()
  self.assertNotEqual(vm.identity_chat_contract_hash(rows['gateway-core'],True),vm.identity_chat_contract_hash(actual['gateway-core'],True))
class DirectoryRecovery(unittest.TestCase):
 def setUp(self):self.old=recovery.vm;recovery.vm=vm
 def tearDown(self):recovery.vm=self.old
 def test_five_and_six_service_closed_plans(self):
  for include_proxy in [False,True]:
   _,manifest,_,actual,before=case(include_proxy)
   plan=recovery.plan_restored_workdir_repairs(actual,manifest,before)
   self.assertEqual(len(plan),1);self.assertEqual(plan[0]['service'],'gateway-core');self.assertEqual(plan[0]['directory'],str(ROOT/'active-config'))
 def test_other_contract_drift_is_not_hidden(self):
  for field in ['environment','mount','argument']:
   _,manifest,_,actual,before=case()
   if field=='environment':actual['gateway-core']['Config']['Env']=['EXTRA=fixture']
   elif field=='mount':actual['gateway-core']['HostConfig']['ReadonlyRootfs']=True
   else:actual['gateway-core']['Args']=['--unexpected']
   with self.subTest(field=field),self.assertRaises(RuntimeError):recovery.plan_restored_workdir_repairs(actual,manifest,before)
 def test_original_image_and_restart_identity_required(self):
  for key,value in [('Image','other-image'),('RestartCount',1)]:
   _,manifest,_,actual,before=case();actual['gateway-core'][key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):recovery.plan_restored_workdir_repairs(actual,manifest,before)
 def test_arbitrary_directory_transition_rejected(self):
  _,manifest,_,actual,before=case();actual['gateway-core']['Config']['Labels'][KEY]=str(ROOT/'other')
  with self.assertRaises(RuntimeError):recovery.plan_restored_workdir_repairs(actual,manifest,before)
 def test_failure_classifier_does_not_accept_other_failures(self):
  good={'failure_type':'RuntimeError','restore_failure_type':'RuntimeError','failure_message':recovery.RESTORE_FAILURE,'restore_failure_message':recovery.RESTORE_FAILURE}
  self.assertTrue(recovery.workdir_contract_failure(good))
  for key in good:
   bad=dict(good);bad[key]='other'
   self.assertFalse(recovery.workdir_contract_failure(bad))
class RepairController(unittest.TestCase):
 def setUp(self):self.old=recovery.vm;recovery.vm=vm
 def tearDown(self):recovery.vm=self.old
 def exercise(self,change=None,verify_failure=False):
  with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
   media=Path(directory)/'media';home=Path(directory)/'recovery';(media/'state').mkdir(parents=True);home.mkdir()
   _,manifest,_,actual,before=case();before['runtime']=dict(actual);before['ledger']=['fixture'];before['policy']={'fixture':True}
   actual['postgres']=row('postgres',ROOT);actual['postgres']['Config']['Env']=['POSTGRES_USER=fixture_user'];before['runtime']['postgres']={}
   nonce='a'*32;command=['pg_restore','--clean','--if-exists','--create','--exit-on-error','-U','fixture_user','-d','postgres']
   attempt={'status':'database_restored','exit_code':0,'application_name':'jjdguard-restore-'+nonce,'stderr_file':'pg-restore-'+nonce+'.stderr.log','stderr_sha256':recovery.sha(b''),'process':{'phase':'restore','argv_sha256':recovery.sha(json.dumps(command,separators=(',',':')).encode())}}
   failure={'failure_type':'RuntimeError','restore_failure_type':'RuntimeError','failure_message':recovery.RESTORE_FAILURE,'restore_failure_message':recovery.RESTORE_FAILURE}
   if change:change(attempt,actual,before)
   (media/'failure.json').write_text(json.dumps(failure));(media/'state/restore-attempt-fixture.json').write_text(json.dumps(attempt));(media/'state'/attempt['stderr_file']).write_bytes(b'')
   (media/'state/backup.json').write_text(json.dumps({'sha256':'backup-digest','size':10}));(media/'state/rollback.json').write_bytes(b'original-model')
   stack.enter_context(patch.object(recovery,'pinned',side_effect=lambda path,*args:Path(path).read_bytes()))
   stack.enter_context(patch.object(recovery,'no_restore_processes'))
   stack.enter_context(patch.object(recovery,'private_digest',return_value=('backup-digest',10)))
   stack.enter_context(patch.object(recovery,'installed_read',return_value=b'original-model'))
   stack.enter_context(patch.object(vm,'inspect_runtime',return_value=actual))
   stack.enter_context(patch.object(vm,'read_migration_ledger',return_value=['fixture']))
   stack.enter_context(patch.object(vm,'read_policy',return_value={'fixture':True}))
   stack.enter_context(patch.object(vm,'identity_chat_snapshot',return_value={}))
   projected=stack.enter_context(patch.object(vm,'verify_identity_chat_snapshot'))
   composed=stack.enter_context(patch.object(recovery,'compose_original'))
   verified=stack.enter_context(patch.object(recovery,'verify_restored',side_effect=RuntimeError('actual contract rejected') if verify_failure else None))
   writes=stack.enter_context(patch.object(vm,'write_json'))
   try:recovery.repair_restored_workdirs(media,home,manifest,before)
   except RuntimeError:
    self.assertFalse(any(call.args[0].name=='working-directory-repair-complete.json' for call in writes.call_args_list))
    if not verify_failure:composed.assert_not_called()
    raise
   composed.assert_called_once();self.assertEqual(composed.call_args.args[-1],'gateway-core');self.assertEqual(composed.call_args.kwargs['project_directory'],ROOT/'active-config')
   projected.assert_called_once();verified.assert_called_once_with(media,manifest,before)
   self.assertFalse(writes.call_args.args[1]['database_replayed'])
 def test_completed_restore_recreates_only_original_gateway_then_verifies_actual(self):self.exercise()
 def test_failed_restore_does_not_mutate(self):
  with self.assertRaisesRegex(RuntimeError,'completed authenticated'):self.exercise(lambda attempt,*rest:attempt.update(status='failed'))
 def test_wrong_restore_command_does_not_mutate(self):
  with self.assertRaisesRegex(RuntimeError,'command or private evidence'):self.exercise(lambda attempt,*rest:attempt['process'].update(argv_sha256='other'))
 def test_starting_process_does_not_prove_completed_restore(self):
  with self.assertRaisesRegex(RuntimeError,'command or private evidence'):self.exercise(lambda attempt,*rest:attempt['process'].update(phase='starting'))
 def test_changed_stderr_does_not_mutate(self):
  with self.assertRaisesRegex(RuntimeError,'stderr differs'):self.exercise(lambda attempt,*rest:attempt.update(stderr_sha256='other'))
 def test_other_runtime_drift_does_not_mutate(self):
  with self.assertRaisesRegex(RuntimeError,'another runtime contract'):self.exercise(lambda attempt,rows,before:rows['gateway-core']['Config'].update(Env=['EXTRA=fixture']))
 def test_failed_actual_verification_never_records_success(self):
  with self.assertRaisesRegex(RuntimeError,'actual contract rejected'):self.exercise(verify_failure=True)
if __name__=='__main__':unittest.main()
