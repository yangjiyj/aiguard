import subprocess,json,os,tempfile,pathlib,uuid
root=pathlib.Path(__file__).resolve().parents[2]
dsn=os.environ['QUALITY_DATABASE_URL']
from urllib.parse import urlparse
u=urlparse(dsn)
assert u.hostname=='127.0.0.1' and u.path=='/jjd267' and os.environ.get('QUALITY_FIXTURE_ONLY')=='1', 'isolated fixture required'
tenant='quality_repair_'+uuid.uuid4().hex[:12]; group=tenant+'_group'; request=tenant+'_req'
def sql(q):return subprocess.check_output(['psql',dsn,'-At','-v','ON_ERROR_STOP=1','-c',q],text=True).strip()
def call(mode,backup=None):
 a=[str(root/'work/security-counter-repair'),'--tenant',tenant,'--mode',mode]
 if backup:a+=['--backup',str(backup)]
 return json.loads(subprocess.check_output(a,env={**os.environ,'QUALITY_DATABASE_URL':dsn},text=True))
try:
 sql(f"INSERT INTO tenants(id,name,edition,status,is_test) VALUES('{tenant}','synthetic','enterprise','active',true); INSERT INTO request_logs(id,request_id,tenant_id,project_id,endpoint_type,request_status) VALUES('{request}','{request}','{tenant}','project_default','chat_completions','success'); INSERT INTO alert_groups(id,tenant_id,project_id,group_key,status,severity,alert_type,title,request_id,representative_event_id,principal_key,first_seen_at,last_seen_at,occurrence_count,body_json,distinct_occurrences,affected_users) VALUES('{group}','{tenant}','project_default','synthetic','false_positive','high','security_event','synthetic','{request}','{request}','subject',NOW(),NOW(),1,'{{}}',77,99); INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,conversation_key,principal_key,alert_group_id) VALUES('{request}','{request}','{tenant}','project_default','security_check','high','audit','conversation','subject','{group}')")
 before=sql(f"SELECT distinct_occurrences||'|'||affected_users||'|'||status FROM alert_groups WHERE id='{group}'")
 preview=call('dry-run');assert len(preview['changes'])==1 and preview['changes'][0]['new_occurrences']==1
 assert sql(f"SELECT distinct_occurrences||'|'||affected_users||'|'||status FROM alert_groups WHERE id='{group}'")==before
 with tempfile.TemporaryDirectory(prefix='counter-repair-test-',dir=root/'work') as d:
  b=pathlib.Path(d)/'backup.json';apply=call('apply',b);assert len(apply['changes'])==1
  assert sql(f"SELECT distinct_occurrences||'|'||affected_users||'|'||status FROM alert_groups WHERE id='{group}'")=='1|1|false_positive'
  assert call('dry-run')['changes']==[]
  assert call('restore',b)['restored']==1
  assert sql(f"SELECT distinct_occurrences||'|'||affected_users||'|'||status FROM alert_groups WHERE id='{group}'")==before
  assert call('restore',b)['skipped_newer_or_missing']==1
  b2=pathlib.Path(d)/'backup2.json';call('apply',b2)
  sql(f"UPDATE alert_groups SET last_calc_at=NOW(),distinct_occurrences=23 WHERE id='{group}'")
  assert call('restore',b2)['skipped_newer_or_missing']==1
 print(json.dumps({'dry_run_readonly':'PASS','apply':'PASS','idempotence':'PASS','restore':'PASS','preserve_human_disposition':'PASS','reject_newer_counts':'PASS'}))
finally:
 for table in ['alert_inbox','security_events','security_event_occurrences','alert_groups','request_logs']:
  sql(f"DELETE FROM {table} WHERE tenant_id='{tenant}'")
 sql(f"DELETE FROM tenants WHERE id='{tenant}'")
