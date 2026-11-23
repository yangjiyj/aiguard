#!/usr/bin/env python3
"""Revalidate persisted alerts on the test VM; dry-run by default.
Only proven invalid candidates are changed. Preserve original evidence and a
protected before-image; compare-and-swap guards concurrent event annotations.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"deploy/release"))
from deploy_vm_development import guest

GUEST = r'''import sys,types,json,subprocess,collections,os,datetime,copy,hashlib
from pathlib import Path
for name in ('app','app.detectors'):
 mod=types.ModuleType(name);mod.__path__=[];sys.modules[name]=mod
for name,source in SOURCES:
 mod=types.ModuleType(name);sys.modules[name]=mod;exec(compile(source,name,'exec'),mod.__dict__)
from app.alert_evidence_validation import revalidate,VERSION,RANK
containers=json.loads(subprocess.check_output(['docker','inspect']+subprocess.check_output(['docker','ps','-q'],text=True).split(),text=True))
pg=next(c for c in containers if c['Config'].get('Labels',{}).get('com.docker.compose.service')=='postgres')
env=dict(v.split('=',1) for v in pg['Config']['Env'] if '=' in v)
base=['docker','exec','-i',pg['Id'],'psql','-X','-v','ON_ERROR_STOP=1','-U',env.get('POSTGRES_USER','postgres'),'-d',env.get('POSTGRES_DB','postgres'),'-qAt']
def sql(s):
 return subprocess.check_output(base,input="SET statement_timeout='20s'; SET lock_timeout='3s';\n"+s,text=True)
def quote(s): return "'"+s.replace("'","''")+"'"
def nullable(s): return 'NULL' if s is None else quote(s)
report=collections.Counter();last='';backup=None;groups=set();backup_path=None
review_decisions=REVIEW_DECISIONS
# The live alert scope comes from the same settings the control plane signs for
# gateway, proxy and engine (absent keys use the documented defaults). Without
# --inspection-scope no scope rule runs and older decisions are unchanged.
inspection_scope=None
if INSPECTION_SCOPE_MODE=='live':
 defaults={'inspect_user_input':True,'inspect_model_output':True,'inspect_builtin_context':False,'inspect_history':False,'inspect_tool_results':True}
 stored=dict(line.split('|',1) for line in sql("SELECT key||'|'||value FROM system_settings WHERE key IN ('inspect_user_input','inspect_model_output','inspect_builtin_context','inspect_history','inspect_tool_results');").splitlines() if '|' in line)
 inspection_scope={key:(stored[key].strip().lower()=='true') if stored.get(key,'').strip() else default for key,default in defaults.items()}
 report['inspection_scope_builtin_context']=int(inspection_scope['inspect_builtin_context'])
def digest(value): return hashlib.sha256(json.dumps(value,ensure_ascii=False,separators=(',',':'),sort_keys=True).encode()).hexdigest()
if APPLY:
 os.umask(0o077)
 folder=Path('/opt/jjdguard/maintenance-backups');folder.mkdir(mode=0o700,exist_ok=True)
 backup_path=folder/('alert-evidence-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.jsonl')
 backup=backup_path.open('x')
while True:
 query="SELECT json_build_object('id',id,'tenant_id',tenant_id,'severity',severity,'effective_severity',effective_severity,'alert_group_id',alert_group_id,'matched_summary',matched_summary) FROM security_events WHERE jsonb_typeof(matched_summary->'findings')='array' AND id>"+quote(last)+" ORDER BY id LIMIT 250;"
 rows=[json.loads(line) for line in sql(query).splitlines() if line.startswith('{')]
 if not rows: break
 updates=[]; expected=[]
 for row in rows:
  last=row['id'];report['events_examined']+=1
  review_source=copy.deepcopy(row['matched_summary']);manual_reasons=[]
  for decision in review_decisions:
   if decision['event_id']!=row['id'] or decision['tenant_id']!=row['tenant_id']: continue
   if digest(row['matched_summary'])!=decision['expected_summary_sha256']:
    report['review_fingerprint_skipped']+=1;continue
   index=decision['finding_index'];items=review_source.get('findings',[])
   if index>=len(items) or hashlib.sha256(str(items[index].get('evidence_context') or '').encode()).hexdigest()!=decision['expected_context_sha256']:
    report['review_fingerprint_skipped']+=1;continue
   finding=items[index]
   if finding.get('counts_as_security_finding') is False:continue
   finding['evidence_revalidation']={'version':VERSION,'status':'reference','reason':decision['reason'],'reviewer':'codex-context-review','expected_context_sha256':decision['expected_context_sha256'],'original_counts_as_security_finding':finding.get('counts_as_security_finding')}
   finding['counts_as_security_finding']=False;manual_reasons.append(decision['reason'])
  result=revalidate(review_source,row['severity'],inspection_scope=inspection_scope)
  if manual_reasons:
   revised=result[0] if result else review_source
   active=[f for f in revised['findings'] if isinstance(f,dict) and f.get('counts_as_security_finding') is not False]
   revised['findings_count']=len(active)
   primary=revised.get('primary_finding')
   if isinstance(primary,dict):
    for finding in revised['findings']:
     if isinstance(finding,dict) and all(finding.get(k)==primary.get(k) for k in ('rule_id','matched_location','message_index','raw_evidence')):
      revised['primary_finding']=copy.deepcopy(finding);break
   revised['evidence_revalidation']={'version':VERSION,'original_severity':row['severity'],'reasons':manual_reasons+(result[2] if result else [])}
   level=max((f.get('severity',row['severity']) for f in active),key=lambda v:RANK.get(v,0),default='low')
   result=(revised,level,revised['evidence_revalidation']['reasons'])
  if result is None:
   if not isinstance(row['matched_summary'].get('evidence_revalidation'),dict): continue
   revised=row['matched_summary']
   active=[f for f in revised['findings'] if isinstance(f,dict) and f.get('counts_as_security_finding') is not False]
   severity=max((f.get('severity',row['severity']) for f in active),key=lambda v:RANK.get(v,0),default='low')
   reasons=[]
  else:
   revised,severity,reasons=result
  if row.get('alert_group_id'): groups.add((row['tenant_id'],row['alert_group_id']))
  if result is None and row['effective_severity']==severity: continue
  report['events_correctable']+=1
  if severity=='low': report['events_without_confirmed_risk']+=1
  report.update(reasons)
  if APPLY:
   backup.write(json.dumps({'table':'security_events','row':row},ensure_ascii=False)+'\n')
   # Authored severity/evidence stays intact; only the effective classification changes.
   update="UPDATE security_events SET matched_summary="+quote(json.dumps(revised))+"::jsonb,effective_severity="+quote(severity)+" WHERE id="+quote(row['id'])+" AND tenant_id="+quote(row['tenant_id'])+" AND matched_summary="+quote(json.dumps(row['matched_summary']))+"::jsonb AND severity="+quote(row['severity'])+" AND effective_severity IS NOT DISTINCT FROM "+nullable(row['effective_severity'])+" AND alert_group_id IS NOT DISTINCT FROM "+nullable(row['alert_group_id'])+" RETURNING id;"
   updates.append(update);expected.append(row['id'])
 if updates:
  backup.flush();os.fsync(backup.fileno())
  returned=set(sql('BEGIN;\n'+'\n'.join(updates)+'\nCOMMIT;').splitlines())
  report['events_corrected']+=sum(i in returned for i in expected)
  report['concurrent_change_skipped']+=sum(i not in returned for i in expected)
# Recompute affected group effective state from every member, never just its
# selected example. Status/read acknowledgements and original bodies survive.
if APPLY and groups:
 for tenant,group_id in sorted(groups):
  q="SELECT row_to_json(ag),(SELECT COUNT(*) FROM security_events e WHERE e.tenant_id=ag.tenant_id AND e.alert_group_id=ag.id),(SELECT COALESCE(MAX(CASE COALESCE(NULLIF(e.effective_severity,''),e.severity) WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END),0) FROM security_events e WHERE e.tenant_id=ag.tenant_id AND e.alert_group_id=ag.id) FROM alert_groups ag WHERE ag.tenant_id="+quote(tenant)+" AND ag.id="+quote(group_id)+";"
  lines=sql(q).splitlines()
  if not lines: continue
  raw,member_count,member_rank=lines[0].rsplit('|',2)
  before=json.loads(raw);body_json=dict(before.get('body_json') or {})
  original_rank=RANK.get(before.get('effective_severity') or before['severity'],0)
  cached_rank=original_rank
  for key in ('matched','matched_summary'):
   cached=body_json.get(key)
   if not isinstance(cached,dict) or not isinstance(cached.get('findings'),list): continue
   revised_cached=revalidate(cached,before['severity'],inspection_scope=inspection_scope)
   if revised_cached: cached=revised_cached[0];body_json[key]=cached
   cached_rank=max((RANK.get(f.get('severity',before['severity']),original_rank) for f in cached['findings'] if isinstance(f,dict) and f.get('counts_as_security_finding') is not False),default=0)
   break
  previous=body_json.get('evidence_revalidation') or {}
  note={'version':VERSION,'original_effective_severity':previous.get('original_effective_severity',before.get('effective_severity')),'original_disposition_class':previous.get('original_disposition_class',before.get('disposition_class'))}
  body_json['evidence_revalidation']=note
  expected_rank=max(int(member_rank),cached_rank,original_rank if int(member_count)<before['occurrence_count'] else 0)
  expected_level=['low','medium','high','critical'][expected_rank]
  expected_disposition='informational' if expected_rank==0 else before.get('disposition_class')
  if before.get('effective_severity')==expected_level and before.get('disposition_class')==expected_disposition and body_json==before.get('body_json'): continue
  backup.write(json.dumps({'table':'alert_groups','row':before},ensure_ascii=False)+'\n');backup.flush();os.fsync(backup.fileno())
  # Members can change without touching a group's updated_at. Freeze both
  # tables briefly and calculate the maximum inside this transaction. Missing
  # retained occurrences and unmatched cached risk preserve the old maximum.
  member_sql="SELECT COUNT(*) AS n,COALESCE(MAX(CASE COALESCE(NULLIF(effective_severity,''),severity) WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END),0) AS r FROM security_events WHERE tenant_id="+quote(tenant)+" AND alert_group_id="+quote(group_id)
  rank_sql="GREATEST(m.r,"+str(cached_rank)+",CASE WHEN m.n<ag.occurrence_count THEN "+str(original_rank)+" ELSE 0 END)"
  level_sql="CASE "+rank_sql+" WHEN 3 THEN 'critical' WHEN 2 THEN 'high' WHEN 1 THEN 'medium' ELSE 'low' END"
  update="WITH m AS ("+member_sql+") UPDATE alert_groups ag SET effective_severity="+level_sql+",disposition_class=CASE WHEN "+rank_sql+"=0 THEN 'informational' ELSE ag.disposition_class END,body_json="+quote(json.dumps(body_json))+"::jsonb,updated_at=now() FROM m WHERE ag.tenant_id="+quote(tenant)+" AND ag.id="+quote(group_id)+" AND to_jsonb(ag)="+quote(json.dumps(before))+"::jsonb RETURNING ag.id;"
  changed=group_id in set(sql('BEGIN; LOCK TABLE alert_groups,security_events IN SHARE ROW EXCLUSIVE MODE;\n'+update+'\nCOMMIT;').splitlines())
  report['groups_corrected' if changed else 'groups_concurrent_change_skipped']+=1
 # Notification snapshots have their own retained evidence. Revalidate it too,
 # and never downgrade below either the live group or unresolved cached risk.
 for tenant,group_id in sorted(groups):
  query="SELECT json_build_object('row',row_to_json(ai),'group_updated_at',ag.updated_at,'group_severity',COALESCE(NULLIF(ag.effective_severity,''),ag.severity)) FROM alert_inbox ai JOIN alert_groups ag ON ag.tenant_id=ai.tenant_id AND ag.id=ai.body_json->>'alert_group_id' WHERE ai.tenant_id="+quote(tenant)+" AND ag.id="+quote(group_id)+" AND ai.type='security_event';"
  for line in sql(query).splitlines():
   current=json.loads(line);before=current['row'];body=dict(before.get('body_json') or {})
   old_rank={'info':0,'warning':1,**RANK}.get(before['severity'],0)
   cached_rank=old_rank;cached=body.get('matched')
   if isinstance(cached,dict) and isinstance(cached.get('findings'),list):
    result=revalidate(cached,body.get('severity','low'),inspection_scope=inspection_scope)
    if result: cached=result[0];body['matched']=cached
    cached_rank=max((RANK.get(f.get('severity','low'),old_rank) for f in cached['findings'] if isinstance(f,dict) and f.get('counts_as_security_finding') is not False),default=0)
   rank=max(cached_rank,RANK.get(current['group_severity'],old_rank))
   effective=['low','medium','high','critical'][rank];notification=['info','warning','high','critical'][rank]
   previous=body.get('evidence_revalidation') or {}
   body['evidence_revalidation']={'version':VERSION,'original_severity':previous.get('original_severity',before['severity']),'effective_severity':effective}
   body['severity']=effective
   if before['severity']==notification and body==before.get('body_json'):continue
   backup.write(json.dumps({'table':'alert_inbox','row':before},ensure_ascii=False)+'\n');backup.flush();os.fsync(backup.fileno())
   update="UPDATE alert_inbox ai SET severity="+quote(notification)+",body_json="+quote(json.dumps(body))+"::jsonb FROM alert_groups ag WHERE ai.tenant_id="+quote(tenant)+" AND ai.id="+quote(before['id'])+" AND ag.tenant_id=ai.tenant_id AND ag.id="+quote(group_id)+" AND ag.updated_at="+quote(current['group_updated_at'])+"::timestamptz AND to_jsonb(ai)="+quote(json.dumps(before))+"::jsonb RETURNING ai.id;"
   changed=before['id'] in set(sql('BEGIN; LOCK TABLE alert_groups,alert_inbox IN SHARE ROW EXCLUSIVE MODE;\n'+update+'\nCOMMIT;').splitlines())
   report['inbox_corrected' if changed else 'inbox_concurrent_change_skipped']+=1
if backup: backup.close()
print(json.dumps({'mode':'apply' if APPLY else 'dry-run','version':VERSION,'inspection_scope':inspection_scope,'counts':dict(report),'backup_path':str(backup_path) if backup_path else None},ensure_ascii=False))
'''

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--apply',action='store_true')
 parser.add_argument('--review-file',type=Path,help='Exact reviewed occurrence decisions with expected evidence hashes')
 parser.add_argument('--inspection-scope',choices=['live'],help='Also withdraw semantic verdicts on builtin context when the live scope excludes it')
 args=parser.parse_args()
 decisions=json.loads(args.review_file.read_text()) if args.review_file else []
 if not isinstance(decisions,list): raise ValueError('review decisions must be a list')
 for decision in decisions:
  if not isinstance(decision,dict) or type(decision.get('finding_index')) is not int or not 0<=decision['finding_index']<=100000: raise ValueError('invalid review finding index')
  for key in ('tenant_id','event_id','reason','expected_summary_sha256','expected_context_sha256'):
   if not isinstance(decision.get(key),str) or not decision[key]: raise ValueError('incomplete review decision')
 names=['app.detectors.pii_checksum','app.detectors.numeric_context','app.detectors.config_evidence','app.detectors.data_leak','app.detectors.policy_catalog','app.alert_evidence_validation']
 sources=[(name,(ROOT/'apps/security-engine'/Path(*name.split('.'))).with_suffix('.py').read_text()) for name in names]
 code=GUEST.replace('SOURCES',repr(sources)).replace('APPLY',repr(args.apply)).replace('REVIEW_DECISIONS',repr(decisions)).replace('INSPECTION_SCOPE_MODE',repr(args.inspection_scope))
 guest('jjdguard-gateway',code,seconds=900)

if __name__=='__main__':main()
