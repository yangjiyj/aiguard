#!/usr/bin/env python3
"""Recheck retained text; preserve original failures. Dry-run by default."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'release'))
from deploy_vm_development import guest
GUEST = r'''
import collections,datetime,json,os,subprocess
from pathlib import Path
os.umask(0o077)
VERSION='retained-text-recheck-v1'
rows=json.loads(subprocess.check_output(['docker','inspect']+subprocess.check_output(['docker','ps','-q'],text=True).split(),text=True))
def service(name): return next(c for c in rows if c['Config'].get('Labels',{}).get('com.docker.compose.service')==name)
pg=service('postgres');engine=service('security-engine')
env=dict(x.split('=',1) for x in pg['Config']['Env'])
base=['docker','exec','-i',pg['Id'],'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U',env['POSTGRES_USER'],'-d',env['POSTGRES_DB']]
def sql(query): return subprocess.check_output(base,input="SET statement_timeout='20s'; SET lock_timeout='3s';\n"+query,text=True)
def quote(text): return "'"+str(text).replace("'","''")+"'"
query="""
SELECT jsonb_build_object('tenant',j.tenant_id,'request',j.request_id,'environment',j.environment_scope,
 'event',e.id,'summary',e.matched_summary,'snapshot',md5(e.matched_summary::text),'project',COALESCE(e.project_id,'project_default'),
 'text',CASE WHEN a.retention_until IS NULL OR a.retention_until>now() THEN COALESCE(a.request_content_redacted,'') ELSE '' END)
FROM proxy_inspection_jobs j
JOIN security_events e ON e.tenant_id=j.tenant_id AND e.id=encode(sha256(convert_to('proxy-inspection:'||j.tenant_id||':'||j.request_id,'UTF8')),'hex')
LEFT JOIN LATERAL(SELECT request_content_redacted,retention_until FROM access_content_logs a
 WHERE a.tenant_id=j.tenant_id AND a.request_id=j.request_id AND a.environment_scope=j.environment_scope ORDER BY created_at DESC LIMIT 1) a ON true
WHERE j.status='failed' AND j.created_at<'2026-09-19T11:30:00Z'::timestamptz
 AND (COALESCE(e.matched_summary#>>'{remediation,version}','')<>'retained-text-recheck-v1' OR (RETRY AND e.matched_summary#>>'{remediation,status}'='recheck_incomplete'))
ORDER BY j.created_at,j.request_id;
"""
items=[json.loads(line) for line in sql(query).splitlines() if line.startswith('{')]
if TASK_LIMIT: items=items[:TASK_LIMIT]
counts=collections.Counter(inventory=len(items),retained_text=sum(bool(x['text'].strip()) for x in items))
print(json.dumps(dict(counts)),flush=True)
if not APPLY: raise SystemExit(0)
folder=Path('/opt/jjdguard/maintenance-backups');folder.mkdir(mode=0o700,exist_ok=True)
backup_path=folder/('retained-text-recheck-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.jsonl')
backup=backup_path.open('x')
probe=r"""
import concurrent.futures,hashlib,json,os,sys,urllib.request
from app.semantic_config_loader import _auth_headers
item=json.load(sys.stdin)
headers={'Content-Type':'application/json','X-JJDGuard-Internal-Token':os.environ['JJD_INTERNAL_API_SECRET']}
req=urllib.request.Request(os.environ['CONTROL_PLANE_URL']+'/admin/v1/internal/security/semantic-config/engine',headers=_auth_headers(os.environ['JJD_INTERNAL_API_SECRET']))
with urllib.request.urlopen(req,timeout=10) as response: revision=json.load(response)['revision']
prior=item.get('cache',{})
cached=prior.get('results',{}) if prior.get('revision')==revision else {}
text=item['text'];size=2048;step=1792
windows=[text[n:n+size] for n in range(0,len(text),step)]
def inspect(pair):
 index,content=pair;sha=hashlib.sha256(content.encode()).hexdigest()
 if sha in cached:return sha,cached[sha]
 payload={'request_id':'retained-recheck:'+item['request']+':'+str(index),'content':content,'content_source':'unknown','project_id':item['project'],'context':{'tenant_id':item['tenant'],'maintenance_recheck':True}}
 req=urllib.request.Request('http://127.0.0.1:8000/check-input/',data=json.dumps(payload).encode(),headers=headers)
 try:
  with urllib.request.urlopen(req,timeout=40) as response: out=json.load(response)
  complete=out.get('inspection_status')=='completed' and out.get('semantic_status') not in ('incomplete','unavailable','failed') and out.get('semantic_config_revision')==revision
  return sha,{'complete':complete,'engine_build':out.get('engine_build',''),'finding_count':len(out.get('findings',[])),'reason':out.get('semantic_reason','') or out.get('inspection_reason','')}
 except Exception as exc:return sha,{'complete':False,'reason':type(exc).__name__,'finding_count':0}
# At most two calls; successful identical windows are reused only inside the
# same tenant/project and exact signed semantic revision.
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(inspect,enumerate(windows)))
completed=sum(result['complete'] for _,result in results)
for sha,result in results:
 if result['complete']:cached[sha]=result
failures=[r.get('reason','incomplete') for _,r in results if not r['complete']]
print(json.dumps({'status':'partial_rechecked' if completed==len(windows) else 'recheck_incomplete','engine_build':next((r.get('engine_build') for _,r in results if r.get('engine_build')),''),'semantic_config_revision':revision,'finding_count':sum(r['finding_count'] for _,r in results),'windows':len(windows),'completed_windows':completed,'reason':failures[0] if failures else '', 'window_cache':{'revision':revision,'results':cached}}))
"""
window_cache={}

for index,item in enumerate(items):
 result={'status':'retained_content_unavailable','reason':'original_payload_purged'}
 if item['text'].strip():
  data={key:item[key] for key in ('request','tenant','text','project')}
  data['cache']=window_cache.get((item['tenant'],item['project']),{})
  try:
   proc=subprocess.run(['docker','exec','-i',engine['Id'],'python','-c',probe],input=json.dumps(data),capture_output=True,text=True,timeout=900)
   result=json.loads(proc.stdout)
   window_cache[(item['tenant'],item['project'])]=result.pop('window_cache',{})
  except Exception: result={'status':'recheck_incomplete','reason':'invalid_engine_response'}
 remediation={**result,'version':VERSION,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'coverage':'retained_text_only' if item['text'].strip() else 'none','original_gap_resolved':False}
 # Protected before-image, flushed before CAS. No content or credentials in stdout.
 backup.write(json.dumps({'tenant':item['tenant'],'event':item['event'],'before':item['summary'],'remediation':remediation})+'\n');backup.flush();os.fsync(backup.fileno())
 patch=json.dumps({'remediation':remediation})
 changed=sql('UPDATE security_events SET matched_summary=matched_summary || '+quote(patch)+'::jsonb WHERE tenant_id='+quote(item['tenant'])+' AND id='+quote(item['event'])+' AND md5(matched_summary::text)='+quote(item['snapshot'])+' RETURNING id;').strip()
 counts[result['status'] if changed else 'concurrent_change_skipped']+=1
 if (index+1)%10==0: print(json.dumps({'processed':index+1,**dict(counts)}),flush=True)
backup.close()
print(json.dumps({'done':True,'backup':str(backup_path),**dict(counts)}),flush=True)
'''
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--apply',action='store_true')
 parser.add_argument('--retry-incomplete',action='store_true')
 parser.add_argument('--limit',type=int,default=0)
 args=parser.parse_args()
 guest('jjdguard-gateway',GUEST.replace('APPLY',repr(args.apply)).replace('RETRY','TRUE' if args.retry_incomplete else 'FALSE').replace('TASK_LIMIT',str(max(0,args.limit))),seconds=3600)
if __name__=='__main__': main()

