#!/usr/bin/env python3
"""Re-disposition persisted alert groups on the test VM; dry-run by default.
Only groups the trusted-development routing rule proves are observation-only are
moved from action_required to informational. The rule itself lives in
deploy/maintenance/trusted_dev_route.py and is executed verbatim inside the VM,
so this sweep reaches the same verdict the live bridge reaches -- on rows that
were written before the rule existed. Evidence is read from the representative
security event, not from the group body, so an event revised after the group was
written is judged on its current evidence. Every update is a compare-and-swap on
updated_at and the original row is kept in a protected before-image, so a
concurrent bridge write is never clobbered. Status is never changed and no event
is ever deleted.
"""
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"deploy/release"))
from deploy_vm_development import guest

GUEST = r'''import sys,types,json,subprocess,collections,os,datetime
from pathlib import Path
for name,source in __SOURCES__:
 mod=types.ModuleType(name);mod.__path__=[];sys.modules[name]=mod
 exec(compile(source,name,'exec'),mod.__dict__)
from trusted_dev_route import trusted_development_route,VERSION,ROUTE_NAME
containers=json.loads(subprocess.check_output(['docker','inspect']+subprocess.check_output(['docker','ps','-q'],text=True).split(),text=True))
pg=next(c for c in containers if c['Config'].get('Labels',{}).get('com.docker.compose.service')=='postgres')
env=dict(v.split('=',1) for v in pg['Config']['Env'] if '=' in v)
base=['docker','exec','-i',pg['Id'],'psql','-X','-v','ON_ERROR_STOP=1','-U',env.get('POSTGRES_USER','postgres'),'-d',env.get('POSTGRES_DB','postgres'),'-At']
def sql(s):
 return subprocess.check_output(base,input=s,text=True)
def quote(s): return "'"+s.replace("'","''")+"'"
agents=__CONFIG__.get('agents') or None
principals=__CONFIG__.get('principals') or None
tenant=__CONFIG__.get('tenant') or ''
limit=__CONFIG__.get('limit') or 0
report=collections.Counter();by_reason=collections.Counter();last='';backup=None;applied=0
if __APPLY__:
 os.umask(0o077)
 folder=Path('/opt/jjdguard/maintenance-backups');folder.mkdir(mode=0o700,exist_ok=True)
 backup=(folder/('trusted-dev-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.jsonl')).open('x',encoding='utf-8')
filters=["ag.status IN ('open','acknowledged')","COALESCE(NULLIF(ag.disposition_class,''),'action_required')='action_required'"]
if tenant: filters.append("ag.tenant_id="+quote(tenant))
filters=' AND '.join(filters)
# The row version is rendered server-side in a fixed shape so the compare-and-swap
# in the UPDATE clause compares equal to the value we just read.
column_list=("json_build_object('id',ag.id,'tenant_id',ag.tenant_id,'status',ag.status,"
 "'disposition_class',ag.disposition_class,'body_json',ag.body_json,"
 "'event_id',se.id,'event_type',se.event_type,'severity',se.severity,'action_taken',se.action_taken,"
 "'principal_key',COALESCE(NULLIF(se.principal_key,''),COALESCE(ag.principal_key,'')),"
 "'matched_summary',se.matched_summary,"
 "'row_version',to_char(ag.updated_at,'YYYY-MM-DD\"T\"HH24:MI:SS.US'))")
def page_query(after):
 return ("SELECT "+column_list+" FROM alert_groups ag LEFT JOIN security_events se ON se.id=ag.representative_event_id AND se.tenant_id=ag.tenant_id WHERE "+filters+" AND ag.id>"+quote(after)+" ORDER BY ag.id LIMIT 250;")
while True:
 rows=[json.loads(line) for line in sql(page_query(last)).splitlines() if line.startswith('{')]
 if not rows: break
 updates=[];expected=[];captured=[];stop=False
 for row in rows:
  last=row['id'];report['groups_examined']+=1
  if not row.get('event_id'):
   # No representative event left to judge: fail closed, leave it actionable.
   report['groups_without_event']+=1;continue
  event={'event_type':row.get('event_type') or '','severity':row.get('severity') or '','action_taken':row.get('action_taken') or '','principal_key':row.get('principal_key') or '','matched_summary':row.get('matched_summary') or {}}
  route,routed=trusted_development_route(event,agents=agents,principals=principals)
  if not routed: continue
  report['groups_routed']+=1;by_reason[route['reason']]+=1
  if not __APPLY__: continue
  if limit and applied+len(updates)>=limit:
   stop=True;break
  captured.append(row)
  patch={'triage_route':{'route':route['route'],'reason':route['reason']}}
  updates.append("UPDATE alert_groups SET disposition_class='informational', body_json=body_json||"+quote(json.dumps(patch))+"::jsonb, updated_at=NOW() WHERE id="+quote(row['id'])+" AND tenant_id="+quote(row['tenant_id'])+" AND COALESCE(NULLIF(disposition_class,''),'action_required')='action_required' AND to_char(updated_at,'YYYY-MM-DD\"T\"HH24:MI:SS.US')="+quote(row['row_version'])+" RETURNING id;")
  expected.append(row['id'])
 if updates:
  for row in captured: backup.write(json.dumps(row,ensure_ascii=False)+'\n')
  backup.flush();os.fsync(backup.fileno())
  returned=set(sql('BEGIN;\n'+'\n'.join(updates)+'\nCOMMIT;').splitlines())
  report['groups_redisposed']+=sum(i in returned for i in expected)
  report['concurrent_change_skipped']+=sum(i not in returned for i in expected)
  applied+=len(updates)
 if stop: break
if backup: backup.close()
print(json.dumps({'mode':'apply' if __APPLY__ else 'dry-run','version':VERSION,'route':ROUTE_NAME,'limit':limit,'counts':dict(report),'by_reason':dict(by_reason)},ensure_ascii=False))
'''

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--apply',action='store_true',help='write the redispositions (default is a dry run)')
 parser.add_argument('--tenant',default='',help='restrict the sweep to a single tenant_id')
 parser.add_argument('--limit',type=int,default=0,help='write at most N groups, useful to rehearse the write path')
 args=parser.parse_args()
 config={'tenant':args.tenant,'limit':args.limit}
 source=(ROOT/"deploy/maintenance/trusted_dev_route.py").read_text()
 # Distinct placeholders, so substituting the rule source (which itself contains
 # the word SOURCES inside MACHINE_SOURCES) cannot collide with a later replace.
 code=GUEST.replace('__SOURCES__',repr([('trusted_dev_route',source)])).replace('__CONFIG__',repr(config)).replace('__APPLY__',repr(args.apply))
 guest('jjdguard-gateway',code,seconds=900)

if __name__=='__main__':main()
