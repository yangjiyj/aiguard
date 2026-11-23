"""VM-side protected snapshot, dry-run plan and approved-plan CAS application."""
import collections, copy, datetime, hashlib, json, os, pathlib, subprocess, sys, types
os.umask(0o077)
options=OPTIONS
core=types.ModuleType('semantic_recompute');exec(CORE,core.__dict__)
containers=json.loads(subprocess.check_output(['docker','inspect']+subprocess.check_output(['docker','ps','-q'],text=True).split(),text=True))
pg=next(c for c in containers if c['Config'].get('Labels',{}).get('com.docker.compose.service')=='postgres')
se=next(c for c in containers if c['Config'].get('Labels',{}).get('com.docker.compose.service')=='security-engine')
base=['docker','exec','-i',pg['Id'],'psql','-X','-v','ON_ERROR_STOP=1','-U','jjdguard','-d','jjdguard','-qAt']
def sql(query,write=False):
 if not write:query='BEGIN READ ONLY; SET LOCAL statement_timeout=\'120s\'; '+query+'; COMMIT;'
 return subprocess.check_output(base,input=query,text=True)
def q(value):return "'"+str(value).replace("'","''")+"'"
def rows(query):return [json.loads(v) for v in sql(query).splitlines() if v.startswith('{')]
folder=pathlib.Path(options['output']);folder.mkdir(mode=0o700,parents=True,exist_ok=True)
if options.get('apply_plan'):
 plan_path=pathlib.Path(options['apply_plan']);raw=plan_path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=options['plan_sha256']:raise RuntimeError('reviewed plan hash mismatch')
 plan=json.loads(raw);backup=folder/('before-apply-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.jsonl')
 changes=plan['changes']
 with backup.open('x') as f:
  for c in changes:f.write(json.dumps({'table':c['table'],'row':c['before']},ensure_ascii=False)+'\n')
  f.flush();os.fsync(f.fileno())
 sql(core.build_apply_sql(changes,plan.get('group_guards',[])),write=True)
 print(json.dumps({'applied':len(changes),'tables':dict(collections.Counter(c['table'] for c in changes)),'backup':str(backup)}));sys.exit(0)

previous={}
for line in pathlib.Path(options['previous_backup']).read_text().splitlines():
 b=json.loads(line)
 if b['table']=='security_events':previous[(b['row']['tenant_id'],b['row']['id'])]=b['row']
events=rows("SELECT row_to_json(e) FROM security_events e WHERE e.created_at>="+q(options['since'])+" AND jsonb_typeof(e.matched_summary->'findings')='array' AND EXISTS(SELECT 1 FROM jsonb_array_elements(e.matched_summary->'findings') f WHERE f->>'type'='semantic_attack') ORDER BY e.id")
stored=dict(line.split('|',1) for line in sql("SELECT key||'|'||value FROM system_settings WHERE key IN ('judge_url','judge_model','judge_backend','judge_allow_private_egress')").splitlines() if '|' in line)
cfg={k:stored.get(k,'') for k in ('judge_url','judge_model','judge_backend')};cfg['priv']=stored.get('judge_allow_private_egress')=='true'
snapshot_path=folder/'snapshot.json'
if snapshot_path.exists():
 snapshot=json.loads(snapshot_path.read_text());events=snapshot['events'];items=snapshot['items']
else:
 items=[];requests={}
 for e in events:
  tenant=e['tenant_id'];rid=e.get('request_id');identity=(tenant,rid)
  if identity not in requests:
   rs=rows('SELECT row_to_json(r) FROM request_logs r WHERE tenant_id='+q(tenant)+' AND request_id='+q(rid)+' ORDER BY created_at DESC LIMIT 1') if rid else []
   request=rs[0] if rs else {}
   content=rows('SELECT row_to_json(c) FROM content_logs c WHERE tenant_id='+q(tenant)+' AND request_id='+q(request.get('id',''))+' ORDER BY message_index') if request else []
   access=rows('SELECT row_to_json(a) FROM access_content_logs a WHERE tenant_id='+q(tenant)+' AND request_id='+q(rid)+' ORDER BY created_at DESC LIMIT 1') if rid else []
   parts=rows('SELECT row_to_json(p) FROM proxy_inspection_parts p WHERE tenant_id='+q(tenant)+' AND request_id='+q(rid)+' ORDER BY part_index') if rid else []
   requests[identity]={'request':request,'content':content,'access':access[0] if access else {},'parts':parts}
  retained=requests[identity];prior=previous.get((tenant,e['id']));originals=(prior or e)['matched_summary'].get('findings',[])
  for index,current in enumerate(e['matched_summary'].get('findings',[])):
   if current.get('type')!='semantic_attack':continue
   old=current.get('evidence_revalidation') or {}
   if current.get('counts_as_security_finding') is False and old.get('version')!='semantic-revalidate-v1':continue
   if old.get('version')=='semantic-revalidate-v1' and (not prior or index>=len(originals)):raise RuntimeError('missing previous before-image')
   finding=originals[index] if old.get('version')=='semantic-revalidate-v1' else current
   context=finding.get('task_context') or finding.get('triage',{}).get('task_context')
   if not context and retained['content']:
    index_value=finding.get('message_index')
    refs=[{'content':c['content'],'message_role':c['role'],'message_index':c.get('message_index'),'content_source':'user' if c['role']=='user' else c['role'],'alert_target':False,'inspection_is_history':True} for c in retained['content'] if c.get('message_index')!=index_value and c.get('content')]
    context={'judgment_context':refs[-32:]} if refs else None
   items.append(dict(retained,event_id=e['id'],tenant_id=tenant,request_id=rid,finding_index=index,finding=finding,agent_type=retained['request'].get('agent_type') or e['matched_summary'].get('agent_type') or '<null>',task_context=context))
 snapshot={'events':events,'previous':list(previous.values()),'items':items}
 (folder/'snapshot.json').write_text(json.dumps(snapshot,ensure_ascii=False))
print('snapshot_events='+str(len(events))+' previous_events='+str(len(previous))+' findings='+str(len(items)),flush=True)
previous_outcomes=json.loads((folder/'outcomes.json').read_text()) if options.get('reuse_outcomes') and (folder/'outcomes.json').exists() else {}
if previous_outcomes:
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 for name in ('summary.json','plan.json','outcomes.json'):
  existing=folder/name
  if existing.exists():(folder/(stamp+'-'+name)).write_bytes(existing.read_bytes())
prior_ids={row['id'] for row in previous.values()}
items.sort(key=lambda i:(0 if i['agent_type'] in ('hermes-agent','workbuddy') else 1 if i['event_id'] in prior_ids else 2,i['event_id'],i['finding_index']))
payload=json.dumps({'core':CORE,'config':cfg,'items':items,'max_calls':options['max_judge_calls'],'previous':previous_outcomes},ensure_ascii=False)
with (folder/'judge-stderr.log').open('w') as err:
 raw=subprocess.check_output(['docker','exec','-i',se['Id'],'python3','-c',WORKER],input=payload,text=True,stderr=err,timeout=10800)
judged=json.loads(raw.strip().splitlines()[-1]);(folder/'outcomes.json').write_text(json.dumps(judged,ensure_ascii=False))
outcomes={(r['event_id'],r['finding_index']):r for r in judged['results']}
group_guards=[];changes=[];planned={};counts=collections.Counter();grouped=collections.defaultdict(collections.Counter);affected=set()
for e in events:
 revised=copy.deepcopy(e['matched_summary']);prior=previous.get((e['tenant_id'],e['id']));originals=(prior or e)['matched_summary'].get('findings',[])
 for index,current in enumerate(revised.get('findings',[])):
  result=outcomes.get((e['id'],index))
  if result is None:continue
  original=originals[index] if index<len(originals) else current
  replacement,decision=core.reconcile_finding(current,original,result)
  revised['findings'][index]=replacement;counts[decision]+=1;counts['outcome_'+result['outcome']]+=1
  grouped[result['agent_type']+'|'+result['source']][result['outcome']]+=1
 if revised==e['matched_summary']:continue
 revised,level=core.recompute_summary(revised,e['severity'])
 revised['evidence_revalidation']={'version':core.VERSION,'recomputed_against':'exact-evidence-plan','previous_backup':options['previous_backup']}
 after={'matched_summary':revised,'effective_severity':level};changes.append({'table':'security_events','before':e,'after':after});planned[(e['tenant_id'],e['id'])]=dict(e,**after)
 if e.get('alert_group_id'):affected.add((e['tenant_id'],e['alert_group_id']))
for tenant,gid in sorted(affected):
 groups=rows('SELECT row_to_json(g) FROM alert_groups g WHERE tenant_id='+q(tenant)+' AND id='+q(gid))
 if not groups:continue
 g=groups[0];members=rows('SELECT row_to_json(e) FROM security_events e WHERE tenant_id='+q(tenant)+' AND alert_group_id='+q(gid))
 occurrence_rows=rows('SELECT row_to_json(o) FROM security_event_occurrences o WHERE tenant_id='+q(tenant)+' AND alert_group_id='+q(gid))
 group_guards.append({'tenant_id':tenant,'group_id':gid,'security_events':members,'security_event_occurrences':occurrence_rows})
 counters=rows(COUNTER_SQL.replace('$1',q(tenant)).replace('$2',q(gid)))[0]
 members=[planned.get((tenant,m['id']),m) for m in members]
 rank=max((core.RANK.get(m.get('effective_severity') or m['severity'],0) for m in members),default=0)
 # Missing retained occurrences cannot justify lowering an unresolved group.
 if len(members)<g['occurrence_count']:rank=max(rank,core.RANK.get(g.get('effective_severity') or g['severity'],0));counts['groups_missing_occurrences_preserved']+=1
 level=['low','medium','high','critical'][rank];body=copy.deepcopy(g.get('body_json') or {})
 representative=next((m for m in members if m['id']==g.get('representative_event_id')),None)
 if representative:
  for key in ('matched','matched_summary'):
   if key in body:body[key]=representative['matched_summary']
 body['evidence_revalidation']={'version':core.VERSION,'member_events':len(members),'review_plan':str(folder/'plan.json')}
 disposition='informational' if rank==0 else ('action_required' if g.get('disposition_class')=='informational' and any((m['tenant_id'],m['id']) in planned for m in members) else g.get('disposition_class'))
 after={'effective_severity':level,'disposition_class':disposition,'body_json':body,'distinct_occurrences':counters['occ'],'affected_users':counters['users'],'last_calc_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 changes.append({'table':'alert_groups','before':g,'after':after})
 for n in rows("SELECT row_to_json(n) FROM alert_inbox n WHERE tenant_id="+q(tenant)+" AND body_json->>'alert_group_id'="+q(gid)):
  nb=copy.deepcopy(n.get('body_json') or {});nb['severity']=level;nb['evidence_revalidation']={'version':core.VERSION,'effective_severity':level}
  if representative and 'matched' in nb:nb['matched']=representative['matched_summary']
  changes.append({'table':'alert_inbox','before':n,'after':{'severity':['info','warning','high','critical'][rank],'body_json':nb}})
summary={'mode':'dry-run','previous_events':len(previous),'events_examined':len(events),'findings':len(items),'judge_calls':judged['judge_calls'],'unique_targets':judged['unique_targets'],'stopped_on_unavailable':judged['stopped_on_unavailable'],'counts':dict(counts),'by_agent_source':{k:dict(v) for k,v in sorted(grouped.items())},'planned_tables':dict(collections.Counter(c['table'] for c in changes)),'applied':False,'previous_backup':options['previous_backup'],'snapshot':str(folder/'snapshot.json')}
plan={'version':core.VERSION,'summary':summary,'changes':changes,'group_guards':group_guards}
path=folder/'plan.json';path.write_text(json.dumps(plan,ensure_ascii=False))
summary['plan_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();summary['plan_path']=str(path)
(folder/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2));print(json.dumps(summary,ensure_ascii=False),flush=True)
