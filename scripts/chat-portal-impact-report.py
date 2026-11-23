#!/usr/bin/env python3
"""Read-only VM model-admission impact report; never reads credential values."""
import argparse,base64,json,re,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--output',default='work/chat-portal-self-service/model-access-impact.md');args=parser.parse_args()
 predicate=re.search(r'const CallablePredicate = `([\s\S]*?)`',(ROOT/'packages/shared-go/modelcatalog/availability.go').read_text()).group(1)
 selects={
 'users':"SELECT u.id,u.tenant_id,u.username,u.role,u.status,u.department_id,u.department_assignment_mode,COALESCE(um.mode,'inherit') mode,COALESCE(um.model_names,'[]'::jsonb) model_names,COALESCE(um.version,0) version FROM users u LEFT JOIN user_model_policies um ON um.tenant_id=u.tenant_id AND um.user_id=u.id",
 'models':'SELECT m.id,m.model_name,p.tenant_id,('+predicate+') callable FROM models m JOIN providers p ON p.id=m.provider_id',
  'teams':"SELECT t.id,t.tenant_id,t.name,t.path,t.model_access_mode,t.system_key,t.is_system,(t.model_access_mode='deny_all' OR EXISTS(SELECT 1 FROM team_models tm WHERE tm.team_id=t.id) OR EXISTS(SELECT 1 FROM audit_operations a WHERE a.target_type='team' AND a.target_id=t.id AND (a.tenant_id=t.tenant_id OR a.tenant_id IS NULL) AND a.action_type='team.models.update')) historically_configured FROM teams t",
 'team_models':'SELECT team_id,model_id,allowed FROM team_models',
 'projects':'SELECT id,tenant_id,team_id,status FROM projects',
 'memberships':'SELECT project_id,user_id FROM project_users',
 'keys':"SELECT id,tenant_id,project_id,user_id FROM internal_keys WHERE status='active' AND (expires_at IS NULL OR expires_at>statement_timestamp()) AND user_id IS NOT NULL",
 'model_policies':"SELECT project_id,allow_models_json,deny_models_json FROM model_policies WHERE scope_type='project'",
 'quota_policies':"SELECT tenant_id,scope_type,scope_ref,key_id,project_id,user_id,enforcement_mode FROM quota_policies WHERE status='active'",
 }
 query="BEGIN READ ONLY; SELECT json_build_object('at',statement_timestamp(),"+','.join("'"+name+"',(SELECT COALESCE(json_agg(row_to_json(x)),'[]'::json) FROM ("+sql+") x)" for name,sql in selects.items())+"); ROLLBACK;"
 code='\n'.join([
 'import subprocess,json',
 "names=subprocess.check_output(['docker','ps','--format','{{.Names}}'],text=True).splitlines()",
 "pg=next(n for n in names if n.endswith('-postgres-1') and not n.endswith('-chat-postgres-1'))",
 'query='+repr(query),
 "r=subprocess.run(['docker','exec',pg,'sh','-c','exec psql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -At -v ON_ERROR_STOP=1 -c \"$1\"','sh',query],capture_output=True,text=True)",
 "if r.returncode:raise RuntimeError('read-only model admission query failed')",
 "data=json.loads(next(line for line in r.stdout.splitlines() if line.startswith('{')))",
 "gw=next(n for n in names if n.endswith('-gateway-core-1'))",
 "inspection=json.loads(subprocess.check_output(['docker','inspect',gw],text=True))[0]",
 "data['governor_disabled']=any(s=='UAG_GOVERNOR_DISABLED=true' for s in inspection['Config']['Env'])",
 'print(json.dumps(data,ensure_ascii=False))'])
 def qga(request):
  r=subprocess.run(['virsh','qemu-agent-command','jjdguard-gateway',json.dumps(request)],capture_output=True,text=True)
  if r.returncode:raise RuntimeError('VM guest-agent operation failed')
  return json.loads(r.stdout)['return']
 pid=qga({'execute':'guest-exec','arguments':{'path':'/usr/bin/python3','arg':['-c',code],'capture-output':True}})['pid']
 for _ in range(60):
  result=qga({'execute':'guest-exec-status','arguments':{'pid':pid}})
  if result.get('exited'):
   if result.get('exitcode'):raise RuntimeError('VM read-only report query failed')
   data=json.loads(base64.b64decode(result['out-data']).decode());break
  time.sleep(1)
 else:raise RuntimeError('VM read-only report still running; inspect pid='+str(pid))
 directory=ROOT/'work/chat-portal-self-service';directory.mkdir(parents=True,exist_ok=True)
 (directory/'impact-snapshot.json').write_text(json.dumps(data,ensure_ascii=False,indent=2))
 teams={t['id']:t for t in data['teams']};projects={p['id']:p for p in data['projects']}
 models=[m for m in data['models'] if m['callable']];policies={p['project_id']:p for p in data['model_policies']}
 def allowed(team,model,after=False):
  if after and team and not team['is_system'] and team['model_access_mode']=='allowlist' and not team['historically_configured']:return True
  return bool(team) and (team['model_access_mode']=='all_active' or (team['model_access_mode']=='allowlist' and any(t['team_id']==team['id'] and t['model_id']==model['id'] and t['allowed'] for t in data['team_models'])))
 def mode(user,project,key):
  ancestors=set((teams.get(project.get('team_id')) or {}).get('path','').strip('/').split('/'));modes=[]
  for q in data['quota_policies']:
   if q['tenant_id']!=user['tenant_id']:continue
   s=q['scope_type'];match=s=='tenant' or (s=='project' and q['project_id']==project['id']) or (s=='user' and q['user_id']==user['id']) or (s=='key' and key and q['key_id']==key) or (s=='team' and q['scope_ref'] in ancestors)
   if match and q['enforcement_mode']!='accounting':modes.append(q['enforcement_mode'] or 'soft')
  return max(modes,key=lambda x:{'bypass':0,'soft':1,'enforce':2}.get(x,1)) if modes else 'soft'
 rows=[]
 for u in data['users']:
  if u['status']!='active':continue
  team=teams.get(u['department_id']);eligible=team is not None and u['department_assignment_mode'] not in ['emergency','service']
  department={m['model_name'] for m in models if m['tenant_id']==u['tenant_id'] and allowed(team,m,True)}
  base=department if u['mode']=='inherit' else department & set(u['model_names'])
  old_department={m['model_name'] for m in models if m['tenant_id']==u['tenant_id'] and allowed(team,m)}
  old_base=old_department if u['mode']=='inherit' else old_department&set(u['model_names'])
  after=base if eligible and team.get('system_key')!='unassigned' else set();governed=u['role']=='chat_user' or u['version']>0
  keys=[k for k in data['keys'] if k['tenant_id']==u['tenant_id'] and k['user_id']==u['id']]
  scopes={(k['project_id'],k['id']) for k in keys}|{(m['project_id'],'') for m in data['memberships'] if m['user_id']==u['id']}
  before=set();modes=set()
  for project_id,key in scopes:
   p=projects.get(project_id)
   if not p or p['tenant_id']!=u['tenant_id'] or p['status']!='active':continue
   model_mode=mode(u,p,key);modes.add(model_mode);policy=policies.get(project_id,{})
   allow=policy.get('allow_models_json') or [];deny=policy.get('deny_models_json') or []
   for m in models:
    name=m['model_name']
    if m['tenant_id']!=u['tenant_id'] or name in deny or (allow and name not in allow):continue
    if governed and (not eligible or name not in old_base):continue
    if not data['governor_disabled'] and model_mode=='enforce' and p.get('team_id') and not allowed(teams.get(p['team_id']),m):continue
    before.add(name)
  rows.append({'username':u['username'],'role':u['role'],'owned_keys':len(keys),'scopes':len(scopes),'quota_modes':sorted(modes),'before':sorted(before),'after':sorted(after),'removed':sorted(before-after)})
 affected=[r for r in rows if r['removed']]
 lines=['# 开发 VM 模型授权收口影响（只读）','', '采集时间（数据库）：`'+data['at']+'`。VM：`192.168.56.10`；基线：`051e3e80`。','',
 '统计口径：单个 READ ONLY 事务读取非凭据字段；旧集合按当前有效用户 Key 与已分配有效应用的模型准入并集计算，含项目名单及数据库 governor 模式。新集合按用户已确认的新默认规则、当前部门与个人收窄计算。普通部门无模型条目且无历史 team.models.update 审计时，迁移 973 识别为未配置，默认开放全部可调用模型；有条目或配置审计时保留。若历史配置审计已清除且条目也为空，现存数据无法区分曾配置空名单与未配置，该识别依据在此明确列出。本次未为存量账号新增额外授权。忽略瞬时限流、余额/预算占用和上游网络故障；旧目录缓存可能有最多 5 分钟漂移。这是模型准入数据库快照，不等于实时上游成功率。','',
 '未读取密码、Key 明文/密文/hash、token 或供应商凭据值；未修改开发 VM 数据。','',
 '| 用户名 | 角色 | 有效用户 Key | 应用/Key 路径数 | 现可用模型数 | 收口后模型数 | 减少数 |','| --- | --- | ---: | ---: | ---: | ---: | ---: |']
 for r in rows:lines.append('| '+r['username'].replace('|','\\|')+' | '+r['role']+' | '+str(r['owned_keys'])+' | '+str(r['scopes'])+' | '+str(len(r['before']))+' | '+str(len(r['after']))+' | '+str(len(r['removed']))+' |')
 lines+=['','将从未配置改为默认开放的普通部门：'+('、'.join(t['name'] for t in data['teams'] if not t['is_system'] and t['model_access_mode']=='allowlist' and not t['historically_configured']) or '无')+'。','', '减少模型的账号：'+str(len(affected))+'。']
 for r in affected:
  lines+=['','## '+r['username']+'（'+r['role']+'）','', '配额模型模式：`'+','.join(r['quota_modes'])+'`。']
  for label,field in [('现可用','before'),('收口后','after'),('差异模型（减少）','removed')]:lines+=['',label+'：'+('、'.join('`'+m+'`' for m in r[field]) or '无')+'。']
 out=ROOT/args.output;out.parent.mkdir(parents=True,exist_ok=True);out.write_text('\n'.join(lines)+'\n')
 print('active_accounts='+str(len(rows))+' affected_accounts='+str(len(affected)))
 for r in affected:print(r['username'],r['role'],'before='+str(len(r['before'])),'after='+str(len(r['after'])),'removed='+str(len(r['removed'])))
 print('report='+str(out))
if __name__=='__main__':main()
