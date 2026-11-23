"""Controlled VM configuration/crypto rotation; no image or certificate replacement."""
import copy
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request

TARGETS=('control-plane','gateway-core','proxy-server','security-engine')
TOKEN_ENV='JJD_INTERNAL_API_SECRET'
HEADER='X-JJDGuard-Internal-Token'
ROOT=Path('/opt/jjdguard')


class RotationError(Exception):
    pass


def command(argv, *, data=None, timeout=180):
    result=subprocess.run(argv,input=data,text=True,capture_output=True,timeout=timeout)
    if result.returncode:
        raise RotationError('command_failed_'+Path(argv[0]).name)
    return result.stdout


def quote(value):
    return "'"+str(value).replace("'","''")+"'"


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def atomic(path,content,owner=None):
    path=Path(path);temporary=path.with_name(path.name+'.rotation-new')
    with temporary.open('xb') as stream:
        os.fchmod(stream.fileno(),0o600)
        if owner:os.fchown(stream.fileno(),owner.st_uid,owner.st_gid)
        stream.write(content);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


def identities(rows):
    return {key:dict(id=value['Id'],image=value['Image'],started=value['State']['StartedAt'],restarts=value['RestartCount']) for key,value in rows.items()}


def inspect(project=None):
    ids=command(['docker','ps','-aq']).split()
    rows=json.loads(command(['docker','inspect',*ids]))
    if project is None:
        controls=[row for row in rows if (row['Config'].get('Labels') or {}).get('com.docker.compose.service')=='control-plane' and row['State']['Status']=='running']
        if len(controls)!=1:raise RotationError('ambiguous_control_plane')
        project=controls[0]['Config']['Labels']['com.docker.compose.project']
    result={}
    for row in rows:
        labels=row['Config'].get('Labels') or {}
        if labels.get('com.docker.compose.project')!=project:continue
        service=labels.get('com.docker.compose.service')
        if service in result:raise RotationError('duplicate_service')
        result[service]=row
    return project,result


def environment(row):
    return dict(value.split('=',1) for value in row['Config'].get('Env',[]) if '=' in value)


def sql_batch(table,rows):
    if table=='ca':
        columns='id text,tenant_id text,old_value text,new_value text'
        update='UPDATE ca_certificates p SET private_key_encrypted=v.new_value FROM v WHERE p.id=v.id AND p.tenant_id IS NOT DISTINCT FROM v.tenant_id AND p.private_key_encrypted=v.old_value RETURNING p.id'
    else:
        columns='tenant_id text,request_id text,part_index integer,old_payload text,old_result text,new_payload text,new_result text'
        update='UPDATE proxy_inspection_parts p SET payload_encrypted=v.new_payload,result_encrypted=v.new_result FROM v WHERE p.tenant_id=v.tenant_id AND p.request_id=v.request_id AND p.part_index=v.part_index AND p.payload_encrypted=v.old_payload AND p.result_encrypted=v.old_result RETURNING p.request_id'
    values=quote(json.dumps(rows,ensure_ascii=False,separators=(',',':')))
    return 'WITH v AS (SELECT * FROM jsonb_to_recordset('+values+'::jsonb) AS x('+columns+')),changed AS ('+update+') SELECT 1/(CASE WHEN COUNT(*)='+str(len(rows))+' THEN 1 ELSE 0 END) FROM changed;\n'


def prepare_rekey(sql,old,new,path,crypto,probe=None):
    counts={'ca':0,'parts':0};batch=[];batch_bytes=0
    with Path(path).open('x',encoding='utf-8') as output:
        os.chmod(path,0o600)
        output.write("BEGIN; SET LOCAL lock_timeout='5s'; LOCK TABLE ca_certificates,proxy_inspection_parts IN SHARE ROW EXCLUSIVE MODE;\n")
        ca_query="SELECT json_build_object('id',id,'tenant_id',tenant_id,'value',private_key_encrypted) FROM ca_certificates WHERE private_key_encrypted LIKE 'enc:ca:v1:%' ORDER BY tenant_id,id"
        ca_rows=[json.loads(line) for line in sql(ca_query).splitlines()]
        for row in ca_rows:
            revised=crypto.rewrap_ca(row['value'],old,new)
            batch.append(dict(id=row['id'],tenant_id=row['tenant_id'],old_value=row['value'],new_value=revised));counts['ca']+=1
            if probe is not None and not probe:probe.update(query='SELECT private_key_encrypted FROM ca_certificates WHERE id='+quote(row['id']),old=row['value'],new=revised)
        output.write("SELECT 1/(CASE WHEN COUNT(*)="+str(counts['ca'])+" THEN 1 ELSE 0 END) FROM ca_certificates WHERE private_key_encrypted LIKE 'enc:ca:v1:%';\n")
        if batch:output.write(sql_batch('ca',batch))
        batch=[];cursor=None
        expected=int(sql("SELECT COUNT(*) FROM proxy_inspection_parts WHERE payload_encrypted<>'' OR result_encrypted<>''").strip())
        if expected>100000:raise RotationError('queue_rotation_limit')
        output.write("SELECT 1/(CASE WHEN COUNT(*)="+str(expected)+" THEN 1 ELSE 0 END) FROM proxy_inspection_parts WHERE payload_encrypted<>'' OR result_encrypted<>'';\n")
        while True:
            where="(payload_encrypted<>'' OR result_encrypted<>'')"
            if cursor:where+=' AND (tenant_id,request_id,part_index)>('+','.join((quote(cursor[0]),quote(cursor[1]),str(cursor[2])))+')'
            query="SELECT json_build_object('tenant_id',tenant_id,'request_id',request_id,'part_index',part_index,'payload',payload_encrypted,'result',result_encrypted) FROM proxy_inspection_parts WHERE "+where+' ORDER BY tenant_id,request_id,part_index LIMIT 100'
            rows=[json.loads(line) for line in sql(query).splitlines()]
            if not rows:break
            for row in rows:
                tenant,request,index=row['tenant_id'],row['request_id'],row['part_index']
                item=dict(tenant_id=tenant,request_id=request,part_index=index,old_payload=row['payload'],old_result=row['result'],new_payload=crypto.rewrap_part(row['payload'],tenant,request,index,'payload',old,new),new_result=crypto.rewrap_part(row['result'],tenant,request,index,'result',old,new))
                if probe is not None and not probe:
                    kind='payload' if row['payload'] else 'result'
                    probe.update(query='SELECT '+kind+'_encrypted FROM proxy_inspection_parts WHERE tenant_id='+quote(tenant)+' AND request_id='+quote(request)+' AND part_index='+str(index),old=row[kind],new=item['new_'+kind])
                batch.append(item);batch_bytes+=sum(len(str(v)) for v in item.values());counts['parts']+=1
                if len(batch)>=100 or batch_bytes>=8*1024*1024:
                    output.write(sql_batch('parts',batch));batch=[];batch_bytes=0
                cursor=(tenant,request,index)
        if batch:output.write(sql_batch('parts',batch))
        if counts['parts']!=expected:raise RotationError('queue_changed_during_plan')
        output.write('COMMIT;\n');output.flush();os.fsync(output.fileno())
    return counts


def http_status(url,token,header=HEADER):
    request=urllib.request.Request(url,headers={header:token})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request,timeout=5) as response:return response.status
    except urllib.error.HTTPError as error:return error.code
    except Exception:return 0


def authentication_endpoints(rows):
    routes={'control-plane':(8081,'/admin/v1/internal/security/semantic-config/gateway'),
            'gateway-core':(8080,'/admin/v1/internal/metrics'),
            'proxy-server':(3128,'/internal/v1/inspection-scope/status'),
            'security-engine':(8000,'/ready')}
    result={}
    for service,(port,path) in routes.items():
        row=rows[service]
        addresses=[item.get('IPAddress') for item in row['NetworkSettings'].get('Networks',{}).values() if item.get('IPAddress')]
        address=addresses[0] if addresses else '127.0.0.1' if row['HostConfig'].get('NetworkMode')=='host' else ''
        try:address=str(ipaddress.ip_address(address))
        except ValueError:raise RotationError('runtime_address_unavailable') from None
        if ':' in address:address='['+address+']'
        result[service]=f'http://{address}:{port}{path}'
    return result


def rotate(apply,revision,vm,crypto):
    os.umask(0o077)
    project,rows=inspect()
    if any(name not in rows for name in (*TARGETS,'postgres')):raise RotationError('missing_service')
    before=identities(rows)
    if any(rows[name]['State']['Status']!='running' for name in TARGETS):raise RotationError('baseline_not_running')
    authentication_endpoints(rows)
    labels=rows['control-plane']['Config']['Labels'];workdir=Path(labels['com.docker.compose.project.working_dir']).resolve()
    if not workdir.is_relative_to(ROOT/'releases'):raise RotationError('unexpected_release_path')
    old=environment(rows['control-plane']).get(TOKEN_ENV,'')
    if len(old)<16 or any(environment(rows[name]).get(TOKEN_ENV)!=old for name in TARGETS):raise RotationError('inconsistent_internal_secret')
    baseline_auth={name:http_status(url,old,'X-JJDGuard-Internal-Secret' if name=='gateway-core' else HEADER) for name,url in authentication_endpoints(rows).items()}
    if any(status!=200 for status in baseline_auth.values()):raise RotationError('baseline_authentication_unavailable:'+','.join(name+'='+str(status) for name,status in baseline_auth.items()))
    if any(old in value for name,row in rows.items() for key,value in environment(row).items() if not (name in TARGETS and key==TOKEN_ENV)):
        raise RotationError('unexpected_secret_reuse')
    binary=workdir/'bin/docker-compose'
    def compose(files,*args):
        call=[str(binary),'--project-directory',str(workdir),'-p',project]
        for file in files:call+=['-f',str(file)]
        return command(call+list(args),timeout=180)
    def render(files):return json.loads(compose(files,'config','--format','json'))
    def image_id(name):return json.loads(command(['docker','image','inspect',name]))[0]['Id']
    canonical,inputs=vm.resolve_release_compose(rows,workdir,TARGETS,False,render,image_id)
    model=render(canonical)
    env_path=workdir/'.env';env_before=env_path.read_bytes();env_stat=env_path.stat()
    match=list(re.finditer(rb'(?m)^JJD_INTERNAL_API_SECRET=([^\r\n]*)',env_before))
    if len(match)!=1 or match[0].group(1).strip(b'\"\x27').decode()!=old:raise RotationError('persistent_secret_differs')
    pg=rows['postgres']['Id'];pg_env=environment(rows['postgres'])
    psql=['docker','exec','-i',pg,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U',pg_env['POSTGRES_USER'],'-d',pg_env['POSTGRES_DB']]
    def sql(query):return command(psql,data="SET statement_timeout='60s';\n"+query+';')
    inspection=int(sql("SELECT COUNT(*) FROM proxy_inspection_parts WHERE payload_encrypted<>'' OR result_encrypted<>''").strip())
    certificate_query="SELECT COALESCE(json_agg(json_build_object('id',id,'tenant_id',tenant_id,'certificate_pem',certificate_pem) ORDER BY id),'[]'::json) FROM ca_certificates"
    certificate_fingerprint=hashlib.sha256(sql(certificate_query).encode()).hexdigest()
    active_ca=sql("SELECT id FROM ca_certificates WHERE status='active' AND ca_type='root' AND expires_at>NOW() AND (tenant_id IS NULL OR tenant_id IN ('tenant_default','default')) ORDER BY CASE WHEN tenant_id='tenant_default' THEN 0 WHEN tenant_id IS NULL THEN 1 ELSE 2 END,created_at DESC LIMIT 1").strip()
    if not active_ca:raise RotationError('no_persistent_active_ca')
    report=dict(mode='apply' if apply else 'dry-run',source_revision=revision,application_revision=environment(rows['control-plane']).get('JJD_COMMIT'),project=project,affected_services=list(TARGETS),encrypted_queue_rows=inspection)
    if not apply:
        print(json.dumps(report));return
    run_id=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
    state=ROOT/'maintenance-backups'/('internal-secret-'+run_id);state.mkdir(mode=0o700)
    new=secrets.token_hex(32);candidate=copy.deepcopy(model)
    for name,item in candidate['services'].items():
        if name in TARGETS:
            item['image']=rows[name]['Image']
            item.pop('build',None);item.pop('env_file',None);item['pull_policy']='never'
        env=item.get('environment',{})
        if TOKEN_ENV in env:
            if env[TOKEN_ENV]==old:env[TOKEN_ENV]=new
            elif name in TARGETS:raise RotationError('candidate_secret_differs')
    new_path=workdir/'active-config'/('internal-secret-'+run_id+'.json')
    candidate_bytes=(json.dumps(candidate,indent=2)+'\n').encode()
    atomic(state/'candidate.json',candidate_bytes)
    if render((state/'candidate.json',))!=candidate:raise RotationError('candidate_round_trip_differs')
    atomic(state/'original-env',env_before)
    atomic(state/'original-model.json',(json.dumps(model,indent=2)+'\n').encode())
    input_hashes={str(path):digest(path) for path in (*inputs,binary,env_path)}
    atomic(state/'before.json',json.dumps(dict(runtime=before,inputs=input_hashes,canonical=[str(p) for p in canonical]),indent=2).encode())
    interface=json.loads(command(['ip','-j','route','show','default']))[0]['dev']
    ports={item['HostPort'] for name,row in rows.items() if name in (*TARGETS,'web-console','chat-portal-proxy') for items in (row['HostConfig'].get('PortBindings') or {}).values() for item in (items or [])}
    chain='JJDROT'+secrets.token_hex(5).upper();fenced=False;chain_created=False;release_fence=False;stopping_started=False
    db_changed=False;switched=False;data_phase_unknown=False;env_changed=False;active_config_written=False
    def verify_runtime(expected,revoke):
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            current=inspect(project)[1];endpoints=authentication_endpoints(current)
            statuses={name:http_status(url,expected,'X-JJDGuard-Internal-Secret' if name=='gateway-core' else HEADER) for name,url in endpoints.items()}
            if all(status==200 for status in statuses.values()) and all(current[name]['State']['Status']=='running' and current[name]['RestartCount']==0 for name in TARGETS):break
            time.sleep(2)
        else:raise RotationError('authentication_not_ready')
        rejected={name:http_status(url,revoke,'X-JJDGuard-Internal-Secret' if name=='gateway-core' else HEADER) for name,url in endpoints.items()}
        if any(status not in (401,403) for status in rejected.values()):raise RotationError('retired_authentication_still_accepted')
        for name in TARGETS:
            actual=environment(current[name]);original=environment(rows[name])
            if current[name]['Image']!=rows[name]['Image'] or actual.get(TOKEN_ENV)!=expected or {k:v for k,v in actual.items() if k!=TOKEN_ENV}!={k:v for k,v in original.items() if k!=TOKEN_ENV}:raise RotationError('runtime_configuration_differs')
        if {k:v for k,v in identities(current).items() if k not in TARGETS}!={k:v for k,v in before.items() if k not in TARGETS}:raise RotationError('non_target_runtime_changed')
        if hashlib.sha256(sql(certificate_query).encode()).hexdigest()!=certificate_fingerprint:raise RotationError('public_certificate_changed')
        logs=subprocess.run(['docker','logs',current['proxy-server']['Id']],capture_output=True,text=True,timeout=30)
        startup=logs.stdout+logs.stderr
        if ('Activated MITM root CA id='+active_ca) not in startup or 'No active CA found, generating self-signed' in startup:raise RotationError('proxy_did_not_load_original_ca')
        return statuses,rejected
    lock=(ROOT/'development-releases/.release.lock').open('a')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BaseException:
        lock.close();raise
    try:
        if identities(inspect(project)[1])!=before or any(digest(path)!=value for path,value in input_hashes.items()):raise RotationError('baseline_changed')
        command(['iptables','-N',chain]);chain_created=True
        for port in sorted(ports):command(['iptables','-A',chain,'-p','tcp','-m','conntrack','--ctdir','ORIGINAL','--ctorigdstport',port,'-j','REJECT'])
        command(['iptables','-I','DOCKER-USER','1','-i',interface,'-j',chain]);fenced=True
        print(json.dumps({'phase':'fenced_and_stopping','state':str(state)}),flush=True)
        stopping_started=True
        compose(canonical,'stop','--timeout','25',*TARGETS)
        with (state/'database.dump').open('xb') as stream:
            result=subprocess.run(['docker','exec',pg,'pg_dump','-Fc','-U',pg_env['POSTGRES_USER'],'-d',pg_env['POSTGRES_DB']],stdout=stream,stderr=subprocess.PIPE,timeout=300)
            if result.returncode:raise RotationError('database_backup_failed')
        with (state/'database.dump').open('rb') as stream:
            result=subprocess.run(['docker','exec','-i',pg,'pg_restore','--list'],stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60)
            if result.returncode:raise RotationError('database_backup_invalid')
        probe={}
        counts=prepare_rekey(sql,old,new,state/'forward.sql',crypto,probe)
        print(json.dumps({'phase':'prepared_reencryption','counts':counts}),flush=True)
        data_phase_unknown=True
        try:
            with (state/'forward.sql').open() as stream:
                result=subprocess.run(psql,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=300)
        finally:
            if probe:
                persisted=sql(probe['query']).strip()
                if persisted not in (probe['old'],probe['new']):raise RotationError('database_commit_outcome_unknown')
                db_changed=persisted==probe['new']
            data_phase_unknown=False
        if result.returncode or (probe and not db_changed):raise RotationError('database_reencryption_failed')
        if any(digest(path)!=value for path,value in input_hashes.items()):raise RotationError('configuration_changed_during_rotation')
        env_new=env_before[:match[0].start(1)]+new.encode()+env_before[match[0].end(1):]
        atomic(env_path,env_new,env_stat)
        env_changed=True
        atomic(new_path,candidate_bytes);active_config_written=True
        switched=True
        compose((new_path,),'up','-d','--no-deps','--pull','never','--force-recreate',*TARGETS)
        statuses,rejected=verify_runtime(new,old)
        report.update(status='rotated',counts=counts,new_authentication=statuses,old_authentication=rejected,certificate_material_changed=False,images_changed=False,backup=str(state/'database.dump'),configuration=str(new_path),new_token_sha256=hashlib.sha256(new.encode()).hexdigest())
        atomic(state/'receipt.json',(json.dumps(report,indent=2)+'\n').encode())
    except BaseException as failure:
        atomic(state/'failure.json',json.dumps({'error_type':type(failure).__name__,'code':str(failure) if isinstance(failure,RotationError) else 'protected_rotation_error','database_changed':db_changed,'configuration_switched':switched}).encode())
        if not stopping_started:
            release_fence=True
            raise RotationError('preflight_failed_without_service_changes') from None
        if data_phase_unknown:raise RotationError('database_phase_unknown_ingress_remains_fenced') from None
        try:
            if switched:compose((new_path,),'stop','--timeout','25',*TARGETS)
            if db_changed:
                reverse_probe={}
                prepare_rekey(sql,new,old,state/'rollback.sql',crypto,reverse_probe)
                try:
                    with (state/'rollback.sql').open() as stream:
                        result=subprocess.run(psql,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=300)
                finally:
                    if reverse_probe and sql(reverse_probe['query']).strip()!=reverse_probe['new']:raise RotationError('rollback_reencryption_not_verified')
                if result.returncode:raise RotationError('rollback_reencryption_failed')
            if env_changed:
                if env_path.read_bytes()!=env_new:raise RotationError('environment_changed_during_rollback')
                atomic(env_path,env_before,env_stat)
            compose(canonical,'up','-d','--no-deps','--pull','never','--force-recreate',*TARGETS)
            verify_runtime(old,new)
            if active_config_written:
                if new_path.read_bytes()!=candidate_bytes:raise RotationError('candidate_changed_during_rollback')
                os.replace(new_path,state/'unused-candidate-config.json')
            atomic(state/'rollback.json',json.dumps({'status':'rolled_back','token_rotation_complete':False}).encode())
        except BaseException:
            raise RotationError('rollback_failed_ingress_remains_fenced') from None
        raise RotationError('rotation_failed_rolled_back') from None
    finally:
        try:
            if chain_created and (release_fence or (state/'receipt.json').exists() or (state/'rollback.json').exists()):
                if fenced:command(['iptables','-D','DOCKER-USER','-i',interface,'-j',chain])
                command(['iptables','-F',chain]);command(['iptables','-X',chain])
        finally:lock.close()
    print(json.dumps(report),flush=True)
