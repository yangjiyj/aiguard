#!/usr/bin/env python3
"""Run portal authorization PostgreSQL tests in an owned disposable database."""
import argparse,json,os,secrets,subprocess,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(args,**kw):
 result=subprocess.run(args,**kw)
 if result.returncode: raise RuntimeError('test subprocess failed, exit='+str(result.returncode)+'; inspect protected test log')
 return result
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--modules',choices=['all','control-plane','gateway-core'],default='all')
 parser.add_argument('--full-unit',action='store_true',help='Full changed-package suite with mandatory DB contracts; focused identity DB tests run separately')
 parser.add_argument('--pattern',default='TestPersonalExtraGrant|TestUnconfiguredDepartment|TestDepartmentDefaultMigration|TestUserModelAccessSameDepartment|TestPortalUserAuthorizationContext|TestTenantAdminModel|TestPortalOwnedKeyProject')
 args=parser.parse_args()
 name='jjdguard-chat-portal-test-'+uuid.uuid4().hex[:16]
 label='com.jjdguard.chat-portal-test.owner'
 owner=uuid.uuid4().hex
 password=secrets.token_urlsafe(24)
 created=False
 logdir=ROOT/'work/chat-portal-self-service';logdir.mkdir(parents=True,exist_ok=True)
 try:
  run(['docker','run','-d','--name',name,'--label',label+'='+owner,'-e','POSTGRES_USER=jjd_portal_test','-e','POSTGRES_PASSWORD='+password,'-e','POSTGRES_DB=jjd_portal_test','-p','127.0.0.1::5432','-v',str(ROOT/'deploy/migrations')+':/migrations:ro','-v',str(ROOT/'deploy/docker-compose/initdb/001_init_enterprise.sql')+':/docker-entrypoint-initdb.d/001_init_enterprise.sql:ro','-v',str(ROOT/'deploy/lib')+':/migration-lib:ro','postgres:16'],stdout=subprocess.DEVNULL)
  created=True
  for _ in range(120):
   ready=subprocess.run(['docker','exec',name,'psql','-U','jjd_portal_test','-d','jjd_portal_test','-Atc',"SELECT to_regclass('public.audit_dispositions') IS NOT NULL"],capture_output=True,text=True)
   if ready.returncode==0 and ready.stdout.strip()=='t':break
   time.sleep(1)
  else:raise RuntimeError('isolated PostgreSQL did not initialize')
  with (logdir/'db-migrations.log').open('w') as log:
   run(['docker','exec','-e','PGHOST=127.0.0.1','-e','PGPORT=5432','-e','PGUSER=jjd_portal_test','-e','PGPASSWORD='+password,'-e','PGDATABASE=jjd_portal_test','-e','MIGRATION_PSQL=/usr/bin/psql',name,'/bin/bash','/migration-lib/migration-runner.sh','--migrations-dir','/migrations'],stdout=log,stderr=subprocess.STDOUT)
  port=json.loads(subprocess.check_output(['docker','inspect','--format','{{json .NetworkSettings.Ports}}',name],text=True))['5432/tcp'][0]['HostPort']
  dsn='postgres://jjd_portal_test:'+password+'@127.0.0.1:'+port+'/jjd_portal_test?sslmode=disable'
  env={**os.environ,'GOWORK':'off','GOFLAGS':'-buildvcs=false','NODE_OPTIONS':'--max-old-space-size=2048','CONTENT_LOGS_TEST_DATABASE_URL':dsn,'CONSOLE_LOGIN_TEST_DATABASE_URL':dsn,'C_WHITELIST_TEST_DATABASE_URL':dsn,'MCP_SUPPLY_CHAIN_TEST_DATABASE_URL':dsn,'MCP_ANALYSIS_TEST_DATABASE_URL':dsn,'BILLING_TEST_DATABASE_URL':dsn,'JJD_REQUIRE_IDENTITY_DB_TESTS':'1'}
  if args.full_unit:
   env.pop('CONTENT_LOGS_TEST_DATABASE_URL',None);env.pop('CONSOLE_LOGIN_TEST_DATABASE_URL',None);env.pop('JJD_REQUIRE_IDENTITY_DB_TESTS',None)
   env['GOFLAGS']='-buildvcs=false'
  failures=0
  for module,packages in [('apps/control-plane',['./internal/repository','./internal/handler']+(['./internal/permission','./internal/billing','./internal/auth','./internal/identitybinding'] if args.full_unit else [])),('apps/gateway-core',['./internal/handler','./internal/auth']+(['./internal/governor'] if args.full_unit else []))]:
   if args.modules!='all' and not module.endswith(args.modules):continue
   command=['/usr/local/go/bin/go','test','-json',*packages,'-run','.' if args.full_unit else args.pattern,'-count=1','-p','1']
   result=subprocess.run(command,cwd=ROOT/module,env=env,capture_output=True,text=True)
   (logdir/(module.replace('/','-')+('-full-unit.json' if args.full_unit else '-db-tests.json'))).write_text(result.stdout.replace(password,'[REDACTED]'))
   passed=[];skipped=[]
   for line in result.stdout.splitlines():
    try:e=json.loads(line)
    except json.JSONDecodeError:continue
    if e.get('Action')=='fail' and e.get('Test'):print('FAIL:',e['Test'])
    if e.get('Action')=='pass' and e.get('Test'):passed.append(e['Test'])
    if e.get('Action')=='skip':skipped.append(e.get('Test',e.get('Package')))
    if not args.full_unit and e.get('Action') in ['output','build-output'] and ('Error:' in e.get('Output','') or '--- FAIL:' in e.get('Output','') or '_test.go:' in e.get('Output','')):print(e['Output'].rstrip())
   if result.stderr:print(result.stderr.replace(password,'[REDACTED]'))
   print(module,'passed='+str(len(passed)),'skipped='+str(len(skipped)),'exit='+str(result.returncode),flush=True)
   failures+=int(result.returncode!=0 or (not args.full_unit and bool(skipped)) or not passed)
  if args.full_unit:
   mandatory_env={**env,'CONTENT_LOGS_TEST_DATABASE_URL':dsn,'CONSOLE_LOGIN_TEST_DATABASE_URL':dsn,'JJD_REQUIRE_IDENTITY_DB_TESTS':'1'}
   gateway_binary=logdir/'review-gateway-process'
   build=subprocess.run(['/usr/local/go/bin/go','build','-o',str(gateway_binary),'./cmd/server'],cwd=ROOT/'apps/gateway-core',env=mandatory_env,capture_output=True,text=True)
   if build.returncode:
    print(build.stderr.replace(password,'[REDACTED]'));failures+=1
   else:
    mandatory_env['PORTAL_PROXY_GATEWAY_TEST_BINARY']=str(gateway_binary)
    required_pattern='TestReview|TestPersonalExtraGrant|TestUnconfiguredDepartment|TestDepartmentDefaultMigration|TestDepartmentModelModesAPI|TestUserModelAccess|TestPortalUserAuthorizationContext|TestTenantAdminModel|TestPortalOwnedKey|TestAccountMerge|TestEmployeeManagedKey|TestPersonalEmployeeCredential|TestEmployeeAPIKey|TestEmployeeAccountLockout|TestEmployeeAdministrator|TestEmployeeForwardedIP|TestEmployeeTrustedProxy|TestEmployeeDirectoryFailures|TestPortalBoundIdentityProxyAndRealGateway'
    for module,packages in [('apps/control-plane',['./internal/repository','./internal/handler']),('apps/gateway-core',['./internal/handler','./internal/auth']),('packages/shared-go',['./modelaccess','./modelcatalog','./userhistory'])]:
     if args.modules!='all' and not module.endswith(args.modules) and module!='packages/shared-go':continue
     command=['/usr/local/go/bin/go','test','-json',*packages,'-run',required_pattern,'-count=1','-p','1']
     result=subprocess.run(command,cwd=ROOT/module,env=mandatory_env,capture_output=True,text=True)
     (logdir/(module.replace('/','-')+'-mandatory-review-pg.json')).write_text(result.stdout.replace(password,'[REDACTED]'))
     counts={'pass':0,'fail':0,'skip':0}
     for line in result.stdout.splitlines():
      try:e=json.loads(line)
      except json.JSONDecodeError:continue
      if e.get('Action') in counts and e.get('Test'):counts[e['Action']]+=1
      if e.get('Action') in ['output','build-output'] and ('--- FAIL:' in e.get('Output','') or '_test.go:' in e.get('Output','')):print(e['Output'].rstrip())
     if result.stderr:print(result.stderr.replace(password,'[REDACTED]'))
     print(module,'mandatory_review_pg',counts,'exit='+str(result.returncode),flush=True)
     failures+=int(result.returncode!=0 or counts['skip']>0 or counts['pass']==0)
  if failures:raise SystemExit(1)
 finally:
  if created:
   actual=subprocess.run(['docker','inspect','--format','{{index .Config.Labels "'+label+'"}}',name],capture_output=True,text=True)
   if actual.returncode==0 and actual.stdout.strip()==owner:run(['docker','rm','-f','-v',name],stdout=subprocess.DEVNULL)
if __name__=='__main__':main()
