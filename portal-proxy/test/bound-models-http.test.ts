import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const root = new URL('../', import.meta.url).pathname;
async function listen(server: http.Server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return `http://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}`;
}
async function freePort() {
  const server = http.createServer();
  const url = await listen(server);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return new URL(url).port;
}

test('bound models HTTP uses the employee key and fails closed without a CP catalog fallback', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'portal-bound-models-'));
  const databaseUrl = `file:${join(directory, 'employee.sqlite')}`;
  let gatewayMode = 'ok';
  let contextMode = 'ok';
  let currentProject = 'cp-current-project';
  let keyFailure = false;
  let currentCredential='fixture-employee-key';
  const cpCalls: Array<{ method: string; path: string; query: string; body: any }> = [];
  const gatewayKeys: string[] = [];
  const gatewayBodies:Array<Record<string,unknown>>=[];
  const cp = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    const url = new URL(req.url!, 'http://fixture.invalid');
    cpCalls.push({ method: req.method!, path: url.pathname, query: url.search, body: body ? JSON.parse(body) : null });
    res.setHeader('content-type', 'application/json');
    if(url.pathname.endsWith('/system/chat-portal-status')){res.end(JSON.stringify({enabled:true}));
    }else if (url.pathname.endsWith('/authorization-context')) {
      res.end(JSON.stringify({ data: { user_id: contextMode === 'wrong-user' ? 'someone-else' : 'bound-user', department_id: 'cp-current-department', project_id: contextMode === 'missing-project' ? '' : currentProject, chat_allowed: contextMode !== 'disabled', department_version: 2 } }));
    } else if (url.pathname.endsWith('/employee-key/credential')) {
      if(keyFailure){res.writeHead(503);res.end('{}');return;}
      res.end(JSON.stringify({key:{id:'managed-key',prefix:'fixture',tenant_id:'fixture-tenant',user_id:'bound-user',project_id:currentProject,status:'active'},credential:currentCredential}));
    } else if (url.pathname.endsWith('/users')) {
      res.end(JSON.stringify({ user_id: 'bound-user', project_id: 'cp-current-project', created: false }));
    } else if (url.pathname.endsWith('/keys')) {
      if (keyFailure) { res.writeHead(503); res.end('{}'); return; }
      res.end(JSON.stringify({ id: 'issued-key', key_prefix: 'jjd_fixture', full_key: 'fixture-employee-key' }));
    } else if (url.pathname.endsWith('/policies/model')) {
      res.end(JSON.stringify({ allow_list: ['callable-model', 'app-denied', 'no-credential', 'unsupported-protocol'], deny_list: ['app-denied'] }));
    } else if (url.pathname.endsWith('/models')) {
      res.end(JSON.stringify({ data: ['callable-model','app-denied','no-credential','unsupported-protocol'].map(model_name => ({ model_name })) }));
    } else res.end('{}');
  });
  const gateway = http.createServer(async(req, res) => {
    if(req.method==='POST'){
      let raw='';for await(const chunk of req)raw+=chunk;
      gatewayBodies.push(JSON.parse(raw));
      gatewayKeys.push(req.headers.authorization??'');
      res.setHeader('content-type','application/json');res.end(JSON.stringify({id:'fixture-response',object:'chat.completion',choices:[{index:0,message:{role:'assistant',content:'fixture'},finish_reason:'stop'}],usage:{prompt_tokens:1,completion_tokens:1,total_tokens:2}}));return;
    }
    gatewayKeys.push(req.headers.authorization ?? '');
    res.setHeader('content-type', 'application/json');
    if (gatewayMode === 'error') {
      res.writeHead(503);
      res.end('fixture-secret-network-detail');
    } else if (gatewayMode === 'malformed') res.end('{');
    else if (gatewayMode === 'missing-data') res.end(JSON.stringify({ models: [{ id: 'cp-catalog' }] }));
    else res.end(JSON.stringify({ object: 'list', data: gatewayMode === 'empty' ? [] : [{ id: 'callable-model' }, { id: '' }, { id: 2 }, { model_name: 'wrong-shape' }, null, { id: 'callable-model' }] }));
  });
  const cpUrl = await listen(cp);
  const gatewayUrl = await listen(gateway);
  const proxyPort = await freePort();
  const env = { ...process.env, DATABASE_URL: databaseUrl, PORT: proxyPort,
    PORTAL_INTERNAL_TOKEN: 'fixture-internal-token', PORTAL_KEY_ENC_SECRET: 'fixture-encryption-secret',
    NEWAPI_PORTAL_API_SECRET: 'fixture-cp-secret', PORTAL_TENANT_ID: 'fixture-tenant',
    GATEWAY_CP_URL: cpUrl, GATEWAY_BASE_URL: gatewayUrl, LOBE_DATABASE_URL: 'postgres://unused@127.0.0.1:1/unused' };
  await exec(process.execPath, ['node_modules/prisma/build/index.js','migrate','deploy'], { cwd: root, env });
  const child = spawn(process.execPath, ['--import','tsx','src/server.ts'], { cwd: root, env, stdio: ['ignore','pipe','pipe'] });
  let output = '';
  child.stdout!.on('data', chunk => { output += String(chunk); });
  child.stderr!.on('data', chunk => { output += String(chunk); });
  t.after(async () => {
    child.kill('SIGTERM');
    if (child.exitCode === null) await once(child, 'exit');
    await Promise.all([new Promise<void>(resolve=>cp.close(()=>resolve())), new Promise<void>(resolve=>gateway.close(()=>resolve()))]);
    await rm(directory,{recursive:true,force:true});
  });
  const proxyUrl = `http://127.0.0.1:${proxyPort}`;
  for (let attempt = 0; attempt < 200; attempt++) {
    try { if ((await fetch(`${proxyUrl}/healthz`)).ok) break; } catch {}
    if (child.exitCode !== null) throw new Error('proxy exited before ready');
    if (attempt === 199) throw new Error('proxy readiness timeout');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  const headers = { authorization: 'Bearer fixture-internal-token',
    'x-portal-direct-sso-subject': 'bound-subject', 'x-portal-direct-gateway-user-id': 'bound-user',
    'x-portal-direct-department': 'forged-external-department', 'x-portal-direct-email': '' };
  const models = async () => fetch(`${proxyUrl}/v1/models`, { headers });
  const first = await models();
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { models: [{ id:'callable-model', displayName:'callable-model' }], defaultModelId:'callable-model' });
  assert.equal(first.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(gatewayKeys, ['Bearer fixture-employee-key']);
  assert.ok(cpCalls.some(call => call.method === 'GET' && call.path.endsWith('/authorization-context') && new URLSearchParams(call.query).get('external_subject') === 'bound-subject'));
  assert.equal(cpCalls.filter(call=>call.method==='POST' && call.path.endsWith('/users')).length, 0);
  assert.equal(new URLSearchParams(cpCalls.find(call=>call.path.endsWith('/employee-key/credential'))?.query).get('user_id'),'bound-user');
  assert.equal(cpCalls.filter(call=>call.path.endsWith('/keys')).length,0,'managed employee never creates a legacy cached Key');
  currentCredential='fixture-reset-key';
  const afterReset=await models();
  assert.equal(afterReset.status,200);
  assert.equal(gatewayKeys.at(-1),'Bearer fixture-reset-key','next request uses the current credential after reset');
  assert.ok(cpCalls.filter(call=>call.path.endsWith('/employee-key/credential')).length>=2);
  currentCredential='fixture-employee-key';
  for (const mode of ['error','malformed','missing-data']) {
    gatewayMode = mode;
    const response = await models();
    assert.equal(response.status, 502, mode);
    const body = await response.text();
    assert.doesNotMatch(body, /fixture-secret|127\.0\.0\.1|cp-catalog|no-credential/);
  }
  gatewayMode = 'empty';
  assert.deepEqual(await (await models()).json(),{models:[],defaultModelId:null});
  for (const mode of ['wrong-user','missing-project','disabled']) {
    contextMode = mode;
    const response = await models();
    assert.notEqual(response.status,200, mode);
  }
  assert.equal(cpCalls.filter(call=>call.path.endsWith('/models') || call.path.endsWith('/policies/model')).length,0,'direct identity must not use legacy CP catalog reconciliation');
  contextMode = 'ok';
  gatewayMode = 'ok';
  currentProject = 'cp-next-project';
  keyFailure = true;
  const gatewayCallsBeforeMove = gatewayKeys.length;
  const failedMove = await models();
  assert.equal(failedMove.status, 502, 'a failed department/application move must not reuse the old key');
  assert.equal(gatewayKeys.length, gatewayCallsBeforeMove, 'old employee key must not reach the gateway');
  keyFailure=false;
  const aliased=await fetch(proxyUrl+'/v1/chat/completions',{method:'POST',headers:{...headers,'content-type':'application/json'},body:JSON.stringify({model:'gpt5.5',messages:[{role:'user',content:'fixture'}]})});
  const aliasBody=await aliased.text();assert.ok(aliased.status===200,aliasBody);
  assert.equal(gatewayBodies.at(-1)?.model,'gpt-5.5','display alias must be restored before gateway admission');
  assert.equal(gatewayKeys.at(-1),'Bearer fixture-employee-key');
  assert.doesNotMatch(output,/fixture-employee-key|fixture-encryption-secret|fixture-secret-network-detail/);
});
