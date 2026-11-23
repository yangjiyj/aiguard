import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';

const image = 'data:image/svg+xml;base64,'+Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>').toString('base64');
let payload: unknown = {captcha_id:'captcha-1',image,expires_in:300};
let status=200;
const server=createServer((request,response)=>{
  assert.equal(request.url,'/admin/v1/captcha');
  assert.equal(request.headers.authorization,undefined);
  response.statusCode=status;
  response.setHeader('content-type','application/json');
  response.end(JSON.stringify(payload));
});
let GET: () => Promise<Response>;
test.before(async()=>{
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  const address=server.address(); assert.ok(address&&typeof address==='object');
  process.env.JJD_CP_URL='http://127.0.0.1:'+address.port;
  process.env.JJD_PORTAL_API_SECRET='captcha-fixture-server-secret';
  ({GET}=await import('../src/app/api/login/captcha/route.js'));
});
test.after(()=>server.close());

test('captcha is a public no-store proxy with a bounded inline image and no credential forwarding',async()=>{
  const response=await GET();
  assert.equal(response.status,200);
  assert.equal(response.headers.get('cache-control'),'private, no-store');
  assert.deepEqual(await response.json(),{captcha_id:'captcha-1',image,expires_in:300});
});

test('remote URLs, unbounded payloads and malformed captcha contracts fail closed',async()=>{
  for(const body of [{captcha_id:'captcha-1',image:'https://attacker.test/image.svg',expires_in:300},
    {captcha_id:'captcha-1',image,expires_in:999999},{captcha_id:'captcha-1',image:'data:image/svg+xml;base64,'+'A'.repeat(300001),expires_in:300},
    {captcha_id:'',image,expires_in:300},{error:'sensitive upstream message'}]){
    payload=body;
    const response=await GET();
    assert.equal(response.status,502);
    assert.deepEqual(await response.json(),{error:'captcha_unavailable'});
  }
});

test('control-plane captcha failure never passes through raw upstream details',async()=>{
  status=503;payload={error:'captcha_store_detail',password:'must-not-leak'};
  const response=await GET();
  assert.equal(response.status,502);
  assert.deepEqual(await response.json(),{error:'captcha_unavailable'});
});
