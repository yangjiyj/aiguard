import test from 'node:test';
import assert from 'node:assert/strict';
import {trustedPortalOrigin,requirePortalOrigin} from '../src/lib/portal-write-security';

test.beforeEach(()=>{
 for(const name of ['PORTAL_PUBLIC_URL','AUTH_URL','NEXTAUTH_URL','PORTAL_TRUSTED_ORIGINS'])delete process.env[name];
});
const request=(host:string,origin:string|null,extra:Record<string,string>={})=>new Request('http://portal-container:3100/chat/api/me/keys',{
 method:'POST',headers:{host,...(origin?{origin}:{}),...extra}
});
test('无需配置，IP、域名、端口和 IPv6 同源请求通过',()=>{
 for(const host of ['192.168.20.246','chat.example.cn','100.64.0.36','chat.example.cn:8443','[fd00::1]:8443']){
  assert.equal(trustedPortalOrigin(request(host,'https://'+host,{'sec-fetch-site':'same-origin'})),true,host);
 }
});
test('跨站、缺失和无效 Origin 均拒绝',()=>{
 for(const origin of ['https://evil.test',null,'null','https://portal.test/path','https://user@portal.test','https://portal.test,https://evil.test']){
  assert.equal(requirePortalOrigin(request('portal.test',origin))?.status,403);
 }
 assert.equal(requirePortalOrigin(request('portal.test','https://portal.test',{'sec-fetch-site':'cross-site'}))?.status,403);
 assert.equal(requirePortalOrigin(request('portal.test','https://portal.test',{'sec-fetch-site':'same-site'}))?.status,403);
});
test('非可信来源伪造转发 Host 不能授权跨站请求',()=>{
 assert.equal(trustedPortalOrigin(request('portal.test','https://evil.test',{'x-forwarded-host':'evil.test','x-forwarded-proto':'https'})),false);
 assert.equal(trustedPortalOrigin(request('portal.test:8443','https://portal.test',{'x-forwarded-host':'portal.test'})),false);
});
test('配置的地址和受信任 Origin 只作为额外允许项',()=>{
 process.env.PORTAL_PUBLIC_URL='https://configured.test/chat';
 process.env.PORTAL_TRUSTED_ORIGINS='https://extra.test:8443, broken';
 assert.equal(trustedPortalOrigin(request('192.168.20.246','https://192.168.20.246')),true);
 assert.equal(trustedPortalOrigin(request('internal.test','https://configured.test')),true);
 assert.equal(trustedPortalOrigin(request('internal.test','https://extra.test:8443')),true);
 assert.equal(trustedPortalOrigin(request('internal.test','https://extra.test:8443',{'sec-fetch-site':'cross-site'})),false);
});
