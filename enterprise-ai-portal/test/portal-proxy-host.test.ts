import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {once} from 'node:events';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {spawn,execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {trustedPortalOrigin} from '../src/lib/portal-write-security';
const listen=async(server:http.Server)=>{server.listen(0,'127.0.0.1');await once(server,'listening');const address=server.address();assert.ok(address&&typeof address==='object');return address.port};
test('真实 HTTPS web-console → Caddy chat-edge → 门户链路保留原始 Host 并覆盖伪造转发头',async(t)=>{
 const caddy=process.env.JJD_TEST_CADDY_BINARY||'/usr/bin/caddy';
 if(!existsSync(caddy)){t.skip('Caddy integration runtime not installed');return}
 const version=execFileSync(caddy,['version'],{encoding:'utf8'});
 if(!process.env.JJD_TEST_CADDY_BINARY&&!/^v2\.(?:1[1-9]|[2-9]\d)\./.test(version)){t.skip('Product Caddy 2.11+ required; set JJD_TEST_CADDY_BINARY');return}
 const scratch=await mkdtemp(join(tmpdir(),'jjdguard-portal-chain-'));
 const certificate=join(scratch,'cert.pem'),key=join(scratch,'key.pem');
 execFileSync('nice',['-n','10','openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',certificate,'-days','1','-subj','/CN=portal.fixture','-addext','subjectAltName=DNS:portal.fixture,DNS:chat.acme.test,IP:127.0.0.1,IP:192.168.20.246,IP:100.64.0.36'],{stdio:'ignore'});
 const backend=http.createServer((request,response)=>{
  if(request.url==='/gate'){response.end();return}
  response.setHeader('content-type','application/json');
  response.end(JSON.stringify({host:request.headers.host,forwarded:request.headers['x-forwarded-host'],origin:request.headers.origin,site:request.headers['sec-fetch-site'],path:request.url}));
 });
 const backendPort=await listen(backend);
 const ports:number[]=[];for(let i=0;i<3;i++){const reserved=http.createServer();ports.push(await listen(reserved));await new Promise<void>(resolve=>reserved.close(()=>resolve()))}
 let config=await readFile('../deploy/docker-compose/chat/Caddyfile','utf8');
 for(const [index,port] of [3100,8280,8180].entries())config=config.replace(':'+port+' {',':'+ports[index]+' {\n\tbind 127.0.0.1');
 for(const target of ['chat-portal-proxy:8788','chat-portal-ui:3100','chat-idp:8180'])config=config.replaceAll(target,'127.0.0.1:'+backendPort);
 const configPath=join(scratch,'Caddyfile');await writeFile(configPath,config);
 let edgeErrors='';
 const edge=spawn('nice',['-n','10',caddy,'run','--config',configPath,'--adapter','caddyfile'],{stdio:['ignore','ignore','pipe']});
 edge.stderr.on('data',chunk=>edgeErrors+=String(chunk));
 let web:https.Server|undefined;
 try{
  let ready=false;
  for(let retry=0;retry<100&&!ready;retry++){
   try{const result=await fetch('http://127.0.0.1:'+ports[0]+'/chat/host-probe');ready=result.ok}catch{await new Promise(resolve=>setTimeout(resolve,50))}
  }
  assert.equal(ready,true,'Caddy must start: '+edgeErrors);
  const {createHttpsServer}=await import('../../apps/web-console/server.js');
  web=createHttpsServer({certFile:certificate,keyFile:key,chatTarget:'http://127.0.0.1:'+ports[0]});
  const webPort=await listen(web);
  for(const host of ['192.168.20.246','chat.acme.test','chat.acme.test:8443','100.64.0.36']){
   const body=await new Promise<string>((resolve,reject)=>{
    const request=https.request({hostname:'127.0.0.1',servername:'portal.fixture',port:webPort,ca:execFileSync('cat',[certificate]),method:'POST',path:'/chat/api/me/keys',headers:{host,origin:'https://'+host,'sec-fetch-site':'same-origin','x-forwarded-host':'evil.test'}},response=>{
     let raw='';response.on('data',chunk=>raw+=chunk);response.on('end',()=>resolve(raw));
    });request.on('error',reject);request.end('{}');
   });
   const seen=JSON.parse(body);assert.equal(seen.host,host);assert.equal(seen.forwarded,host);assert.equal(seen.path,'/chat/api/me/keys');
   const headers={host:seen.host,origin:seen.origin,'sec-fetch-site':seen.site,'x-forwarded-host':seen.forwarded};
   assert.equal(trustedPortalOrigin(new Request('http://portal-container:3100/chat/api/me/keys',{headers})),true);
   assert.equal(trustedPortalOrigin(new Request('http://portal-container:3100/chat/api/me/keys',{headers:{...headers,origin:'https://evil.test'}})),false);
   console.log(JSON.stringify({public_host:host,portal_host:seen.host,forwarded_host:seen.forwarded,same_origin:'allowed',cross_origin:'rejected'}));
  }
 }finally{
  if(web){web.closeAllConnections();await new Promise<void>(resolve=>web!.close(()=>resolve()))}
  edge.kill('SIGTERM');if(edge.exitCode===null)await once(edge,'exit');
  backend.closeAllConnections();await new Promise<void>(resolve=>backend.close(()=>resolve()));
  await rm(scratch,{recursive:true,force:true});
 }
});
