import {createHmac,timingSafeEqual} from 'node:crypto';
import {isIP} from 'node:net';
export function signedClientIP(headers:Headers):string {
 const key=process.env.JJD_LOGIN_IP_FORWARD_SECRET?.trim();
 if(!key)return headers.get('x-real-ip')?.trim()||headers.get('x-forwarded-for')?.split(',').at(-1)?.trim()||'';
 const ip=headers.get('x-real-ip')?.trim()||'';
 const timestamp=headers.get('x-jjd-client-ip-time')||'',signature=headers.get('x-jjd-client-ip-signature')||'';
 if(!isIP(ip)||!/^\d{10}$/.test(timestamp)||Math.abs(Date.now()/1000-Number(timestamp))>90||!/^[a-f0-9]{64}$/.test(signature))return '';
 const expected=createHmac('sha256',key).update('v1\n'+ip+'\n'+timestamp).digest();
 const given=Buffer.from(signature,'hex');
 return given.length===expected.length&&timingSafeEqual(given,expected)?ip:'';
}
export function clientIPHeaders(ip:string):Record<string,string>{
 if(!ip)return {};
 const key=process.env.JJD_LOGIN_IP_FORWARD_SECRET?.trim();
 if(!key)return {'X-Forwarded-For':ip};
 const timestamp=String(Math.floor(Date.now()/1000));
 return {'X-Forwarded-For':ip,'X-JJD-Client-IP-Time':timestamp,'X-JJD-Client-IP-Signature':createHmac('sha256',key).update('v1\n'+ip+'\n'+timestamp).digest('hex')};
}
