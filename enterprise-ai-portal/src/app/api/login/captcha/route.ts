import { loadGatewayEnv } from '@/lib/gateway-env';

const NO_STORE = { 'cache-control':'private, no-store', pragma:'no-cache' };

export async function GET() {
  try {
    const gateway = loadGatewayEnv();
    const response = await fetch(gateway.baseUrl+'/admin/v1/captcha', {
      cache:'no-store', signal:AbortSignal.timeout(10000),
    });
    const data = await response.json().catch(()=>null) as {captcha_id?:unknown; image?:unknown; expires_in?:unknown} | null;
    if (!response.ok || !data || typeof data.captcha_id!=='string' || !data.captcha_id || data.captcha_id.length>256 ||
        typeof data.image!=='string' || data.image.length>300000 || !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/.test(data.image) ||
        typeof data.expires_in!=='number' || !Number.isSafeInteger(data.expires_in) || data.expires_in<=0 || data.expires_in>600) {
      return Response.json({error:'captcha_unavailable'},{status:502,headers:NO_STORE});
    }
    return Response.json({captcha_id:data.captcha_id,image:data.image,expires_in:data.expires_in},{headers:NO_STORE});
  } catch {
    return Response.json({error:'captcha_unavailable'},{status:502,headers:NO_STORE});
  }
}
