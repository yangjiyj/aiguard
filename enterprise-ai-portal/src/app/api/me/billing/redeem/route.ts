import {withPersonalAction} from '@/lib/portal-write-security';
import {personalControlPlaneError,requirePortalOrigin,limitPersonalAction} from '@/lib/portal-write-security';
import { auth } from '@/auth';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { PORTAL_DEFAULT_TENANT_ID } from '@/lib/control-plane';
import { requireActivePortalUser } from '@/lib/require-active-user';

// A card code is never written to browser logs or returned by this BFF.
async function POSTImpl(request: Request) {
  const session = await auth();
  if (!session?.user?.id) return Response.json({ error: 'unauthorized' }, { status: 401 });

  const originDenied=requirePortalOrigin(request);
  if(originDenied)return originDenied;
  const payload = await request.json().catch(() => null) as { code?: unknown } | null;
  const code = typeof payload?.code === 'string' ? payload.code.trim() : '';
  if (!code || code.length > 128) return Response.json({ error: 'invalid_redemption_code' }, { status: 400 });
  const limited=limitPersonalAction(session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,session.user.id,'redeem');
  if(limited)return limited;
  const gateway = loadGatewayEnv();
  const active = await requireActivePortalUser(session, { gateway });
  if (active instanceof Response) return active;
  try {
    const response = await fetch(`${gateway.baseUrl}/admin/v1/portal-integration/customer-billing/redemptions`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${gateway.portalSecret}`,
        'content-type': 'application/json',
        'X-JJDGuard-Tenant-Id': session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,
      },
      body: JSON.stringify({ user_id: session.user.id, code }),
      cache: 'no-store',
    });
    const body = await response.json().catch(() => ({ error: 'invalid_control_plane_response' }));
    if (!response.ok) return Response.json({ error: personalControlPlaneError(body,'redemption_unavailable') }, { status: response.status >= 400 && response.status < 500 ? response.status : 502 });
    return Response.json(body, { headers: { 'cache-control': 'private, no-store' } });
  } catch {
    return Response.json({ error: 'control_plane_unreachable' }, { status: 502 });
  }
}

export async function POST(request:Request){return withPersonalAction(request,"redeem",()=>POSTImpl(request));}
