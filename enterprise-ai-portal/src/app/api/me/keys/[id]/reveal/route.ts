import {withPersonalAction} from '@/lib/portal-write-security';
import {signedClientIP,clientIPHeaders} from '@/lib/signed-client-ip';
import {personalControlPlaneError,requirePortalOrigin,limitPersonalAction} from '@/lib/portal-write-security';
import { auth } from '@/auth';
import { PORTAL_DEFAULT_TENANT_ID } from '@/lib/control-plane';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { requireActivePortalUser } from '@/lib/require-active-user';

function clientErrorStatus(status: number): number {
  return [400, 403, 404, 409,429].includes(status) ? status : 502;
}

async function POSTImpl(request: Request, context: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }

  const originDenied=requirePortalOrigin(request);
  if(originDenied)return originDenied;
  const { id: rawKeyId } = await context.params;
  const keyId = rawKeyId.trim();
  if (!keyId || keyId.length > 128 || /[\u0000-\u001f\u007f]/.test(keyId)) {
    return Response.json({ error: 'invalid_key_id' }, { status: 400 });
  }

  const limited=limitPersonalAction(session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,session.user.id,'reveal');
  if(limited)return limited;
  const gateway = loadGatewayEnv();
  const active = await requireActivePortalUser(session, { gateway });
  if (active instanceof Response) return active;
  const authorization = { userId: active.user.id };

  let response: Response;
  try {
    response = await fetch(
      `${gateway.baseUrl}/admin/v1/portal-integration/customer-keys/${encodeURIComponent(keyId)}/reveal?user_id=${encodeURIComponent(authorization.userId)}`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${gateway.portalSecret}`,
          'X-JJDGuard-Tenant-Id': session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,
 ...clientIPHeaders(signedClientIP(request.headers)),
        },
        cache: 'no-store',
      },
    );
  } catch {
    return Response.json({ error: 'control_plane_unreachable' }, { status: 502 });
  }

  const payload = (await response.json().catch(() => null)) as {
    full_key?: unknown;
    reason?: unknown;
    error?: unknown;
  } | null;
  if (!response.ok) {
    const error = personalControlPlaneError(payload);
    return Response.json({ error }, { status: clientErrorStatus(response.status) });
  }
  if (typeof payload?.full_key !== 'string' || !payload.full_key) {
    const reason = typeof payload?.reason === 'string' ? payload.reason : 'key_not_recoverable';
    return Response.json({ error: reason }, { status: 409 });
  }

  return Response.json({ full_key: payload.full_key }, {
    headers: {
      'cache-control': 'private, no-store',
      pragma: 'no-cache',
    },
  });
}

export async function POST(request:Request,context:{params:Promise<{id:string}>}){return withPersonalAction(request,"key_reveal",()=>POSTImpl(request,context));}
