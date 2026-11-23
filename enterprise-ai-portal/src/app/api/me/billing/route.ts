import {personalControlPlaneError} from '@/lib/portal-write-security';
import { auth } from '@/auth';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { PORTAL_DEFAULT_TENANT_ID } from '@/lib/control-plane';
import { resolvePublicGatewayUrl } from '@/lib/public-gateway-url';
import { requireActivePortalUser } from '@/lib/require-active-user';

// Customer billing BFF. Identity always comes from the signed server session;
// query/body user ids are intentionally not accepted.
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }
  const gateway = loadGatewayEnv();
  const active = await requireActivePortalUser(session, { gateway });
  if (active instanceof Response) return active;
  try {
    const response = await fetch(
      `${gateway.baseUrl}/admin/v1/portal-integration/customer-billing?user_id=${encodeURIComponent(session.user.id)}`,
      {
        headers: {
          authorization: `Bearer ${gateway.portalSecret}`,
          'X-JJDGuard-Tenant-Id': session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,
          // This is a server-configured display coordinate, not browser input.
          ...(resolvePublicGatewayUrl(process.env)?{'X-JJDGuard-Gateway-URL':resolvePublicGatewayUrl(process.env)}:{}),
        },
        cache: 'no-store',
      },
    );
    const body = await response.json().catch(() => ({ error: 'invalid_control_plane_response' }));
    if (!response.ok) {
      return Response.json({ error: personalControlPlaneError(body) }, { status: 502 });
    }
    return Response.json(body, { headers: { 'cache-control': 'private, no-store' } });
  } catch {
    return Response.json({ error: 'control_plane_unreachable' }, { status: 502 });
  }
}
