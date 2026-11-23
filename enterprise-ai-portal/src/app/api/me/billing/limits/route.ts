import {personalControlPlaneError} from '@/lib/portal-write-security';
import {requirePortalOrigin} from '@/lib/portal-write-security';
import { auth } from '@/auth';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { PORTAL_DEFAULT_TENANT_ID } from '@/lib/control-plane';
import { requireActivePortalUser } from '@/lib/require-active-user';

type LimitsInput = {
  daily_amount_micros?: unknown;
  monthly_amount_micros?: unknown;
  daily_token_limit?: unknown;
  monthly_token_limit?: unknown;
  rpm_limit?: unknown;
  concurrency_limit?: unknown;
};

function nonNegativeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

// The signed session owns user_id. Browser input can only change numeric caps.
export async function PUT(request: Request) {
  const session = await auth();
  if (!session?.user?.id) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const input = await request.json().catch(() => null) as LimitsInput | null;
  if (!input) return Response.json({ error: 'invalid_request' }, { status: 400 });
  const dailyAmount = nonNegativeInteger(input.daily_amount_micros);
  const monthlyAmount = nonNegativeInteger(input.monthly_amount_micros);
  const dailyTokens = nonNegativeInteger(input.daily_token_limit);
  const monthlyTokens = nonNegativeInteger(input.monthly_token_limit);
  const rpmLimit = nonNegativeInteger(input.rpm_limit);
  const concurrencyLimit = nonNegativeInteger(input.concurrency_limit);
  if (dailyAmount === null || monthlyAmount === null || dailyTokens === null || monthlyTokens === null ||
    rpmLimit === null || concurrencyLimit === null) {
    return Response.json({ error: 'invalid_limits' }, { status: 400 });
  }
  const originDenied=requirePortalOrigin(request);
  if(originDenied)return originDenied;
  const gateway = loadGatewayEnv();
  const active = await requireActivePortalUser(session, { gateway });
  if (active instanceof Response) return active;
  try {
    const response = await fetch(`${gateway.baseUrl}/admin/v1/portal-integration/customer-billing/limits`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${gateway.portalSecret}`,
        'content-type': 'application/json',
        'X-JJDGuard-Tenant-Id': session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,
      },
      body: JSON.stringify({
        user_id: session.user.id, daily_amount_micros: dailyAmount, monthly_amount_micros: monthlyAmount,
        daily_token_limit: dailyTokens, monthly_token_limit: monthlyTokens,
        rpm_limit: rpmLimit, concurrency_limit: concurrencyLimit,
      }),
      cache: 'no-store',
    });
    const body = await response.json().catch(() => ({ error: 'invalid_control_plane_response' }));
    if (!response.ok) return Response.json({ error: personalControlPlaneError(body) }, { status: response.status >= 400 && response.status < 500 ? response.status : 502 });
    return Response.json(body, { headers: { 'cache-control': 'private, no-store' } });
  } catch {
    return Response.json({ error: 'control_plane_unreachable' }, { status: 502 });
  }
}
