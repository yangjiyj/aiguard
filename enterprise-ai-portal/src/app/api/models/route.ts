// GET /api/models
// 调 portal-proxy GET /v1/models 拿当前用户被允许的真实模型清单（从网关 project 策略动态拉取）；
// 再调 control-plane /admin/v1/portal-integration/models 合并 capabilities.supports_image_input（vision 门禁用）。
import { auth } from '@/auth';
import {
  ControlPlaneError,
  getCurrentPortalAuthorization,
  PORTAL_DEFAULT_TENANT_ID,
} from '@/lib/control-plane';
import { loadGatewayEnv } from '@/lib/gateway-env';

const PORTAL_PROXY_URL = process.env.PORTAL_PROXY_URL!;
const PORTAL_INTERNAL_TOKEN = process.env.PORTAL_INTERNAL_TOKEN!;

interface ModelEntry {
  id: string;
  displayName: string;
  capabilities?: Record<string, unknown>;
}

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }
  const directIdentity = session.user as typeof session.user & { externalSubject?: unknown };
  const directSsoSubject = typeof directIdentity.externalSubject === 'string'
    ? directIdentity.externalSubject.trim()
    : '';
  if (!directSsoSubject) {
    return Response.json({ error: 'identity_not_ready' }, { status: 502 });
  }
  const gateway = loadGatewayEnv();
  let authorization;
  try {
    authorization = await getCurrentPortalAuthorization(
      PORTAL_DEFAULT_TENANT_ID,
      session.user.id,
      { gateway },
    );
  } catch (error) {
    const denied = error instanceof ControlPlaneError && error.code === 'authorization_denied';
    return Response.json(
      { error: denied ? 'authorization_denied' : 'control_plane_unavailable' },
      { status: denied ? 403 : 502 },
    );
  }

  // 1. portal-proxy 取授权清单（含默认模型）
  let upstream: Response;
  try {
    upstream = await fetch(`${PORTAL_PROXY_URL}/v1/models`, {
      headers: {
        authorization: `Bearer ${PORTAL_INTERNAL_TOKEN}`,
        'x-portal-direct-sso-subject': directSsoSubject,
        'x-portal-direct-login-mode': session.user.localLogin === true ? 'local' : 'oidc',
        ...(session.user.localLogin===true?{'x-portal-direct-local-credential-version':String(session.user.localCredentialVersion)}:{}),
        'x-portal-direct-email': session.user.email ?? '',
        'x-portal-direct-department': authorization.departmentId,
        'x-portal-direct-gateway-user-id': authorization.userId,
      },
      cache: 'no-store',
    });
  } catch (e) {
    return Response.json(
      { error: 'upstream_unreachable', message: e instanceof Error ? e.message : '上游不可达' },
      { status: 502 },
    );
  }

  if (!upstream.ok) {
    return Response.json(
      { error: 'upstream_error', status: upstream.status },
      { status: upstream.status },
    );
  }

  const data = (await upstream.json()) as { models?: ModelEntry[]; defaultModelId?: string | null };
  const allowedModelIds = new Set(authorization.modelIds);
  let models = (data.models ?? []).filter((model) => allowedModelIds.has(model.id));

  // 2. control-plane 取 capabilities（supports_image_input 用于 vision 门禁）
  //    按 model_name 关联；CP 不可达时不返回缓存/降级结果，避免绕过实时策略。
  try {
    const cpResp = await fetch(`${gateway.baseUrl}/admin/v1/portal-integration/models`, {
      headers: {
        authorization: `Bearer ${gateway.portalSecret}`,
        'X-JJDGuard-Tenant-Id': 'tenant_default',
      },
      cache: 'no-store',
    });
    if (!cpResp.ok) {
      return Response.json({ error: 'control_plane_error', status: cpResp.status }, { status: 502 });
    }
    const cpData = (await cpResp.json()) as { data?: Array<{ model_name: string; capabilities?: Record<string, unknown> }> };
    const capMap = new Map<string, Record<string, unknown>>();
    for (const m of cpData.data ?? []) {
      if (m.model_name && m.capabilities) capMap.set(m.model_name, m.capabilities);
    }
    models = models.map((m) => {
      const caps = capMap.get(m.id);
      return caps ? { ...m, capabilities: caps } : m;
    });
  } catch (error) {
    return Response.json(
      { error: 'control_plane_unreachable', message: error instanceof Error ? error.message : '控制面不可达' },
      { status: 502 },
    );
  }

  const defaultModelId =
    data.defaultModelId && allowedModelIds.has(data.defaultModelId)
      ? data.defaultModelId : (models[0]?.id ?? null);
  return Response.json(
    { models, defaultModelId },
    { headers: { 'cache-control': 'private, no-store' } },
  );
}
