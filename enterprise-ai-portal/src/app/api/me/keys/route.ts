import {withPersonalAction} from '@/lib/portal-write-security';
import {personalControlPlaneError,requirePortalOrigin} from '@/lib/portal-write-security';
import { auth } from '@/auth';
import { PORTAL_DEFAULT_TENANT_ID } from '@/lib/control-plane';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { requireActivePortalUser } from '@/lib/require-active-user';

const EMPLOYEE_MODEL_SCOPES = ['chat', 'responses', 'embeddings', 'models'] as const;

function clientErrorStatus(status: number): number {
  return [400, 403, 404, 409,429].includes(status) ? status : 502;
}

async function POSTImpl(request: Request) {
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: 'unauthorized' }, { status: 401 });
  }

  const originDenied=requirePortalOrigin(request);
  if(originDenied)return originDenied;

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return Response.json({ error: 'invalid_json' }, { status: 400 });
  }
  if (!raw || typeof raw !== 'object') {
    return Response.json({ error: 'invalid_request' }, { status: 400 });
  }
  const body = raw as Record<string, unknown>;
  if(body.model_allowlist!==undefined&&(!Array.isArray(body.model_allowlist)||body.model_allowlist.length>500||!body.model_allowlist.every(m=>typeof m==='string')))return Response.json({error:'invalid_model_allowlist'},{status:400});
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (Array.from(name).length > 128 || /[\u0000-\u001f\u007f]/.test(name)) {
    return Response.json({ error: 'invalid_name' }, { status: 400 });
  }

  const gateway = loadGatewayEnv();
  const active = await requireActivePortalUser(session, { gateway });
  if (active instanceof Response) return active;
  const authorization = { userId: active.user.id };
  const projectId = active.user.projectId;
  if (!projectId) return Response.json({error:'project_unavailable'}, {status:403,headers:{'cache-control':'private, no-store'}});

  let response: Response;
  try {
    response = await fetch(`${gateway.baseUrl}/admin/v1/portal-integration/keys`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${gateway.portalSecret}`,
        'content-type': 'application/json',
        'X-JJDGuard-Tenant-Id': session.user.tenantId||PORTAL_DEFAULT_TENANT_ID,
      },
      body: JSON.stringify({
        project_id: projectId,
        user_id: authorization.userId,
        name: name || '个人 API Key',
        scopes: EMPLOYEE_MODEL_SCOPES,
        ...(body.model_allowlist!==undefined?{model_allowlist:body.model_allowlist}:{}),
      }),
      cache: 'no-store',
    });
  } catch {
    return Response.json({ error: 'control_plane_unreachable' }, { status: 502 });
  }

  const payload = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok) {
    const error = personalControlPlaneError(payload);
    return Response.json({ error }, { status: clientErrorStatus(response.status) });
  }
  if (
    !payload ||
    typeof payload.id !== 'string' ||
    typeof payload.full_key !== 'string' ||
    !payload.full_key ||
    typeof payload.key_prefix !== 'string' ||
    payload.project_id !== projectId ||
    !Array.isArray(payload.scopes) ||
    !payload.scopes.every((scope) => typeof scope === 'string') ||
    typeof payload.status !== 'string' ||
    typeof payload.created_at !== 'string'
  ) {
    return Response.json({ error: 'invalid_control_plane_response' }, { status: 502 });
  }

  return Response.json({
    data: {
      id: payload.id,
      name: typeof payload.name === 'string' ? payload.name : name || '个人 API Key',
      prefix: payload.key_prefix,
      project_id: payload.project_id,
      scopes: payload.scopes,
      status: payload.status,
      created_at: payload.created_at,
      model_allowlist:Array.isArray(payload.model_allowlist)?payload.model_allowlist:[],
    },
    full_key: payload.full_key,
  }, {
    status: 201,
    headers: { 'cache-control': 'private, no-store' },
  });
}

import {personalKeysRequest} from '@/lib/personal-keys';
export async function GET(request:Request){return personalKeysRequest(request);}

export async function POST(request:Request){return withPersonalAction(request,"key_create",()=>POSTImpl(request));}
