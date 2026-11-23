import { auth } from "@/auth";
import { PORTAL_DEFAULT_TENANT_ID } from "@/lib/control-plane";
import { loadGatewayEnv } from "@/lib/gateway-env";
import { requireActivePortalUser } from "@/lib/require-active-user";
import {
  PERSONAL_NO_STORE,
  limitPersonalAction,
  personalControlPlaneError,
  requirePortalOrigin,
  withPersonalAction,
} from "@/lib/portal-write-security";

// 员工诊断助手 BFF。员工身份只取自服务端会话，浏览器传来的 user_id 一律忽略；
// 控制面再校验该员工在租户内存在且 active，并把调用身份固定为非管理员。

const SESSION_BASE = "/admin/v1/portal-integration/diagnostics/sessions";
const MAX_TEXT = 4000;
const PASSTHROUGH_ERRORS = [400, 403, 404, 409, 429, 503];

export const DIAGNOSIS_SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

type Json = Record<string, unknown>;

function fail(error: string, status: number): Response {
  return Response.json({ error }, { status, headers: PERSONAL_NO_STORE });
}

async function readBody(request: Request): Promise<Json | null> {
  const raw: unknown = await request.json().catch(() => null);
  return raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Json) : null;
}

function cleanText(value: unknown, required: boolean): string | null {
  if (typeof value !== "string") return required ? null : "";
  const text = value.trim();
  if (required && !text) return null;
  if (text.length > MAX_TEXT || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) return null;
  return text;
}

interface Call {
  action: string;
  method: "GET" | "POST";
  path: string;
  /** 写操作需要同源校验与限速；轮询读取不限速。 */
  write: boolean;
  body?: Json;
}

async function forward(request: Request, call: Call): Promise<Response> {
  const session = await auth();
  if (!session?.user?.id) return fail("unauthorized", 401);
  const tenant = session.user.tenantId || PORTAL_DEFAULT_TENANT_ID;
  if (call.write) {
    const denied = requirePortalOrigin(request);
    if (denied) return denied;
    const limited = limitPersonalAction(tenant, session.user.id, "diagnostics");
    if (limited) return limited;
  }
  const gateway = loadGatewayEnv();
  const active = await requireActivePortalUser(session, { gateway });
  if (active instanceof Response) return active;

  const userId = active.user.id;
  let url = gateway.baseUrl + call.path;
  if (call.method === "GET") url += (call.path.includes("?") ? "&" : "?") + new URLSearchParams({ user_id: userId });
  const response = await fetch(url, {
    method: call.method,
    headers: {
      authorization: "Bearer " + gateway.portalSecret,
      "X-JJDGuard-Tenant-Id": tenant,
      "content-type": "application/json",
    },
    body: call.method === "POST" ? JSON.stringify({ ...call.body, user_id: userId }) : undefined,
    cache: "no-store",
    signal: AbortSignal.timeout(15000),
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const status = PASSTHROUGH_ERRORS.includes(response.status) ? response.status : 502;
    return fail(personalControlPlaneError(payload, "diagnostics_unavailable"), status);
  }
  return Response.json(payload ?? {}, { headers: PERSONAL_NO_STORE });
}

function run(request: Request, call: Call): Promise<Response> {
  return withPersonalAction(request, call.action, () => forward(request, call));
}

export async function createDiagnosisSession(request: Request): Promise<Response> {
  const body = await readBody(request);
  const input = body?.input && typeof body.input === "object" ? (body.input as Json) : null;
  if (!input || (input.kind !== "question" && input.kind !== "health")) return fail("invalid_request", 400);
  const text = cleanText(input.text, input.kind === "question");
  if (text === null) return fail("invalid_request", 400);
  return run(request, {
    action: "diagnostics_create",
    method: "POST",
    path: SESSION_BASE,
    write: true,
    body: { input: { kind: input.kind, text: input.kind === "health" ? "" : text, ref: "", window_hours: 1 } },
  });
}

export function listDiagnosisSessions(request: Request): Promise<Response> {
  return run(request, { action: "diagnostics_list", method: "GET", path: SESSION_BASE, write: false });
}

export function getDiagnosisSession(request: Request, id: string): Promise<Response> {
  if (!DIAGNOSIS_SESSION_ID.test(id)) return Promise.resolve(fail("invalid_session_id", 400));
  return run(request, {
    action: "diagnostics_get",
    method: "GET",
    path: SESSION_BASE + "/" + encodeURIComponent(id),
    write: false,
  });
}

export async function addDiagnosisMessage(request: Request, id: string): Promise<Response> {
  if (!DIAGNOSIS_SESSION_ID.test(id)) return fail("invalid_session_id", 400);
  const body = await readBody(request);
  const text = cleanText(body?.text, true);
  if (!text) return fail("invalid_request", 400);
  return run(request, {
    action: "diagnostics_message",
    method: "POST",
    path: SESSION_BASE + "/" + encodeURIComponent(id) + "/messages",
    write: true,
    body: { text },
  });
}
