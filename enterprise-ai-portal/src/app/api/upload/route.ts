// POST /api/upload (multipart/form-data)
// 安全：身份服务端注入（session.user.id），删/忽略客户端任何 user 字段；
// 字节不落 Prisma；门禁只信真实 mime/size。
import { auth } from '@/auth';
import { checkRateLimit } from '@/lib/rate-limit';
import { sanitizeFilename, sha256Hex } from '@/lib/upload';
import {
  extractFileText,
  mimeToExtractorKind,
  truncateText,
  buildIngestRequest,
} from '@/lib/file-extract';
import { loadGatewayEnv, type GatewayEnv } from '@/lib/gateway-env';
import { describePortalError, parseErrorBody } from '@/lib/portal-errors';
import { requireActiveSessionUser } from '@/lib/conversation-access';

export async function POST(req: Request) {
  // 1. 鉴权——未登录 401
  const session = await auth();
  if (!session?.user?.id) {
    return Response.json({ error: 'unauthorized', message: describePortalError({ code: 'unauthorized' }).message }, { status: 401 });
  }
  const gateway = loadGatewayEnv();
  // 6.10：停用/移除/无权限的账号不能再上传（JWT 未过期也拒）
  const active = await requireActiveSessionUser(session, { gateway });
  if (active instanceof Response) return active;

  // 1.1 按用户限流
  const rl = checkRateLimit(session.user.id);
  if (!rl.allowed) {
    return Response.json(
      { error: 'rate_limited', message: '请求过于频繁，请稍后再试' },
      { status: 429 },
    );
  }

  let maxFileMB: number;
  try {
    maxFileMB = await loadPortalFileMaxMB(gateway);
  } catch {
    return Response.json(
      { error: 'file_policy_unavailable', message: '文件发送策略暂不可用，请稍后重试' },
      { status: 502 },
    );
  }

  // 2. 解析 multipart（客户端可能伪造 user 字段——一律忽略，归因只用 session.user.id）
  const form = await req.formData();
  const file = form.get('file');
  const clientUserId = form.get('user');
  const clientModel = form.get('model');
  void clientUserId; // 明确忽略客户端身份字段（纵深防御）
  if (!(file instanceof File)) {
    return Response.json({ error: 'missing_file', message: describePortalError({ code: 'missing_file', status: 400 }).message }, { status: 400 });
  }

  // 3. 浏览器声明的 MIME 只用于抽取分派；真实文件类型由控制面按字节判定。
  const mime = file.type || 'application/octet-stream';
  const size = file.size;
  const maxBytes = maxFileMB * 1024 * 1024;

  // 4. 类型策略由控制面统一执行，门户不以可伪造 MIME 抢先拒绝。
  if (size > maxBytes) {
    return Response.json(
      { error: 'file_too_large', max_mb: maxFileMB, message: '文件超过当前上传大小限制' },
      { status: 400 },
    );
  }

  // 5. 读字节 + sha256（服务端权威）
  const arrayBuf = await file.arrayBuffer();
  const buffer = Buffer.from(arrayBuf);
  const sha256 = await sha256Hex(new Uint8Array(arrayBuf));

  // 6. 抽取文本仅用于模型输入增强；抽取失败或不支持时仍把原始字节交给控制面。
  let extractedText = '';
  if (mimeToExtractorKind(mime) !== 'unsupported') {
    try {
      extractedText = await withTimeout(extractFileText(buffer, mime), 30_000);
    } catch {
      extractedText = '';
    }
  }
  // 抽取文本大小上限（防 DoS：超过 1MB 截断）
  extractedText = extractedText.slice(0, 1024 * 1024);

  // 7. 调网关 ingest（字节旁路留证 + audit-only 检测 + 留痕）
  const bytesBase64 = buffer.toString('base64');
  const ingestPayload = buildIngestRequest({
    filename: sanitizeFilename(file.name, 0),
    mime,
    size,
    sha256,
    bytesBase64,
    extractedText,
    model: typeof clientModel === 'string' ? clientModel : undefined,
  });
  // 服务端注入 user_id（不可伪造）
  ingestPayload.user_id = session.user.id;

  let ingestResp: Response;
  try {
    ingestResp = await fetch(`${gateway.baseUrl}/admin/v1/portal-integration/upload-ingest`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${gateway.portalSecret}`,
        'X-JJDGuard-Tenant-Id': 'tenant_default',
      },
      body: JSON.stringify(ingestPayload),
    });
  } catch {
    return Response.json(
      { error: 'ingest_unreachable', message: describePortalError({ code: 'ingest_unreachable', status: 502 }).message },
      { status: 502 },
    );
  }

  if (!ingestResp.ok) {
    // 6.2：透传控制面/网关的 code 与 message（{"error":{"code","message"}}），
    // 不再只回 "上传失败 403"。403 → 拦截；413 → 超限；400 + code 原样映射。
    const upstreamStatus = ingestResp.status;
    const clientStatus =
      upstreamStatus === 400 || upstreamStatus === 403 || upstreamStatus === 413 || upstreamStatus === 429
        ? upstreamStatus
        : 502;
    const parsed = parseErrorBody(await ingestResp.text().catch(() => ''));
    const fallbackCode =
      upstreamStatus === 403
        ? 'file_content_blocked'
        : upstreamStatus === 413
          ? 'file_too_large'
          : upstreamStatus === 429
            ? 'rate_limited'
            : 'ingest_failed';
    const e = describePortalError({
      code: parsed?.code ?? fallbackCode,
      status: clientStatus,
      upstreamMessage: parsed?.message,
      requestId: parsed?.requestId,
    });
    return Response.json(
      {
        error: e.code,
        message: e.message,
        ...(parsed?.message && parsed.message !== e.message ? { detail: parsed.message.slice(0, 500) } : {}),
        ...(e.requestId ? { request_id: e.requestId } : {}),
        status: upstreamStatus,
      },
      { status: clientStatus },
    );
  }

  const ingest = (await ingestResp.json()) as { reference?: unknown; action?: unknown };
  // 8. 返回 reference + textPreview（字节不落门户库；textPreview 仅短预览）
  //    action 是控制面实际执行的处置（audit/mask），前端据此显示"已记录/已脱敏"。
  return Response.json({
    reference: typeof ingest.reference === 'string' ? ingest.reference : '',
    text_preview: truncateText(extractedText, 500),
    text: extractedText,
    sha256,
    action: typeof ingest.action === 'string' ? ingest.action : 'audit',
  });
}

async function loadPortalFileMaxMB(gateway: GatewayEnv): Promise<number> {
  const response = await fetch(gateway.baseUrl + '/admin/v1/portal-integration/policies/file', {
    headers: {
      authorization: 'Bearer ' + gateway.portalSecret,
      'X-JJDGuard-Tenant-Id': 'tenant_default',
    },
  });
  if (!response.ok) {
    throw new Error('file policy request failed');
  }
  const policy = (await response.json()) as { max_file_mb?: unknown };
  if (
    typeof policy.max_file_mb !== 'number'
    || !Number.isInteger(policy.max_file_mb)
    || policy.max_file_mb < 1
    || policy.max_file_mb > 100
  ) {
    throw new Error('file policy response is invalid');
  }
  return policy.max_file_mb;
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error('抽取超时')), ms)),
  ]);
}
