// POST /api/chat
// 安全关键：身份从服务端 Auth.js 会话取，请求体里客户端传来的任何身份字段一律忽略/覆盖。
// 调 portal-proxy POST /v1/chat/completions，注入 X-Portal-Direct-* 头（仅服务端可发）。
import { auth } from '@/auth';
import { requireActiveSessionUser } from '@/lib/conversation-access';
import { loadGatewayEnv } from '@/lib/gateway-env';
import { prisma } from '@/lib/prisma';
import { checkRateLimit } from '@/lib/rate-limit';
import {
  DEFAULT_IMAGE_POLICY,
  extractImageParts,
  validateImageParts,
  sanitizeFilename,
  textForPersistence,
  sha256Hex,
  base64ToBytes,
  type MessageContent,
} from '@/lib/upload';
import { validateChatHistory, type AssistantOutcome } from '@/lib/chat-history';
import { describePortalError, parseErrorBody, PORTAL_ERROR_MESSAGES } from '@/lib/portal-errors';
import { SSELineParser } from '@/lib/sse';

const PORTAL_PROXY_URL = process.env.PORTAL_PROXY_URL!;
const PORTAL_INTERNAL_TOKEN = process.env.PORTAL_INTERNAL_TOKEN!;

// 6.16：网关陈述本轮安全动作的响应头，透传给浏览器（同源，前端可读）。
const FORWARDED_UPSTREAM_HEADERS = ['x-security-action', 'x-request-id', 'x-jjdguard-block-id'];

function errorJson(code: string, status: number, extra: { upstreamMessage?: string; requestId?: string; blockId?: string } = {}) {
  const e = describePortalError({ code, status, ...extra });
  return Response.json(
    {
      error: e.code,
      message: e.message,
      ...(e.notice ? { notice: e.notice } : {}),
      ...(e.requestId ? { request_id: e.requestId } : {}),
      ...(e.blockId ? { block_id: e.blockId } : {}),
      status,
    },
    { status },
  );
}

export async function POST(req: Request) {
  // 1. 校验会话——未登录 401
  const session = await auth();
  if (!session?.user?.id) {
    return errorJson('unauthorized', 401);
  }
  const directIdentity = session.user as typeof session.user & { externalSubject?: unknown };
  const directSsoSubject = typeof directIdentity.externalSubject === 'string'
    ? directIdentity.externalSubject.trim()
    : '';
  if (!directSsoSubject) {
    return errorJson('identity_not_ready', 502);
  }
  // 6.10：每次请求向控制面复核账号有效（停用/移除/无权限即拒，控制面故障 fail-closed）
  const active = await requireActiveSessionUser(session, { gateway: loadGatewayEnv() });
  if (active instanceof Response) return active;
  const authorization = { userId: active.id, departmentId: active.departmentId, modelIds: active.modelIds };

  // 1.1 按用户限流（令牌桶，防滥用）
  const rl = checkRateLimit(session.user.id);
  if (!rl.allowed) {
    const res = errorJson('rate_limited', 429);
    res.headers.set('retry-after', String(rl.retryAfterSec));
    return res;
  }

  // 2. 解析请求体（只取业务字段，忽略任何身份字段）
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return errorJson('invalid_json', 400);
  }
  if (typeof body !== 'object' || body === null) {
    return errorJson('invalid_body', 400);
  }
  const b = body as Record<string, unknown>;
  // 安全：附件元数据仅用于留痕文件名展示，绝不用于门禁判定（门禁从真实字节推导）
  const attachmentsMeta = Array.isArray(b.attachments)
    ? (b.attachments as unknown[]).filter(
        (a): a is { name?: unknown } => typeof a === 'object' && a !== null,
      )
    : [];
  const conversationId = typeof b.conversationId === 'string' ? b.conversationId : null;
  const model = typeof b.model === 'string' ? b.model : null;
  // 6.6：重新生成——替换最后一轮回答，不再写 user 消息
  const regenerate = b.regenerate === true;
  if (!model || !Array.isArray(b.messages)) {
    return errorJson('missing_fields', 400);
  }
  // 6.15：只接受 user/assistant，防伪造 system 提示
  const history = validateChatHistory(b.messages);
  if (!history.ok) {
    return Response.json(
      { error: 'invalid_request', message: PORTAL_ERROR_MESSAGES.invalid_request, reason: history.reason, status: 400 },
      { status: 400 },
    );
  }
  const messages = history.messages;
  // 3. 本地校验 model 在该用户允许清单内（纵深防御，最终拒绝点在网关）
  if (!authorization.modelIds.includes(model)) {
    return errorJson('model_not_allowed', 403);
  }

  // 3.1 当轮 user 消息（校验保证最后一条是 user）；含图片 → 权威门禁 + 逐图 sha256 轻留痕
  const lastUser = messages[messages.length - 1]!;
  let uploadRows: { filename: string; mime: string; size: number; sha256: string }[] = [];
  if (Array.isArray(lastUser.content)) {
    const imgs = extractImageParts(lastUser.content as MessageContent);
    const v = validateImageParts(imgs, DEFAULT_IMAGE_POLICY);
    if (!v.ok) {
      return Response.json(
        { error: 'upload_rejected', message: v.errors[0] ?? PORTAL_ERROR_MESSAGES.upload_rejected, messages: v.errors, status: 400 },
        { status: 400 },
      );
    }
    uploadRows = await Promise.all(
      imgs.map(async (img, i) => {
        const meta = attachmentsMeta[i] as { name?: unknown } | undefined;
        const rawName = typeof meta?.name === 'string' ? meta.name : '';
        return {
          filename: sanitizeFilename(rawName, i),
          mime: img.mime,
          size: img.bytes,
          sha256: await sha256Hex(base64ToBytes(img.base64)),
        };
      }),
    );
  }

  // 4. 会话归属（任何落库前先查；已软删的会话不能继续写）
  let persist = false;
  if (conversationId) {
    let conv: { userId: string; deletedAt?: Date | null } | null = null;
    let dbAvailable = true;
    try {
      conv = await prisma.conversation.findUnique({ where: { id: conversationId } });
    } catch {
      dbAvailable = false; // 库不可用：不落库，但不阻断对话（与原行为一致）
    }
    if (dbAvailable) {
      if (!conv || !(active.historyUserIds??[active.id]).includes(conv.userId) || conv.deletedAt) {
        return errorJson('forbidden', 403);
      }
      persist = true;
    }
  }

  // 4.1 落库本轮用户消息（含图时降解为 文本 + [图片:名] 占位，绝不入库 base64）
  if (persist && conversationId) {
    try {
      if (regenerate) {
        // 6.6：删掉被替换的最后一条 assistant（仅当它在最后一条 user 之后）
        const last = await prisma.message.findFirst({
          where: { conversationId },
          orderBy: { createdAt: 'desc' },
        });
        if (last && last.role === 'assistant') {
          await prisma.message.delete({ where: { id: last.id } });
        }
      } else {
        const persistText = textForPersistence(lastUser.content as MessageContent, uploadRows.map((r) => r.filename));
        await prisma.message.create({ data: { conversationId, role: 'user', content: persistText } });
      }
      await prisma.conversation.update({ where: { id: conversationId }, data: { updatedAt: new Date() } });
    } catch {
      // 落库失败不阻断对话
    }
  }

  // 4.2 写图片轻留痕（纯元数据无字节，归因用服务端 session.user.id）
  if (uploadRows.length > 0) {
    try {
      await prisma.uploadEvent.createMany({
        data: uploadRows.map((r) => ({
          userId: session.user.id,
          filename: r.filename,
          mime: r.mime,
          size: r.size,
          sha256: r.sha256,
          model,
          kind: 'image',
        })),
      });
    } catch (e) {
      // audit-only 底线：留痕失败不阻断对话，但记日志留迹（可观测 + 事后对账），不 throw
      console.error('UploadEvent 写入失败', {
        count: uploadRows.length,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  // 输出计量（服务端口径，与前端 ChatTimer 一致）：TTFT = 上游发起到首 delta；TPS = usage 帧 outputTokens / 首 delta 后生成窗口。
  // 生成窗口不足 200ms 时不记 TPS（与 lib/chat-timing.ts 口径一致），上游未回传 usage 时三列都留空。
  const meteringStart = performance.now();
  let firstDeltaAt: number | null = null;
  let usageAt: number | null = null;
  let usageOutputTokens: number | null = null;

  const persistAssistant = async (content: string, outcome: AssistantOutcome) => {
    if (!persist || !conversationId) return;
    if (!content && outcome.status === null) return;
    let outputTokens: number | null = null;
    let ttftMs: number | null = null;
    let tps: number | null = null;
    if (outcome.status === null && usageOutputTokens !== null && usageOutputTokens > 0 && firstDeltaAt !== null && usageAt !== null) {
      const ttft = Math.round(firstDeltaAt - meteringStart);
      const generationSpanMs = usageAt - firstDeltaAt;
      if (ttft >= 0) ttftMs = ttft;
      if (generationSpanMs >= 200) tps = Math.round((usageOutputTokens * 1000 / generationSpanMs) * 10) / 10;
      outputTokens = usageOutputTokens;
    }
    try {
      await prisma.message.create({
        data: {
          conversationId,
          role: 'assistant',
          content,
          model,
          status: outcome.status,
          errorCode: outcome.errorCode ?? null,
          outputTokens,
          ttftMs,
          tps,
        },
      });
    } catch {
      // 落库失败不报错
    }
  };

  // 5. 注入直接身份头，调 portal-proxy（OpenAI 兼容请求体，只带白名单业务字段）
  const forwardBody: Record<string, unknown> = { model, messages, stream: true, stream_options: { include_usage: true } };
  for (const key of ['temperature', 'top_p', 'max_tokens'] as const) {
    if (typeof b[key] === 'number') forwardBody[key] = b[key];
  }
  let upstream: Response;
  try {
    upstream = await fetch(PORTAL_PROXY_URL + '/v1/chat/completions', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'text/event-stream',
        authorization: 'Bearer ' + PORTAL_INTERNAL_TOKEN,
        'x-portal-direct-sso-subject': directSsoSubject,
        'x-portal-direct-login-mode': session.user.localLogin === true ? 'local' : 'oidc',
        ...(session.user.localLogin===true?{'x-portal-direct-local-credential-version':String(session.user.localCredentialVersion)}:{}),
        'x-portal-direct-email': session.user.email ?? '',
        'x-portal-direct-department': authorization.departmentId,
        'x-portal-direct-gateway-user-id': authorization.userId,
      },
      body: JSON.stringify(forwardBody),
      signal: req.signal,
    });
  } catch {
    if (req.signal.aborted) {
      await persistAssistant('', { status: 'interrupted', errorCode: 'stopped' });
      return errorJson('stopped', 499);
    }
    await persistAssistant('', { status: 'failed', errorCode: 'upstream_unavailable' });
    return errorJson('upstream_unreachable', 502);
  }

  const passHeaders = new Headers();
  for (const name of FORWARDED_UPSTREAM_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) passHeaders.set(name, value);
  }

  // 6.3：非 2xx —— 透传上游 code（网关 {"error":{code,message,request_id}}），给中文文案
  if (!upstream.ok || !upstream.body) {
    const text = await upstream.text().catch(() => '');
    const parsed = parseErrorBody(text);
    const status = upstream.ok ? 502 : upstream.status;
    const e = describePortalError({
      code: parsed?.code,
      status,
      upstreamMessage: parsed?.message,
      requestId: parsed?.requestId ?? upstream.headers.get('x-request-id'),
      blockId: parsed?.blockId ?? upstream.headers.get('x-jjdguard-block-id'),
    });
    await persistAssistant(e.notice ?? e.message, {
      status: e.kind === 'blocked' ? 'blocked' : 'failed',
      errorCode: e.code,
    });
    const res = Response.json(
      {
        error: e.code,
        message: e.message,
        ...(e.notice ? { notice: e.notice } : {}),
        ...(e.requestId ? { request_id: e.requestId } : {}),
        ...(e.blockId ? { block_id: e.blockId } : {}),
        status,
      },
      { status },
    );
    passHeaders.forEach((value, name) => res.headers.set(name, value));
    return res;
  }

  // 6. SSE 原样透传回浏览器；服务端行缓冲解析（6.4）累计 assistant 内容与结局用于落库
  const reader = upstream.body.getReader();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const parser = new SSELineParser();
  // 头里的动作在网关保活提前发头时只反映输入阶段，末帧 x_jjdguard_security_action 可把它升级为 block
  let blockedByHeader = (upstream.headers.get('x-security-action') ?? '').toLowerCase() === 'block';
  let assistantContent = '';
  let sawDone = false;
  let sawFinish = false;
  let errorFrame: { code: string; message: string } | null = null;
  let cancelled = false;
  let persisted = false;

  const finalize = async (streamBroken: boolean) => {
    if (persisted) return;
    persisted = true;
    let outcome: AssistantOutcome = { status: null };
    let content = assistantContent;
    if (errorFrame) {
      const e = describePortalError({ code: errorFrame.code, upstreamMessage: errorFrame.message });
      outcome = { status: e.kind === 'blocked' ? 'blocked' : 'failed', errorCode: e.code };
      // 已生成的部分 + 网关说明都留下，历史里能看到这一轮为什么结束
      const tail = e.notice ?? e.message;
      content = content ? `${content}\n\n${tail}` : tail;
    } else if (cancelled || streamBroken || (!sawDone && !sawFinish)) {
      outcome = { status: 'interrupted', errorCode: cancelled ? 'stopped' : 'stream_interrupted' };
    } else if (blockedByHeader) {
      outcome = { status: 'blocked', errorCode: 'security_blocked' };
    }
    await persistAssistant(content, outcome);
  };

  const handle = (text: string) => {
    for (const ev of parser.push(text)) apply(ev);
  };
  const apply = (ev: ReturnType<SSELineParser['flush']>[number]) => {
    if (ev.type === 'delta') {
      if (firstDeltaAt === null) firstDeltaAt = performance.now();
      assistantContent += ev.content;
    }
    else if (ev.type === 'usage') { usageAt = performance.now(); usageOutputTokens = ev.outputTokens; }
    else if (ev.type === 'done') sawDone = true;
    else if (ev.type === 'finish') sawFinish = true;
    else if (ev.type === 'security_action') blockedByHeader = blockedByHeader || ev.action === 'block';
    else if (ev.type === 'error' && !errorFrame) errorFrame = { code: ev.error.code, message: ev.error.message };
  };

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let broken = false;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          handle(decoder.decode(value, { stream: true }));
          controller.enqueue(value);
        }
        handle(decoder.decode());
        for (const ev of parser.flush()) apply(ev);
      } catch (e) {
        broken = true;
        await finalize(true);
        if (!cancelled) {
          try { controller.error(e); } catch {}
        }
        return;
      } finally {
        try { reader.releaseLock(); } catch {}
      }
      await finalize(broken);
      if (cancelled) return;
      if (!sawDone && !errorFrame) {
        // 有 finish_reason 只是缺 [DONE]：补上；什么都没有就是断流——告诉浏览器"中断"，
        // 不能补 [DONE] 让前端误判为完整回答（与落库的 interrupted 保持一致）
        const tail = sawFinish
          ? 'data: [DONE]\n\n'
          : `data: ${JSON.stringify({ error: { code: 'stream_interrupted', message: '' } })}\n\n`;
        controller.enqueue(encoder.encode(tail));
      }
      controller.close();
    },
    async cancel() {
      cancelled = true;
      try { await reader.cancel(); } catch {}
      await finalize(true);
    },
  });

  passHeaders.set('content-type', 'text/event-stream; charset=utf-8');
  passHeaders.set('cache-control', 'no-cache, no-transform');
  passHeaders.set('connection', 'keep-alive');
  return new Response(stream, { headers: passHeaders });
}
