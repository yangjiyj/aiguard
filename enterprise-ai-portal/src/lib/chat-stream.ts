// 浏览器侧 /api/chat 流消费（W6 · 6.1/6.3/6.5/6.16），不依赖 React，可在 node:test 里用 mock fetch 测。
import { describePortalError, parseErrorBody, type PortalError } from "./portal-errors";
import { SSELineParser } from "./sse";

export type StreamOutcome =
  | { kind: "done" }
  | { kind: "error"; error: PortalError }
  | { kind: "stopped" };

export type StreamHandlers = {
  onChunk: (text: string) => void;
  /** 响应头到达：网关陈述的本轮安全动作（mask/audit/block），无则 undefined */
  onMeta?: (meta: { securityAction?: string; requestId?: string }) => void;
  /** 末帧 usage 里的输出 token 数（上游未回传时不调用） */
  onUsage?: (outputTokens: number) => void;
  /** 恰好调用一次 */
  onEnd: (outcome: StreamOutcome) => void;
};

export function streamChatRequest(
  url: string,
  payload: unknown,
  handlers: StreamHandlers,
  fetchImpl: typeof fetch = fetch,
): { cancel: () => void } {
  const ctrl = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let ended = false;
  const end = (o: StreamOutcome) => {
    if (ended) return;
    ended = true;
    handlers.onEnd(o);
  };

  (async () => {
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
      const requestId = res.headers.get("x-request-id") ?? undefined;
      handlers.onMeta?.({ securityAction: res.headers.get("x-security-action") ?? undefined, requestId });
      let headerAction = res.headers.get("x-security-action") ?? undefined;
      if (!res.ok || !res.body) {
        // 6.3：非 2xx 不再显示原始 JSON，按 code 查文案表
        const text = await res.text().catch(() => "");
        const parsed = parseErrorBody(text);
        let notice: string | undefined;
        try {
          const raw = JSON.parse(text) as { notice?: unknown };
          if (typeof raw?.notice === "string") notice = raw.notice;
        } catch {}
        end({
          kind: "error",
          error: describePortalError({
            code: parsed?.code,
            status: res.status,
            upstreamMessage: notice,
            requestId: parsed?.requestId ?? requestId,
            blockId: parsed?.blockId ?? res.headers.get("x-jjdguard-block-id"),
          }),
        });
        return;
      }
      reader = res.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SSELineParser();
      const handle = (events: ReturnType<SSELineParser["push"]>): boolean => {
        for (const ev of events) {
          if (ev.type === "delta") handlers.onChunk(ev.content);
          else if (ev.type === "usage") handlers.onUsage?.(ev.outputTokens);
          else if (ev.type === "security_action") {
            if (ev.action !== headerAction) {
              headerAction = ev.action;
              handlers.onMeta?.({ securityAction: ev.action, requestId });
            }
          } else if (ev.type === "done") {
            end({ kind: "done" });
            return true;
          } else if (ev.type === "error") {
            // 6.1：网关 HTTP 200 + data:{"error":{code,message,request_id}} —— 不能吞
            end({
              kind: "error",
              error: describePortalError({
                code: ev.error.code,
                upstreamMessage: ev.error.message,
                requestId: ev.error.requestId ?? requestId,
                blockId: ev.error.blockId ?? res.headers.get("x-jjdguard-block-id"),
              }),
            });
            return true;
          }
        }
        return false;
      };
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (handle(parser.push(decoder.decode(value, { stream: true })))) {
          try { await reader.cancel(); } catch {}
          return;
        }
      }
      if (handle(parser.push(decoder.decode()))) return;
      if (handle(parser.flush())) return;
      // 没有 [DONE] 就结束：按断流处理（6.5）
      end({ kind: "error", error: describePortalError({ code: "stream_interrupted", requestId }) });
    } catch (e) {
      if (ctrl.signal.aborted) {
        end({ kind: "stopped" });
        return;
      }
      void e;
      end({ kind: "error", error: describePortalError({ code: "stream_interrupted" }) });
    }
  })();

  return {
    cancel: () => {
      ctrl.abort();
      try { void reader?.cancel(); } catch {}
      end({ kind: "stopped" });
    },
  };
}
