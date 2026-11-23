// OpenAI 兼容 SSE 行缓冲解析（W6 · 6.1/6.4）。前端与 /api/chat 共用，可单测。
// - 跨 chunk 缓冲：一行被拆到两个网络包里时不丢字（6.4）。
// - 识别网关 error 帧：网关对流式请求返回 HTTP 200 + `data: {"error":{...}}`
//   （apps/gateway-core writeSSEError / liveChatBlockPayloads，格式不改，由这里适配）（6.1）。

export type SSEErrorFrame = {
  code: string;
  message: string;
  requestId?: string;
  blockId?: string;
  type?: string;
};

export type SSEEvent =
  | { type: "delta"; content: string }
  | { type: "error"; error: SSEErrorFrame }
  | { type: "finish"; reason: string }
  | { type: "security_action"; action: string }
  | { type: "usage"; outputTokens: number }
  | { type: "done" };

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** 解析单个 data 负载（不含 `data:` 前缀）。无关帧返回空数组。 */
export function parseSSEData(data: string): SSEEvent[] {
  if (data === "[DONE]") return [{ type: "done" }];
  let json: unknown;
  try {
    json = JSON.parse(data);
  } catch {
    return [];
  }
  if (!json || typeof json !== "object") return [];
  const root = json as Record<string, unknown>;
  if (root.error && typeof root.error === "object") {
    const e = root.error as Record<string, unknown>;
    return [{
      type: "error",
      error: {
        code: str(e.code) ?? "upstream_unavailable",
        message: typeof e.message === "string" ? e.message : "",
        requestId: str(e.request_id),
        blockId: str(e.block_id),
        type: str(e.type),
      },
    }];
  }
  const events: SSEEvent[] = [];
  // 网关保活已提前发头时，最终安全动作改随末帧带出（与 X-Security-Action 同值域）。
  const action = str(root.x_jjdguard_security_action);
  if (action) events.push({ type: "security_action", action: action.toLowerCase() });
  const choice = Array.isArray(root.choices) ? (root.choices[0] as Record<string, unknown> | undefined) : undefined;
  const delta = choice?.delta as Record<string, unknown> | undefined;
  if (typeof delta?.content === "string" && delta.content) {
    events.push({ type: "delta", content: delta.content });
  }
  if (typeof choice?.finish_reason === "string" && choice.finish_reason) {
    events.push({ type: "finish", reason: choice.finish_reason });
  }
  // stream_options.include_usage 的末帧：choices 为空、带 usage，只取输出 token 数用于前端计时。
  const usage = root.usage && typeof root.usage === "object" ? root.usage as Record<string, unknown> : undefined;
  const outputTokens = typeof usage?.completion_tokens === "number" ? usage.completion_tokens : typeof usage?.output_tokens === "number" ? usage.output_tokens : undefined;
  if (typeof outputTokens === "number" && outputTokens >= 0) events.push({ type: "usage", outputTokens });
  return events;
}

/** 有状态的行缓冲解析器：push 任意切分的文本，返回已完整的事件。 */
export class SSELineParser {
  private buf = "";

  push(text: string): SSEEvent[] {
    this.buf += text;
    const lines = this.buf.split("\n");
    this.buf = lines.pop() ?? "";
    return this.consume(lines);
  }

  /** 流结束：处理末尾没有换行的最后一行。 */
  flush(): SSEEvent[] {
    const rest = this.buf;
    this.buf = "";
    return rest ? this.consume([rest]) : [];
  }

  private consume(lines: string[]): SSEEvent[] {
    const out: SSEEvent[] = [];
    for (const raw of lines) {
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (!line.startsWith("data:")) continue;
      out.push(...parseSSEData(line.slice(5).trim()));
    }
    return out;
  }
}
