// /api/chat 的纯逻辑（W6 · 6.4/6.5/6.15）：无 Prisma、无 IO，可单测。

export const MAX_HISTORY_MESSAGES = 200;

export type ChatHistoryMessage = { role: "user" | "assistant"; content: unknown };

/**
 * 校验客户端提交的 history（6.15）：
 * - 只接受 user / assistant；system、tool、developer 等一律拒绝——防止伪造系统提示或"模型已同意"的回复。
 * - content 只能是字符串或 OpenAI 多模态数组；数组只允许出现在最后一条 user 消息（当轮），历史轮必须是字符串。
 * - 最后一条必须是 user。
 */
export function validateChatHistory(input: unknown):
  | { ok: true; messages: ChatHistoryMessage[] }
  | { ok: false; reason: string } {
  if (!Array.isArray(input) || input.length === 0) return { ok: false, reason: "messages_required" };
  if (input.length > MAX_HISTORY_MESSAGES) return { ok: false, reason: "messages_too_many" };
  const out: ChatHistoryMessage[] = [];
  for (let i = 0; i < input.length; i++) {
    const m = input[i] as { role?: unknown; content?: unknown } | null;
    if (!m || typeof m !== "object") return { ok: false, reason: "message_invalid" };
    if (m.role !== "user" && m.role !== "assistant") return { ok: false, reason: "role_not_allowed" };
    const isLast = i === input.length - 1;
    if (typeof m.content === "string") {
      out.push({ role: m.role, content: m.content });
      continue;
    }
    if (Array.isArray(m.content) && isLast && m.role === "user") {
      out.push({ role: m.role, content: m.content });
      continue;
    }
    return { ok: false, reason: "content_invalid" };
  }
  if (out[out.length - 1]!.role !== "user") return { ok: false, reason: "last_message_not_user" };
  return { ok: true, messages: out };
}

export type AssistantOutcome = {
  /** null = 完整结束 */
  status: null | "interrupted" | "blocked" | "failed";
  errorCode?: string;
};

/** 标题归一（6.13）：去首尾空白、折叠换行、限长；空串返回 null。 */
export const MAX_TITLE_LENGTH = 60;
export function normalizeTitle(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const t = raw.replace(/\s+/g, " ").trim();
  if (!t) return null;
  return Array.from(t).slice(0, MAX_TITLE_LENGTH).join("");
}
