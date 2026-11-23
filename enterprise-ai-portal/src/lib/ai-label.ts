/**
 * 导出对话时的 AI 生成内容标识（《人工智能生成合成内容标识办法》的显式标识）。
 * 配置（服务端读取，运行时生效，不在构建期固化）：
 * - PORTAL_AI_LABEL：设为 0/false/off/no 关闭；默认开启。
 * - PORTAL_AI_LABEL_TEXT：自定义标识文案，可选，最长 40 字符。
 */
const OFF_VALUES = new Set(["0", "false", "off", "no"]);
export const DEFAULT_AI_LABEL_TEXT = "本文件中「助手」的回复为 AI 生成内容。";

export function exportAILabel(env: Record<string, string | undefined> = process.env): string {
  const raw = (env.PORTAL_AI_LABEL ?? "").trim().toLowerCase();
  if (OFF_VALUES.has(raw)) return "";
  const text = (env.PORTAL_AI_LABEL_TEXT ?? "").replace(/[\r\n\t]+/g, " ").trim().slice(0, 40);
  return text || DEFAULT_AI_LABEL_TEXT;
}
