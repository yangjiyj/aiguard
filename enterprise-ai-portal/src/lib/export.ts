// 对话导出（个人，浏览器侧）。纯序列化逻辑可测；下载动作用浏览器 API。

type ExportMessage = { role: string; content: string; model?: string };
type ExportConversation = { title: string; messages: ExportMessage[] };
type ExportOptions = { aiLabel?: string };

function roleLabel(role: string): string {
  if (role === "user") return "我";
  if (role === "assistant") return "助手";
  return "系统";
}

/** 把一段对话序列化成 Markdown。纯函数，可测。 */
export function conversationToMarkdown(conv: ExportConversation, options: ExportOptions = {}): string {
  const lines: string[] = [`# ${conv.title || "对话"}`, ""];
  if (options.aiLabel) lines.push(`> ${options.aiLabel}`, "");
  for (const m of conv.messages) {
    const suffix = m.role === "assistant" && m.model ? `（${m.model}）` : "";
    lines.push(`## ${roleLabel(m.role)}${suffix}`, "", m.content ?? "", "");
  }
  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

/** 把多段对话拼成一个 Markdown（用于「导出全部」）。纯函数，可测。 */
export function allConversationsToMarkdown(convs: ExportConversation[], options: ExportOptions = {}): string {
  if (convs.length === 0) return "# 我的对话历史\n\n（暂无对话）\n";
  const body = convs.map((c) => conversationToMarkdown(c)).join("\n---\n\n");
  return options.aiLabel ? `> ${options.aiLabel}\n\n${body}` : body;
}

/** 规整文件名：去掉文件系统非法字符、限长，空则回退。纯函数，可测。 */
export function safeFilename(name: string, fallback = "对话"): string {
  const cleaned = (name || "")
    .replace(/[\\/:*?"<>|\n\r\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 60);
  return cleaned || fallback;
}

/** 触发浏览器下载文本文件（仅客户端）。 */
export function downloadText(
  filename: string,
  text: string,
  mime = "text/markdown;charset=utf-8"
) {
  if (typeof document === "undefined") return;
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
