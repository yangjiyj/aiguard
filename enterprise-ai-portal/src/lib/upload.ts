// 门户上传纯逻辑层：无 React、无 Prisma、无 IO，可被前端与 API 路由共用并单测。
// 安全：所有"权威"校验都从真实字节推导；前端校验只是第一道体验优化。

export type ImagePolicy = {
  allowedTypes: string[]; // MIME
  maxFileMB: number; // 单图上限
  maxAttachments: number; // 张数上限
  maxTotalMB: number; // 单轮总大小上限（DoS 护栏）
};

// 与网关 FilePolicy 默认对齐（Phase-2 起改为读网关 file-policy 端点）
export const DEFAULT_IMAGE_POLICY: ImagePolicy = {
  allowedTypes: ["image/png", "image/jpeg", "image/webp"],
  maxFileMB: 20,
  maxAttachments: 10,
  maxTotalMB: 50,
};

export type ImagePart = { type: "image_url"; image_url: { url: string } };
// extracted_content：门户抽取的文件文本契约（对齐网关 claude.ai 客户端抽取先例）；
// reference 指向网关留证仓 Key（字节旁路，不进 messages）。仅当轮 user 消息携带。
export type TextPart = { type: "text"; text: string; extracted_content?: { reference: string; filename: string; source: string } };
export type ContentPart = TextPart | ImagePart;
/** OpenAI 兼容 message.content：纯字符串或多模态数组 */
export type MessageContent = string | ContentPart[];

/** 前端选中的一张图（含 dataURL 与展示元数据） */
export type ImageAttachmentMeta = { name: string; mime: string; size: number; dataUrl: string };

/** 后端从字节抽出的图片块 */
export type ExtractedImage = { mime: string; base64: string; bytes: number };

export function mimeAllowed(mime: string, policy: ImagePolicy): boolean {
  return policy.allowedTypes.includes(mime);
}

/** 由 base64 字符串长度估原始字节数（不解码，O(1)） */
export function bytesOfBase64(b64: string): number {
  const s = b64.trim();
  if (!s) return 0;
  const pad = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  return Math.floor((s.length * 3) / 4) - pad;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const DATA_URL_RE = /^data:([^;,]+);base64,([\s\S]*)$/;

/** 从当轮 message.content 抽出所有 image_url data URL 图片块（字符串 content → 空） */
export function extractImageParts(content: MessageContent): ExtractedImage[] {
  if (!Array.isArray(content)) return [];
  const out: ExtractedImage[] = [];
  for (const part of content) {
    if (part && part.type === "image_url" && typeof part.image_url?.url === "string") {
      const m = DATA_URL_RE.exec(part.image_url.url);
      if (!m) continue; // 非 data URL（远程 URL）本期不接受
      out.push({ mime: m[1], base64: m[2], bytes: bytesOfBase64(m[2]) });
    }
  }
  return out;
}

/** 权威校验：类型白名单 / 单图大小 / 张数上限 / 单轮总大小。返回中文错误串数组（空=通过） */
export function validateImageParts(
  imgs: { mime: string; bytes: number }[],
  policy: ImagePolicy
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (imgs.length > policy.maxAttachments) {
    errors.push(`附件张数超限（最多 ${policy.maxAttachments} 张）`);
  }
  const totalBytes = imgs.reduce((s, i) => s + i.bytes, 0);
  if (totalBytes > policy.maxTotalMB * 1024 * 1024) {
    errors.push(`附件总大小超限（最多 ${policy.maxTotalMB} MB）`);
  }
  const maxBytes = policy.maxFileMB * 1024 * 1024;
  for (const img of imgs) {
    if (!mimeAllowed(img.mime, policy)) {
      errors.push(`不支持的文件类型：${img.mime}`);
    }
    if (img.bytes > maxBytes) {
      errors.push(`单张图片超过大小上限（${policy.maxFileMB} MB）`);
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * 文件名消毒：去控制字符/路径分隔符/`..`/危险保留字符，保留中文与常规 unicode，长度上限 128，空则回退。
 * 安全：文件名是客户端可控输入，只用于留痕/展示，绝不用于门禁判定（门禁只信真实字节 mime/size）。
 * React 渲染文本自带转义，此处再消一层作纵深防御。
 */
export function sanitizeFilename(name: string, index = 0): string {
  const cleaned = (name ?? "")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, "") // 控制字符 C0/DEL/C1（转义写法，不依赖 es2018）
    .replace(/[\\/]/g, "_") // 路径分隔符
    .replace(/\.\.+/g, ".") // 折叠 .. 防遍历
    .replace(/[<>:"|?*]/g, "_") // 危险/保留字符
    .slice(0, 128)
    .trim();
  return cleaned || `图片${index + 1}`;
}

/** 组当轮 user message content：无图返回纯文本；有图返回 [text?, ...image_url] */
export function assembleUserContent(text: string, attachments: ImageAttachmentMeta[]): MessageContent {
  if (attachments.length === 0) return text;
  const parts: ContentPart[] = [];
  if (text.trim()) parts.push({ type: "text", text });
  for (const a of attachments) parts.push({ type: "image_url", image_url: { url: a.dataUrl } });
  return parts;
}

/** 落库降解：多模态 content → 文本 + 每图一行 [图片:名]；绝不含字节。names 与图片块按序对应 */
export function textForPersistence(content: MessageContent, names: string[]): string {
  if (!Array.isArray(content)) return content;
  const lines: string[] = [];
  let imgIdx = 0;
  for (const part of content) {
    if (part.type === "text") lines.push(part.text);
    else if (part.type === "image_url") {
      const name = names[imgIdx] ?? `图片${imgIdx + 1}`;
      lines.push(`[图片:${name}]`);
      imgIdx++;
    }
  }
  return lines.join("\n");
}

/** 同构 sha256 → hex（Node 22 / 浏览器均有全局 crypto.subtle） */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** base64 → Uint8Array（供后端从 data URL 算 sha256） */
export function base64ToBytes(b64: string): Uint8Array {
  const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
