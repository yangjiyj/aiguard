/**
 * 6.9：页面水印（用户名 + 工号/账号 + 时间）。
 * 配置（服务端读取，运行时生效，不在构建期固化）：
 * - PORTAL_WATERMARK：设为 0/false/off/no 关闭；默认开启。
 * - PORTAL_WATERMARK_EXTRA：追加的固定文字（如公司简称），可选，最长 40 字符。
 * 门户会话里没有独立的"工号"字段：优先取邮箱 @ 前的账号，其次控制面 user_id。
 */
export type WatermarkIdentity = {
  name?: string | null;
  email?: string | null;
  id?: string | null;
};

export type WatermarkConfig = { enabled: boolean; extra: string };

const OFF_VALUES = new Set(["0", "false", "off", "no"]);

export function watermarkConfig(env: Record<string, string | undefined> = process.env): WatermarkConfig {
  const raw = (env.PORTAL_WATERMARK ?? "").trim().toLowerCase();
  const extra = (env.PORTAL_WATERMARK_EXTRA ?? "").trim().slice(0, 40);
  return { enabled: !OFF_VALUES.has(raw), extra };
}

export function watermarkAccount(identity: WatermarkIdentity): string {
  const email = (identity.email ?? "").trim();
  const at = email.indexOf("@");
  if (at > 0) return email.slice(0, at);
  if (email) return email;
  return (identity.name ?? "").trim() || (identity.id ?? "").trim().slice(0, 8);
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function formatWatermarkTime(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function watermarkLines(identity: WatermarkIdentity, time: string, extra = ""): string[] {
  const name = (identity.name ?? "").trim();
  const account = watermarkAccount(identity);
  const who = [...new Set([name, account].filter(Boolean))].join(" ");
  if (!who) return [];
  return [who, [extra, time].filter(Boolean).join(" ")].filter(Boolean);
}
