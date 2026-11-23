// 员工个人偏好（只存当前浏览器 localStorage，不影响服务端 / 不碰身份权限）。
// 纯逻辑 + 类型放这里（可 node:test）；React Provider/hook 在 components/preferences-provider.tsx。

export type FontSize = "sm" | "base" | "lg";

export type Preferences = {
  /** 新建对话默认模型（限授权范围内） */
  defaultModel: string | null;
  /** true: Enter 发送、Shift+Enter 换行；false: Enter 换行、⌘/Ctrl+Enter 发送 */
  sendOnEnter: boolean;
  /** 对话区字号 */
  fontSize: FontSize;
  /** 个人常用提示词/快捷指令 */
  quickPrompts: string[];
};

export const MAX_QUICK_PROMPTS = 20;

export const DEFAULT_PREFS: Preferences = {
  defaultModel: null,
  sendOnEnter: true,
  fontSize: "base",
  quickPrompts: [],
};

/** 规整常用提示词：只留非空字符串、去空白、去重、限量。可测。 */
export function normalizeQuickPrompts(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of input) {
    if (typeof x !== "string") continue;
    const t = x.trim();
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
    if (out.length >= MAX_QUICK_PROMPTS) break;
  }
  return out;
}

export const PREFS_STORAGE_KEY = "eap.preferences.v1";

export function loadPrefs(): Preferences {
  if (typeof window === "undefined") return DEFAULT_PREFS;
  try {
    const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
    if (!raw) return DEFAULT_PREFS;
    const p = JSON.parse(raw) as Partial<Preferences>;
    return {
      defaultModel: typeof p.defaultModel === "string" ? p.defaultModel : null,
      sendOnEnter: typeof p.sendOnEnter === "boolean" ? p.sendOnEnter : DEFAULT_PREFS.sendOnEnter,
      fontSize: p.fontSize === "sm" || p.fontSize === "lg" ? p.fontSize : "base",
      quickPrompts: normalizeQuickPrompts(p.quickPrompts),
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

export function savePrefs(p: Preferences) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(p));
  } catch {}
}

/** 纯函数：给定按键事件与偏好，判断是否应发送（否则视为换行）。可测。
 *  输入法组字：isComposing 为真，或 Safari 等在组字结束那一下报 keyCode 229（6.13）。 */
export function shouldSubmitOnKey(
  e: { key: string; shiftKey: boolean; metaKey: boolean; ctrlKey: boolean; isComposing?: boolean; keyCode?: number },
  sendOnEnter: boolean
): boolean {
  if (e.key !== "Enter" || e.isComposing || e.keyCode === 229) return false;
  if (sendOnEnter) return !e.shiftKey; // Enter 发送；Shift+Enter 换行
  return e.metaKey || e.ctrlKey; // ⌘/Ctrl+Enter 发送；Enter 换行
}
