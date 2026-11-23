"use client";

import * as React from "react";
import { Boxes, ChevronDown, KeyRound, ReceiptText, ScrollText, SquarePen } from "lucide-react";
import { BrandMark } from "@/components/brand-mark";
import { brand } from "@/lib/brand";
import { portalPath } from "@/lib/portal-path";

// 对话以外的四个页面组成「工作台」：常驻在侧栏下方，可收起。
export type WorkspaceKey = "models" | "keys" | "billing" | "records";
export const WORKSPACE_NAV: { key: WorkspaceKey; label: string; href: string; icon: typeof Boxes }[] = [
  { key: "models", label: "模型", href: "/models", icon: Boxes },
  { key: "keys", label: "API 密钥", href: "/keys", icon: KeyRound },
  { key: "billing", label: "用量与费用", href: "/billing", icon: ReceiptText },
  { key: "records", label: "调用记录", href: "/records", icon: ScrollText },
];

type KeyLike = { key: string; metaKey: boolean; ctrlKey: boolean; altKey: boolean; shiftKey: boolean };
export const isNewChatShortcut = (e: KeyLike) => (e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k";

// 旧链接 /billing#api-keys 仍按「API 密钥」处理（计费页会再跳到 /keys）。
export const activeFromHash = (active: WorkspaceKey, hash: string): WorkspaceKey =>
  active === "billing" && hash === "#api-keys" ? "keys" : active;

const COLLAPSE_KEY = "portal.workspace.collapsed";

// 收起状态只是个人偏好：存储不可用时按展开处理。
export function useWorkspaceCollapsed(): [boolean, () => void] {
  const [collapsed, setCollapsed] = React.useState(false);
  React.useEffect(() => {
    try {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- 首次渲染后读取个人偏好，避免水合不一致。
      if (window.localStorage.getItem(COLLAPSE_KEY) === "1") setCollapsed(true);
    } catch {}
  }, []);
  const toggle = React.useCallback(() => setCollapsed((c) => {
    try { window.localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1"); } catch {}
    return !c;
  }), []);
  return [collapsed, toggle];
}

export function WorkspaceNav({ active, collapsed, onToggle }: { active?: WorkspaceKey; collapsed: boolean; onToggle: () => void }) {
  return <div className="border-t border-sidebar-border px-2.5 pb-1 pt-1.5">
    <button type="button" onClick={onToggle} aria-expanded={!collapsed} aria-controls="workspace-nav"
      className="flex w-full items-center justify-between rounded-md px-3 py-1.5 text-[11.5px] font-medium text-muted-foreground/80 transition-colors hover:text-foreground">
      工作台<ChevronDown className={"h-3.5 w-3.5 transition-transform " + (collapsed ? "-rotate-90" : "")} />
    </button>
    {!collapsed && <nav id="workspace-nav" aria-label="工作台" className="space-y-0.5 pb-1">
      {WORKSPACE_NAV.map(({ key, label, href, icon: Icon }) => (
        <a key={key} href={portalPath(href)} aria-current={key === active ? "page" : undefined}
          className={"flex h-8 items-center gap-2.5 rounded-lg px-3 text-[13px] transition-colors " + (key === active ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground")}>
          <Icon className="h-4 w-4" />{label}
        </a>
      ))}
    </nav>}
  </div>;
}

// 对话侧栏顶部：品牌、收起按钮和「新对话」，⌘/Ctrl+K 同样新建对话。
export function SidebarHeader({ onNewChat, trailing }: { onNewChat?: () => void; trailing?: React.ReactNode }) {
  const newChat = React.useCallback(() => {
    if (onNewChat) onNewChat();
    else window.location.href = portalPath("/");
  }, [onNewChat]);
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (isNewChatShortcut(e)) { e.preventDefault(); newChat(); } };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [newChat]);
  return <div className="px-2.5 pt-4">
    <div className="flex items-center gap-2.5 px-2 pb-4">
      <BrandMark size="sm" />
      <span className="min-w-0 flex-1 truncate text-[15px] font-semibold">{brand.shortName}</span>
      {trailing}
    </div>
    <button type="button" onClick={newChat} className="flex h-9 w-full items-center justify-between rounded-[10px] border border-sidebar-border bg-background px-3 text-sm transition-colors hover:bg-accent">
      <span className="flex items-center gap-2"><SquarePen className="h-4 w-4" />新对话</span>
      <kbd className="font-mono text-[11px] text-muted-foreground">⌘ K</kbd>
    </button>
  </div>;
}
