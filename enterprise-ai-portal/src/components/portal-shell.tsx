"use client";

import * as React from "react";
import { Menu } from "lucide-react";
import { ChatStoreProvider } from "@/components/chat/store";
import { Sidebar } from "@/components/chat/sidebar";
import type { WorkspaceKey } from "@/components/portal-nav";

// 工作台页面与对话页共用同一个侧栏：历史对话在上，工作台分组在下，当前页高亮。
export function PortalShell({ active, children }: { active: WorkspaceKey; children: React.ReactNode }) {
  const [collapsed, setCollapsed] = React.useState(false);
  const [mobileOpen, setMobileOpen] = React.useState(false);
  return <ChatStoreProvider>
    <div className="portal-canvas flex h-dvh w-full overflow-hidden bg-background">
      <div className="hidden lg:block"><Sidebar active={active} collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} /></div>
      {mobileOpen && <div className="fixed inset-0 z-50 lg:hidden">
        <div className="absolute inset-0 bg-black/50" onClick={() => setMobileOpen(false)} />
        <div className="absolute left-0 top-0 h-full"><Sidebar active={active} collapsed={false} onToggle={() => setMobileOpen(false)} /></div>
      </div>}
      <main className="min-w-0 flex-1 overflow-y-auto">
        <button type="button" aria-label="打开侧栏" onClick={() => setMobileOpen(true)} className="m-3 rounded-lg border p-2 lg:hidden"><Menu className="h-4 w-4" /></button>
        {children}
      </main>
    </div>
  </ChatStoreProvider>;
}
