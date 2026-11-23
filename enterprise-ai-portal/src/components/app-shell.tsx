"use client";

import * as React from "react";
import { Sidebar } from "@/components/chat/sidebar";
import { ChatPanel } from "@/components/chat/chat-panel";

export function AppShell() {
  const [collapsed, setCollapsed] = React.useState(false);
  const [mobileOpen, setMobileOpen] = React.useState(false);

  return (
    <div className="portal-canvas flex h-dvh w-full overflow-hidden bg-background">
      {/* 桌面侧栏 */}
      <div className="hidden lg:block">
        <Sidebar
          collapsed={collapsed}
          onToggle={() => setCollapsed((v) => !v)}
        />
      </div>

      {/* 移动端抽屉 */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => setMobileOpen(false)}
          />
          <div className="absolute left-0 top-0 h-full">
            <Sidebar
              collapsed={false}
              onToggle={() => setMobileOpen(false)}
            />
          </div>
        </div>
      )}

      <ChatPanel
        onOpenSidebar={() => setMobileOpen(true)}
        sidebarCollapsed={collapsed}
      />
    </div>
  );
}
