import type { Metadata } from "next";
import "./globals.css";

import { SessionProvider } from "next-auth/react";
import { ThemeProvider } from "@/components/theme-provider";
import { PreferencesProvider } from "@/components/preferences-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SessionGuard } from "@/components/session-guard";
import { WatermarkSlot } from "@/components/watermark-slot";
import { brand } from "@/lib/brand";
import { PORTAL_AUTH_BASE_PATH } from "@/lib/portal-path";

export const metadata: Metadata = {
  title: `${brand.name}`,
  description: "企业级 AI 对话门户 · SSO 登录 · 审批模型 · 安全归因",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="zh-CN"
      suppressHydrationWarning
      className="h-full antialiased"
    >
      <head>
        {/* 动态品牌强调色（M3 可改 env 覆盖） */}
        <style>{`:root{--brand-500:${brand.accent};--brand-600:${brand.accent};--primary:${brand.accent};}`}</style>
      </head>
      <body className="min-h-full">
        <SessionProvider basePath={PORTAL_AUTH_BASE_PATH}>
        <ThemeProvider>
          <PreferencesProvider>
            <TooltipProvider delayDuration={200}><SessionGuard>{children}</SessionGuard></TooltipProvider>
            <WatermarkSlot />
          </PreferencesProvider>
        </ThemeProvider>
        </SessionProvider>
      </body>
    </html>
  );
}
