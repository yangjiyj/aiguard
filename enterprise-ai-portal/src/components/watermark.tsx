"use client";

import * as React from "react";
import { useSession } from "next-auth/react";
import { formatWatermarkTime, watermarkLines } from "@/lib/watermark";

function escapeXml(s: string): string {
  return s.replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" })[c] ?? c);
}

export function watermarkTile(lines: string[], dark: boolean): string {
  const fill = dark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.045)";
  const text = lines
    .map((l, i) => `<text x="0" y="${i * 20}" fill="${fill}" font-size="12" font-family="sans-serif">${escapeXml(l)}</text>`)
    .join("");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="480" height="300"><g transform="translate(30 120) rotate(-20)">${text}</g></svg>`;
  return `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
}

/**
 * 6.9 全屏水印叠加层：pointer-events-none 不挡交互，aria-hidden 不进读屏。
 * 身份来自 SessionProvider；未登录（登录页）不渲染。时间在挂载后按浏览器本地时区生成、每分钟刷新，
 * 首帧不渲染以避免 SSR/CSR 不一致。enabled/extra 由根 layout 从服务端环境变量传入。
 */
export function Watermark({ enabled, extra = "" }: { enabled: boolean; extra?: string }) {
  const { data } = useSession();
  const [time, setTime] = React.useState("");
  const [dark, setDark] = React.useState(false);

  React.useEffect(() => {
    if (!enabled) return;
    const root = document.documentElement;
    const sync = () => {
      setDark(root.classList.contains("dark"));
    };
    const observer = new MutationObserver(sync);
    observer.observe(root, { attributes: true, attributeFilter: ["class"] });
    const raf = window.requestAnimationFrame(() => {
      sync();
      setTime(formatWatermarkTime(new Date()));
    });
    const timer = window.setInterval(() => setTime(formatWatermarkTime(new Date())), 60_000);
    return () => {
      window.clearInterval(timer);
      window.cancelAnimationFrame(raf);
      observer.disconnect();
    };
  }, [enabled]);

  const user = data?.user as { id?: string | null; name?: string | null; email?: string | null } | undefined;
  if (!enabled || !user?.id || !time) return null;
  const lines = watermarkLines({ id: user.id, name: user.name, email: user.email }, time, extra);
  if (lines.length === 0) return null;

  return (
    <div
      aria-hidden="true"
      data-portal-watermark=""
      className="pointer-events-none fixed inset-0 z-[60] select-none"
      style={{ backgroundImage: watermarkTile(lines, dark), backgroundRepeat: "repeat" }}
    />
  );
}
