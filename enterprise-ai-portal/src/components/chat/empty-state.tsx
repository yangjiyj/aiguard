"use client";

import * as React from "react";
import { examplePrompts } from "@/lib/brand";
import { usePreferences } from "@/components/preferences-provider";

export function greeting(hour: number, name: string): string {
  const word = hour >= 5 && hour < 12 ? "上午好" : hour >= 12 && hour < 18 ? "下午好" : "晚上好";
  return name ? `${word}，${name}` : word;
}

const chip = "max-w-full truncate rounded-full border px-3.5 py-1.5 text-[13px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground";

export function EmptyState({
  name,
  composer,
  onPick,
}: {
  name: string;
  composer: React.ReactNode;
  onPick: (prompt: string) => void;
}) {
  const { prefs } = usePreferences();
  const prompts = [...prefs.quickPrompts, ...examplePrompts].filter((p, i, all) => all.indexOf(p) === i).slice(0, 6);
  return (
    <div className="flex min-h-full flex-col items-center justify-center px-2 pb-20 pt-10">
      {/* 时段按浏览器本地时间；服务端渲染的时区可能不同，允许水合时改写这一行文字 */}
      <h1 suppressHydrationWarning className="mb-7 text-center text-[28px] font-semibold tracking-tight">{greeting(new Date().getHours(), name)}</h1>
      <div className="w-full max-w-[760px]">{composer}</div>
      <div className="mt-1 flex max-w-[720px] flex-wrap justify-center gap-2 px-4">
        {prompts.map((p) => (
          <button key={p} type="button" onClick={() => onPick(p)} title={p} className={chip}>
            {p}
          </button>
        ))}
      </div>
    </div>
  );
}
