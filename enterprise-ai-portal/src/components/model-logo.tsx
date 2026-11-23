"use client";

import * as React from "react";
import { Anthropic, DeepSeek, Doubao, Gemini, OpenAI, Qwen, Zhipu } from "@lobehub/icons";
import { Boxes } from "lucide-react";

const BRAND_MAP: Record<string, React.ComponentType<{ size?: number }>> = {
  zhipu: Zhipu.Color,
  deepseek: DeepSeek.Color,
  qwen: Qwen.Color,
  // Anthropic 官方标志本身即单色，无独立 .Color 子组件
  anthropic: Anthropic,
  // OpenAI 官方标志本身即单色，无独立 .Color 子组件
  openai: OpenAI,
  google: Gemini.Color,
  doubao: Doubao.Color,
};

export function ModelLogo({ vendorId, size = 18 }: { vendorId: string; size?: number }) {
  const Brand = BRAND_MAP[vendorId];
  if (!Brand) {
    return (
      <span
        data-fallback="true"
        aria-hidden
        className="inline-flex items-center justify-center text-muted-foreground"
        style={{
          width: size,
          height: size,
        }}
      >
        <Boxes size={size} strokeWidth={1.8} />
      </span>
    );
  }
  return <Brand size={size} />;
}
