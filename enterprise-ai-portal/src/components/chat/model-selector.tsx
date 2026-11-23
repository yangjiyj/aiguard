"use client";

import * as React from "react";
import { ArrowRight, ChevronDown, Search } from "lucide-react";

import { cn } from "@/lib/utils";
import { enrichModel, filterModels } from "@/lib/model-catalog";
import { formatMoneyMicros as money } from "@/lib/money-micros";
import { fmtMs, fmtRate, healthOf, type Health, type ModelPerformance } from "@/lib/model-market";
import type { PortalModelPrice } from "@/lib/model-prices";
import { portalPath } from "@/lib/portal-path";
import { useChatStore } from "./store";

type ModelItem = { id: string; displayName: string; capabilities?: Record<string, unknown> };

const DOT: Record<Health, string> = { good: "bg-emerald-500", warn: "bg-amber-500", bad: "bg-red-500", unknown: "bg-muted-foreground/30" };

function HealthDot({ health }: { health: Health }) {
  return <span aria-hidden data-health={health} className={cn("inline-block h-[7px] w-[7px] shrink-0 rounded-full", DOT[health])} />;
}

// 纯展示的选项列表：性能接口失败（perf 为 null）时只隐藏性能列，模型照常可选。
export function ModelOptionList({ models, current, query, perf, prices, onPick }: {
  models: ModelItem[]; current: string; query: string; perf: ModelPerformance[] | null; prices: PortalModelPrice[]; onPick: (id: string) => void;
}) {
  const visible = filterModels(models.map(enrichModel), query);
  const perfBy = new Map((perf ?? []).map((p) => [p.model_name, p]));
  const priceBy = new Map(prices.map((p) => [p.model_name, p]));
  const cols = perf ? "grid-cols-[1fr_64px_64px_18px]" : "grid-cols-[1fr]";
  return <>
    <div className="max-h-[360px] overflow-y-auto py-1">
      {perf && visible.length > 0 && <div className={cn("grid gap-2 px-3.5 pb-1 pt-1.5 text-[11px] text-muted-foreground", cols)}><span /><span className="text-right">首字</span><span className="text-right">成功率</span><span /></div>}
      {visible.length === 0 && <p className="px-3.5 py-8 text-center text-sm text-muted-foreground">没有匹配的模型</p>}
      {visible.map((m) => {
        const p = perfBy.get(m.id);
        const price = priceBy.get(m.id);
        return <button key={m.id} type="button" role="option" aria-selected={m.id === current} onClick={() => onPick(m.id)}
          className={cn("grid w-full items-center gap-2 px-3.5 py-2 text-left text-[13px] transition-colors", cols, m.id === current ? "bg-accent" : "hover:bg-accent/60")}>
          <span className="min-w-0">
            <span className="block truncate">{m.displayName}</span>
            {price && <span className="block text-[11px] leading-tight text-muted-foreground tabular-nums">{money(price.input_per_million_micros, price.currency)} / {money(price.output_per_million_micros, price.currency)}</span>}
          </span>
          {perf && <>
            <span className="text-right text-xs tabular-nums text-muted-foreground">{fmtMs(p?.ttft_p50_ms)}</span>
            <span className="text-right text-xs tabular-nums text-muted-foreground">{fmtRate(p?.success_rate)}</span>
            <HealthDot health={healthOf(p?.success_rate)} />
          </>}
        </button>;
      })}
    </div>
    <a href={portalPath("/models")} className="flex items-center gap-1 border-t px-3.5 py-2 text-xs text-primary hover:underline">全部模型<ArrowRight className="h-3 w-3" /></a>
  </>;
}

async function getData<T>(path: string): Promise<T> {
  const r = await fetch(portalPath(path), { cache: "no-store" });
  if (!r.ok) throw new Error("unavailable");
  return ((await r.json()) as { data: T }).data;
}

export function ModelSelector({
  value,
  onChange,
  disabled,
  placement = "down",
}: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  placement?: "up" | "down";
}) {
  const { models } = useChatStore();
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [perf, setPerf] = React.useState<ModelPerformance[] | null>(null);
  const [prices, setPrices] = React.useState<PortalModelPrice[]>([]);
  const rootRef = React.useRef<HTMLDivElement>(null);
  const searchRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    getData<ModelPerformance[]>("/api/me/model-performance?window=168").then((d) => setPerf(Array.isArray(d) ? d : [])).catch(() => setPerf(null));
    getData<PortalModelPrice[]>("/api/me/model-prices").then((d) => setPrices(Array.isArray(d) ? d : [])).catch(() => setPrices([]));
  }, []);

  React.useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => searchRef.current?.focus(), 20);
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(t);
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const selected = models.find((m) => m.id === value);
  const selectedPerf = perf?.find((p) => p.model_name === value);

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => {
          if (disabled) return;
          if (!open) setQuery("");
          setOpen((current) => !current);
        }}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label="选择模型"
        className="flex h-8 min-w-0 items-center gap-2 rounded-full border bg-card px-3 text-[13px] transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
      >
        {perf && <HealthDot health={healthOf(selectedPerf?.success_rate)} />}
        <span className="min-w-0 max-w-[200px] truncate">{selected?.displayName ?? value ?? "选择模型"}</span>
        <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div
          role="listbox"
          aria-label="可用模型"
          className={cn(
            "absolute left-1/2 z-50 w-[460px] -translate-x-1/2 overflow-hidden rounded-2xl border bg-popover text-popover-foreground shadow-2xl max-sm:fixed max-sm:inset-x-4 max-sm:w-auto max-sm:translate-x-0",
            placement === "up" ? "bottom-[calc(100%+8px)]" : "top-[calc(100%+8px)]",
          )}
        >
          <label className="flex items-center gap-2 border-b px-3.5 py-2.5">
            <Search className="h-3.5 w-3.5 text-muted-foreground" />
            <input
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索模型"
              aria-label="搜索模型"
              className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
            />
          </label>
          <ModelOptionList models={models} current={value} query={query} perf={perf} prices={prices}
            onPick={(id) => { onChange(id); setOpen(false); }} />
        </div>
      )}
    </div>
  );
}
