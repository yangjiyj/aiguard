import * as React from "react";
import { formatMoneyMicros as money } from "@/lib/money-micros";
import { vendorFromId } from "@/lib/model-catalog";
import { vendorName } from "@/lib/model-prices";
import { MIN_SAMPLES, PROTOCOL_LABELS, fmtMs, fmtRate, fmtTps, healthOf, type MarketRow, type PerfPoint } from "@/lib/model-market";

const VENDOR_MARK: Record<string, [string, string]> = {
  openai: ["O", "bg-neutral-900 dark:bg-neutral-700"],
  anthropic: ["A", "bg-[#c96442]"],
  deepseek: ["D", "bg-[#4d6bfe]"],
  qwen: ["Q", "bg-[#615ced]"],
  zhipu: ["Z", "bg-[#3859ff]"],
  google: ["G", "bg-[#4285f4]"],
  doubao: ["豆", "bg-[#1f7aff]"],
  other: ["企", "bg-slate-500"],
};

// 7 天调用量趋势：只看形状，不画坐标轴。
function Sparkline({ points }: { points: PerfPoint[] }) {
  const max = Math.max(1, ...points.map((p) => p.samples));
  const step = points.length > 1 ? 300 / (points.length - 1) : 300;
  const xy = points.map((p, i) => `${(i * step).toFixed(1)},${(26 - (p.samples / max) * 22).toFixed(1)}`);
  return <svg viewBox="0 0 300 28" preserveAspectRatio="none" className="mt-3 h-7 w-full text-primary" aria-hidden>
    <path d={`M0,28 L${xy.join(" L")} L300,28Z`} fill="currentColor" opacity={0.08} />
    <polyline points={xy.join(" ")} fill="none" stroke="currentColor" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
  </svg>;
}

function Metric({ label, value, health }: { label: string; value: string; health?: string }) {
  return <div className="min-w-0">
    <div className="text-[11.5px] text-muted-foreground">{label}</div>
    <div data-health={health} className={"mt-0.5 text-[17px] font-semibold tabular-nums " + (health === "bad" ? "text-red-500" : "")}>{value}</div>
  </div>;
}

export function ModelCard({ row, loading, selected, onSelect, currency }: {
  row: MarketRow; loading: boolean; selected: boolean; onSelect: (model: string) => void; currency?: string;
}) {
  const vendor = vendorFromId(row.model);
  const [mark, tone] = VENDOR_MARK[vendor] ?? VENDOR_MARK.other;
  const perf = row.perf;
  const samples = perf?.samples ?? 0;
  const price = row.price;
  let body: React.ReactNode;
  if (loading) {
    body = <div data-loading aria-hidden className="mt-3.5 grid grid-cols-3 gap-2">
      {[0, 1, 2].map((i) => <div key={i} className="space-y-1.5"><div className="h-2.5 w-8 animate-pulse rounded bg-muted" /><div className="h-4 w-14 animate-pulse rounded bg-muted" /></div>)}
    </div>;
  } else if (samples < MIN_SAMPLES) {
    body = <p className="mt-3.5 flex h-[74px] items-center text-[13px] text-muted-foreground">{samples ? `近 7 天 ${samples} 次调用，样本不足` : "近 7 天暂无调用"}</p>;
  } else {
    body = <>
      <div className="mt-3.5 grid grid-cols-3 gap-2">
        <Metric label="首字" value={fmtMs(perf?.ttft_p50_ms)} />
        <Metric label="速度" value={fmtTps(perf?.tps_p50)} />
        <Metric label="成功率" value={fmtRate(perf?.success_rate)} health={healthOf(perf?.success_rate)} />
      </div>
      <Sparkline points={perf?.hourly ?? []} />
    </>;
  }
  return <button type="button" onClick={() => onSelect(row.model)} aria-pressed={selected}
    className={"flex w-full flex-col rounded-2xl border bg-card px-[18px] pb-3.5 pt-4 text-left transition-[border-color,box-shadow] hover:border-primary/40 hover:shadow-[0_6px_20px_rgba(15,157,118,.08)] focus-visible:outline-2 focus-visible:outline-primary " + (selected ? "border-primary/60" : "")}>
    <div className="flex items-center gap-3">
      <span className={"grid h-[34px] w-[34px] shrink-0 place-items-center rounded-[9px] text-[13px] font-bold text-white " + tone}>{mark}</span>
      <span className="min-w-0">
        <span className="block truncate text-[15px] font-semibold">{row.model}</span>
        <span className="block text-xs text-muted-foreground">{vendorName(row.model)}</span>
      </span>
    </div>
    {(perf?.protocols?.length ?? 0) > 0 && <div className="mt-3 flex flex-wrap gap-1.5">
      {perf!.protocols.map((p) => <span key={p} className="rounded-[5px] bg-muted px-2 py-px text-[11.5px] text-muted-foreground">{PROTOCOL_LABELS[p] ?? p}</span>)}
    </div>}
    {body}
    <div className="mt-2.5 flex items-baseline gap-3 border-t pt-2.5 text-[12.5px] text-muted-foreground">
      <span className="flex-1">每百万 tokens</span>
      {price ? <>
        <span>输入 <b className="font-semibold text-foreground tabular-nums">{money(price.input_per_million_micros, price.currency, currency)}</b></span>
        <span>输出 <b className="font-semibold text-foreground tabular-nums">{money(price.output_per_million_micros, price.currency, currency)}</b></span>
      </> : <span>未定价</span>}
    </div>
  </button>;
}
