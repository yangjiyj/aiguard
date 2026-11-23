import * as React from "react";
import { KeyRound, X } from "lucide-react";
import { formatMoneyMicros as money } from "@/lib/money-micros";
import { priceExtras } from "@/lib/model-prices";
import { PROTOCOL_LABELS, curlExample, fmtMs, fmtRate, fmtTps, healthOf, type MarketRow, type ModelPerformance } from "@/lib/model-market";
import { portalPath } from "@/lib/portal-path";
import { PerfChart } from "./perf-chart";

export type DrawerTab = "overview" | "performance" | "access";
const TABS: [DrawerTab, string][] = [["overview", "概览"], ["performance", "性能"], ["access", "接入"]];
export const HEALTH_CLASS = { good: "text-emerald-500", warn: "text-amber-500", bad: "text-red-500", unknown: "" } as const;

export function ModelDrawer({ row, tab, onTab, onClose, window, onWindow, windowPerf, baseUrl, currency }: {
  row: MarketRow; tab: DrawerTab; onTab: (t: DrawerTab) => void; onClose: () => void;
  window: 24 | 168; onWindow: (w: 24 | 168) => void; windowPerf: ModelPerformance | null; baseUrl: string; currency?: string;
}) {
  const perf = row.perf;
  const price = row.price;
  const fmt = (micros: number) => price ? money(micros, price.currency, currency) : "—";
  const extras = price ? priceExtras(price).filter((e) => !e.label.startsWith("缓存")) : [];
  const protocols = (perf?.protocols ?? []).map((p) => PROTOCOL_LABELS[p] ?? p);
  const kpis: [string, string, string][] = [
    ["TPS", fmtTps(perf?.tps_p50), ""],
    ["首字延迟", fmtMs(perf?.ttft_p50_ms), ""],
    ["成功率", fmtRate(perf?.success_rate), HEALTH_CLASS[healthOf(perf?.success_rate)]],
  ];
  return <aside role="dialog" aria-label={row.model} className="fixed inset-y-0 right-0 z-40 flex w-full max-w-[440px] flex-col border-l bg-card shadow-2xl">
    <header className="flex items-start justify-between gap-3 px-6 pt-6">
      <h2 className="truncate text-lg font-semibold">{row.model}</h2>
      <button type="button" aria-label="关闭" onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-5 w-5" /></button>
    </header>
    <div role="tablist" className="mt-4 flex gap-6 border-b px-6">
      {TABS.map(([key, label]) => <button key={key} type="button" role="tab" aria-selected={tab === key} onClick={() => onTab(key)} className={"-mb-px border-b-2 pb-2.5 text-sm transition-colors " + (tab === key ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>{label}</button>)}
    </div>
    <div className="flex-1 overflow-y-auto px-6 py-5">
      {tab === "overview" && <>
        <div className="grid grid-cols-3 overflow-hidden rounded-xl border">
          {kpis.map(([label, value, cls]) => <div key={label} className="border-r px-4 py-3.5 last:border-r-0"><p className="text-xs text-muted-foreground">{label}</p><p className={"mt-1 text-xl font-semibold tabular-nums " + cls}>{value}</p></div>)}
        </div>
        {price ? <>
          <section className="mt-7">
            <h3 className="mb-3 flex justify-between text-sm font-semibold">标准价<span className="font-normal text-muted-foreground">{price.currency} / 1M tokens</span></h3>
            <dl className="grid grid-cols-2 gap-x-5 gap-y-3">
              <div><dt className="text-xs text-muted-foreground">输入</dt><dd className="text-base tabular-nums">{fmt(price.input_per_million_micros)}</dd></div>
              <div><dt className="text-xs text-muted-foreground">输出</dt><dd className="text-base tabular-nums">{fmt(price.output_per_million_micros)}</dd></div>
            </dl>
          </section>
          {(price.has_cached_input_price || price.has_cache_write_price) && <section className="mt-7">
            <h3 className="mb-3 text-sm font-semibold">缓存价</h3>
            <dl className="grid grid-cols-2 gap-x-5 gap-y-3">
              {price.has_cached_input_price && <div><dt className="text-xs text-muted-foreground">缓存命中</dt><dd className="text-base tabular-nums">{fmt(price.cached_input_per_million_micros)}</dd></div>}
              {price.has_cache_write_price && <div><dt className="text-xs text-muted-foreground">缓存写入</dt><dd className="text-base tabular-nums">{fmt(price.cache_write_per_million_micros)}</dd></div>}
            </dl>
          </section>}
          {!!extras.length && <section className="mt-7">
            <h3 className="mb-3 text-sm font-semibold">其他计费</h3>
            <dl className="space-y-1.5 text-sm">{extras.map((e) => <div key={e.label} className="flex justify-between gap-3"><dt className="text-muted-foreground">{e.label}</dt><dd className="tabular-nums">{fmt(e.micros)} <span className="text-muted-foreground">{e.unit}</span></dd></div>)}</dl>
          </section>}
        </> : <p className="mt-7 text-sm text-muted-foreground">未定价</p>}
      </>}
      {tab === "performance" && <>
        <div className="mb-3 inline-flex overflow-hidden rounded-lg border text-xs">
          {([24, 168] as const).map((w) => <button key={w} type="button" aria-pressed={window === w} onClick={() => onWindow(w)} className={"px-3 py-1 " + (window === w ? "bg-accent text-foreground" : "text-muted-foreground")}>{w === 24 ? "24 小时" : "7 天"}</button>)}
        </div>
        <PerfChart points={windowPerf?.hourly ?? []} />
        <dl className="mt-5 grid grid-cols-3 gap-3 text-xs text-muted-foreground">
          <div><dt>首字 P50 / P95</dt><dd className="mt-0.5 text-sm font-medium text-foreground tabular-nums">{fmtMs(windowPerf?.ttft_p50_ms)} / {fmtMs(windowPerf?.ttft_p95_ms)}</dd></div>
          <div><dt>总耗时 P50 / P95</dt><dd className="mt-0.5 text-sm font-medium text-foreground tabular-nums">{fmtMs(windowPerf?.latency_p50_ms)} / {fmtMs(windowPerf?.latency_p95_ms)}</dd></div>
          <div><dt>调用次数</dt><dd className="mt-0.5 text-sm font-medium text-foreground tabular-nums">{(windowPerf?.samples ?? 0).toLocaleString("zh-CN")}</dd></div>
        </dl>
      </>}
      {tab === "access" && <>
        <dl className="grid grid-cols-[88px_1fr] gap-x-3 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Base URL</dt><dd className="break-all font-mono">{baseUrl || "—"}</dd>
          <dt className="text-muted-foreground">模型 ID</dt><dd className="break-all font-mono">{row.model}</dd>
          <dt className="text-muted-foreground">协议</dt><dd>{protocols.join(" · ") || "—"}</dd>
        </dl>
        {baseUrl && <pre className="mt-4 overflow-x-auto whitespace-pre-wrap break-all rounded-lg border bg-background p-3 font-mono text-xs leading-relaxed">{curlExample(baseUrl, row.model, perf?.protocols ?? [])}</pre>}
      </>}
    </div>
    <footer className="flex justify-end gap-2.5 border-t px-6 py-3.5">
      <a href={portalPath("/billing#api-keys")} className="inline-flex items-center gap-1.5 rounded-lg bg-foreground px-3.5 py-2 text-sm text-background"><KeyRound className="h-4 w-4" />管理 API 密钥</a>
      <button type="button" onClick={onClose} className="rounded-lg border px-3.5 py-2 text-sm hover:bg-accent">关闭</button>
    </footer>
  </aside>;
}
