"use client";

import * as React from "react";
import { Search } from "lucide-react";
import { SORT_OPTIONS, buildMarketRows, filterRows, sortPreset, sortRows, vendorFacets, type MarketRow, type MarketSortKey, type ModelPerformance } from "@/lib/model-market";
import type { PortalModelPrice } from "@/lib/model-prices";
import { portalPath } from "@/lib/portal-path";
import { ModelDrawer, type DrawerTab } from "./model-drawer";
import { ModelCard } from "./model-card";

export function ModelsGrid({ rows, loading, selected, onSelect, currency }: {
  rows: MarketRow[]; loading: boolean; selected: string | null; onSelect: (model: string) => void; currency?: string;
}) {
  if (!rows.length) return <p className="py-16 text-center text-sm text-muted-foreground">没有匹配的模型</p>;
  return <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3">
    {rows.map((row) => <ModelCard key={row.model} row={row} loading={loading} selected={selected === row.model} onSelect={onSelect} currency={currency} />)}
  </div>;
}


async function getJSON<T>(path: string): Promise<T> {
  const r = await fetch(portalPath(path), { cache: "no-store" });
  if (!r.ok) throw new Error("unavailable");
  return r.json() as Promise<T>;
}

export function ModelsPage() {
  const [models, setModels] = React.useState<string[] | null>(null);
  const [prices, setPrices] = React.useState<PortalModelPrice[]>([]);
  const [perf, setPerf] = React.useState<Partial<Record<24 | 168, ModelPerformance[]>>>({});
  const [perfError, setPerfError] = React.useState(false);
  const [baseUrl, setBaseUrl] = React.useState("");
  const [error, setError] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [sortKey, setSortKey] = React.useState<MarketSortKey>("samples");
  const [vendor, setVendor] = React.useState("all");
  const [selected, setSelected] = React.useState<string | null>(null);
  const [tab, setTab] = React.useState<DrawerTab>("overview");
  const [window, setWindow] = React.useState<24 | 168>(168);
  const loadPerf = React.useCallback((w: 24 | 168) => {
    getJSON<{ data: ModelPerformance[] }>(`/api/me/model-performance?window=${w}`)
      .then((b) => { setPerf((p) => ({ ...p, [w]: b.data ?? [] })); setPerfError(false); })
      .catch(() => setPerfError(true));
  }, []);
  React.useEffect(() => {
    getJSON<{ data: { modelIds: string[] } }>("/api/me/model-access").then((b) => setModels(b.data.modelIds)).catch(() => setError("模型授权暂不可用，请稍后重试。"));
    getJSON<{ data: PortalModelPrice[] }>("/api/me/model-prices").then((b) => setPrices(Array.isArray(b.data) ? b.data : [])).catch(() => {});
    getJSON<{ data: { openai?: string } }>("/api/me/gateway").then((b) => setBaseUrl(b.data?.openai ?? "")).catch(() => {});
    loadPerf(168);
  }, [loadPerf]);
  React.useEffect(() => { if (selected && !perf[window]) loadPerf(window); }, [selected, window, perf, loadPerf]);
  React.useEffect(() => {
    if (!selected) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setSelected(null); };
    globalThis.addEventListener("keydown", onKey);
    return () => globalThis.removeEventListener("keydown", onKey);
  }, [selected]);
  const rows = buildMarketRows(models ?? [], prices, perf[168] ?? []);
  const visible = sortRows(filterRows(rows, query, vendor), sortPreset(sortKey));
  const facets = vendorFacets(rows);
  const perfLoading = !perf[168] && !perfError;
  const current = rows.find((r) => r.model === selected) ?? null;
  const chip = (on: boolean) => "h-[30px] shrink-0 rounded-full px-3.5 text-[13px] transition-colors " + (on ? "bg-foreground text-background" : "bg-muted text-muted-foreground hover:text-foreground");
  return <div className="mx-auto max-w-6xl px-4 py-7 sm:px-8">
    <div className="flex flex-wrap items-center gap-3">
      <h1 className="mr-auto text-[22px] font-semibold">模型</h1>
      <label className="relative w-full sm:w-[300px]"><span className="sr-only">搜索模型</span><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索模型" className="h-9 w-full rounded-[9px] border bg-card pl-9 pr-3 text-sm outline-none focus:ring-2 focus:ring-primary/30" /></label>
      <label><span className="sr-only">排序</span><select value={sortKey} onChange={(e) => setSortKey(e.target.value as MarketSortKey)} className="h-9 rounded-[9px] border bg-card px-3 text-[13px] outline-none focus:ring-2 focus:ring-primary/30">{SORT_OPTIONS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}</select></label>
    </div>
    {perfError && <p role="alert" className="mt-3 text-sm text-amber-600 dark:text-amber-400">性能数据暂不可用 · <button type="button" className="underline" onClick={() => loadPerf(168)}>重试</button></p>}
    {error && <p role="alert" className="mt-3 text-sm text-destructive">{error}</p>}
    {models && <div role="group" aria-label="厂商" className="mb-5 mt-[18px] flex gap-2 overflow-x-auto">
      <button type="button" aria-pressed={vendor === "all"} onClick={() => setVendor("all")} className={chip(vendor === "all")}>全部 {rows.length}</button>
      {facets.map((f) => <button key={f.id} type="button" aria-pressed={vendor === f.id} onClick={() => setVendor(f.id)} className={chip(vendor === f.id)}>{f.name}</button>)}
    </div>}
    {models === null && !error ? <div data-loading className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3">{[0, 1, 2].map((i) => <div key={i} className="h-[214px] animate-pulse rounded-2xl border bg-muted/40" />)}</div>
      : <ModelsGrid rows={visible} loading={perfLoading} selected={selected} onSelect={(m) => { setSelected(m); setTab("overview"); }} />}
    {current && <ModelDrawer row={current} tab={tab} onTab={setTab} onClose={() => setSelected(null)} window={window} onWindow={setWindow}
      windowPerf={(perf[window] ?? []).find((p) => p.model_name === current.model) ?? null} baseUrl={baseUrl} />}
  </div>;
}
