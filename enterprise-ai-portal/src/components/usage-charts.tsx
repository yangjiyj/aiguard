"use client";

import * as React from "react";
import { formatMoneyMicros as money } from "@/lib/money-micros";
import { compactNumber, fillDailySeries, modelShares, type DailyUsage, type ModelUsage } from "@/lib/usage-charts";

type Metric = "amount" | "tokens" | "requests";
const METRICS: [Metric, string][] = [["amount", "金额"], ["tokens", "Token"], ["requests", "调用次数"]];
const SHARE_COLORS = ["#3b6af6", "#16a34a", "#f59e0b", "#a855f7", "#ef4444", "#0ea5e9", "#94a3b8"];

function metricValue(item: DailyUsage, metric: Metric) {
  return metric === "amount" ? item.amount_micros : metric === "tokens" ? item.tokens : item.requests;
}

export function UsageTrendChart({ daily, currency }: { daily: DailyUsage[]; currency: string }) {
  const [metric, setMetric] = React.useState<Metric>("amount");
  const [hover, setHover] = React.useState<number | null>(null);
  const series = React.useMemo(() => fillDailySeries(daily), [daily]);
  const values = series.map((item) => metricValue(item, metric));
  const max = Math.max(1, ...values);
  const total = values.reduce((sum, v) => sum + v, 0);
  const active = series.filter((item) => metricValue(item, metric) > 0).length;
  const fmt = (v: number) => metric === "amount" ? money(v, currency) : compactNumber(v) + (metric === "tokens" ? "" : " 次");
  const focus = hover === null ? null : series[hover];
  return <div data-testid="usage-trend">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div><p className="text-xs text-muted-foreground">近 30 天合计</p><p className="text-xl font-semibold tabular-nums">{fmt(total)}</p></div>
      <div role="tablist" aria-label="趋势指标" className="flex rounded-lg bg-muted p-0.5 text-xs">{METRICS.map(([id, label]) => <button key={id} type="button" role="tab" aria-selected={metric === id} onClick={() => setMetric(id)} className={"rounded-md px-3 py-1 transition " + (metric === id ? "bg-background font-medium shadow-sm" : "text-muted-foreground hover:text-foreground")}>{label}</button>)}</div>
    </div>
    <div className="mt-2 h-5 text-xs text-muted-foreground">{focus ? <span><span className="font-medium text-foreground">{focus.date}</span> · {money(focus.amount_micros, focus.currency, currency)} · {compactNumber(focus.tokens)} Token · {compactNumber(focus.requests)} 次</span> : <span>{active ? "有调用的天数 " + active + " 天，日均 " + fmt(Math.round(total / Math.max(1, active))) : "近 30 天暂无已结算调用"}</span>}</div>
    <div className="relative mt-2 h-40">
      <div aria-hidden className="pointer-events-none absolute inset-0 flex flex-col justify-between">{[0, 1, 2, 3].map((i) => <div key={i} className="border-t border-dashed border-border/70" />)}</div>
      <div className="relative flex h-full items-end gap-[3px]" onMouseLeave={() => setHover(null)}>
        {series.map((item, index) => {
          const value = values[index];
          const height = value > 0 ? Math.max(4, value / max * 100) : 0;
          return <div key={item.date} className="flex h-full flex-1 cursor-default items-end" onMouseEnter={() => setHover(index)} title={item.date + " · " + fmt(value)}>
            <div className={"w-full rounded-t-[3px] transition-colors " + (value === 0 ? "h-[2px] bg-muted" : hover === index ? "bg-primary" : "bg-primary/60")} style={value ? { height: height + "%" } : undefined} />
          </div>;
        })}
      </div>
    </div>
    <div className="mt-1 flex justify-between text-[10px] text-muted-foreground tabular-nums"><span>{series[0]?.date.slice(5)}</span><span>{series[14]?.date.slice(5)}</span><span>{series.at(-1)?.date.slice(5)}</span></div>
  </div>;
}

export function ModelShareChart({ models, currency }: { models: ModelUsage[]; currency: string }) {
  const shares = modelShares(models);
  if (!shares.length) return <p className="py-10 text-center text-sm text-muted-foreground">暂无模型调用</p>;
  return <div data-testid="model-share">
    <div className="flex h-3 overflow-hidden rounded-full bg-muted">{shares.map((item, i) => <div key={item.model_name} title={item.model_name + " " + (item.share * 100).toFixed(1) + "%"} style={{ width: item.share * 100 + "%", background: SHARE_COLORS[i % SHARE_COLORS.length] }} />)}</div>
    <ul className="mt-4 space-y-2.5">{shares.map((item, i) => <li key={item.model_name} className="text-sm">
      <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: SHARE_COLORS[i % SHARE_COLORS.length] }} /><span className="min-w-0 flex-1 truncate" title={item.model_name}>{item.model_name}</span><span className="tabular-nums text-muted-foreground">{(item.share * 100).toFixed(1)}%</span><span className="w-24 text-right font-medium tabular-nums">{money(item.amount_micros, item.currency, currency)}</span></div>
      <p className="ml-[18px] text-[11px] text-muted-foreground">{compactNumber(item.requests)} 次 · {compactNumber(item.tokens)} Token</p>
    </li>)}</ul>
  </div>;
}
