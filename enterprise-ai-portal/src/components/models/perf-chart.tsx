import * as React from "react";
import type { PerfPoint } from "@/lib/model-market";

type Series = { key: "success_rate" | "ttft_p50_ms"; label: string; color: string; max?: number };
const SERIES: Series[] = [
  { key: "success_rate", label: "成功率", color: "var(--primary)", max: 1 },
  { key: "ttft_p50_ms", label: "首字延迟", color: "oklch(0.7 0.13 250)" },
];

// 断点处（无样本的桶）断开折线，不做插值，避免把没有流量的时段画成正常。
function segments(points: PerfPoint[], s: Series, w: number, h: number, pad: number): string[] {
  const max = s.max ?? Math.max(1, ...points.map((p) => p[s.key] ?? 0));
  const x = (i: number) => (points.length <= 1 ? 0 : (i / (points.length - 1)) * w);
  const out: string[][] = [[]];
  points.forEach((p, i) => {
    const v = p[s.key];
    if (v == null) { out.push([]); return; }
    out[out.length - 1].push(`${x(i).toFixed(1)},${(h - pad - (v / max) * (h - pad * 2)).toFixed(1)}`);
  });
  return out.filter((seg) => seg.length > 0).map((seg) => seg.length === 1 ? `${seg[0]} ${seg[0]}` : seg.join(" "));
}

export function PerfChart({ points }: { points: PerfPoint[] }) {
  const w = 400, h = 140, pad = 16;
  if (!points.some((p) => p.samples > 0)) return <p className="py-10 text-center text-sm text-muted-foreground">暂无样本</p>;
  return <figure>
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" role="img" aria-label="成功率与首字延迟趋势">
      {[pad, h / 2, h - pad].map((y) => <line key={y} x1={0} x2={w} y1={y} y2={y} stroke="var(--border)" />)}
      {SERIES.flatMap((s) => segments(points, s, w, h, pad).map((pts, i) => <polyline key={s.key + i} points={pts} fill="none" stroke={s.color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />))}
    </svg>
    <figcaption className="mt-2 flex gap-4 text-xs text-muted-foreground">
      {SERIES.map((s) => <span key={s.key} className="inline-flex items-center gap-1.5"><i className="inline-block h-0.5 w-3 rounded" style={{ background: s.color }} />{s.label}</span>)}
    </figcaption>
  </figure>;
}
