"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  FileText,
  RefreshCw,
} from "lucide-react";

import {
  agentTypeLabel,
	billingAmountPresentation,
  callSourceLabel,
  callStatusPresentation,
  endpointTypeLabel,
  formatTokenCount,
} from "@/lib/call-records";
import type { PortalCallRecord, PortalCallRecordSummary } from "@/lib/control-plane";
import type { MergedRecord } from "@/lib/records";
import { formatBytes } from "@/lib/upload";
import { cn } from "@/lib/utils";
import { portalPath } from "@/lib/portal-path";
import { PortalShell } from "@/components/portal-shell";

const PAGE_SIZE = 50;
const CALL_RECORD_DAYS = 30;
const REQUEST_ID_PATTERN = /^(?:req_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type RecordTab = "calls" | "files";

const dateFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "时间未知" : dateFormatter.format(date);
}

function formatLatency(value: number): string {
  if (value < 1000) return value + " ms";
  return (value / 1000).toFixed(value < 10000 ? 1 : 0) + " s";
}

/** 输出 TPS = 输出 Token / 总耗时（端到端口径，与服务端 latency_ms 同源）；Token 或时长无效时不展示。 */
function outputTps(outputTokens: number, latencyMs: number): number | null {
  if (!Number.isFinite(outputTokens) || !Number.isFinite(latencyMs) || outputTokens <= 0 || latencyMs <= 0) return null;
  return outputTokens / (latencyMs / 1000);
}
function formatTps(value: number): string {
  return `${value >= 100 ? Math.round(value) : Number(value.toFixed(1))} tok/s`;
}

function StatusBadge({ record }: { record: PortalCallRecord }) {
  const status = callStatusPresentation(record.status);
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center rounded border px-2 text-xs font-medium",
        status.tone === "success" &&
          "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300",
        status.tone === "warning" &&
          "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-300",
        status.tone === "danger" &&
          "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/60 dark:text-rose-300",
      )}
    >
      {status.label}
    </span>
  );
}

function Pagination({
  startIndex,
  total,
  canPrevious,
  canNext,
  onPrevious,
  onNext,
}: {
  startIndex: number;
  total: number;
  canPrevious: boolean;
  canNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
}) {
  if (total <= PAGE_SIZE) return null;
  return (
    <div className="flex min-h-12 items-center justify-between gap-3 border-t px-4 py-2">
      <span className="text-xs tabular-nums text-muted-foreground">
        {startIndex + 1}-{Math.min(startIndex + PAGE_SIZE, total)} / {total}
      </span>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          className="flex h-9 w-9 items-center justify-center rounded-md border bg-background text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-35"
          disabled={!canPrevious}
          onClick={onPrevious}
          aria-label="上一页"
          title="上一页"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <button
          type="button"
          className="flex h-9 w-9 items-center justify-center rounded-md border bg-background text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-35"
          disabled={!canNext}
          onClick={onNext}
          aria-label="下一页"
          title="下一页"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function LoadingRows() {
  return (
    <div aria-label="加载中" className="divide-y" aria-live="polite">
      {[0, 1, 2, 3].map((item) => (
		<div key={item} className="grid min-h-16 grid-cols-[1fr_5rem] items-center gap-5 px-4 py-3 lg:grid-cols-[7.5rem_1.2fr_1fr_4rem_5rem_5rem_5rem_5rem_6rem_2.25rem]">
          <span className="h-3 w-24 animate-pulse rounded bg-muted" />
          <span className="h-3 w-16 animate-pulse rounded bg-muted" />
          <span className="hidden h-3 w-28 animate-pulse rounded bg-muted lg:block" />
          <span className="hidden h-6 w-12 animate-pulse rounded bg-muted lg:block" />
          <span className="hidden h-3 w-10 animate-pulse rounded bg-muted lg:block" />
          <span className="hidden h-3 w-10 animate-pulse rounded bg-muted lg:block" />
          <span className="hidden h-3 w-10 animate-pulse rounded bg-muted lg:block" />
          <span className="hidden h-3 w-10 animate-pulse rounded bg-muted lg:block" />
		  <span className="hidden h-3 w-20 animate-pulse rounded bg-muted lg:block" />
          <span className="hidden h-8 w-8 animate-pulse rounded bg-muted lg:block" />
        </div>
      ))}
    </div>
  );
}

function ErrorBand({ label, onRetry }: { label: string; onRetry: () => void }) {
  return (
    <div className="flex min-h-40 flex-col items-center justify-center gap-3 px-5 py-10 text-center">
      <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400" />
      <p className="text-sm font-medium">{label}</p>
      <button
        type="button"
        onClick={onRetry}
        className="inline-flex h-9 items-center gap-2 rounded-md border bg-background px-3 text-sm font-medium transition-colors hover:bg-accent"
      >
        <RefreshCw className="h-4 w-4" />
        重试
      </button>
    </div>
  );
}

function EmptyBand({ label }: { label: string }) {
  return (
    <div className="flex min-h-40 items-center justify-center px-5 py-10 text-sm text-muted-foreground">
      {label}
    </div>
  );
}

function CallRecordRows({
  records,
  tenantCurrency,
  expandedRequestId,
  focusRequestId,
  onToggle,
}: {
  records: PortalCallRecord[];
  tenantCurrency: string;
  expandedRequestId: string | null;
  focusRequestId?: string;
  onToggle: (requestId: string) => void;
}) {
  return (
    <div className="divide-y">
      {records.map((record) => {
        const expanded = expandedRequestId === record.requestId;
        const source = callSourceLabel(record.endpointType, record.agentType);
        const tps = outputTps(record.outputTokens, record.latencyMs);
        return (
          <div key={record.requestId} className={cn(record.requestId === focusRequestId && "bg-accent/40")}>
			<div className="hidden min-h-16 grid-cols-[7.5rem_minmax(5rem,1.2fr)_minmax(5rem,1fr)_4rem_5rem_5rem_5rem_5rem_6rem_2.25rem] items-center gap-3 px-4 py-3 text-sm lg:grid">
              <time className="tabular-nums text-xs text-muted-foreground">
                {formatDate(record.createdAt)}
              </time>
              <span className="truncate font-medium" title={source}>
                {source}
              </span>
              <span className="truncate text-muted-foreground" title={record.model}>
                {record.model}
              </span>
              <StatusBadge record={record} />
              <span className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                {formatTokenCount(record.inputTokens)}
                <span className="mt-1 block text-[10px] leading-relaxed">输入 Token 已包含缓存读取与写入</span>
              </span>
              <span className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                {record.cachedInputTokens > 0 ? formatTokenCount(record.cachedInputTokens) : "—"}
              </span>
              <span className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                {formatTokenCount(record.outputTokens)}
                {tps !== null && (
                  <span className="mt-1 block text-[10px] leading-relaxed" title="输出 Token / 总耗时">
                    输出 TPS {formatTps(tps)}
                  </span>
                )}
              </span>
              <span className="text-right font-mono text-xs font-semibold tabular-nums">
                {formatTokenCount(record.totalTokens)}
              </span>
			  <span className="text-right font-mono text-xs font-medium tabular-nums">
				{billingAmountPresentation(
				  record.billingState,
				  record.billingAmountMicros,
				  record.billingCurrency,
                  tenantCurrency,
				)}
			  </span>
              <button
                type="button"
                className="flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                onClick={() => onToggle(record.requestId)}
                aria-label={expanded ? "收起调用概览" : "展开调用概览"}
                aria-expanded={expanded}
                title={expanded ? "收起调用概览" : "展开调用概览"}
              >
                <ChevronDown
                  className={cn("h-4 w-4 transition-transform", expanded && "rotate-180")}
                />
              </button>
            </div>

            <div className="px-4 py-3 lg:hidden">
              <div className="flex min-w-0 items-start gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge record={record} />
                    <time className="text-xs tabular-nums text-muted-foreground">
                      {formatDate(record.createdAt)}
                    </time>
                  </div>
                  <p className="mt-2 truncate text-sm font-semibold" title={record.model}>
                    {record.model}
                  </p>
                  <p className="mt-0.5 truncate text-xs text-muted-foreground" title={source}>
                    {source}
                  </p>
                </div>
                <button
                  type="button"
                  className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                  onClick={() => onToggle(record.requestId)}
                  aria-label={expanded ? "收起调用概览" : "展开调用概览"}
                  aria-expanded={expanded}
                  title={expanded ? "收起调用概览" : "展开调用概览"}
                >
                  <ChevronDown
                    className={cn("h-4 w-4 transition-transform", expanded && "rotate-180")}
                  />
                </button>
              </div>
              <dl className="mt-3 grid grid-cols-2 gap-y-3 sm:grid-cols-4 rounded-md border bg-muted/20 py-2">
                <div className="px-2 text-center">
                  <dt className="text-[10px] text-muted-foreground">输入 Token</dt>
                  <dd className="mt-1 font-mono text-xs font-medium tabular-nums">
                    {formatTokenCount(record.inputTokens)}
                    <span className="mt-1 block font-sans text-[10px] leading-relaxed text-muted-foreground">输入 Token 已包含缓存读取与写入</span>
                  </dd>
                </div>
                <div className="px-2 text-center">
                  <dt className="text-[10px] text-muted-foreground">缓存读取</dt>
                  <dd className="mt-1 font-mono text-xs font-medium tabular-nums">
                    {record.cachedInputTokens > 0 ? formatTokenCount(record.cachedInputTokens) : "—"}
                  </dd>
                </div>
                <div className="px-2 text-center">
                  <dt className="text-[10px] text-muted-foreground">输出 Token</dt>
                  <dd className="mt-1 font-mono text-xs font-medium tabular-nums">
                    {formatTokenCount(record.outputTokens)}
                  </dd>
                </div>
                <div className="px-2 text-center">
                  <dt className="text-[10px] text-muted-foreground">总 Token</dt>
                  <dd className="mt-1 font-mono text-xs font-semibold tabular-nums">
                    {formatTokenCount(record.totalTokens)}
                  </dd>
                </div>
              </dl>
			  <div className="mt-2 flex min-h-9 items-center justify-between gap-3 rounded-md border bg-muted/20 px-3 py-2 text-xs">
				<span className="text-muted-foreground">消耗金额</span>
				<span className="font-mono font-semibold tabular-nums">
				  {billingAmountPresentation(
					record.billingState,
					record.billingAmountMicros,
					record.billingCurrency,
                  tenantCurrency,
				  )}
				</span>
			  </div>
            </div>

            {expanded && (
              <div className="border-t bg-muted/25 px-4 py-4">
                <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <dt className="text-xs text-muted-foreground">端点</dt>
                    <dd className="mt-1 text-sm font-medium">
                      {endpointTypeLabel(record.endpointType)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">智能体类型</dt>
                    <dd className="mt-1 text-sm font-medium">
                      {agentTypeLabel(record.agentType) || "未识别"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">总耗时</dt>
                    <dd className="mt-1 text-sm font-medium tabular-nums">
                      {formatLatency(record.latencyMs)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">输出 TPS</dt>
                    <dd className="mt-1 text-sm font-medium tabular-nums" title="输出 Token / 总耗时">
                      {tps !== null ? formatTps(tps) : "—"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">缓存读取 Token</dt>
                    <dd className="mt-1 font-mono text-sm tabular-nums">{formatTokenCount(record.cachedInputTokens)}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">缓存写入 Token</dt>
                    <dd className="mt-1 font-mono text-sm tabular-nums">{formatTokenCount(record.cacheWriteInputTokens)}</dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-xs text-muted-foreground">请求编号</dt>
                    <dd className="mt-1 break-all font-mono text-xs">{record.requestId}</dd>
                  </div>
                </dl>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function FileRecordRows({ records }: { records: MergedRecord[] }) {
  return (
    <div className="divide-y">
      {records.map((record) => (
        <div
          key={record.id}
          className="grid min-h-16 grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-4 py-3 sm:grid-cols-[minmax(0,1.5fr)_minmax(7rem,0.7fr)_8rem]"
        >
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate text-sm font-medium" title={record.filename}>
                {record.filename}
              </span>
              <span
                className={cn(
                  "shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium",
                  record.source === "gateway"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300"
                    : "border-border bg-muted text-muted-foreground",
                )}
              >
                {record.source === "gateway" ? "已留证" : "本地"}
              </span>
            </div>
            <p className="mt-1 truncate text-xs text-muted-foreground">
              {record.mime} · {formatBytes(record.size)}
            </p>
          </div>
          <span className="hidden truncate text-xs text-muted-foreground sm:block">
            {record.model || "未关联模型"}
          </span>
          <time className="text-right text-xs tabular-nums text-muted-foreground">
            {formatDate(record.createdAt)}
          </time>
        </div>
      ))}
    </div>
  );
}

function RecordsContent() {
  const [callDays, setCallDays] = React.useState(CALL_RECORD_DAYS);
  const [callSummary, setCallSummary] = React.useState<PortalCallRecordSummary | null>(null);
  const [tab, setTab] = React.useState<RecordTab>("calls");
  const [callRecords, setCallRecords] = React.useState<PortalCallRecord[] | null>(null);
  const [tenantCurrency, setTenantCurrency] = React.useState("");
  const [callTotal, setCallTotal] = React.useState(0);
  const [callPage, setCallPage] = React.useState(0);
  const [callCursors, setCallCursors] = React.useState<string[]>([""]);
  const [nextCallCursor, setNextCallCursor] = React.useState("");
  const [callError, setCallError] = React.useState(false);
  const [callReload, setCallReload] = React.useState(0);
  const searchParams = useSearchParams();
  const requestIdParam = searchParams.get("request_id") ?? "";
  const focusRequestId = REQUEST_ID_PATTERN.test(requestIdParam) ? requestIdParam : "";
  const [expandedRequestId, setExpandedRequestId] = React.useState<string | null>(focusRequestId || null);

  const [fileRecords, setFileRecords] = React.useState<MergedRecord[] | null>(null);
  const [fileTotal, setFileTotal] = React.useState(0);
  const [fileOffset, setFileOffset] = React.useState(0);
  const [fileError, setFileError] = React.useState(false);
  const [fileReload, setFileReload] = React.useState(0);
  const callCursor = callCursors[callPage] ?? "";

  React.useEffect(() => {
    const controller = new AbortController();
    // 使用个人账单透传的租户币种，不向浏览器开放管理员设置接口。
    void fetch(portalPath("/api/me/billing"), {cache: "no-store", signal: controller.signal})
      .then(async response => response.ok ? response.json() as Promise<{data?: {currency?: string}}> : null)
      .then(body => setTenantCurrency(body?.data?.currency ?? ""))
      .catch(() => {});
    return () => controller.abort();
  }, []);

  React.useEffect(() => {
    if (tab !== "calls") return;
    const controller = new AbortController();
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      days: String(callDays),
    });
    if (callCursor) params.set("cursor", callCursor);
    if (focusRequestId) params.set("request_id", focusRequestId);
    fetch(portalPath("/api/me/call-records?" + params.toString()), {
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("call_records_unavailable");
        return response.json() as Promise<{
          summary?: PortalCallRecordSummary;
          records?: PortalCallRecord[];
          total?: number;
          nextCursor?: string;
        }>;
      })
      .then((payload) => {
        setCallSummary(payload.summary ?? null);
        setCallRecords(Array.isArray(payload.records) ? payload.records : []);
        setCallTotal(typeof payload.total === "number" ? payload.total : 0);
        setNextCallCursor(typeof payload.nextCursor === "string" ? payload.nextCursor : "");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setCallSummary(null);
        setCallRecords([]);
        setNextCallCursor("");
        setCallError(true);
      });
    return () => controller.abort();
  }, [tab, callCursor, callReload, callDays, focusRequestId]);

  React.useEffect(() => {
    if (tab !== "files") return;
    const controller = new AbortController();
    fetch(portalPath("/api/me/records?limit=" + PAGE_SIZE + "&offset=" + fileOffset), {
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("file_records_unavailable");
        return response.json() as Promise<{ records?: MergedRecord[]; total?: number }>;
      })
      .then((payload) => {
        setFileRecords(Array.isArray(payload.records) ? payload.records : []);
        setFileTotal(typeof payload.total === "number" ? payload.total : 0);
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setFileRecords([]);
        setFileError(true);
      });
    return () => controller.abort();
  }, [tab, fileOffset, fileReload]);

  const selectTab = (nextTab: RecordTab) => {
    if (nextTab === tab) return;
    if (nextTab === "calls") {
      setCallRecords(null);
      setNextCallCursor("");
      setCallError(false);
    } else {
      setFileRecords(null);
      setFileError(false);
    }
    setTab(nextTab);
  };

  const prepareCallPageChange = () => {
    setExpandedRequestId(null);
    setCallRecords(null);
    setNextCallCursor("");
    setCallError(false);
  };

  const showPreviousCallPage = () => {
    if (callPage === 0) return;
    prepareCallPageChange();
    setCallPage((current) => current - 1);
  };

  const showNextCallPage = () => {
    if (!nextCallCursor) return;
    const nextPage = callPage + 1;
    const cursor = nextCallCursor;
    prepareCallPageChange();
    setCallCursors((current) => {
      const next = current.slice(0, nextPage);
      next[nextPage] = cursor;
      return next;
    });
    setCallPage(nextPage);
  };

  const retryCallRecords = () => {
    setCallRecords(null);
    setNextCallCursor("");
    setCallError(false);
    setCallReload((value) => value + 1);
  };

  const changeFileOffset = (nextOffset: number) => {
    setFileRecords(null);
    setFileError(false);
    setFileOffset(nextOffset);
  };

  const retryFileRecords = () => {
    setFileRecords(null);
    setFileError(false);
    setFileReload((value) => value + 1);
  };

  return (
    <PortalShell active="records">
      <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-10">
        <header className="flex flex-col gap-5 border-b pb-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold">调用记录</h1>
            <p className="mt-1.5 text-sm text-muted-foreground">最近 {callDays} 天 · 当前账号</p>
          </div>
          <div className="inline-flex w-fit items-center rounded-md border bg-muted/35 p-1" role="tablist" aria-label="留痕类型">
            <button
              type="button"
              role="tab"
              aria-selected={tab === "calls"}
              onClick={() => selectTab("calls")}
              className={cn(
                "inline-flex h-9 items-center gap-2 rounded px-3 text-sm font-medium transition-colors",
                tab === "calls"
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Activity className="h-4 w-4" />
              调用留痕
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === "files"}
              onClick={() => selectTab("files")}
              className={cn(
                "inline-flex h-9 items-center gap-2 rounded px-3 text-sm font-medium transition-colors",
                tab === "files"
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <FileText className="h-4 w-4" />
              文件留痕
            </button>
          </div>
        </header>

        {tab === "calls" && (
          <div className="mt-6 space-y-4">
            {focusRequestId && (
              <div className="flex items-center gap-3 rounded-md border bg-background px-4 py-2 text-sm">
                <span className="min-w-0 truncate font-mono text-xs">{focusRequestId}</span>
                <Link href="/records" className="shrink-0 text-primary hover:underline">查看全部</Link>
              </div>
            )}
            <label className="flex items-center gap-3 text-sm text-muted-foreground">
              时间范围
              <select className="rounded-md border bg-background px-3 py-2 text-foreground" value={callDays} onChange={(event) => {
                prepareCallPageChange();
                setCallSummary(null);
                setCallPage(0);
                setCallCursors([""]);
                setCallDays(Number(event.target.value));
              }}>
                {[1, 7, 30, 90].map(days => <option key={days} value={days}>最近 {days} 天</option>)}
              </select>
            </label>
            <dl aria-label="所选时间范围汇总" className="grid grid-cols-3 gap-3 rounded-md border bg-background p-4">
              <div><dt className="text-xs text-muted-foreground">平均总耗时</dt><dd className="mt-2 font-semibold tabular-nums">{callSummary?.averageLatencyMs == null ? "—" : formatLatency(callSummary.averageLatencyMs)}</dd></div>
              <div><dt className="text-xs text-muted-foreground">成功率</dt><dd className="mt-2 font-semibold tabular-nums">{callSummary?.successRate == null ? "—" : (callSummary.successRate * 100).toFixed(1) + "%"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">请求数</dt><dd className="mt-2 font-semibold tabular-nums">{callSummary == null ? "—" : formatTokenCount(callSummary.requests)}</dd></div>
            </dl>
          </div>
        )}

        <section className="mt-6 overflow-hidden rounded-md border bg-background/95">
          {tab === "calls" ? (
            <>
			  <div className="hidden min-h-11 grid-cols-[7.5rem_minmax(5rem,1.2fr)_minmax(5rem,1fr)_4rem_5rem_5rem_5rem_5rem_6rem_2.25rem] items-center gap-3 border-b bg-muted/35 px-4 text-xs font-medium text-muted-foreground lg:grid">
                <span>时间</span>
                <span>来源</span>
                <span>模型</span>
                <span>状态</span>
                <span className="text-right">输入 Token</span>
                <span className="text-right">缓存读取</span>
                <span className="text-right">输出 Token</span>
                <span className="text-right">总 Token</span>
				<span className="text-right">消耗金额</span>
                <span />
              </div>
              {callRecords === null ? (
                <LoadingRows />
              ) : callError ? (
                <ErrorBand label="调用留痕暂时不可用" onRetry={retryCallRecords} />
              ) : callRecords.length === 0 ? (
                <EmptyBand label="暂无调用记录" />
              ) : (
                <CallRecordRows
                  records={callRecords}
                  tenantCurrency={tenantCurrency}
                  expandedRequestId={expandedRequestId}
                  focusRequestId={focusRequestId}
                  onToggle={(requestId) =>
                    setExpandedRequestId((current) =>
                      current === requestId ? null : requestId,
                    )
                  }
                />
              )}
              <Pagination
                startIndex={callPage * PAGE_SIZE}
                total={callTotal}
                canPrevious={callPage > 0}
                canNext={Boolean(nextCallCursor)}
                onPrevious={showPreviousCallPage}
                onNext={showNextCallPage}
              />
            </>
          ) : (
            <>
              {fileRecords === null ? (
                <LoadingRows />
              ) : fileError ? (
                <ErrorBand label="文件留痕暂时不可用" onRetry={retryFileRecords} />
              ) : fileRecords.length === 0 ? (
                <EmptyBand label="暂无文件记录" />
              ) : (
                <FileRecordRows records={fileRecords} />
              )}
              <Pagination
                startIndex={fileOffset}
                total={fileTotal}
                canPrevious={fileOffset > 0}
                canNext={fileOffset + PAGE_SIZE < fileTotal}
                onPrevious={() => changeFileOffset(Math.max(0, fileOffset - PAGE_SIZE))}
                onNext={() => changeFileOffset(fileOffset + PAGE_SIZE)}
              />
            </>
          )}
        </section>
      </div>
    </PortalShell>
  );
}

export default function RecordsPage() {
  return (
    <React.Suspense fallback={null}>
      <RecordsContent />
    </React.Suspense>
  );
}
