"use client";

import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { Bot, LoaderCircle, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DIAGNOSIS_LEVEL_LABEL,
  summaryLabel,
  visibleFindings,
  type DiagnosisReport,
  type DiagnosisSession,
  type DiagnosisSummary,
} from "@/lib/diagnosis";
import { portalPath } from "@/lib/portal-path";
import { cn } from "@/lib/utils";

const BASE = "/api/me/diagnostics/sessions";
const POLL_MS = 1000;
const REQUEST_ID_PATTERN = /^(?:req_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(portalPath(path), {
    cache: "no-store",
    ...init,
    headers: init?.body ? { "content-type": "application/json" } : undefined,
  });
  if (!response.ok) throw new Error("diagnostics_" + response.status);
  return (await response.json()) as T;
}

const LEVEL_TONE: Record<string, string> = {
  confirmed: "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-300",
  suspected: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-300",
  unknown: "border-border bg-muted text-muted-foreground",
};

export function DiagnosisReportCard({ report, onNavigate }: { report: DiagnosisReport; onNavigate?: () => void }) {
  const findings = visibleFindings(report);
  const evidence = findings.flatMap((finding) => finding.evidence ?? []);
  const steps = report.steps ?? [];
  return (
    <div className="space-y-4 break-words rounded-xl border bg-card p-4 text-sm" data-testid="diagnosis-report">
      {report.degraded && <p className="text-xs text-muted-foreground">{report.degraded}</p>}
      {findings.map((finding, index) => (
        <section key={finding.check_id + "-" + index} className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("inline-flex h-6 items-center rounded border px-2 text-xs font-medium", LEVEL_TONE[finding.level] ?? LEVEL_TONE.unknown)}>
              {DIAGNOSIS_LEVEL_LABEL[finding.level] ?? DIAGNOSIS_LEVEL_LABEL.unknown}
            </span>
            <span className="font-semibold">{finding.title}</span>
          </div>
          <p>{finding.impact}</p>
          {!!finding.advice?.length && (
            <ul className="list-disc space-y-1 pl-5">
              {finding.advice.map((advice, i) => <li key={i}>{advice.text}</li>)}
            </ul>
          )}
          {!!finding.excluded?.length && (
            <p className="text-xs text-muted-foreground">已排除：{finding.excluded.join("，")}</p>
          )}
        </section>
      ))}
      {!findings.length && <p>未发现问题</p>}
      {!!report.ok_count && report.ok_count > 0 && (
        <p className="text-xs text-muted-foreground">另有 {report.ok_count} 项正常</p>
      )}
      {!!steps.length && (
        <details>
          <summary className="cursor-pointer text-xs font-medium">排查过程</summary>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs">{steps.map((step, i) => <li key={i}>{step.summary}</li>)}</ol>
        </details>
      )}
      {!!evidence.length && (
        <details>
          <summary className="cursor-pointer text-xs font-medium">证据</summary>
          <div className="mt-2 space-y-3 text-xs">
            {evidence.map((item, i) => (
              <div key={i}>
                {item.kind === "request" && REQUEST_ID_PATTERN.test(item.ref) ? (
                  <a
                    href={portalPath("/records?request_id=" + encodeURIComponent(item.ref))}
                    className="font-mono text-primary hover:underline"
                    onClick={onNavigate}
                  >
                    {item.ref}
                  </a>
                ) : (
                  <div className={cn(item.kind === "request" && "font-mono")}>{item.ref}</div>
                )}
                <div className="text-muted-foreground">{item.summary}</div>
                {item.raw && <pre className="mt-1 whitespace-pre-wrap break-words rounded bg-muted p-2">{item.raw}</pre>}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

export function DiagnosisAssistant() {
  const [open, setOpen] = React.useState(false);
  const [text, setText] = React.useState("");
  const [followup, setFollowup] = React.useState("");
  const [recent, setRecent] = React.useState<DiagnosisSummary[]>([]);
  const [session, setSession] = React.useState<DiagnosisSession | null>(null);
  const [target, setTarget] = React.useState<{ id: string; round: number } | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState("");
  const [asked, setAsked] = React.useState("");
  const submittingRef = React.useRef(false);

  const refreshHistory = React.useCallback(async () => {
    try {
      const list = await api<DiagnosisSummary[]>(BASE);
      setRecent(Array.isArray(list) ? list.slice(0, 5) : []);
    } catch { /* 历史不可用时仍可开始诊断 */ }
  }, []);

  // 每秒轮询一次，会话结束即停。
  React.useEffect(() => {
    if (!target) return;
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const next = await api<DiagnosisSession>(BASE + "/" + encodeURIComponent(target.id));
        if (!active) return;
        setSession(next);
        if (next.status === "running") timer = window.setTimeout(poll, POLL_MS);
        else {
          void refreshHistory();
          if (next.status === "failed") setError("诊断失败，请重试或重新开始诊断");
        }
      } catch {
        if (!active) return;
        setError("诊断进度读取失败，请从最近诊断重新打开");
        setSession({ status: "failed", steps: [] });
      }
    };
    void poll();
    return () => { active = false; window.clearTimeout(timer); };
  }, [target, refreshHistory]);

  const startPolling = (id: string, question?: string) => {
    setError("");
    setAsked(question ?? "");
    setSession({ status: "running", steps: [] });
    setTarget((previous) => ({ id, round: (previous?.round ?? 0) + 1 }));
  };

  const send = async (input?: { kind: "question" | "health"; text: string }) => {
    if (submittingRef.current || session?.status === "running") return;
    const question = followup.trim();
    if (!input && (!target || !question)) return;
    submittingRef.current = true;
    setSubmitting(true);
    setError("");
    try {
      const reply = input
        ? await api<{ session_id?: string }>(BASE, { method: "POST", body: JSON.stringify({ input }) })
        : await api<{ session_id?: string }>(BASE + "/" + encodeURIComponent(target!.id) + "/messages", { method: "POST", body: JSON.stringify({ text: question }) });
      startPolling(reply.session_id || target!.id, input ? undefined : question);
      if (input) setText(""); else setFollowup("");
      void refreshHistory();
    } catch {
      setError("诊断发送失败，请重试");
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  };

  const create = () => { if (text.trim()) void send({ kind: "question", text: text.trim() }); };
  const busy = submitting || session?.status === "running";
  const finished = !!session && session.status !== "running";
  const onEnter = (event: React.KeyboardEvent<HTMLTextAreaElement>, action: () => void) => {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      action();
    }
  };
  const fieldClass = "w-full resize-none rounded-lg border bg-background px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring";

  return (
    <DialogPrimitive.Root open={open} onOpenChange={(next) => { setOpen(next); if (next) void refreshHistory(); }}>
      <DialogPrimitive.Trigger asChild>
        <Button variant="ghost" size="icon" className="h-9 w-9 rounded-xl" aria-label="诊断助手">
          <Bot className="h-4 w-4" />
        </Button>
      </DialogPrimitive.Trigger>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <DialogPrimitive.Content
          aria-describedby={undefined}
          className="fixed inset-y-0 right-0 z-50 flex w-full max-w-[480px] flex-col border-l bg-background shadow-xl focus:outline-none"
        >
          <header className="flex h-16 shrink-0 items-center justify-between border-b px-5">
            <DialogPrimitive.Title className="text-base font-semibold">诊断助手</DialogPrimitive.Title>
            <DialogPrimitive.Close className="rounded-md p-1 opacity-70 hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="关闭">
              <X className="h-4 w-4" />
            </DialogPrimitive.Close>
          </header>
          <div className="flex-1 space-y-4 overflow-y-auto p-5">
            <textarea
              aria-label="诊断问题"
              rows={3}
              className={fieldClass}
              placeholder="粘贴报错、请求编号，或直接描述问题"
              value={text}
              onChange={(event) => setText(event.target.value)}
              onKeyDown={(event) => onEnter(event, create)}
            />
            <div className="flex gap-2">
              <Button disabled={busy || !text.trim()} onClick={create}>发送</Button>
              <Button variant="outline" disabled={busy} onClick={() => void send({ kind: "health", text: "" })}>一键体检</Button>
            </div>
            {!!recent.length && (
              <section aria-label="最近诊断" className="space-y-1">
                <h3 className="text-xs font-medium text-muted-foreground">最近诊断</h3>
                {recent.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    disabled={busy}
                    onClick={() => startPolling(item.id)}
                    className="block w-full truncate rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent disabled:opacity-50"
                  >
                    {summaryLabel(item)}
                  </button>
                ))}
              </section>
            )}
            {error && <p role="alert" className="rounded-lg border border-destructive/40 px-3 py-2 text-sm text-destructive">{error}</p>}
            {session?.status === "running" && (
              <section aria-label="诊断进度" className="space-y-2 text-sm">
                <LoaderCircle className="h-4 w-4 animate-spin text-muted-foreground" />
                <ol className="list-decimal space-y-1 pl-5">{session.steps?.map((step, i) => <li key={i}>{step.summary}</li>)}</ol>
              </section>
            )}
            {finished && asked && (
              <p className="rounded-lg border bg-muted/50 px-3 py-2 text-sm">
                <span className="text-muted-foreground">你的追问：</span>
                {asked}
              </p>
            )}
            {finished && session.report && <DiagnosisReportCard report={session.report} onNavigate={() => setOpen(false)} />}
            {finished && (
              <div className="space-y-2">
                <textarea
                  aria-label="追问"
                  rows={2}
                  className={fieldClass}
                  placeholder="继续追问"
                  value={followup}
                  onChange={(event) => setFollowup(event.target.value)}
                  onKeyDown={(event) => onEnter(event, () => void send())}
                />
                <Button variant="outline" disabled={busy || !followup.trim()} onClick={() => void send()}>发送追问</Button>
              </div>
            )}
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
