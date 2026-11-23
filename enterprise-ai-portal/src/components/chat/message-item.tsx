"use client";

import * as React from "react";
import { Markdown } from "./markdown";
import { AlertCircle, Check, CircleStop, Copy, FileText, RefreshCw, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { fmtMs, fmtTps } from "@/lib/model-market";
import { OUTCOME_LABELS, PORTAL_ERROR_MESSAGES, SECURITY_ACTION_LABELS } from "@/lib/portal-errors";
import type { ChatMessage } from "./store";

// 隐私 HTTP 部署（非安全上下文）没有 navigator.clipboard，降级为原生选区复制。
async function copyText(text: string) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
  } catch { /* 走降级路径 */ }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  try {
    textarea.select();
    if (!document.execCommand("copy")) throw new Error("copy_failed");
  } finally {
    textarea.remove();
  }
}

// 回答下方一行：复制、重新生成、脱敏标记、本轮首字与输出速度。审计动作不打扰用户，不显示。
export function MessageMeta({
  securityAction,
  timing,
  onCopy,
  onRegenerate,
}: {
  securityAction?: string;
  timing?: ChatMessage["timing"];
  onCopy: () => Promise<void> | void;
  onRegenerate?: () => void;
}) {
  const [copied, setCopied] = React.useState(false);
  const [failed, setFailed] = React.useState(false);
  const copy = async () => {
    setCopied(false);
    setFailed(false);
    try {
      await onCopy();
      setCopied(true);
    } catch {
      setFailed(true);
    }
    setTimeout(() => { setCopied(false); setFailed(false); }, 1500);
  };
  return (
    <div className="mt-2 flex flex-wrap items-center gap-3.5 text-xs text-muted-foreground/80">
      <button type="button" onClick={copy} className="inline-flex items-center gap-1 hover:text-foreground">
        {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
        {copied ? "已复制" : failed ? "复制失败，请手动选择文本复制" : "复制"}
      </button>
      {onRegenerate && (
        <button type="button" onClick={onRegenerate} className="inline-flex items-center gap-1 hover:text-foreground">
          <RefreshCw className="h-3 w-3" />
          重新生成
        </button>
      )}
      {securityAction === "mask" && (
        <span className="rounded-md border border-amber-500/40 px-1.5 text-amber-600 dark:text-amber-400">{SECURITY_ACTION_LABELS.mask}</span>
      )}
      {timing?.ttftMs != null && (
        <span className="tabular-nums">首字 {fmtMs(timing.ttftMs)}{timing.tps != null ? ` · ${fmtTps(timing.tps)}` : ""}</span>
      )}
    </div>
  );
}

export const MessageItem = React.memo(function MessageItem({
  message,
  streaming,
  isLastAssistant,
  onRegenerate,
}: {
  message: ChatMessage;
  streaming?: boolean;
  isLastAssistant?: boolean;
  onRegenerate?: () => void;
}) {
  const isUser = message.role === "user";
  // 失败/拦截的消息正文为空，可读内容在结局说明里：复制错误说明与请求/拦截编号，而不是空字符串。
  const copyContent =
    !message.content && (message.status === "failed" || message.status === "blocked")
      ? [
          message.error?.message ?? (message.status === "failed" ? PORTAL_ERROR_MESSAGES.upstream_unavailable : PORTAL_ERROR_MESSAGES.security_blocked),
          message.error?.blockId ? `${OUTCOME_LABELS.blockId}：${message.error.blockId}` : "",
          message.error?.requestId ? `${OUTCOME_LABELS.requestId}：${message.error.requestId}` : "",
        ].filter(Boolean).join("\n")
      : message.content;
  const attachments = message.attachments?.length ? (
    <div className="mb-2.5 flex flex-wrap gap-2">
      {message.attachments.map((a, i) =>
        a.previewUrl ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            key={`${a.name}-${i}`}
            src={a.previewUrl}
            alt={a.name}
            title={a.name}
            className="h-24 w-24 rounded-xl border object-cover"
          />
        ) : (
          <span
            key={`${a.name}-${i}`}
            className="inline-flex max-w-full items-center gap-2 rounded-[10px] border bg-background px-2.5 py-1.5 text-xs"
          >
            <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="truncate">{a.name}</span>
          </span>
        ),
      )}
    </div>
  ) : null;
  if (isUser) {
    return (
      <div className="mx-auto mb-5 flex w-full max-w-[760px] justify-end px-6 first:mt-7">
        <div className="max-w-[78%] rounded-2xl rounded-br-sm bg-muted px-4 py-2.5">
          {attachments}
          <Markdown content={message.content} />
        </div>
      </div>
    );
  }
  return (
    <div className="mx-auto mb-6 w-full max-w-[760px] px-6 first:mt-7">
      {attachments}
      <Markdown content={message.content} streaming={streaming} />
      {!streaming && <MessageOutcome message={message} />}
      {!streaming && message.status !== "blocked" && (
        <MessageMeta
          securityAction={message.securityAction}
          timing={message.timing}
          onCopy={() => copyText(copyContent)}
          onRegenerate={isLastAssistant ? onRegenerate : undefined}
        />
      )}
    </div>
  );
});

// 6.1/6.5/6.16：本轮结局说明。拦截 = 网关说明原文 + 请求/拦截编号；停止 = 中性提示，不是红色错误。
function MessageOutcome({ message }: { message: ChatMessage }) {
  const e = message.error;
  if (message.status === "blocked") {
    return (
      <div role="alert" className="mt-2 rounded-xl border border-red-500/35 bg-red-500/5 px-3.5 py-3 text-[13px]">
        <div className="flex items-center gap-1.5 font-medium text-red-600 dark:text-red-400">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
          {e?.message ?? PORTAL_ERROR_MESSAGES.security_blocked}
        </div>
        {e?.notice && <p className="mt-1.5 whitespace-pre-line leading-relaxed">{e.notice}</p>}
        <OutcomeIds requestId={e?.requestId} blockId={e?.blockId} />
      </div>
    );
  }
  if (message.status === "failed") {
    return (
      <div role="alert" className="mt-2 rounded-xl border border-destructive/25 bg-destructive/5 px-3.5 py-2.5 text-[13px] text-destructive">
        <div className="flex items-center gap-1.5">
          <AlertCircle className="h-3.5 w-3.5 shrink-0" />
          {e?.message ?? PORTAL_ERROR_MESSAGES.upstream_unavailable}
        </div>
        <OutcomeIds requestId={e?.requestId} />
      </div>
    );
  }
  if (message.status === "interrupted") {
    return (
      <p className={cn("mt-2 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground")}>
        <CircleStop className="h-3 w-3" />
        {e?.code === "stream_interrupted" ? PORTAL_ERROR_MESSAGES.stream_interrupted : OUTCOME_LABELS.interrupted}
      </p>
    );
  }
  return null;
}

function OutcomeIds({ requestId, blockId }: { requestId?: string; blockId?: string }) {
  if (!requestId && !blockId) return null;
  return (
    <p className="mt-1.5 select-all font-mono text-[11px] text-muted-foreground">
      {blockId ? `${OUTCOME_LABELS.blockId}：${blockId}` : null}
      {blockId && requestId ? " · " : null}
      {requestId ? `${OUTCOME_LABELS.requestId}：${requestId}` : null}
    </p>
  );
}
