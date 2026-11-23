"use client";

import * as React from "react";
import { Menu, AlertCircle, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { DiagnosisAssistant } from "@/components/diagnosis-assistant";
import { Composer } from "./composer";
import { EmptyState } from "./empty-state";
import { MessageItem } from "./message-item";
import { ModelSelector } from "./model-selector";
import { useChatStore, type ChatMessage } from "./store";
import { assembleUserContent, type ImageAttachmentMeta, type MessageContent, type ContentPart } from "@/lib/upload";
import type { FileAttachment } from "./composer";
import { portalPath } from "@/lib/portal-path";
import { ChatTimer } from "@/lib/chat-timing";
import { streamChatRequest } from "@/lib/chat-stream";
import { OUTCOME_LABELS, PORTAL_ERROR_MESSAGES } from "@/lib/portal-errors";
import { enrichModel } from "@/lib/model-catalog";

function messageId(suffix: "u" | "a") {
  return `m${Date.now()}${Math.random().toString(36).slice(2, 6)}${suffix}`;
}

function buildUserContent(text: string, attachments: ImageAttachmentMeta[], files: FileAttachment[]): MessageContent {
  // 历史消息保持 string；仅当轮 user 消息组多模态（图片不进历史，防字节重传）
  const userContent = assembleUserContent(text, attachments);
  // 文件附件转 extracted_content 契约（对齐网关 claude.ai 客户端抽取先例）：
  // 文本进 messages，reference 标字节留证位置；原始字节已在 /api/upload 旁路网关留证仓，不进 messages
  const fileParts: ContentPart[] = files.map((f) => ({
    type: "text" as const,
    text: f.text || `[文件:${f.name}]`,
    extracted_content: { reference: f.reference, filename: f.name, source: "portal_upload" },
  }));
  if (fileParts.length === 0) return userContent;
  return Array.isArray(userContent)
    ? [...userContent, ...fileParts]
    : [{ type: "text", text: userContent }, ...fileParts];
}

/** 进历史的消息：只发 user/assistant；被拦截/失败且无正文的 assistant 不进上下文 */
function historyOf(msgs: ChatMessage[]) {
  return msgs
    .filter((m) => m.role === "user" || m.role === "assistant")
    .filter((m) => !(m.role === "assistant" && (m.status === "blocked" || m.status === "failed")))
    .filter((m) => m.role === "user" || m.content)
    .map((m) => ({ role: m.role, content: m.content as MessageContent }));
}

export function ChatPanel({
  onOpenSidebar,
}: {
  onOpenSidebar: () => void;
  sidebarCollapsed?: boolean;
}) {
  const {
    current,
    currentId,
    currentLoaded,
    currentModel,
    modelsState,
    models,
    setCurrentModel,
    newConversation,
    ensureConversationPersisted,
    getConversation,
    appendMessage,
    appendToMessage,
    patchMessage,
    user,
  } = useChatStore();

  // 6.7：流状态按会话隔离（切会话不影响另一个会话的生成，也不串写）
  const [streaming, setStreaming] = React.useState<Record<string, string>>({});
  const [notice, setNotice] = React.useState<{ cid: string | null; text: string } | null>(null);
  const streamsRef = React.useRef<Map<string, { cancel: () => void }>>(new Map());
  const scrollRef = React.useRef<HTMLDivElement>(null);
  const stickRef = React.useRef(true);

  const streamingId = currentId ? streaming[currentId] ?? null : null;
  const messages = React.useMemo(() => current?.messages ?? [], [current]);
  const lastContentLength = messages.length ? messages[messages.length - 1]!.content.length : 0;

  // 6.14：生成中跟随滚动；用户上翻后不再强拉到底
  React.useEffect(() => {
    const el = scrollRef.current;
    if (el && stickRef.current) el.scrollTop = el.scrollHeight;
  }, [messages.length, lastContentLength, streamingId]);
  React.useEffect(() => {
    stickRef.current = true;
  }, [currentId]);
  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    stickRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  };

  const selectedModel = React.useMemo(() => models.map(enrichModel).find((m) => m.id === currentModel), [models, currentModel]);
  const supportsImages = selectedModel?.supportsImageInput === true;
  const modelUnavailable = modelsState !== "ready" || !currentModel;

  const setStreamingFor = (cid: string, id: string | null) =>
    setStreaming((prev) => {
      const next = { ...prev };
      if (id) next[cid] = id;
      else delete next[cid];
      return next;
    });

  const runStream = (
    cid: string,
    assistantId: string,
    history: { role: string; content: MessageContent }[],
    attachments: ImageAttachmentMeta[],
    regenerate: boolean,
  ) => {
    streamsRef.current.get(cid)?.cancel();
    setStreamingFor(cid, assistantId);
    const timer = new ChatTimer();
    const handle = streamChatRequest(
      portalPath("/api/chat"),
      {
        conversationId: cid,
        model: currentModel,
        messages: history,
        attachments: attachments.map((a) => ({ name: a.name, mime: a.mime, size: a.size })),
        ...(regenerate ? { regenerate: true } : {}),
      },
      {
        onChunk: (chunk) => {
          timer.chunk();
          appendToMessage(cid, assistantId, chunk);
        },
        onUsage: (n) => timer.usage(n),
        onMeta: ({ securityAction }) => {
          if (securityAction) patchMessage(cid, assistantId, { securityAction });
        },
        onEnd: (outcome) => {
          if (streamsRef.current.get(cid) === handle) streamsRef.current.delete(cid);
          setStreamingFor(cid, null);
          if (outcome.kind === "done") {
            patchMessage(cid, assistantId, { timing: timer.result() });
          } else if (outcome.kind === "stopped") {
            patchMessage(cid, assistantId, { status: "interrupted" });
          } else if (outcome.kind === "error") {
            const e = outcome.error;
            patchMessage(cid, assistantId, {
              status: e.kind === "blocked" ? "blocked" : e.kind === "interrupted" ? "interrupted" : "failed",
              error: e,
            });
          }
        },
      },
    );
    streamsRef.current.set(cid, handle);
  };

  const send = async (text: string, attachments: ImageAttachmentMeta[] = [], files: FileAttachment[] = []) => {
    if (modelUnavailable) return;
    if (attachments.length > 0 && !supportsImages) {
      setNotice({ cid: currentId, text: OUTCOME_LABELS.imageNotSupported });
      return;
    }
    let cid = currentId;
    if (!cid) cid = await newConversation();
    // 首条消息发送时才真正落库（懒创建：避免空"新对话"堆在侧栏）
    const fallbackTitle = Array.from(text.replace(/\s+/g, " ").trim() || "新对话").slice(0, 20).join("");
    try {
      cid = await ensureConversationPersisted(cid, fallbackTitle);
    } catch {
      setNotice({ cid, text: PORTAL_ERROR_MESSAGES.upstream_unavailable });
      return;
    }
    setNotice(null);

    // 6.7：从 store 的最新快照取历史，而不是闭包里的旧列表
    const priorMessages = getConversation(cid)?.messages ?? [];
    appendMessage(cid, {
      id: messageId("u"),
      role: "user",
      content: text,
      sendImages: attachments,
      sendFiles: files,
      attachments: [
        ...attachments.map((a) => ({ name: a.name, mime: a.mime, size: a.size, previewUrl: a.dataUrl })),
        ...files.map((f) => ({ name: f.name, mime: "document", size: f.size, previewUrl: "" })),
      ],
    });
    const assistantId = messageId("a");
    appendMessage(cid, { id: assistantId, role: "assistant", content: "", model: currentModel });
    runStream(
      cid,
      assistantId,
      [...historyOf(priorMessages), { role: "user", content: buildUserContent(text, attachments, files) }],
      attachments,
      false,
    );
  };

  // 6.5：停止不是错误——只标记这条回答"已中断"，已生成内容保留
  const stop = () => {
    if (!currentId) return;
    streamsRef.current.get(currentId)?.cancel();
  };

  // 6.6：替换最后一轮回答；不重复写 user；带回当轮图片/文件
  const regenerate = () => {
    if (!current || streamingId || modelUnavailable) return;
    const msgs = current.messages;
    const lastUserIdx = msgs.map((m) => m.role).lastIndexOf("user");
    if (lastUserIdx < 0) return;
    const lastUser = msgs[lastUserIdx]!;
    const lastAssistant = msgs.slice(lastUserIdx + 1).find((m) => m.role === "assistant");
    const images = lastUser.sendImages ?? [];
    const files = lastUser.sendFiles ?? [];
    const history = [
      ...historyOf(msgs.slice(0, lastUserIdx)),
      { role: "user", content: buildUserContent(lastUser.content, images, files) },
    ];
    let assistantId = lastAssistant?.id;
    if (lastAssistant) {
      patchMessage(current.id, lastAssistant.id, {
        content: "",
        status: null,
        error: undefined,
        securityAction: undefined,
        model: currentModel,
      });
    } else {
      assistantId = messageId("a");
      appendMessage(current.id, { id: assistantId, role: "assistant", content: "", model: currentModel });
    }
    runStream(current.id, assistantId!, history, images, true);
  };

  // 6.14：MessageItem 是 memo 组件，传稳定引用，避免每个 token 让整列消息重渲染
  const regenerateRef = React.useRef(regenerate);
  React.useLayoutEffect(() => {
    regenerateRef.current = regenerate;
  });
  const onRegenerate = React.useCallback(() => regenerateRef.current(), []);

  const lastAssistantId = [...messages].reverse().find((m) => m.role === "assistant")?.id;
  const visibleNotice = notice && (notice.cid === currentId || notice.cid === null) ? notice.text : null;
  const composerHint =
    modelsState === "loading"
      ? undefined
      : modelsState !== "ready"
        ? OUTCOME_LABELS.noModel
        : !currentLoaded
          ? OUTCOME_LABELS.loadingConversation
          : undefined;

  const empty = messages.length === 0;
  const modelSelector = (
    <ModelSelector value={currentModel} onChange={setCurrentModel} disabled={!!streamingId} placement="up" />
  );
  const composer = (
    <Composer
      onSend={(t, atts, files) => send(t, atts, files)}
      onStop={stop}
      isStreaming={!!streamingId}
      disabled={modelUnavailable || !currentLoaded}
      allowImages={supportsImages}
      model={currentModel}
      modelSlot={modelSelector}
      placeholder={empty ? undefined : "继续提问…"}
    />
  );

  return (
    <section className="relative flex h-full min-w-0 flex-1 flex-col">
      <header className={cn("grid h-[52px] shrink-0 grid-cols-[1fr_auto_1fr] items-center gap-3 px-4 sm:px-5", !empty && "border-b")}>
        <div className="flex min-w-0 items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 rounded-lg lg:hidden"
            onClick={onOpenSidebar}
            aria-label="打开侧栏"
          >
            <Menu className="h-4 w-4" />
          </Button>
          {!empty && <span className="truncate text-sm text-muted-foreground">{current?.title ?? "新对话"}</span>}
        </div>
        <div />
        <div className="flex items-center justify-end gap-3">
          <DiagnosisAssistant />
          <span className="inline-flex items-center gap-1.5 text-xs text-primary" title="守护中">
            <ShieldCheck className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">守护中</span>
          </span>
        </div>
      </header>

      <div ref={scrollRef} onScroll={onScroll} className="flex-1 overflow-y-auto">
        {empty ? (
          <EmptyState name={user?.name ?? ""} composer={composer} onPick={(p) => send(p)} />
        ) : (
          <div className="pb-4">
            {messages.map((m) => (
              <MessageItem
                key={m.id}
                message={m}
                streaming={streamingId === m.id}
                isLastAssistant={m.id === lastAssistantId}
                onRegenerate={m.id === lastAssistantId ? onRegenerate : undefined}
              />
            ))}
          </div>
        )}
      </div>

      {(visibleNotice || composerHint) && (
        <div className="px-4 pb-2">
          <p className="mx-auto flex max-w-[760px] items-center gap-2 rounded-lg bg-destructive/5 px-4 py-2 text-xs text-destructive">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            {visibleNotice ?? composerHint}
          </p>
        </div>
      )}

      {!empty && composer}
    </section>
  );
}
